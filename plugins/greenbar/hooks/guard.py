#!/usr/bin/env python3
"""greenbar guard: a PreToolUse hook for Claude Code. Python 3.9+, standard library only.

Runs before Claude reads or edits a file, searches, or runs a shell command, and blocks
(exit code 2, with the reason shown to Claude):

  1. Reading, searching or editing off-limits paths (default: env files, private keys,
     secrets/), including through shell commands, wildcards and `cd`.
  2. Credential folders in your home directory (~/.ssh, ~/.aws, ~/.gnupg, ...).
  3. Writes to read-only paths, and to "locked once committed" paths such as applied
     migrations (creating a new file there is still fine).
  4. Weakening tests: adding skip markers to test files, or deleting test files.
  5. Forced pushes, `--no-verify`, `git reset --hard`, `git clean -f`, and `rm -rf` aimed
     at /, ~, .. or the project root.
  6. A `git commit` whose changes contain a never-commit file or something that looks like
     a secret (cloud keys, tokens, private keys, quoted passwords).

Rules live in .claude/guard.json (see guard.example.json). It is a guard rail for an
assistant, not a sandbox: see README, "What it does not do".
Turn it off for the repo: touch .claude/guard.off
"""

from __future__ import annotations

import fnmatch
import glob
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

DEFAULTS: Dict[str, Any] = {
    "off_limits": [
        ".env", ".env.*", "!.env.example", "!.env.sample", "!.env.template",
        "*.pem", "*.key", "id_rsa*", "id_ed25519*", "secrets/**", ".secrets/**",
    ],
    "read_only": [],
    "locked_once_committed": [],
    "test_files": [
        "test_*.py", "*_test.py", "tests/**", "test/**", "__tests__/**", "spec/**",
        "*.test.*", "*.spec.*", "*_test.go", "*Test.java", "*_spec.rb",
    ],
    "protect_tests": True,
    "never_commit": [".env", ".env.*", "!.env.example", "!.env.sample", "*.pem", "*.key", "id_rsa*"],
    "scan_commits_for_secrets": True,
    "block_force_push": True,
    "block_no_verify": True,
    "block_destructive_git": True,
    "block_rm_rf_roots": True,
}
SENSITIVE_HOME = (".ssh", ".aws", ".gnupg", ".netrc", ".docker", ".kube", ".pypirc",
                  ".config/gcloud", ".azure", ".npmrc")
FILE_TOOLS = {"Read", "Edit", "Write", "MultiEdit", "NotebookEdit"}
WRITE_TOOLS = FILE_TOOLS - {"Read"}
SEPARATORS = {";", "&&", "||", "|", "&", "(", ")", "\n"}
SEARCH_COMMANDS = {"grep", "egrep", "fgrep", "rg", "ag"}
FILE_COMMANDS = {
    "ls", "cd", "pushd", "find", "tree", "du", "cat", "bat", "head", "tail", "less", "more",
    "wc", "sort", "uniq", "cut", "awk", "sed", "xxd", "od", "strings", "file", "stat",
    "cp", "mv", "rm", "tar", "zip", "unzip", "rsync", "scp", "open", "diff", "cmp",
    "base64", "nl", "tac", "jq", "column", "iconv", "split", "ln", "chmod", "source", ".",
    "vi", "vim", "nano", "code", "xargs", "env", "dotenv", "shred", "truncate", "tee",
}
CHANGES_ALL_ARGS = {"rm", "mv", "tee", "truncate", "touch", "ln", "chmod", "install",
                    "unlink", "shred"}
GIT_FILE_CHANGERS = {"mv", "rm", "checkout", "restore"}
FIND_PATTERN_OPTIONS = {"-path", "-ipath", "-name", "-iname", "-wholename", "-regex", "-iregex"}
GLOB_CHARS = set("*?[")
MAX_SCAN_BYTES = 1_000_000
MESSAGE_ARG = re.compile(r"""(?<!\S)(?:-m|--message)(?:=|\s+)(?:"[^"]*"|'[^']*'|\S+)""")
GIT_COMMAND = re.compile(r"\bgit\b(?:\s+(?:-[cC]\s*\S+|--?[\w-]+(?:=\S+)?))*\s+(\w[\w-]*)")
SKIP_MARKER = re.compile(
    r"@pytest\.mark\.(skip|xfail)\b|@unittest\.skip|\bpytest\.skip\(|\bself\.skipTest\(|"
    r"\b(it|test|describe|context)\.(skip|todo)\(|\b(xit|xtest|xdescribe)\(|"
    r"\bt\.Skip(Now|f)?\(|#\[ignore\]|@Disabled\b|@Ignore\b|\bskip:\s*true\b"
)
SECRET = re.compile(
    r"AKIA[0-9A-Z]{16}"
    r"|sk_live_[0-9a-zA-Z]{16,}|rk_live_[0-9a-zA-Z]{16,}"
    r"|sk-ant-[0-9a-zA-Z_-]{20,}|sk-proj-[0-9a-zA-Z_-]{20,}"
    r"|gh[pousr]_[0-9a-zA-Z]{30,}|github_pat_[0-9a-zA-Z_]{30,}"
    r"|xox[baprs]-[0-9a-zA-Z-]{10,}|AIza[0-9A-Za-z_-]{35}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|(?i:password|passwd|secret|api[_-]?key|token)\w*[\"']?\s*[:=]\s*[\"'][^\"'\s]{12,}[\"']"
)


def block(message: str) -> None:
    print(f"greenbar guard: {message}", file=sys.stderr)
    sys.exit(2)


# ---------- patterns ----------

def glob_to_regex(pattern: str) -> str:
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return "".join(out)


class Rules:
    """A gitignore-style list: a pattern without '/' matches a name at any depth; '!' excepts."""

    def __init__(self, patterns: Iterable[str]) -> None:
        self.include: List[re.Pattern] = []
        self.exclude: List[re.Pattern] = []
        for raw in patterns:
            text = str(raw).strip()
            negate = text.startswith("!")
            text = text[1:] if negate else text
            if not text:
                continue
            anchored = "/" in text.rstrip("/").replace("**/", "", 1) if text.startswith("**/") else "/" in text.rstrip("/")
            core = text.lstrip("/")
            while core.endswith("/**") or core.endswith("/"):
                core = core[:-3] if core.endswith("/**") else core[:-1]  # "dir/**" also matches "dir"
            body = glob_to_regex(core)
            rx = re.compile(("" if anchored else "(?:.*/)?") + body + "(?:/.*)?$", re.IGNORECASE)
            (self.exclude if negate else self.include).append(rx)

    def match(self, rel: str) -> bool:
        rel = rel.strip("/")
        if not rel or rel == ".":
            return False
        if any(rx.match(rel) for rx in self.exclude):
            return False
        return any(rx.match(rel) for rx in self.include)


class Config:
    def __init__(self, root: Path) -> None:
        data: Dict[str, Any] = {}
        path = root / ".claude" / "guard.json"
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except ValueError as exc:
                block(f"cannot parse {path} ({exc}). Fix it so the guard can run.")
            if not isinstance(data, dict):
                block(f"{path} must contain a JSON object.")
        merged = {**DEFAULTS, **data}
        self.flags = merged
        self.off_limits = Rules(merged["off_limits"])
        self.read_only = Rules(merged["read_only"])
        self.locked = Rules(merged["locked_once_committed"])
        self.tests = Rules(merged["test_files"])
        self.never_commit = Rules(merged["never_commit"])


# ---------- paths ----------

def project_dir() -> Path:
    return Path(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()).resolve()


def relative(path_text: str, root: Path, base: Optional[Path] = None) -> Optional[str]:
    path = Path(path_text).expanduser()
    if not path.is_absolute():
        path = (base or root) / path
    try:
        return path.resolve().relative_to(root).as_posix()
    except (ValueError, OSError, RuntimeError):
        return None


def names_sensitive_home(text: str) -> bool:
    home = re.escape(str(Path.home()))
    folders = "|".join(re.escape(f) for f in SENSITIVE_HOME)
    return bool(re.search(rf"(?:~|\$HOME|\$\{{HOME\}}|{home})/(?:{folders})(?![\w-])", text))


def expand(pattern: str) -> List[str]:
    """Wildcard expansion that, like the shell, also matches hidden files in the last part."""
    folder, name = os.path.split(pattern)
    if GLOB_CHARS & set(folder):
        return glob.glob(pattern)[:500]
    try:
        entries = os.listdir(folder or ".")
    except OSError:
        return []
    return [os.path.join(folder, e) for e in fnmatch.filter(entries, name)][:500]


def git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=False,
                            text=True, errors="replace", timeout=15)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout


def is_committed(rel: str, root: Path) -> bool:
    """Fails closed: if git cannot answer, treat the file as committed."""
    try:
        return bool(git(root, "ls-files", "--", rel).strip())
    except (RuntimeError, OSError, subprocess.SubprocessError):
        return True


def write_problem(rel: str, root: Path, cfg: Config) -> Optional[str]:
    if cfg.read_only.match(rel):
        return f"{rel} is read-only in this repo (guard.json, read_only)."
    if cfg.locked.match(rel) and (root / rel).exists() and is_committed(rel, root):
        return (f"{rel} is already committed and locked (guard.json, locked_once_committed). "
                "Add a new file instead of changing this one.")
    return None


# ---------- file and search tools ----------

def added_text(tool: str, tool_input: Dict[str, Any]) -> List[str]:
    """(old, new) text pairs for the change, so we can tell whether skip markers were added."""
    if tool == "Edit":
        return [str(tool_input.get("old_string") or ""), str(tool_input.get("new_string") or "")]
    if tool == "MultiEdit":
        edits = tool_input.get("edits") or []
        old = "\n".join(str(e.get("old_string") or "") for e in edits if isinstance(e, dict))
        new = "\n".join(str(e.get("new_string") or "") for e in edits if isinstance(e, dict))
        return [old, new]
    return ["", str(tool_input.get("content") or tool_input.get("new_source") or "")]


def check_test_tamper(tool: str, tool_input: Dict[str, Any], rel: str, root: Path) -> None:
    old, new = added_text(tool, tool_input)
    if tool in ("Write", "NotebookEdit"):
        try:
            old = (root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            old = ""
    if len(SKIP_MARKER.findall(new)) > len(SKIP_MARKER.findall(old)):
        block(f"this change adds a skip/ignore marker to the test file {rel}. Fix the code "
              "or the test instead; if a test really must be skipped, ask the user first.")


def check_file_tool(tool: str, tool_input: Dict[str, Any], root: Path, cfg: Config) -> None:
    target = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
    if names_sensitive_home(str(Path(target).expanduser())):
        block("that file is in a credential folder in your home directory.")
    rel = relative(target, root)
    if rel is None:
        return
    if cfg.off_limits.match(rel):
        block(f"{rel} is off limits in this repo (guard.json, off_limits).")
    if tool in WRITE_TOOLS:
        problem = write_problem(rel, root, cfg)
        if problem:
            block(problem)
        if cfg.flags["protect_tests"] and cfg.tests.match(rel):
            check_test_tamper(tool, tool_input, rel, root)


def check_search_tool(tool: str, tool_input: Dict[str, Any], root: Path, cfg: Config) -> None:
    base_text = str(tool_input.get("path") or ".")
    if names_sensitive_home(str(Path(base_text).expanduser())):
        block("that search reaches into a credential folder in your home directory.")
    base = relative(base_text, root)
    if base is not None and cfg.off_limits.match(base):
        block(f"{base} is off limits in this repo (guard.json, off_limits).")
    pattern = tool_input.get("pattern") if tool == "Glob" else tool_input.get("glob")
    for word in str(pattern or "").replace(",", " ").replace("{", " ").replace("}", " ").split():
        if pattern_hits(word, cfg.off_limits):
            block(f"this search targets an off-limits path ({word}).")


# ---------- shell ----------

def split_words(command: str) -> List[str]:
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:
        return command.split()


def segments(words: List[str]) -> List[range]:
    out, begin = [], 0
    for stop in [*(i for i, w in enumerate(words) if w in SEPARATORS), len(words)]:
        if stop > begin:
            out.append(range(begin, stop))
        begin = stop + 1
    return out


def command_name(words: List[str], seg: range) -> str:
    """The program a segment runs, skipping `sudo`, `env`, `VAR=x` and `command` prefixes."""
    for i in seg:
        w = words[i]
        if "=" in w and not w.startswith("-") or w in ("sudo", "command", "nohup", "time"):
            continue
        return os.path.basename(w)
    return ""


def bare_path_args(words: List[str]) -> Set[int]:
    picked: Set[int] = set()
    for seg in segments(words):
        name = os.path.basename(words[seg[0]])
        positional = [i for i in seg[1:] if not words[i].startswith("-")]
        if name in SEARCH_COMMANDS:
            picked.update(positional[1:])
        elif name in FILE_COMMANDS:
            picked.update(positional)
    return picked


def write_targets(words: List[str]) -> Set[int]:
    targets: Set[int] = set()
    for seg in segments(words):
        name = command_name(words, seg)
        args = [i for i in seg[1:] if not words[i].startswith("-")]
        if name in CHANGES_ALL_ARGS or (name == "sed" and any(words[i].startswith("-i") for i in seg)):
            targets.update(args)
        elif name in ("cp", "mv") and args:
            targets.add(args[-1])
        elif name == "git" and len(args) > 1 and words[args[0]] in GIT_FILE_CHANGERS:
            targets.update(args[1:])
        targets.update(i + 1 for i in seg if words[i] in (">", ">>", ">|", "&>") and i + 1 < len(words))
    return targets


def deleted_targets(words: List[str]) -> Set[int]:
    found: Set[int] = set()
    for seg in segments(words):
        name = command_name(words, seg)
        args = [i for i in seg[1:] if not words[i].startswith("-")]
        if name in ("rm", "unlink", "shred"):
            found.update(args)
        elif name == "git" and len(args) > 1 and words[args[0]] == "rm":
            found.update(args[1:])
        elif name == "mv" and len(args) > 1:
            found.update(args[:-1])
    return found


def working_dirs(words: List[str], start: Path) -> List[Path]:
    dirs: List[Path] = []
    current, pending, begin = start, None, 0
    for index, word in enumerate(words):
        if word in SEPARATORS:
            if pending is not None:
                current, pending = pending, None
            begin = index + 1
        elif index == begin + 1 and words[begin] in ("cd", "pushd"):
            target = Path(word).expanduser()
            pending = (target if target.is_absolute() else current / target).resolve()
        elif index == begin and word in ("cd", "pushd"):
            pending = Path.home()
        dirs.append(current)
    return dirs


def paths_named(words: List[str], root: Path, start: Path, only: Optional[Set[int]] = None) -> List[str]:
    dirs = working_dirs(words, start)
    as_path = bare_path_args(words) if only is None else only
    patterns = {i + 1 for i, w in enumerate(words) if w in FIND_PATTERN_OPTIONS}
    found: List[str] = []
    for index, word in enumerate(words):
        if (only is not None and index not in only) or index in patterns:
            continue
        here = dirs[index] if index < len(dirs) else start
        for piece in re.split(r"[=:<>|;&(){}]", word):
            if not piece or piece.startswith("-"):
                continue
            if GLOB_CHARS & set(piece) and not any(c.isspace() for c in word):
                matches = expand(piece if os.path.isabs(piece) else str(here / piece))
                if not matches and (index in as_path or "/" in piece):
                    matches = [piece]  # unmatched wildcard: judge the pattern text itself
            elif "/" in piece or index in as_path:
                matches = [piece]
            else:
                continue
            for match in matches:
                rel = relative(match, root, here)
                if rel is not None:
                    found.append(rel)
    return found


def pattern_hits(pattern: str, rules: Rules) -> bool:
    """Could this wildcard pattern match an off-limits path? Tries a few concrete stand-ins."""
    text = pattern.replace("**/", "").lstrip("/")
    samples = {re.sub(r"\*+|\?", fill, text) for fill in ("", "x", ".local", "/x")}
    samples |= {s.lstrip("./") for s in samples}
    return any(s and rules.match(s) for s in samples)


def check_find_patterns(words: List[str], cfg: Config) -> None:
    for i, w in enumerate(words[:-1]):
        if w in FIND_PATTERN_OPTIONS and pattern_hits(words[i + 1], cfg.off_limits):
            block(f"this find targets an off-limits path ({words[i + 1]}).")


def check_rm_rf(words: List[str], root: Path, start: Path) -> None:
    dirs = working_dirs(words, start)
    for seg in segments(words):
        if command_name(words, seg) != "rm":
            continue
        flags = "".join(words[i].lstrip("-") for i in seg if words[i].startswith("-"))
        long_flags = {words[i] for i in seg if words[i].startswith("--")}
        recursive = "r" in flags.lower() or "--recursive" in long_flags
        if not recursive:
            continue
        for i in seg[1:]:
            w = words[i]
            if w.startswith("-"):
                continue
            if w in ("/", "/*", "~", "~/", "~/*", "$HOME", "${HOME}", "..", "../", "*", ".", "./"):
                block(f"`rm -r {w}` would delete far more than intended. Name the exact paths.")
            target = Path(w).expanduser()
            target = (target if target.is_absolute() else dirs[i] / target).resolve()
            if target in (Path.home(), Path("/")) or root.is_relative_to(target):
                block(f"`rm -r {w}` would delete the project or a folder that contains it.")


def check_git(command: str, cfg: Config) -> Set[str]:
    subs = {m.group(1) for m in GIT_COMMAND.finditer(command)}
    if not subs:
        return subs
    if re.search(r"--output\b|--no-index\b|--ext-diff\b", command):
        block("git options that read or write arbitrary files are not allowed here.")
    force = r"(?<!\S)(?:--force\S*|-\w*f\w*|\+\S+)(?!\S)"
    if cfg.flags["block_force_push"] and "push" in subs and re.search(force, command):
        block("forced pushes are not allowed. If one is really needed, the user runs it by hand.")
    if cfg.flags["block_no_verify"] and re.search(r"(?<!\S)--no-verify(?!\S)", command) or (
        cfg.flags["block_no_verify"] and "commit" in subs and re.search(r"\bcommit\b.*(?<!\S)-\w*n\w*(?!\S)", command)
    ):
        block("--no-verify skips the repo's own checks. Fix what the hooks report instead.")
    if cfg.flags["block_destructive_git"]:
        if "reset" in subs and re.search(r"\breset\b.*--hard\b", command):
            block("`git reset --hard` throws away uncommitted work. Use `git stash` or ask the user.")
        if "clean" in subs and re.search(r"\bclean\b.*(?<!\S)-\w*f", command):
            block("`git clean -f` deletes untracked files for good. Ask the user first.")
        if subs & {"checkout", "restore"} and re.search(r"\b(checkout|restore)\b(\s+--\S*)*\s+(--\s+)?\.(\s|$)", command):
            block("this discards every uncommitted change in the repo. Name specific files.")
    return subs


def commit_scope(command: str, subs: Set[str]) -> str:
    if subs - {"commit", "status", "diff", "log", "show"}:
        return "everything"
    if re.search(r"\bcommit\b.*(?<!\S)(?:--all|-[a-zA-Z]*a[a-zA-Z]*)(?!\S)", command):
        return "tracked"
    return "staged"


def commit_candidates(root: Path, scope: str):
    has_head = subprocess.run(["git", "-C", str(root), "rev-parse", "--verify", "-q", "HEAD"],
                              capture_output=True, check=False).returncode == 0
    base = ["HEAD"] if has_head else ["--cached"]
    names = git(root, "diff", "--name-only", "--cached").splitlines()
    diff = git(root, "diff", "--text", "-U0", "--cached")
    if scope != "staged":
        names += git(root, "diff", "--name-only", *base).splitlines()
        diff += git(root, "diff", "--text", "-U0", *base)
    untracked = git(root, "ls-files", "--others", "--exclude-standard").splitlines() if scope == "everything" else []
    lines, current = [], "?"
    for ln in diff.splitlines():
        if ln.startswith("+++ "):
            current = ln[6:] if ln.startswith("+++ b/") else ln[4:]
        elif ln.startswith("+"):
            lines.append((current, ln[1:]))
    for name in untracked:
        path = root / name
        try:
            if path.is_file() and path.stat().st_size <= MAX_SCAN_BYTES:
                text = path.read_bytes().decode("utf-8", errors="replace")
                lines += [(name, ln) for ln in text.splitlines()]
        except OSError:
            continue
    return sorted(set(names + untracked)), lines


def check_commit(root: Path, scope: str, cfg: Config) -> None:
    try:
        names, lines = commit_candidates(root, scope)
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        block(f"commit blocked: the secret check could not run ({exc}).")
    bad = [n for n in names if cfg.never_commit.match(n)]
    if bad:
        block("commit blocked: these files must never be committed:\n  " + "\n  ".join(bad[:10])
              + "\nUnstage them (git restore --staged <file>) and add them to .gitignore.")
    if cfg.flags["scan_commits_for_secrets"]:
        hits = sorted({name for name, ln in lines if SECRET.search(ln)})
        if hits:
            block("commit blocked: changed lines look like a secret (key, token or quoted "
                  "password) in:\n  " + "\n  ".join(hits[:10]) + "\nMove the value to an env "
                  "variable. If it is a false alarm, the user can commit by hand.")


def check_bash(command: str, root: Path, start: Path, cfg: Config) -> None:
    command = MESSAGE_ARG.sub(" ", command)  # a commit message may mention .env
    if names_sensitive_home(command):
        block("this command reaches into a credential folder in your home directory.")
    words = split_words(command)
    check_find_patterns(words, cfg)
    named = paths_named(words, root, start)
    off = sorted({rel for rel in named if cfg.off_limits.match(rel)})
    if off:
        block(f"this command touches {', '.join(off[:3])}, which is off limits (guard.json).")
    if cfg.flags["block_rm_rf_roots"]:
        check_rm_rf(words, root, start)
    written = paths_named(words, root, start, only=write_targets(words))
    for rel in sorted(set(written)):
        problem = write_problem(rel, root, cfg)
        if problem:
            block(problem)
    if cfg.flags["protect_tests"]:
        deleted = paths_named(words, root, start, only=deleted_targets(words))
        tests = sorted({rel for rel in deleted if cfg.tests.match(rel)})
        if tests:
            block(f"this deletes test files ({', '.join(tests[:3])}). Ask the user before removing tests.")
    subs = check_git(command, cfg)
    if "commit" in subs:
        check_commit(root, commit_scope(command, subs), cfg)


def main() -> None:
    try:
        event = json.load(sys.stdin)
        tool = event["tool_name"]
        tool_input = event.get("tool_input") or {}
        if not isinstance(tool, str) or not isinstance(tool_input, dict):
            raise TypeError("unexpected hook input shape")
    except (ValueError, KeyError, TypeError) as exc:
        block(f"could not read the hook input ({exc}), so the action was blocked.")
    root = project_dir()
    if (root / ".claude" / "guard.off").exists():
        sys.exit(0)
    cfg = Config(root)
    if tool in FILE_TOOLS:
        check_file_tool(tool, tool_input, root, cfg)
    elif tool in ("Grep", "Glob"):
        check_search_tool(tool, tool_input, root, cfg)
    elif tool == "Bash":
        cwd = event.get("cwd")
        start = Path(cwd) if isinstance(cwd, str) and os.path.isdir(cwd) else root
        check_bash(str(tool_input.get("command", "")), root, start.resolve(), cfg)


if __name__ == "__main__":
    main()
