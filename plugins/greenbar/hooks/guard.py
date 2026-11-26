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

Shell commands are read by shell_parse.py (next to this file): it splits the command line
the way a shell would and hands back each command that would really run, with wrappers such
as `sudo`, `env` or `timeout 30` stripped and `sh -c '...'`, `eval` and `$(...)` followed.

Rules live in .claude/guard.json (see guard.example.json). It is a seatbelt for an
assistant, not a sandbox: see README, "What it does not do".
Turn it off for the repo: touch .claude/guard.off
"""

from __future__ import annotations

import fnmatch
import glob
import hashlib
import itertools
import json
import os
import re
import shlex
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

sys.dont_write_bytecode = True  # leave no __pycache__ in the plugin folder
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import shell_parse as sh
except ImportError as exc:
    print(f"greenbar guard: shell_parse.py must sit next to guard.py ({exc}); not checked.", file=sys.stderr)
    sys.exit(1)

DEFAULTS: Dict[str, Any] = {
    "off_limits": [
        ".env", ".env.*", "!*.example", "!*.sample", "!*.template", "!*.dist",
        "*.pem", "*.key", "id_rsa*", "id_ed25519*", "secrets/**", ".secrets/**",
    ],
    "read_only": [],
    "locked_once_committed": [],
    "test_files": [
        "test_*.py", "*_test.py", "tests/**", "test/**", "__tests__/**", "spec/**",
        "*.test.*", "*.spec.*", "*_test.go", "*Test.java", "*_spec.rb",
        "!__snapshots__/**", "!.pytest_cache/**", "!__pycache__/**", "!*.pyc", "!*.snap",
    ],
    "protect_tests": True,
    "never_commit": [".env", ".env.*", "!.env.example", "!.env.sample", "*.pem", "*.key", "id_rsa*"],
    "scan_commits_for_secrets": True,
    "block_force_push": True,
    "block_no_verify": True,
    "block_destructive_git": True,
    "block_rm_rf_roots": True,
    "block_env_dump": True,
}
LIST_KEYS = ("off_limits", "read_only", "locked_once_committed", "test_files", "never_commit")
SENSITIVE_HOME = (".ssh", ".aws", ".gnupg", ".netrc", ".docker", ".kube", ".pypirc",
                  ".config/gcloud", ".azure", ".npmrc")
FILE_TOOLS = {"Read", "Edit", "Write", "MultiEdit", "NotebookEdit"}
WRITE_TOOLS = FILE_TOOLS - {"Read"}
SEARCH_COMMANDS = {"grep", "egrep", "fgrep", "rg", "ag"}
FILE_COMMANDS = {
    "ls", "cd", "pushd", "find", "tree", "du", "cat", "bat", "head", "tail", "less", "more",
    "wc", "sort", "uniq", "cut", "awk", "sed", "xxd", "od", "strings", "file", "stat",
    "cp", "mv", "rm", "tar", "zip", "unzip", "rsync", "scp", "open", "diff", "cmp",
    "base64", "nl", "tac", "jq", "column", "iconv", "split", "ln", "chmod", "source", ".",
    "vi", "vim", "nano", "code", "xargs", "env", "dotenv", "shred", "truncate", "tee",
    "dd", "rev", "paste", "hexdump", "zcat", "gzip", "fold", "fmt", "comm", "ed", "ex",
    "view", "xz", "bzip2", "install", "ditto",
}
CHANGES_ALL_ARGS = {"rm", "mv", "tee", "truncate", "touch", "ln", "chmod", "install",
                    "unlink", "shred"}
GIT_FILE_CHANGERS = {"mv", "rm", "checkout", "restore"}
FIND_PATTERN_OPTIONS = {"-path", "-ipath", "-name", "-iname", "-wholename", "-regex", "-iregex"}
GLOB_CHARS = set("*?[")
MAX_SCAN_BYTES = 1_000_000
GIT_COMMAND = re.compile(r"\bgit\b(?:\s+(?:-[cC]\s*\S+|--?[\w-]+(?:=\S+)?))*\s+(\w[\w-]*)")
SKIP_MARKER = re.compile(
    r"@pytest\.mark\.(skip|xfail)\b|@unittest\.skip|\bpytest\.skip\(|\bself\.skipTest\(|"
    r"\b(it|test|describe|context)\.(skip|todo)\(|\b(xit|xtest|xdescribe)\(|"
    r"\bt\.Skip(Now|f)?\(|#\[ignore\]|@Disabled\b|@Ignore\b|\bskip:\s*true\b"
)
TEST_DEF = re.compile(
    r"^\s*(?:async\s+)?def\s+test\w*\s*\(|^\s*(?:it|test)\s*\(\s*['\"`]|"
    r"^\s*func\s+Test\w+\s*\(|^\s*#\[test\]|^\s*@Test\b",
    re.MULTILINE,
)
SECRET = re.compile(
    r"AKIA[0-9A-Z]{16}"
    r"|sk_live_[0-9a-zA-Z]{16,}|rk_live_[0-9a-zA-Z]{16,}"
    r"|sk-ant-[0-9a-zA-Z_-]{20,}|sk-proj-[0-9a-zA-Z_-]{20,}"
    r"|gh[pousr]_[0-9a-zA-Z]{30,}|github_pat_[0-9a-zA-Z_]{30,}"
    r"|xox[baprs]-[0-9a-zA-Z-]{10,}|AIza[0-9A-Za-z_-]{35}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|(?i:(?<![a-z0-9])(?:[a-z0-9]+_)?(?:password|passwd|secret|api[_-]?key|token)s?(?![a-z0-9]))"
    r"[\"']?\s*[:=]\s*[\"'][^\"'\s]{12,}[\"']"
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
            core = text.lstrip("/") if not text.startswith("**/") else text[3:]
            while core.endswith("/**") or core.endswith("/"):
                core = core[:-3] if core.endswith("/**") else core[:-1]  # "dir/**" also matches "dir"
            anchored = "/" in core or (text.startswith("/") and not text.startswith("**/"))
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


def trust_entry(root: Path) -> Dict[str, Any]:
    """This folder's record in the trust store that `done_gate.py trust` writes (outside the repo)."""
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    try:
        data = json.loads((Path(base) / "greenbar" / "trusted.json").read_text(encoding="utf-8"))
        entry = data.get(str(root)) if isinstance(data, dict) else None
        return entry if isinstance(entry, dict) else {}
    except (OSError, ValueError):
        return {}


def file_digest(path: Path) -> Optional[str]:
    try:
        return "symlink" if path.is_symlink() else hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def off_stamp(path: Path) -> Optional[str]:
    """Identity of the guard.off file the user trusted: a re-created file does not match."""
    try:
        st = path.lstat()
        return f"{st.st_ino}:{st.st_mtime_ns}"
    except OSError:
        return None


def tighten_only(data: Dict[str, Any]) -> Dict[str, Any]:
    """An untrusted repo's guard.json may add rules but never remove or relax one."""
    merged = dict(DEFAULTS)
    for key in LIST_KEYS:
        extra = [p for p in data.get(key) or [] if isinstance(p, str) and not p.startswith("!")]
        merged[key] = list(DEFAULTS[key]) + extra
    for key, value in DEFAULTS.items():
        if isinstance(value, bool) and data.get(key) is True:
            merged[key] = True
    return merged


class Config:
    def __init__(self, root: Path) -> None:
        data: Dict[str, Any] = {}
        path = root / ".claude" / "guard.json"
        self.error = ""
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(data, dict):
                    raise ValueError("it must contain a JSON object")
            except (OSError, ValueError) as exc:
                self.error = f"{path} is unreadable ({exc}); using the default rules"
                data = {}
        trusted = bool(data) and trust_entry(root).get("guard") == file_digest(path)
        merged = {**DEFAULTS, **data} if trusted else tighten_only(data)
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


def expand(pattern: str, hidden: bool = False) -> List[str]:
    """Wildcard expansion as the shell does it: `*` skips hidden files, `.e*` finds them."""
    folder, name = os.path.split(pattern)
    if GLOB_CHARS & set(folder):
        return list(itertools.islice(glob.iglob(pattern), 500))
    try:
        entries = os.listdir(folder or ".")
    except OSError:
        return []
    if not hidden and not name.startswith("."):
        entries = [e for e in entries if not e.startswith(".")]
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
    if len(TEST_DEF.findall(new)) < len(TEST_DEF.findall(old)):
        block(f"this change removes tests from {rel}. Fix the code instead; if a test is really "
              "obsolete, ask the user to remove it.")


def check_file_tool(tool: str, tool_input: Dict[str, Any], root: Path, cfg: Config) -> None:
    target = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
    try:
        resolved = str(Path(target).expanduser().resolve())
    except (OSError, RuntimeError):
        resolved = target
    if names_sensitive_home(str(Path(target).expanduser())) or names_sensitive_home(resolved):
        block("that file is in a credential folder in your home directory.")
    rel = relative(target, root)
    if rel is None or rel in (".claude/guard.json", ".claude/guard.off"):
        return  # outside the project, or the guard's own config (so a broken one can be fixed)
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
# shell_parse turns the command text into the commands that would really run (wrappers
# stripped, `sh -c` strings and $(...) followed); the checks below judge each of those.

PLAIN = frozenset(FILE_COMMANDS | SEARCH_COMMANDS | CHANGES_ALL_ARGS | {
    "echo", "printf", "git", "test", "[", "[[", "for", "case", "select", "export", "declare",
    "local", "typeset", "readonly", "alias", "set", "unset", "read", "true", "false", ":",
    "printenv", "which", "type", "man", "mkdir", "rmdir", "basename", "dirname", "realpath",
    "readlink", "kill", "sleep", "tr", "seq", "eval", "trap",
})  # programs whose arguments are data, never another command to run
SENSITIVE = frozenset(
    (FILE_COMMANDS | SEARCH_COMMANDS | CHANGES_ALL_ARGS | sh.SHELLS | {"git", "eval", "printenv"})
    - {".", "install", "cd", "pushd", "env", "xargs", "dotenv"}
)  # a word that, found among an unknown program's arguments, is checked as a command
RM_ROOTS = {"/", "/*", "~", "~/", "~/*", "$HOME", "${HOME}", "..", "../", ".", "./"}
MESSAGE_COMMANDS = {"commit", "tag", "merge", "stash", "notes", "revert"}
MAX_DEPTH, MAX_STRINGS, MAX_SECONDS = 12, 400, 25
HOME_VARIABLE = re.compile(r"\$\{HOME\}|\$HOME(?!\w)")
NOT_A_FILE_OPTION = re.compile(r"exclude|ignore|include|glob|pattern|name|regex|expr|format|color|sort|type")
WRAPPER_FILE_OPTIONS = {"-a", "--arg-file", "-o", "--output"}
GIT_VALUE_OPTIONS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path",
                     "--super-prefix", "--config-env"}


def home_text(word: str) -> str:
    return HOME_VARIABLE.sub(lambda _m: str(Path.home()), word)


def word_paths(word: str, here: Path, root: Path, as_path: bool) -> List[str]:
    """Project-relative paths a word may name. Wildcards and braces are expanded."""
    if not as_path and any(c.isspace() for c in word):
        return []  # prose (a PR body, a search pattern), not a file name
    found: List[str] = []
    spellings = sh.braces(home_text(word))
    if "$" in word:  # `.e${nothing}nv`: an unset variable expands to nothing
        spellings += sh.braces(sh.VARIABLE.sub("", word))
    for candidate in spellings:
        for piece in re.split(r"[=:<>|;&(){}]", candidate):
            if not piece or piece.startswith("-"):
                continue
            piece = os.path.expanduser(piece)
            if GLOB_CHARS & set(piece) and not any(c.isspace() for c in word):
                matches = expand(piece if os.path.isabs(piece) else str(here / piece))
                if not matches and (as_path or "/" in piece):
                    matches = [piece]  # unmatched wildcard: judge the pattern text itself
            elif "/" in piece or as_path:
                matches = [piece]
            else:
                continue
            for match in matches:
                rel = relative(match, root, here)
                if rel is not None:
                    found.append(rel)
    return found


def path_args(cmd: sh.Command) -> Set[int]:
    """Positions in argv that are file names even without a slash (`cat notes`)."""
    argv = cmd.argv
    positional = [i for i in range(1, len(argv)) if not argv[i].startswith("-")]
    if cmd.name in SEARCH_COMMANDS:
        patterns = {i + 1 for i, w in enumerate(argv) if re.fullmatch(r"-[A-Za-z]*e|--regexp", w)}
        files = {i + 1 for i, w in enumerate(argv) if re.fullmatch(r"-[A-Za-z]*f|--file", w)}
        if patterns or files or any(w.startswith(("--regexp=", "--file=")) for w in argv):
            return set(positional) - patterns  # the pattern came from an option: the rest are files
        return set(positional[1:])
    if cmd.name == "jq":
        return set(positional[1:])  # the first word is the filter, e.g. `.env.NODE_ENV`
    if cmd.name in FILE_COMMANDS or cmd.name in sh.SHELLS:
        return set(positional)  # for a shell: the script and its arguments
    return set()


def named(cmd: sh.Command, root: Path) -> List[str]:
    as_path = path_args(cmd)
    patterns = {i + 1 for i, w in enumerate(cmd.argv) if w in FIND_PATTERN_OPTIONS}
    here = Path(cmd.cwd)
    found: List[str] = []
    for i, word in enumerate(cmd.argv):
        if i not in patterns:
            found += word_paths(word, here, root, i in as_path)
        option, equals, value = word.partition("=")
        if (equals and option.startswith("--") and (cmd.name in FILE_COMMANDS or cmd.name in SEARCH_COMMANDS)
                and not NOT_A_FILE_OPTION.search(option)):
            found += word_paths(value, here, root, True)  # tar --file=NAME
    for word in cmd.assigns:
        found += word_paths(word, here, root, False)
    for word in cmd.file_redirects():
        found += word_paths(word, here, root, True)
    for i, word in enumerate(cmd.wrapper_words):  # xargs -a FILE, time -o FILE
        option, equals, value = word.partition("=")
        if i and cmd.wrapper_words[i - 1] in WRAPPER_FILE_OPTIONS:
            found += word_paths(word, here, root, True)
        elif equals and option in WRAPPER_FILE_OPTIONS:
            found += word_paths(value, here, root, True)
        else:
            found += word_paths(word, here, root, False)
    return found


def reaches_home_secret(cmd: sh.Command) -> bool:
    """A credential folder named outright, or reached after `cd ~` (`cd ~ && cat .ssh/id_rsa`)."""
    as_path = path_args(cmd)
    home = os.path.realpath(str(Path.home()))
    words = [(w, i in as_path) for i, w in enumerate(cmd.argv)] + [(w, True) for w in cmd.file_redirects()]
    for word, is_path in words + [(w, False) for w in cmd.assigns + cmd.wrapper_words]:
        if names_sensitive_home(word):
            return True
        for piece in home_text(word).split("="):
            if not piece or piece.startswith("-") or not (is_path or "/" in piece):
                continue
            full = os.path.join(cmd.cwd, os.path.expanduser(piece))
            guesses = [full] if cmd.cwd_known else [full, os.path.join(home, piece)]  # `cd $X`: maybe home
            for match in [*guesses, *(expand(full) if GLOB_CHARS & set(piece) else [])]:
                real = os.path.realpath(match)
                for folder in SENSITIVE_HOME:
                    secret = os.path.join(home, folder)
                    if real == secret or real.startswith(secret + os.sep):
                        return True
    return False


def git_words(argv: List[str]) -> List[str]:
    """A git command from its subcommand on: `git -C "my dir" push -f` -> [push, -f]."""
    i = 1
    while i < len(argv) and argv[i].startswith("-"):
        i += 2 if argv[i] in GIT_VALUE_OPTIONS else 1
    return argv[i:]


def write_targets(cmd: sh.Command) -> List[str]:
    args = [w for w in cmd.argv[1:] if not w.startswith("-")]
    targets: List[str] = []
    in_place = cmd.name == "sed" and any(w.startswith(("-i", "--in-place")) for w in cmd.argv)
    if cmd.name in CHANGES_ALL_ARGS or in_place:
        targets += args
    elif cmd.name == "cp" and args:
        targets.append(args[-1])
    elif cmd.name == "git":
        args = [w for w in git_words(cmd.argv) if not w.startswith("-")]
        targets += args[1:] if args and args[0] in GIT_FILE_CHANGERS else []
    return targets + cmd.file_redirects(writes_only=True)


def deleted_targets(cmd: sh.Command) -> List[str]:
    args = [w for w in cmd.argv[1:] if not w.startswith("-")]
    if cmd.name in ("rm", "unlink", "shred"):
        return args
    args = [w for w in git_words(cmd.argv) if not w.startswith("-")] if cmd.name == "git" else []
    if len(args) > 1 and args[0] == "rm" and "--cached" not in cmd.argv:
        return args[1:]
    return []


def moved_out_of_tests(cmd: sh.Command, root: Path, cfg: Config) -> List[str]:
    """Test files that `mv` / `git mv` would move somewhere that is not a test path."""
    args = [w for w in (git_words(cmd.argv) if cmd.name == "git" else cmd.argv[1:]) if not w.startswith("-")]
    if cmd.name == "git" and args and args[0] == "mv":
        args = args[1:]
    elif cmd.name != "mv":
        return []
    if len(args) < 2:
        return []
    here = Path(cmd.cwd)
    dest = relative(args[-1], root, here)
    if dest is not None and (cfg.tests.match(dest.rstrip("/") + "/x_test.py") or cfg.tests.match(dest)):
        return []  # moved into another test location
    rels = [relative(w, root, here) for w in args[:-1]]
    return [rel for rel in rels if rel is not None and cfg.tests.match(rel)]


def pattern_hits(pattern: str, rules: Rules) -> bool:
    """Could this wildcard pattern match an off-limits path? Tries a few concrete stand-ins."""
    text = pattern.replace("**/", "").lstrip("/")
    samples = {re.sub(r"\*+|\?", fill, text) for fill in ("", "x", ".local", "/x")}
    samples |= {s.lstrip("./") for s in samples}
    return any(s and rules.match(s) for s in samples)


def check_find_patterns(cmd: sh.Command, cfg: Config, root: Path) -> None:
    """`find -name PATTERN`: refuse a pattern that fits an off-limits name, real or likely."""
    try:
        present = os.listdir(cmd.cwd)
    except OSError:
        present = []
    for i, w in enumerate(cmd.argv[:-1]):
        if w not in FIND_PATTERN_OPTIONS:
            continue
        value = cmd.argv[i + 1]
        real = [relative(name, root, Path(cmd.cwd)) for name in fnmatch.filter(present, os.path.basename(value))]
        if pattern_hits(value, cfg.off_limits) or any(rel and cfg.off_limits.match(rel) for rel in real):
            block(f"this find targets an off-limits path ({value}).")


def check_rm_rf(cmd: sh.Command, root: Path) -> None:
    if cmd.name != "rm":
        return
    flags = [w for w in cmd.argv[1:] if w.startswith("-")]
    long_form = [w for w in flags if w.startswith("--r") and "--recursive".startswith(w)]
    if not long_form and not any(not w.startswith("--") and "r" in w.lower() for w in flags):
        return
    here = Path(cmd.cwd)
    inside_sub = cmd.cwd_known and here != root and is_within(here, root)
    for word in cmd.argv[1:]:
        for w in ([] if word.startswith("-") else sh.braces(word)):
            if w in RM_ROOTS or (w == "*" and not inside_sub):
                block(f"`rm -r {w}` would delete far more than intended. Name the exact paths.")
            if w == "*":
                continue
            text = home_text(re.sub(r"\$\{?PWD\}?", lambda _m: str(here), w))
            while text.endswith("/*") or (text.endswith("/") and len(text) > 1):
                text = text[:-2] if text.endswith("/*") else text[:-1]  # `dir/*` empties dir
            target = Path(os.path.expandvars(text or "/")).expanduser()
            target = (target if target.is_absolute() else here / target).resolve()
            if target in (Path.home(), Path("/")) or is_within(root, target):
                block(f"`rm -r {w}` would delete the project or a folder that contains it.")


def is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def without_message(argv: List[str]) -> List[str]:
    """A git command minus its message text: a commit message may mention .env or `rm -rf`."""
    if not MESSAGE_COMMANDS & set(argv):
        return argv
    out: List[str] = []
    skip = False
    for word in argv:
        if skip:
            skip = False
        elif word == "--message" or re.fullmatch(r"-[a-zA-Z]*m", word):
            out.append(word)
            skip = True
        elif word.startswith("--message=") or re.fullmatch(r"-m.+", word):
            out.append("-m")
        else:
            out.append(word)
    return out


def check_git(cmds: List[sh.Command], root: Path, cfg: Config) -> None:
    """Check each git invocation on its own words, so `git push && rm -f x` is not a force push."""
    subs: Set[str] = set()
    texts: List[str] = []
    for cmd in cmds:
        if cmd.name == "git":
            text = " ".join(shlex.quote(w) for w in ["git", *git_words(cmd.argv)])
            options = " ".join(cmd.argv[1:len(cmd.argv) - len(git_words(cmd.argv))])
            if cfg.flags["block_no_verify"] and re.search(r"core\.hooksPath", options, re.IGNORECASE):
                block("overriding core.hooksPath switches off the repo's own git hooks. Fix what they report instead.")
            subs |= check_git_segment(text, cfg)
            texts.append(text)
    if "commit" in subs:
        check_commit(root, commit_scope(" ; ".join(texts), subs), cfg)


def check_git_segment(command: str, cfg: Config) -> Set[str]:
    subs = {m.group(1) for m in GIT_COMMAND.finditer(command)}
    if not subs:
        return subs
    if cfg.flags["block_no_verify"] and re.search(r"core\.hooksPath", command, re.IGNORECASE):
        block("overriding core.hooksPath switches off the repo's own git hooks. Fix what they report instead.")
    if re.search(r"--output\b|--no-index\b|--ext-diff\b", command):
        block("git options that read or write arbitrary files are not allowed here.")
    force = r"(?<!\S)(?:--force\S*|-\w*f\w*|\+\S+)(?!\S)"
    if cfg.flags["block_force_push"] and "push" in subs and re.search(force, command):
        block("forced pushes are not allowed. If one is really needed, the user runs it by hand.")
    if cfg.flags["block_no_verify"] and re.search(r"(?<!\S)--no-veri\w*(?!\S)", command) or (
        cfg.flags["block_no_verify"] and "commit" in subs and re.search(r"\bcommit\b.*(?<!\S)-(?!u)\w*n\w*(?!\S)", command)
    ):
        block("--no-verify skips the repo's own checks. Fix what the hooks report instead.")
    if cfg.flags["block_destructive_git"]:
        if "reset" in subs and re.search(r"\breset\b.*--ha\w*", command):
            block("`git reset --hard` throws away uncommitted work. Use `git stash` or ask the user.")
        if "clean" in subs and re.search(r"\bclean\b.*(?<!\S)(?:-\w*f|--f\w*)", command):
            block("`git clean -f` deletes untracked files for good. Ask the user first.")
        if subs & {"checkout", "restore"} and re.search(r"\b(checkout|restore)\b(\s+-\S+)*\s+(--\s+)?\.(\s|$)", command):
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


def check_env_dump(cmd: sh.Command) -> None:
    name, rest = cmd.name, cmd.argv[1:]
    if cmd.derived:
        dumps = name == "printenv" and not rest  # `go env`, `npm pkg set` are not the shell built-ins
    else:
        dumps = name == "env" or (name in ("set", "printenv") and not rest) or (
            name in ("export", "declare", "typeset") and all(w.startswith("-") for w in rest))
    if dumps:
        block(f"`{name}` prints every environment variable, secrets included, into the transcript. "
              "Print the one variable you need, e.g. `echo $NODE_ENV`.")


def check_commands(cmds: List[sh.Command], root: Path, cfg: Config) -> None:
    for cmd in cmds:
        if reaches_home_secret(cmd):
            block("this command reaches into a credential folder in your home directory.")
        check_find_patterns(cmd, cfg, root)
        if cfg.flags["block_env_dump"]:
            check_env_dump(cmd)
    off = sorted({rel for cmd in cmds for rel in named(cmd, root) if cfg.off_limits.match(rel)})
    if off:
        block(f"this command touches {', '.join(off[:3])}, which is off limits (guard.json).")
    written: Set[str] = set()
    deleted: Set[str] = set()
    for cmd in cmds:
        here = Path(cmd.cwd)
        if cfg.flags["block_rm_rf_roots"]:
            check_rm_rf(cmd, root)
        for word in write_targets(cmd):
            written.update(word_paths(word, here, root, True))
        for word in deleted_targets(cmd):
            deleted.update(rel for rel in word_paths(word, here, root, True) if cfg.tests.match(rel))
        deleted.update(moved_out_of_tests(cmd, root, cfg))
    for rel in sorted(written):
        problem = write_problem(rel, root, cfg)
        if problem:
            block(problem)
    if cfg.flags["protect_tests"] and deleted:
        block(f"this deletes test files ({', '.join(sorted(deleted)[:3])}). Ask the user before removing tests.")
    check_git(cmds, root, cfg)


def check_bash(command: str, root: Path, start: Path, cfg: Config, depth: int = 0,
               variables: Optional[Dict[str, str]] = None, budget: Optional[List[int]] = None) -> None:
    budget = [MAX_STRINGS] if budget is None else budget
    budget[0] -= 1
    if depth > MAX_DEPTH or budget[0] < 0:
        block("this command nests more shells than the guard will follow. Run the inner command directly.")
    cmds, strings, unbalanced = sh.parse(command, str(start), variables, PLAIN, SENSITIVE)
    for cmd in cmds:
        if cmd.name == "git":
            cmd.argv = without_message(cmd.argv)
    check_commands(cmds, root, cfg)
    for text, where, known in strings:
        check_bash(text, root, Path(where), cfg, depth + 1, known, budget)
    if unbalanced:  # quotes do not pair up, so the reading above may be wrong: read it again without them
        check_bash(re.sub(r"[\"'`]", " ", command), root, start, cfg, depth + 1, variables, budget)


def timed_out(*_args: Any) -> None:
    raise TimeoutError("the guard took too long to read this command")


def main() -> None:
    try:
        event = json.load(sys.stdin)
        tool = event["tool_name"]
        tool_input = event.get("tool_input") or {}
        if not isinstance(tool, str) or not isinstance(tool_input, dict):
            raise TypeError("unexpected hook input shape")
    except (ValueError, KeyError, TypeError) as exc:
        print(f"greenbar guard: could not read the hook input ({exc}); not checked.", file=sys.stderr)
        sys.exit(1)  # non-blocking error: a future input format must not brick every tool call
    root = project_dir()
    off = root / ".claude" / "guard.off"
    if off.exists() and trust_entry(root).get("guard-off") == off_stamp(off):
        sys.exit(0)
    cfg = Config(root)
    if tool in FILE_TOOLS:
        check_file_tool(tool, tool_input, root, cfg)
    elif tool in ("Grep", "Glob"):
        check_search_tool(tool, tool_input, root, cfg)
    elif tool == "Bash":
        cwd = event.get("cwd")
        start = Path(cwd) if isinstance(cwd, str) and os.path.isdir(cwd) else root
        try:
            if hasattr(signal, "SIGALRM"):  # a command built to stall the guard must not outlast the hook timeout
                signal.signal(signal.SIGALRM, timed_out)
                signal.alarm(MAX_SECONDS)
            check_bash(str(tool_input.get("command", "")), root, start.resolve(), cfg)
        except Exception as exc:  # noqa: BLE001 - an unreadable command must not slip through unchecked
            block(f"could not read this command ({type(exc).__name__}). Simplify it, or ask the user to run it.")
        finally:
            if hasattr(signal, "SIGALRM"):
                signal.alarm(0)


if __name__ == "__main__":
    if sys.version_info < (3, 9):
        print("greenbar guard needs Python 3.9 or newer; not checked.", file=sys.stderr)
        sys.exit(1)
    main()
