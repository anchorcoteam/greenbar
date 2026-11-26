#!/usr/bin/env python3
"""greenbar done gate: a Stop hook for Claude Code. Python 3.9+, standard library only.

When Claude tries to end its turn, this hook runs your project's real checks (tests,
lint, type check: whatever you list in .claude/done-gate.json). If any check fails,
Claude is not allowed to stop. It gets the failing command and the end of its output,
and it has to fix the cause or tell you plainly that it could not.

It does not re-run checks when nothing changed since the last green run, so a
conversation with no code changes costs nothing. After `max_consecutive_blocks`
failed attempts in a row it lets Claude stop and warns you, so it cannot loop forever.

Checks only run after you trust that exact config, so a cloned repo cannot make this hook
run its own commands:     python3 done_gate.py trust [project_dir]
(re-run it whenever you change .claude/done-gate.json; /greenbar:setup does it for you).

Turn it off for one shell:   DONE_GATE_OFF=1 claude
Turn it off for the repo:    touch .claude/done-gate.off
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

CONFIG_NAME = "done-gate.json"
STATE_DIR = ".done-gate"
DEFAULTS: Dict[str, Any] = {
    "checks": [],
    "timeout_seconds": 600,
    "total_timeout_seconds": 1500,
    "max_consecutive_blocks": 3,
    "skip_when_unchanged": True,
    "announce_pass": True,
    "output_tail_lines": 40,
}
SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next",
    "target", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", "coverage",
}
MAX_WALK_FILES = 20000
MAX_UNTRACKED_HASH_BYTES = 4_000_000
MAX_TOTAL_HASH_BYTES = 64_000_000
LOCK_WAIT_SECONDS = 10
SECRET = re.compile(
    r"AKIA[0-9A-Z]{16}|[sr]k_live_[0-9a-zA-Z]{16,}|sk-ant-[0-9a-zA-Z_-]{20,}|sk-proj-[0-9a-zA-Z_-]{20,}"
    r"|gh[pousr]_[0-9a-zA-Z]{30,}|github_pat_[0-9a-zA-Z_]{30,}|xox[baprs]-[0-9a-zA-Z-]{10,}"
    r"|AIza[0-9A-Za-z_-]{35}|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|(?i:(?:password|passwd|secret|api[_-]?key|token)\w*[\"']?\s*[:=]\s*)[\"']?[^\"'\s]{8,}"
)
CLAIM = re.compile(
    r"\b(all (the )?tests (now )?pass|tests (are )?(now )?passing|tests pass|"
    r"everything (is )?(works|working|passes|green)|(it'?s|that'?s|i'?m|all) done|"
    r"\bdone\b|complete[d]?\b|fixed\b|ready to (merge|ship))",
    re.IGNORECASE,
)


def emit(payload: Dict[str, Any]) -> None:
    print(json.dumps(payload))
    sys.exit(0)


def allow(message: Optional[str] = None) -> None:
    if message:
        emit({"systemMessage": message})
    sys.exit(0)


def project_root(event: Dict[str, Any]) -> Path:
    raw = os.environ.get("CLAUDE_PROJECT_DIR") or event.get("cwd") or os.getcwd()
    return Path(str(raw)).resolve()


def load_config(root: Path) -> Optional[Dict[str, Any]]:
    path = root / ".claude" / CONFIG_NAME
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    config = {**DEFAULTS, **data}
    checks = config["checks"]
    if not isinstance(checks, list) or not all(
        isinstance(c, dict) and isinstance(c.get("run"), str) and c["run"].strip() for c in checks
    ):
        raise ValueError(f"{path}: every entry in \"checks\" needs a non-empty \"run\" string")
    for key in ("timeout_seconds", "total_timeout_seconds", "max_consecutive_blocks", "output_tail_lines"):
        if not isinstance(config[key], int) or isinstance(config[key], bool) or config[key] < 1:
            raise ValueError(f"{path}: \"{key}\" must be a whole number of at least 1")
    return config


def trust_file() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "greenbar" / "trusted.json"


def file_digest(path: Path) -> Optional[str]:
    try:
        if path.is_symlink():
            return "symlink"
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def off_stamp(path: Path) -> Optional[str]:
    try:
        st = path.lstat()
        return f"{st.st_ino}:{st.st_mtime_ns}"
    except OSError:
        return None


def trust_entry(root: Path) -> Dict[str, Any]:
    """What `trust` records for a folder: digests of both configs and whether guard.off is set."""
    claude = root / ".claude"
    return {
        "done-gate": file_digest(claude / CONFIG_NAME),
        "guard": file_digest(claude / "guard.json"),
        "guard-off": off_stamp(claude / "guard.off"),
    }


def read_trust() -> Dict[str, str]:
    try:
        data = json.loads(trust_file().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def is_trusted(root: Path) -> bool:
    entry = read_trust().get(str(root))
    return isinstance(entry, dict) and entry.get("done-gate") == file_digest(root / ".claude" / CONFIG_NAME)


def trust(root: Path) -> int:
    """CLI: show the commands and record that this exact config may run in this folder."""
    config = load_config(root) or {"checks": []}
    print(f"Trusting these done-gate commands for {root}:" if config["checks"] else f"Trusting {root} (no done-gate checks):")
    for check in config["checks"]:
        print(f"  {check.get('name') or 'check'}: {check['run']}")
    entry = trust_entry(root)
    if entry["guard"]:
        print("Also trusting .claude/guard.json as written (it may loosen the guard's defaults).")
    if entry["guard-off"]:
        print("Also trusting .claude/guard.off: the guard is OFF in this folder.")
    data = {**read_trust(), str(root): entry}
    path = trust_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    print("Saved. Edit the config and you will need to trust it again.")
    return 0


def git(root: Path, *args: str) -> Optional[bytes]:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args], capture_output=True, timeout=30, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None


def hash_stream(digest: "hashlib._Hash", root: Path, args: List[str]) -> None:
    """Feed a git command's output into the digest in chunks, so a huge diff never sits in memory."""
    try:
        proc = subprocess.Popen(["git", "-C", str(root), *args], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)
    except OSError:
        digest.update(b"git-failed")
        return
    assert proc.stdout is not None
    for chunk in iter(lambda: proc.stdout.read(1 << 16), b""):
        digest.update(chunk)
    proc.wait(timeout=60)


def fingerprint_git(root: Path) -> Optional[str]:
    """Hash of HEAD, the diff against it, and untracked (not ignored) files."""
    if git(root, "rev-parse", "--is-inside-work-tree") is None:
        return None
    digest = hashlib.sha256()
    digest.update(git(root, "rev-parse", "--verify", "-q", "HEAD") or b"no-head")
    has_head = git(root, "rev-parse", "-q", "--verify", "HEAD") is not None
    hash_stream(digest, root, ["diff", "HEAD", "--binary"] if has_head else ["diff", "--cached", "--binary"])
    untracked = (git(root, "ls-files", "--others", "--exclude-standard", "-z") or b"").split(b"\0")
    hashed = 0
    for name in sorted(n for n in untracked if n)[:MAX_WALK_FILES]:
        rel = name.decode("utf-8", "replace")
        if rel.startswith(f".claude/{STATE_DIR}/") or SKIP_DIRS & set(rel.split("/")[:-1]):
            continue
        path = root / rel
        try:
            stat = path.stat()
            digest.update(f"{rel}\0{stat.st_size}\0".encode())
            if stat.st_size <= MAX_UNTRACKED_HASH_BYTES and hashed + stat.st_size <= MAX_TOTAL_HASH_BYTES:
                hashed += stat.st_size
                digest.update(path.read_bytes())
            else:
                digest.update(str(stat.st_mtime_ns).encode())
        except OSError:
            digest.update(f"{rel}\0gone".encode())
    return "git:" + digest.hexdigest()


def fingerprint_walk(root: Path) -> str:
    """No git: hash every file's path, size and modification time (bounded)."""
    digest = hashlib.sha256()
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and d != STATE_DIR)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            try:
                stat = path.stat()
            except OSError:
                continue
            rel = path.relative_to(root).as_posix()
            digest.update(f"{rel}\0{stat.st_size}\0{stat.st_mtime_ns}\n".encode())
            count += 1
            if count >= MAX_WALK_FILES:
                return "walk:" + digest.hexdigest()
    return "walk:" + digest.hexdigest()


def fingerprint(root: Path) -> str:
    return fingerprint_git(root) or fingerprint_walk(root)


def tail(text: str, lines: int) -> str:
    kept = text.strip().splitlines()[-lines:]
    joined = "\n".join(kept)
    return joined[-4000:]


def redact(text: str) -> str:
    return SECRET.sub("[redacted]", text)


def read_tail(handle: Any, limit: int = 64_000) -> str:
    handle.seek(0, os.SEEK_END)
    size = handle.tell()
    handle.seek(max(0, size - limit))
    return handle.read().decode("utf-8", "replace")


def run_check(check: Dict[str, Any], root: Path, timeout: int) -> Tuple[bool, str]:
    """Run one check in its own process group; keep only the end of its output on disk."""
    env = {**os.environ, "CI": os.environ.get("CI", "1"), "DONE_GATE_RUNNING": "1"}
    with tempfile.TemporaryFile() as out:
        proc = subprocess.Popen(check["run"], shell=True, cwd=str(root), env=env, stdout=out,
                                stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
            proc.wait()
            return False, f"(timed out after {timeout}s)\n{redact(read_tail(out))}"
        return code == 0, f"(exit code {code})\n{redact(read_tail(out))}"


class State:
    """Small JSON file under .claude/.done-gate/, guarded by an exclusive lock."""

    def __init__(self, root: Path) -> None:
        self.dir = root / ".claude" / STATE_DIR
        for path in (root / ".claude", self.dir, self.dir / "state.json", self.dir / "lock"):
            if path.is_symlink():
                raise OSError(f"{path} is a symlink; greenbar will not write through it")
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "state.json"
        self.lock = open(self.dir / "lock", "w")  # noqa: SIM115 - held for the hook's life
        try:
            import fcntl  # not on Windows; greenbar documents macOS/Linux only
        except ImportError as exc:
            raise OSError("file locking is not available on this platform") from exc
        deadline = time.monotonic() + LOCK_WAIT_SECONDS
        while True:
            try:
                fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > deadline:
                    raise OSError("another session is running the checks right now") from None
                time.sleep(0.25)
        try:
            self.data: Dict[str, Any] = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.data = {}
        self.data.setdefault("blocks", {})
        self.data.setdefault("turn_start", {})

    def save(self) -> None:
        for table in ("blocks", "turn_start"):
            rows = self.data[table]
            if len(rows) > 50:  # keep the file small: drop the oldest sessions
                for key in sorted(rows, key=lambda k: rows[k].get("at", 0))[:-50]:
                    del rows[key]
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=1), encoding="utf-8")
        os.replace(tmp, self.path)


def block_reason(failures: List[Tuple[str, str, str]], claimed: bool, attempt: int, cap: int) -> str:
    head = "greenbar: the work is not finished. "
    if claimed:
        head += "Do not report this as done or passing. Your last message reads that way, but these checks fail:\n"
    else:
        head += "These checks fail:\n"
    parts = [head]
    for name, command, output in failures:
        parts.append(f"\n--- {name}: `{redact(command)}` {output}\n")
    parts.append(
        f"\nFix the cause, re-run the checks, then finish (attempt {attempt} of {cap}). "
        "Do not delete, skip or weaken tests to make them pass. If you cannot make them "
        "pass, stop and tell the user exactly what still fails instead of claiming success."
    )
    return "".join(parts)


def turn_start() -> None:
    """UserPromptSubmit: remember the tree as the turn begins, so turns that change nothing pass."""
    try:
        event = json.load(sys.stdin)
        root = project_root(event if isinstance(event, dict) else {})
        if os.environ.get("DONE_GATE_OFF") == "1" or not load_config(root) or not is_trusted(root):
            sys.exit(0)
        state = State(root)
        session = str(event.get("session_id") or "unknown")
        state.data["turn_start"][session] = {"fp": fingerprint(root), "at": time.time()}
        state.save()
    except (OSError, ValueError, AttributeError):
        pass  # never get in the way of a prompt
    sys.exit(0)


def main() -> None:
    if os.environ.get("DONE_GATE_OFF") == "1" or os.environ.get("DONE_GATE_RUNNING") == "1":
        allow()
    try:
        event = json.load(sys.stdin)
        if not isinstance(event, dict):
            raise ValueError("hook input is not a JSON object")
    except ValueError as exc:
        allow(f"greenbar could not read its input ({exc}); stop was allowed.")
    root = project_root(event)
    if (root / ".claude" / "done-gate.off").exists():
        allow()
    try:
        config = load_config(root)
    except (OSError, ValueError) as exc:
        allow(f"greenbar config error, stop was allowed: {exc}")
    if not config or not config["checks"]:
        allow()
    if not is_trusted(root):
        allow(
            "greenbar: .claude/done-gate.json here is new or changed and has not been trusted, "
            "so its checks did not run. Review it, then run /greenbar:setup or "
            "`python3 <plugin>/hooks/done_gate.py trust`."
        )

    try:
        state = State(root)
    except OSError as exc:
        allow(f"greenbar: could not use its state folder ({exc}); stop was allowed.")
    session = str(event.get("session_id") or "unknown")
    before = fingerprint(root)
    started_as = (state.data["turn_start"].get(session) or {}).get("fp")
    if started_as == before and session not in state.data["blocks"]:
        state.save()
        allow()  # nothing changed during this turn (a question, a plan): never run or block
    if config["skip_when_unchanged"] and state.data.get("last_green") == before:
        state.data["blocks"].pop(session, None)
        state.save()
        allow()

    timeout = int(config["timeout_seconds"])
    lines = int(config["output_tail_lines"])
    started = time.monotonic()
    failures: List[Tuple[str, str, str]] = []
    budget = int(config["total_timeout_seconds"])
    for index, check in enumerate(config["checks"]):
        name = str(check.get("name") or f"check {index + 1}")
        left = int(budget - (time.monotonic() - started))
        if left < 1:
            failures.append((name, check["run"], f"(not run: the {budget}s total budget was used up)"))
            continue
        ok, output = run_check(check, root, min(timeout, left))
        if not ok:
            failures.append((name, check["run"], tail(output, lines)))
    seconds = time.monotonic() - started
    names = ", ".join(str(c.get("name") or c["run"]) for c in config["checks"])

    if not failures:
        after = fingerprint(root)
        if after == before:  # only cache a tree that did not change while the checks ran
            state.data["last_green"] = after
        state.data["blocks"].pop(session, None)
        state.save()
        allow(f"greenbar: {names} passed ({seconds:.0f}s)." if config["announce_pass"] else None)

    record = state.data["blocks"].get(session) or {"count": 0}
    record = {"count": int(record.get("count", 0)) + 1, "at": time.time()}
    cap = max(1, int(config["max_consecutive_blocks"]))
    if record["count"] > cap:
        state.data["blocks"].pop(session, None)
        state.save()
        failed = ", ".join(name for name, _, _ in failures)
        allow(
            f"greenbar: {failed} still failing after {cap} attempts. Claude was allowed to "
            "stop so it cannot loop; treat any claim that the work is done as false."
        )
    state.data["blocks"][session] = record
    state.save()
    claimed = bool(CLAIM.search(str(event.get("last_assistant_message") or "")))
    emit({"decision": "block", "reason": block_reason(failures, claimed, record["count"], cap)})


if __name__ == "__main__":
    if sys.version_info < (3, 9):
        print("greenbar needs Python 3.9 or newer; the done gate is inactive.", file=sys.stderr)
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == "turn-start":
        turn_start()
    if len(sys.argv) > 1 and sys.argv[1] == "trust":
        target = Path(sys.argv[2] if len(sys.argv) > 2 else os.environ.get("CLAUDE_PROJECT_DIR") or ".")
        try:
            sys.exit(trust(target.resolve()))
        except (OSError, ValueError) as exc:
            print(f"Could not trust: {exc}", file=sys.stderr)
            sys.exit(1)
    main()
