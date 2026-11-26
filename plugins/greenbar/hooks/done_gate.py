#!/usr/bin/env python3
"""greenbar done gate: a Stop hook for Claude Code. Python 3.9+, standard library only.

When Claude tries to end its turn, this hook runs your project's real checks (tests,
lint, type check: whatever you list in .claude/done-gate.json). If any check fails,
Claude is not allowed to stop. It gets the failing command and the end of its output,
and it has to fix the cause or tell you plainly that it could not.

It does not re-run checks when nothing changed since the last green run, so a
conversation with no code changes costs nothing. After `max_consecutive_blocks`
failed attempts in a row it lets Claude stop and warns you, so it cannot loop forever.

Turn it off for one shell:   DONE_GATE_OFF=1 claude
Turn it off for the repo:    touch .claude/done-gate.off
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

CONFIG_NAME = "done-gate.json"
STATE_DIR = ".done-gate"
DEFAULTS: Dict[str, Any] = {
    "checks": [],
    "timeout_seconds": 600,
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
MAX_UNTRACKED_HASH_BYTES = 256_000
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
    return config


def git(root: Path, *args: str) -> Optional[bytes]:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args], capture_output=True, timeout=30, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None


def fingerprint_git(root: Path) -> Optional[str]:
    """Hash of HEAD, the diff against it, and untracked (not ignored) files."""
    if git(root, "rev-parse", "--is-inside-work-tree") is None:
        return None
    digest = hashlib.sha256()
    digest.update(git(root, "rev-parse", "--verify", "-q", "HEAD") or b"no-head")
    diff = git(root, "diff", "HEAD", "--binary") if git(root, "rev-parse", "-q", "--verify", "HEAD") else None
    digest.update(diff if diff is not None else (git(root, "diff", "--cached", "--binary") or b""))
    untracked = (git(root, "ls-files", "--others", "--exclude-standard", "-z") or b"").split(b"\0")
    for name in sorted(n for n in untracked if n)[:MAX_WALK_FILES]:
        rel = name.decode("utf-8", "replace")
        if rel.startswith(f".claude/{STATE_DIR}/"):
            continue
        path = root / rel
        try:
            stat = path.stat()
            digest.update(f"{rel}\0{stat.st_size}\0".encode())
            if stat.st_size <= MAX_UNTRACKED_HASH_BYTES:
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


def run_check(check: Dict[str, Any], root: Path, timeout: int) -> Tuple[bool, str]:
    env = {**os.environ, "CI": os.environ.get("CI", "1"), "DONE_GATE_RUNNING": "1"}
    try:
        result = subprocess.run(
            check["run"], shell=True, cwd=str(root), env=env, timeout=timeout,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace",
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", "replace")
        return False, f"(timed out after {timeout}s)\n{out}"
    return result.returncode == 0, f"(exit code {result.returncode})\n{result.stdout}"


class State:
    """Small JSON file under .claude/.done-gate/, guarded by an exclusive lock."""

    def __init__(self, root: Path) -> None:
        self.dir = root / ".claude" / STATE_DIR
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "state.json"
        self.lock = open(self.dir / "lock", "w")  # noqa: SIM115 - held for the hook's life
        fcntl.flock(self.lock, fcntl.LOCK_EX)
        try:
            self.data: Dict[str, Any] = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.data = {}
        self.data.setdefault("blocks", {})

    def save(self) -> None:
        blocks = self.data["blocks"]
        if len(blocks) > 50:  # keep the file small: drop the oldest sessions
            for key in sorted(blocks, key=lambda k: blocks[k].get("at", 0))[:-50]:
                del blocks[key]
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=1), encoding="utf-8")
        os.replace(tmp, self.path)


def block_reason(failures: List[Tuple[str, str, str]], claimed: bool, attempt: int, cap: int) -> str:
    head = "greenbar: the work is not finished. "
    if claimed:
        head += "Your last message says it is done or passing, but these checks fail:\n"
    else:
        head += "These checks fail:\n"
    parts = [head]
    for name, command, output in failures:
        parts.append(f"\n--- {name}: `{command}` {output}\n")
    parts.append(
        f"\nFix the cause, re-run the checks, then finish (attempt {attempt} of {cap}). "
        "Do not delete, skip or weaken tests to make them pass. If you cannot make them "
        "pass, stop and tell the user exactly what still fails instead of claiming success."
    )
    return "".join(parts)


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

    state = State(root)
    session = str(event.get("session_id") or "unknown")
    before = fingerprint(root)
    if config["skip_when_unchanged"] and state.data.get("last_green") == before:
        state.data["blocks"].pop(session, None)
        state.save()
        allow()

    timeout = int(config["timeout_seconds"])
    lines = int(config["output_tail_lines"])
    failures: List[Tuple[str, str, str]] = []
    started = time.monotonic()
    for index, check in enumerate(config["checks"]):
        name = str(check.get("name") or f"check {index + 1}")
        ok, output = run_check(check, root, timeout)
        if not ok:
            failures.append((name, check["run"], tail(output, lines)))
    seconds = time.monotonic() - started
    names = ", ".join(str(c.get("name") or c["run"]) for c in config["checks"])

    if not failures:
        state.data["last_green"] = fingerprint(root)
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
    main()
