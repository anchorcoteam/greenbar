#!/usr/bin/env python3
"""Test suite for greenbar (done gate + guard). Python 3.9+, standard library only.

Builds a throwaway git repo in a temp folder, feeds each hook the same JSON that Claude
Code sends, and checks the decision. Nothing outside the temp folder is touched.

    python3 tests/run_tests.py            # all cases
    python3 tests/run_tests.py -v         # print every case
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

HERE = Path(__file__).resolve().parent
HOOKS = HERE.parent / "plugins" / "greenbar" / "hooks"
GUARD = HOOKS / "guard.py"
GATE = HOOKS / "done_gate.py"
VERBOSE = "-v" in sys.argv
RESULTS: List[Tuple[str, bool, str]] = []
XDG = Path(tempfile.mkdtemp(prefix="greenbar-xdg-"))  # trust store for the tests, never the real one


def sh(cwd: Path, *args: str) -> None:
    subprocess.run(args, cwd=str(cwd), check=True, capture_output=True)


def make_repo(root: Path) -> None:
    files = {
        ".env": "API_KEY=not-a-real-key\n",
        ".env.local": "X=1\n",
        ".env.example": "API_KEY=\n",
        "secrets/token.txt": "nope\n",
        "certs/server.pem": "-----\n",
        "src/app.py": "def add(a, b):\n    return a + b\n",
        "tests/test_app.py": "import unittest\nfrom src.app import add\n\n"
                             "class T(unittest.TestCase):\n    def test_add(self):\n"
                             "        self.assertEqual(add(1, 2), 3)\n",
        "web/button.test.js": "test('renders', () => { expect(1).toBe(1) })\n",
        "migrations/001_init.sql": "create table t (id int);\n",
        "vendor/lib.js": "// vendored\n",
        "README.md": "demo\n",
        ".gitignore": ".env\n.env.local\nsecrets/\n.claude/.done-gate/\n",
        ".claude/guard.json": json.dumps({
            "read_only": ["vendor/**"],
            "locked_once_committed": ["migrations/*.sql"],
        }),
    }
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    sh(root, "git", "init", "-q", "-b", "main")
    sh(root, "git", "config", "user.email", "test@example.invalid")
    sh(root, "git", "config", "user.name", "test")
    sh(root, "git", "add", "-A")
    sh(root, "git", "commit", "-q", "-m", "init")


def run_hook(hook: Path, root: Path, event: Dict[str, Any], env: Dict[str, str] = None) -> subprocess.CompletedProcess:
    full_env = {**os.environ, "CLAUDE_PROJECT_DIR": str(root), "PYTHONDONTWRITEBYTECODE": "1",
                "XDG_CONFIG_HOME": str(XDG), **(env or {})}
    full_env.pop("DONE_GATE_OFF", None) if not (env or {}).get("DONE_GATE_OFF") else None
    full_env.pop("DONE_GATE_RUNNING", None)
    return subprocess.run([sys.executable, str(hook)], input=json.dumps(event), text=True,
                          capture_output=True, cwd=str(root), env=full_env, timeout=120)


def record(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    if VERBOSE or not ok:
        print(f"{'PASS' if ok else 'FAIL'}  {name}{'  -- ' + detail if detail and not ok else ''}")


# ---------------- Guard ----------------

def guard_cases(root: Path) -> List[Tuple[str, str, Dict[str, Any], str]]:
    """(label, tool, tool_input, expected 'block'|'allow')."""
    B, A = "block", "allow"
    home = str(Path.home())
    cases: List[Tuple[str, Tuple[str, Dict[str, Any]], str]] = [
        # off-limits files through the file tools
        ("Read .env", ("Read", {"file_path": str(root / ".env")}), B),
        ("Read .env.local", ("Read", {"file_path": str(root / ".env.local")}), B),
        ("Read .ENV (case)", ("Read", {"file_path": str(root / ".ENV")}), B),
        ("Read .env.example", ("Read", {"file_path": str(root / ".env.example")}), A),
        ("Read secrets/token.txt", ("Read", {"file_path": str(root / "secrets/token.txt")}), B),
        ("Read certs/server.pem", ("Read", {"file_path": str(root / "certs/server.pem")}), B),
        ("Read src/app.py", ("Read", {"file_path": str(root / "src/app.py")}), A),
        ("Read ~/.ssh/id_rsa", ("Read", {"file_path": home + "/.ssh/id_rsa"}), B),
        ("Read ~/.aws/credentials", ("Read", {"file_path": "~/.aws/credentials"}), B),
        ("Read file outside project", ("Read", {"file_path": "/etc/hosts"}), A),
        ("Edit .env", ("Edit", {"file_path": str(root / ".env"), "old_string": "a", "new_string": "b"}), B),
        ("Write new .env.production", ("Write", {"file_path": str(root / ".env.production"), "content": "x"}), B),
        ("Edit src/app.py", ("Edit", {"file_path": str(root / "src/app.py"), "old_string": "a + b", "new_string": "b + a"}), A),
        # search tools
        ("Grep in secrets/", ("Grep", {"pattern": "x", "path": str(root / "secrets")}), B),
        ("Grep glob .env*", ("Grep", {"pattern": "KEY", "glob": ".env*"}), B),
        ("Glob **/.env", ("Glob", {"pattern": "**/.env"}), B),
        ("Glob **/*.pem", ("Glob", {"pattern": "**/*.pem"}), B),
        ("Glob **/*.py", ("Glob", {"pattern": "**/*.py"}), A),
        ("Grep the code for 'env'", ("Grep", {"pattern": ".env", "path": str(root / "src")}), A),
        ("Grep in ~/.ssh", ("Grep", {"pattern": "x", "path": "~/.ssh"}), B),
        # read-only and locked
        ("Edit vendor/lib.js (read_only)", ("Edit", {"file_path": str(root / "vendor/lib.js"), "old_string": "v", "new_string": "w"}), B),
        ("Read vendor/lib.js", ("Read", {"file_path": str(root / "vendor/lib.js")}), A),
        ("Edit committed migration", ("Edit", {"file_path": str(root / "migrations/001_init.sql"), "old_string": "int", "new_string": "bigint"}), B),
        ("Write new migration 002", ("Write", {"file_path": str(root / "migrations/002_more.sql"), "content": "select 1;"}), A),
        # test tampering
        ("Add @unittest.skip", ("Edit", {"file_path": str(root / "tests/test_app.py"), "old_string": "    def test_add", "new_string": "    @unittest.skip('later')\n    def test_add"}), B),
        ("Add test.skip in JS", ("Edit", {"file_path": str(root / "web/button.test.js"), "old_string": "test('renders'", "new_string": "test.skip('renders'"}), B),
        ("Write test file with xit", ("Write", {"file_path": str(root / "web/button.test.js"), "content": "xit('renders', () => {})\n"}), B),
        ("Add a new assertion to a test", ("Edit", {"file_path": str(root / "tests/test_app.py"), "old_string": "3)", "new_string": "3)\n        self.assertEqual(add(2, 2), 4)"}), A),
        ("Edit removes a test function", ("Edit", {"file_path": str(root / "tests/test_app.py"), "old_string": "    def test_add(self):\n        self.assertEqual(add(1, 2), 3)\n", "new_string": ""}), B),
        ("Write empties a test file", ("Write", {"file_path": str(root / "tests/test_app.py"), "content": "import unittest\n"}), B),
        ("Rename a test (count unchanged)", ("Edit", {"file_path": str(root / "tests/test_app.py"), "old_string": "def test_add(self):", "new_string": "def test_add_two_ints(self):"}), A),
        ("Remove an existing skip", ("Edit", {"file_path": str(root / "tests/test_app.py"), "old_string": "@unittest.skip('x')\n", "new_string": ""}), A),
        ("Write src file mentioning test.skip", ("Write", {"file_path": str(root / "src/notes.py"), "content": "# test.skip( is a JS thing\n"}), A),
        # shell: off-limits paths
        bash_case("cat .env", B), bash_case("head -c 200 .e*", B), bash_case("tail ./.env.local", B),
        bash_case("cat ./.ENV", B), bash_case("ls secrets", B), bash_case("wc -l secrets/*", B),
        bash_case("cd secrets && cat token.txt", B), bash_case("cd src && cat ../.env", B),
        bash_case("grep -rn KEY secrets", B), bash_case("cp .env /tmp/x", B),
        bash_case("base64 certs/server.pem", B), bash_case("find . -name '.env*'", B),
        bash_case("source .env && npm start", B), bash_case("cat " + home + "/.aws/credentials", B),
        bash_case("cat ~/.ssh/id_ed25519", B), bash_case("ls -la ~/.ssh", B),
        bash_case("sudo cat .env", B), bash_case("env cat .env", B),
        bash_case("git -c core.hooksPath=/dev/null commit -m x", B),
        bash_case("cat .env.example", A), bash_case("ls -la", A), bash_case("ls src", A),
        bash_case("grep -rn env src/", A), bash_case("cat README.md", A),
        bash_case("python3 -m unittest discover -s tests", A), bash_case("npm test -- --grep env", A),
        bash_case("cd src && ls", A), bash_case("echo 'load .env with dotenv' > /dev/null", A),
        # shell: read-only / locked writes
        bash_case("echo x > migrations/001_init.sql", B), bash_case("sed -i '' 's/int/bigint/' migrations/001_init.sql", B),
        bash_case("cp README.md migrations/001_init.sql", B), bash_case("rm vendor/lib.js", B),
        bash_case("echo 'select 1;' > migrations/003_new.sql", A), bash_case("cp migrations/001_init.sql /tmp/copy.sql", A),
        bash_case("head -5 migrations/001_init.sql", A),
        # shell: tests
        bash_case("rm tests/test_app.py", B), bash_case("git rm web/button.test.js", B),
        bash_case("mv tests/test_app.py /tmp/", B), bash_case("rm -rf tests", B),
        bash_case("rm src/old.py", A),
        # shell: destructive
        bash_case("rm -rf /", B), bash_case("rm -rf ~", B), bash_case("rm -rf ~/", B),
        bash_case("rm -rf $HOME", B), bash_case("rm -rf ..", B), bash_case("rm -rf .", B),
        bash_case("rm -rf *", B), bash_case("rm -r -f " + str(root), B), bash_case("sudo rm -rf /", B),
        bash_case("rm -rf build", A), bash_case("rm -rf node_modules dist", A),
        bash_case("git reset --hard HEAD~1", B), bash_case("git clean -fdx", B),
        bash_case("git checkout -- .", B), bash_case("git restore .", B),
        bash_case("git reset HEAD src/app.py", A), bash_case("git restore src/app.py", A),
        bash_case("git push --force origin main", B), bash_case("git push -f", B),
        bash_case("git push origin main --force-with-lease", B), bash_case("git push origin +main", B),
        bash_case("git push origin main", A), bash_case("git commit --no-verify -m wip", B),
        bash_case("git commit -n -m wip", B), bash_case("git push --no-verify", B),
        bash_case("git diff --no-index /dev/null .env", B), bash_case("git diff --output=x.txt", B),
        bash_case("git status --short", A), bash_case("git log --oneline -5", A),
        bash_case("git commit -m 'fix .env handling docs'", A),
        # reviewer regressions: flags belong to the git segment only
        bash_case("git push origin main && rm -f x.txt", A), bash_case("git push origin main; ls -f", A),
        bash_case("git commit -m x && head -n 3 README.md", A), bash_case("git clean -n && rm -f out.txt", A),
        bash_case("git reset --soft HEAD~1 && ls -la", A), bash_case("git status && git push --force", B),
        # moves and caches are not deleting tests
        bash_case("mkdir -p tests/unit && mv tests/test_app.py tests/unit/test_app.py", A),
        bash_case("git rm --cached tests/test_app.py", A), bash_case("rm -rf tests/__snapshots__", A),
        bash_case("rm -rf tests/__pycache__", A),
        # example env files, heredocs, subfolders
        bash_case("cat .env.development.example", A),
        bash_case("cat > README.md <<'EOF'\nCopy .env.example to .env and fill it in.\nEOF", A),
        bash_case("cd build && rm -rf *", A), bash_case("rm -rf $PWD", B),
        # nested shells and env dumps
        bash_case("bash -c 'cat .env'", B), bash_case("sh -c \"head .env.local\"", B),
        bash_case("eval cat .env", B), bash_case("echo $(cat .env)", B), bash_case("printenv", B),
        bash_case("env", B), bash_case("export -p", B), bash_case("env NODE_ENV=test npm test", A),
        bash_case("echo $NODE_ENV", A),
        bash_case("env FOO=bar cat .env", B), bash_case("env bash -c 'cat .env'", B),
        bash_case("env git push -f", B), bash_case("env FOO=bar", B), bash_case("sudo -u root cat .env", B),
    ]
    out = []
    for label, (tool, tool_input), expected in cases:
        out.append((label, tool, tool_input, expected))
    return out


def bash_case(command: str, expected: str):
    return (f"Bash: {command}", ("Bash", {"command": command}), expected)


def run_guard(root: Path) -> None:
    for label, tool, tool_input, expected in guard_cases(root):
        event = {"tool_name": tool, "tool_input": tool_input, "cwd": str(root), "hook_event_name": "PreToolUse"}
        res = run_hook(GUARD, root, event)
        got = "block" if res.returncode == 2 else "allow" if res.returncode == 0 else f"error {res.returncode}"
        record(f"guard | {label}", got == expected, f"expected {expected}, got {got}: {res.stderr.strip()[:200]}")


def run_guard_commits(root: Path) -> None:
    """Commit-time scanning needs real staged changes, so each case sets up its own."""
    def attempt(label: str, setup, expected: str, command: str = "git commit -m test") -> None:
        sh(root, "git", "reset", "-q")
        sh(root, "git", "checkout", "-q", "--", ".")
        setup()
        res = run_hook(GUARD, root, {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(root)})
        got = "block" if res.returncode == 2 else "allow"
        record(f"guard | commit: {label}", got == expected, f"expected {expected}, got {got}: {res.stderr.strip()[:200]}")
        for extra in ("src/config.py", "notes.txt", "deploy.key"):
            (root / extra).unlink(missing_ok=True)
        sh(root, "git", "reset", "-q")

    def stage(rel: str, text: str, force: bool = False):
        def go():
            (root / rel).write_text(text)
            sh(root, "git", "add", *(["-f"] if force else []), rel)
        return go

    fake_aws = "AKIA" + "ABCDEFGHIJKLMNOP"
    fake_gh = "ghp_" + "a" * 36
    attempt("clean change", stage("src/app.py", "def add(a, b):\n    return b + a\n"), "allow")
    attempt("AWS key in code", stage("src/config.py", f"KEY = '{fake_aws}'\n"), "block")
    attempt("GitHub token in code", stage("src/config.py", f"TOKEN = '{fake_gh}'\n"), "block")
    attempt("quoted password", stage("src/config.py", "password = 'hunter2hunter2xx'\n"), "block")
    attempt("private key block", stage("notes.txt", "-----BEGIN RSA PRIVATE KEY-----\n"), "block")
    attempt("force-added .env", stage(".env", "API_KEY=changed\n", force=True), "block")
    attempt("staged .key file", stage("deploy.key", "x\n"), "block")
    attempt("secret in untracked file with git add -A", lambda: (root / "src/config.py").write_text(f"K = '{fake_aws}'\n"),
            "block", "git add -A && git commit -m all")
    attempt("ML tokenizer name is not a secret", stage("src/config.py", "tokenizer_name = 'bert-base-uncased-v2'\n"), "allow")
    attempt("password read from env (fine)", stage("src/config.py", "password = os.environ['DB_PASSWORD']\n"), "allow")


def run_guard_misc(root: Path) -> None:
    def read(rel: str) -> int:
        return run_hook(GUARD, root, {"tool_name": "Read", "tool_input": {"file_path": str(root / rel)}}).returncode

    res = run_hook(GUARD, root, {"bad": "input"})
    record("guard | malformed input: non-blocking warning, never bricks tools", res.returncode == 1, res.stderr[:200])
    off = root / ".claude" / "guard.off"
    off.write_text("")
    record("guard | guard.off shipped by an untrusted repo is ignored", read(".env") == 2)
    trust(root)
    record("guard | guard.off after the user trusts it: allows", read(".env") == 0)
    off.unlink()
    trust(root)
    off.write_text("")
    record("guard | guard.off re-created after trust is ignored again", read(".env") == 2)
    off.unlink()
    cfg = root / ".claude" / "guard.json"
    saved = cfg.read_text()
    cfg.write_text("{not json")
    record("guard | broken guard.json: defaults still protect .env", read(".env") == 2)
    record("guard | broken guard.json: normal reads still work", read("README.md") == 0)
    res = run_hook(GUARD, root, {"tool_name": "Edit", "tool_input": {"file_path": str(cfg), "old_string": "{", "new_string": "{}"}})
    record("guard | broken guard.json: Claude can still edit it to fix it", res.returncode == 0, res.stderr[:200])
    cfg.write_text(json.dumps({"off_limits": ["docs/private/**"], "protect_tests": False, "block_force_push": False}))
    record("guard | untrusted guard.json: added off_limits pattern blocks", read("docs/private/plan.md") == 2)
    record("guard | untrusted guard.json: cannot drop the defaults", read(".env") == 2)
    res = run_hook(GUARD, root, {"tool_name": "Bash", "tool_input": {"command": "git push -f"}, "cwd": str(root)})
    record("guard | untrusted guard.json: cannot switch a protection off", res.returncode == 2)
    trust(root)
    record("guard | trusted guard.json: replaces the defaults (documented)", read(".env") == 0)
    record("guard | trusted guard.json: its own pattern blocks", read("docs/private/plan.md") == 2)
    cfg.write_text(saved)
    trust(root)


# ---------------- Done Gate ----------------

def gate_event(root: Path, message: str = "Done. All tests pass.", session: str = "s1") -> Dict[str, Any]:
    return {"session_id": session, "cwd": str(root), "hook_event_name": "Stop",
            "stop_hook_active": False, "last_assistant_message": message}


def trust(root: Path) -> int:
    return subprocess.run([sys.executable, str(GATE), "trust", str(root)], capture_output=True,
                          env={**os.environ, "XDG_CONFIG_HOME": str(XDG)}).returncode


def write_gate(root: Path, checks: List[Dict[str, str]], trusted: bool = True, **extra: Any) -> None:
    (root / ".claude").mkdir(exist_ok=True)
    (root / ".claude" / "done-gate.json").write_text(json.dumps({"checks": checks, **extra}))
    shutil.rmtree(root / ".claude" / ".done-gate", ignore_errors=True)
    if trusted and checks:
        trust(root)


def decision(res: subprocess.CompletedProcess) -> Tuple[str, Dict[str, Any]]:
    if res.returncode != 0:
        return f"error {res.returncode}", {}
    out = res.stdout.strip()
    data = json.loads(out) if out else {}
    return ("block" if data.get("decision") == "block" else "allow"), data


def run_gate(root: Path, counter: Path) -> None:
    py = sys.executable
    passing = {"name": "tests", "run": f"{py} -m unittest discover -s tests -q"}
    counting = {"name": "count", "run": f"echo run >> '{counter}'"}
    failing = {"name": "lint", "run": f"{py} -c \"import sys; print('E501 line too long'); sys.exit(1)\""}

    def check(label: str, want: str, res, extra=lambda d: True) -> Dict[str, Any]:
        got, data = decision(res)
        ok = got == want and extra(data)
        record(f"done-gate | {label}", ok, f"expected {want}, got {got}: {res.stdout[:300]} {res.stderr[:200]}")
        return data

    (root / ".claude" / "done-gate.json").unlink(missing_ok=True)
    check("no config: allows silently", "allow", run_hook(GATE, root, gate_event(root)), lambda d: d == {})
    write_gate(root, [])
    check("empty checks: allows", "allow", run_hook(GATE, root, gate_event(root)))

    write_gate(root, [counting], trusted=False)
    n0 = counter.read_text().count("run") if counter.exists() else 0
    check("untrusted config: allows with a warning", "allow", run_hook(GATE, root, gate_event(root)),
          lambda d: "not been trusted" in d.get("systemMessage", ""))
    record("done-gate | untrusted config: its commands never run",
           (counter.read_text().count("run") if counter.exists() else 0) == n0)
    record("done-gate | trust command succeeds", trust(root) == 0)
    (root / ".claude" / "done-gate.json").write_text(json.dumps({"checks": [counting, failing]}))
    check("config changed after trust: untrusted again", "allow", run_hook(GATE, root, gate_event(root)),
          lambda d: "not been trusted" in d.get("systemMessage", ""))
    record("done-gate | trust store lives under XDG_CONFIG_HOME", (XDG / "greenbar" / "trusted.json").is_file())

    write_gate(root, [passing, counting])
    check("passing checks: allows and announces", "allow", run_hook(GATE, root, gate_event(root)),
          lambda d: "passed" in d.get("systemMessage", ""))
    runs_before = counter.read_text().count("run")
    check("unchanged tree: allows", "allow", run_hook(GATE, root, gate_event(root)))
    record("done-gate | unchanged tree: checks are not re-run", counter.read_text().count("run") == runs_before)
    (root / "src" / "app.py").write_text("def add(a, b):\n    return a + b  # touched\n")
    run_hook(GATE, root, gate_event(root))
    record("done-gate | edited file: checks run again", counter.read_text().count("run") == runs_before + 1)
    (root / "src" / "new_module.py").write_text("X = 1\n")
    run_hook(GATE, root, gate_event(root))
    record("done-gate | new untracked file: checks run again", counter.read_text().count("run") == runs_before + 2)

    (root / "src" / "app.py").write_text("def add(a, b):\n    return a - b\n")
    write_gate(root, [passing])
    data = check("broken code: blocks stop", "block", run_hook(GATE, root, gate_event(root)))
    reason = data.get("reason", "")
    record("done-gate | block reason names the failing check", "tests" in reason and "unittest" in reason)
    record("done-gate | block reason calls out the false 'done' claim", "says it is done" in reason)
    record("done-gate | block reason forbids weakening tests", "Do not delete, skip or weaken tests" in reason)
    data = check("no claim in message: still blocks", "block",
                 run_hook(GATE, root, gate_event(root, "Here is a summary of the change.", "s2")))
    record("done-gate | no claim: reason does not accuse", "says it is done" not in data.get("reason", ""))

    def turn(session: str) -> None:
        subprocess.run([sys.executable, str(GATE), "turn-start"], input=json.dumps(gate_event(root, session=session)),
                       text=True, capture_output=True, cwd=str(root),
                       env={**os.environ, "CLAUDE_PROJECT_DIR": str(root), "XDG_CONFIG_HOME": str(XDG)})

    write_gate(root, [passing, counting])
    turn("ask")
    n = counter.read_text().count("run")
    check("red suite, turn changed nothing: allows", "allow", run_hook(GATE, root, gate_event(root, "Use X or Y?", "ask")))
    record("done-gate | red suite, turn changed nothing: checks not run", counter.read_text().count("run") == n)
    turn("edit")
    (root / "src" / "extra.py").write_text("Y = 2\n")
    check("turn that changes files: checks run and block", "block", run_hook(GATE, root, gate_event(root, session="edit")))
    check("same turn, still red after a block: keeps gating", "block", run_hook(GATE, root, gate_event(root, session="edit")))
    (root / "src" / "extra.py").unlink()

    write_gate(root, [passing], max_consecutive_blocks=2)
    check("loop cap: 1st failure blocks", "block", run_hook(GATE, root, gate_event(root, session="cap")))
    check("loop cap: 2nd failure blocks", "block", run_hook(GATE, root, gate_event(root, session="cap")))
    check("loop cap: 3rd failure lets Claude stop with a warning", "allow",
          run_hook(GATE, root, gate_event(root, session="cap")), lambda d: "still failing" in d.get("systemMessage", ""))
    check("loop cap: counter resets afterwards", "block", run_hook(GATE, root, gate_event(root, session="cap")))
    check("other session counted separately", "block", run_hook(GATE, root, gate_event(root, session="other")))

    (root / "src" / "app.py").write_text("def add(a, b):\n    return a + b\n")
    check("fixed code: allows", "allow", run_hook(GATE, root, gate_event(root, session="cap")))

    write_gate(root, [passing, failing])
    data = check("second check fails: blocks", "block", run_hook(GATE, root, gate_event(root)))
    record("done-gate | reason includes the failing output", "E501" in data.get("reason", ""))
    record("done-gate | reason omits passing checks", "--- tests" not in data.get("reason", ""))

    write_gate(root, [{"name": "slow", "run": f"{py} -c 'import time; time.sleep(5)'"}], timeout_seconds=1)
    data = check("timeout counts as failure", "block", run_hook(GATE, root, gate_event(root)))
    record("done-gate | timeout is reported", "timed out" in data.get("reason", ""))

    write_gate(root, [{"name": "a", "run": f"{py} -c 'import time; time.sleep(2)'"}, passing],
               total_timeout_seconds=1)
    data = check("total time budget: later checks fail, not hang", "block", run_hook(GATE, root, gate_event(root)))
    record("done-gate | budget exhaustion is reported", "total budget" in data.get("reason", "") or "timed out" in data.get("reason", ""))

    write_gate(root, [failing])
    check("DONE_GATE_OFF=1 allows", "allow", run_hook(GATE, root, gate_event(root), {"DONE_GATE_OFF": "1"}))
    (root / ".claude" / "done-gate.off").write_text("")
    check("done-gate.off file allows", "allow", run_hook(GATE, root, gate_event(root)))
    (root / ".claude" / "done-gate.off").unlink()

    (root / ".claude" / "done-gate.json").write_text("{oops")
    check("broken config: allows with a visible warning", "allow", run_hook(GATE, root, gate_event(root)),
          lambda d: "config error" in d.get("systemMessage", ""))
    (root / ".claude" / "done-gate.json").write_text(json.dumps({"checks": [{"name": "x"}]}))
    check("check without 'run': allows with warning", "allow", run_hook(GATE, root, gate_event(root)),
          lambda d: "config error" in d.get("systemMessage", ""))
    res = subprocess.run([sys.executable, str(GATE)], input="not json", text=True, capture_output=True,
                         cwd=str(root), env={**os.environ, "CLAUDE_PROJECT_DIR": str(root)})
    check("malformed input: allows with warning (never traps you)", "allow", res)

    with tempfile.TemporaryDirectory() as plain:
        p = Path(plain)
        (p / "a.txt").write_text("1")
        write_gate(p, [counting])
        run_hook(GATE, p, gate_event(p))
        n = counter.read_text().count("run")
        run_hook(GATE, p, gate_event(p))
        record("done-gate | non-git folder: unchanged skips re-run", counter.read_text().count("run") == n)
        (p / "a.txt").write_text("22")
        run_hook(GATE, p, gate_event(p))
        record("done-gate | non-git folder: change triggers re-run", counter.read_text().count("run") == n + 1)
    (root / ".claude" / "done-gate.json").unlink(missing_ok=True)


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp).resolve() / "repo"
        root.mkdir()
        make_repo(root)
        run_guard(root)
        run_guard_commits(root)
        run_guard_misc(root)
        run_gate(root, Path(tmp).resolve() / "counter.txt")
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    print(f"\n{passed}/{len(RESULTS)} passed")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
