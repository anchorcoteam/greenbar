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
        # reported 2026-11-25: a wrapper command in front hid the real one
        bash_case("timeout 30 cat .env", B), bash_case("timeout 30 rm -rf ~", B),
    ]
    cases += [bash_case(command, B) for command in WRAPPED_BLOCKED + REVIEW_BLOCKED]
    cases += [bash_case(command, A) for command in ORDINARY_ALLOWED + REVIEW_ALLOWED]
    cases += [
        bash_case("cat " + home + "/.s\"s\"h/id_rsa", B), bash_case("d=~/.ssh; cat $d/id_rsa", B),
        bash_case("cd ~ && cat .ssh/id_rsa", B), bash_case("cd ~ && ls", A),
        bash_case("rm -rf " + str(root) + "/*", B), bash_case("(cd build && ls); rm -rf *", B),
        bash_case("echo " + "$(" * 40 + "ls" + ")" * 40, B),  # deeper than the guard follows: refuse
    ]
    out = []
    for label, (tool, tool_input), expected in cases:
        out.append((label, tool, tool_input, expected))
    return out


# The same two forbidden acts (read .env, delete a root) behind every kind of wrapper and
# indirection. The guard must judge the command that really runs.
WRAPPED_BLOCKED = [
    # wrapper commands, with and without options
    "timeout -s KILL 30 cat .env", "timeout --signal=KILL 30s cat .env", "timeout -k 5 30 cat .env",
    "gtimeout 30 cat .env", "nice cat .env", "nice -n 10 cat .env", "nice -10 cat .env", "nohup cat .env",
    "env -i cat .env", "env -u FOO cat .env", "env -S 'cat .env'", "command cat .env", "command -p cat .env",
    "exec cat .env", "exec -a foo cat .env", "time cat .env", "time -p cat .env", "stdbuf -oL cat .env",
    "stdbuf -o L cat .env", "sudo -n -u root cat .env", "sudo -- cat .env", "doas cat .env",
    "ionice -c3 cat .env", "ionice -c 3 cat .env", "caffeinate -i cat .env", "setsid cat .env",
    "chronic cat .env", "unbuffer cat .env", "busybox cat .env", "arch -arm64 cat .env",
    "strace -f cat .env", "flock /tmp/l cat .env", "flock /tmp/l -c 'cat .env'", "chrt -f 10 cat .env",
    "taskset -c 0 cat .env", "watch cat .env", "watch -n 1 'cat .env'", "FOO=1 timeout 3 cat .env",
    "nice -n 5 timeout 10 sudo rm -rf /", "timeout 5 nice rm -rf ~", "nohup nice timeout 3 env cat .env",
    "some-unknown-wrapper --flag 3 cat .env", "some-unknown-wrapper rm -rf ~",
    "nice " * 30 + "cat .env",
    # xargs and find -exec
    "xargs cat .env", "echo .env | xargs cat", "echo ~ | xargs rm -rf", "xargs -n1 rm -rf ~",
    "xargs -n 1 -P 4 rm -rf ~", "printf '%s' .env | xargs -I{} cat {}", "xargs -I{} cat {} <<< .env",
    "find . -name x -exec cat .env \\;", "find . -maxdepth 1 -exec rm -rf ~ \\;",
    "find . -maxdepth 1 -exec sh -c 'rm -rf ~' \\;", "find . -type f -execdir timeout 3 cat .env +",
    # shells and command strings
    "sh -c 'cat .env'", "bash -c \"rm -rf ~\"", "bash -lc 'cat .env'", "bash -xc 'cat .env'",
    "bash -euo pipefail -c 'cat .env'", "bash --norc -c 'cat .env'", "timeout 30 bash -c 'cat .env'",
    "sh -c 'sh -c \"cat .env\"'", "bash -c 'timeout 3 rm -rf ~'", "zsh -c 'rm -rf $HOME'",
    "/bin/sh -c 'cat .env'", "su -c 'cat .env'", "eval 'cat .env'", "eval \"rm -rf ~\"",
    "timeout 3 eval cat .env", "trap 'cat .env' EXIT", "bash <<< 'cat .env'", "echo 'cat .env' | bash",
    "echo 'rm -rf ~' | sh", "echo 'rm -rf ~' | timeout 3 sh -s", "bash <<EOF\ncat .env\nEOF",
    "sh <<'X'\nrm -rf ~\nX", "cat <<EOF | bash\ncat .env\nEOF",
    "bash -c 'bash -c \"bash -c \\\"bash -c cat\\\\ .env\\\"\"'",
    # subshells, groups, chains, control flow
    "(cat .env)", "( rm -rf ~ )", "{ cat .env; }", "true && cat .env", "true; rm -rf ~",
    "false || cat .env", "ls | cat .env", "ls &cat .env", "ls;cat .env", "true&&rm -rf ~",
    "! cat .env", "! rm -rf ~", "if true; then cat .env; fi", "if true; then rm -rf ~; fi",
    "for f in a; do rm -rf ~; done", "while true; do cat .env; done",
    "case x in x) cat .env;; esac", "f() { cat .env; }; f", "ls\ncat .env",
    "while read l; do echo $l; done < .env", "cat < .env", "cat<.env",
    # command substitution
    "echo `cat .env`", "echo $(timeout 3 cat .env)", "echo $(echo $(cat .env))", "x=$(cat .env)",
    "echo \"$(cat .env)\"", "echo \"$(rm -rf ~)\"", "cat <(cat .env)", "echo $((cat .env); ls)",
    "cat <<EOF\n$(cat .env)\nEOF", "cat <<EOF; cat .env\nhello\nEOF",
    "cat <<EOF\n EOF\nit's\nEOF\nrm -rf ~",
    # quoting, escapes, absolute paths
    "cat \".env\"", "cat '.env'", "cat .e\"n\"v", "cat \\.env", "c\\at .env", "\"cat\" .env",
    "'rm' -rf ~", "ca''t .env", "cat $'.e\\x6ev'", "\\cat .env", "\\rm -rf ~", "/bin/cat .env",
    "/usr/bin/env cat .env", "/bin/rm -rf ~", "/usr/bin/timeout 3 /bin/cat .env", "cat {.env,README.md}",
    "rm -rf \"$HOME\"", "rm -rf \"${HOME}\"", "rm -rf \"$HOME/\"", "rm -rf $HOME/*", "rm -rf -- ~",
    "rm -fr ~", "rm --recursive --force ~", "rm -Rf /", "rm -rf /*", "rm -rf ~/*",
    # variables set earlier on the line
    "f=.env; cat $f", "f=.env && cat \"${f}\"", "export F=.env; cat $F", "d=~; rm -rf $d",
    "c='cat .env'; $c", "for f in .env; do cat $f; done", "for f in .env*; do cat \"$f\"; done",
    # the other rules behind a wrapper
    "timeout 30 rm tests/test_app.py", "nice mv tests/test_app.py /tmp/", "timeout 3 git clean -fdx",
    "nice git reset --hard", "timeout 3 git push origin main --force", "timeout 3 printenv", "nohup env",
    "timeout 5 echo x > vendor/lib.js", "sudo tee migrations/001_init.sql", "git checkout -m .",
    "sort -m .env README.md",
    # more ways to spell the same command
    "echo $(<.env)", "< .env cat", "CAT .env", "/BIN/CAT .env", "=cat .env", "cat${IFS}.env",
    "ca\\\nt .env", "noglob cat .env", "repeat 1 cat .env", "rev .env", "dd if=.env",
    "sh -c 'cat \"$0\"' .env", "rm -rf $(pwd)", "rm -rf `pwd`", "rm -rf \"$(pwd)\"/*",
]
# Everyday commands that look similar and must keep working.
ORDINARY_ALLOWED = [
    "timeout 30 npm test", "timeout 30 cat README.md", "timeout -s KILL 60 python3 -m pytest -q",
    "timeout 5m make test", "nice -n 10 make build", "nohup npm start &", "command -v node",
    "command -V git", "time npm run build", "time -p ls", "stdbuf -oL python3 run.py",
    "sudo apt-get install -y jq", "exec npm start", "watch -n 2 ls", "nice ls", "env -i PATH=/usr/bin ls",
    "xargs rm -f < files.txt", "find . -name '*.pyc' | xargs rm -f", "find . -name '*.pyc' -delete",
    "find . -name '*.pyc' -exec rm -f {} +", "find build -type d -name tmp -exec rm -rf {} +",
    "git ls-files | xargs wc -l", "ls | xargs -n1 echo", "ls | xargs -I{} cp {} build/",
    "bash -c 'npm test && npm run lint'", "sh -c \"ls -la\"", "bash scripts/build.sh",
    "(cd src && ls)", "echo \"$(git rev-parse HEAD)\"", "echo `date`", "ls -la && git status",
    "cat README.md | head -5", "rm -rf ./build", "timeout 30 rm -rf build", "rm -rf \"$TMPDIR/greenbar-x\"",
    "rm -rf /tmp/greenbar-x", "/bin/cat README.md", "/bin/ls", "echo 'cat .env is blocked'",
    "echo \"do not rm -rf ~ ever\"", "git commit -m 'block timeout 30 cat .env'",
    "git commit -m \"block rm -rf ~ behind timeout\"", "git commit -am 'never read ~/.ssh or .env'",
    "git commit -m \"$(cat <<'EOF'\nfix: don't let `timeout 30 cat .env` through\n\nrm -rf ~ too.\nEOF\n)\"",
    "grep -rn 'rm -rf' src/", "grep -n \"cat .env\" README.md", "grep -n 'bash -c \"cat .env\"' README.md",
    "python3 -c 'print(1)'", "for f in src/*.py; do wc -l \"$f\"; done",
    "if [ -f README.md ]; then cat README.md; fi", "while read -r l; do echo \"$l\"; done < README.md",
    "cat > notes.md <<'EOF'\nrun timeout 30 cat .env to see it blocked\nEOF",
    "python3 - <<'EOF'\nprint('rm -rf ~ is only text here')\nEOF",
    "echo $HOME", "ls ~", "cp .env.example config.sample", "docker run --rm -it node:20 sh -c 'npm test'",
    "ssh host 'ls'", "make test", "npx eslint .", "sed -n 1,5p README.md", "awk '{print $1, $2}' README.md",
    "printf '%s\\n' \"$PATH\"", "export NODE_ENV=test", "set -euo pipefail", "set -e; npm test",
    "git stash && git pull --rebase", "kill -0 $$", "echo \"a;b\" | tr ';' '\\n'",
    "git log --format='%h %s' | head", "npm run build -- --env production", "go env", "conda env list",
    "npm pkg set scripts.test=jest", "node -e \"console.log(process.env.NODE_ENV)\"",
    "[ -d build ] || mkdir build", "test -f README.md && echo yes", "! grep -q foo README.md",
    "VAR=1 make", "ls build | wc -l", "pytest -k \"not slow\" -x", "curl -s https://example.com | jq .",
    "docker rm -f old-container", "echo $((1 + 2))", "f=README.md; cat $f", "brew install tree",
    "pip install -r requirements.txt", "gh pr diff 12", "echo done 2>&1 | tee build.log",
    "git commit --amend --no-edit", "mkdir -p out && cp -r src out/ && ls out",
    "rm -rf $(pwd)/build", "sh -c 'echo \"$0\"' hello", "bash scripts/build.sh --env production",
    "git checkout -b fix/guard", "git checkout -m main", "echo a${IFS}b", "LS -la",
]

# Found by the security and cross-model reviews of the parser (2026-11-26).
REVIEW_BLOCKED = [
    'cd "$SOMEWHERE" && cat .aws/credentials',
    'echo {,}{,}{,}{,}{,}{,}{,}{,}{,}{,}{,}{,}{,}{,}{,}{,}{,}{,}{,}{,}; cat .env',
    '((x=1<<2))\ncat .env',
    '(( x = 1 << 2 ))\nrm -rf ~',
    'cat$IFS$9.env',
    'cat .e$@nv',
    'c$@at .env',
    'cat .e${u}nv',
    'cat ${x:-.env}',
    'cat ${x-.env}',
    'cat${IFS%?}.env',
    '{cat,.env}',
    'c{a,}t .env',
    'cd $HOME && rm -rf *',
    'cd "$HOME" && rm -rf *',
    'cd build && cd - && rm -rf *',
    'pushd build; popd; rm -rf *',
    'cd "$SOMEWHERE" && rm -rf *',
    'cd "$HOME" && cat .aws/credentials',
    'cat $HOME/./.ssh/config',
    'cat "$HOME/x/../.ssh/config"',
    'cd ~ && dd if=.ssh/id_rsa',
    'f=.env; cat < $f',
    'f=.env; cat < "$f"',
    'f=.e; f+=nv; cat $f',
    'f=.env bash -c \'cat "$f"\'',
    "env f=.env sh -c 'cat $f'",
    "printf '.env\\0' | xargs -0 cat",
    "printf 'cat\\x20.env' | sh",
    "echo -e 'cat\\x20.env' | sh",
    "echo 'cat .env' | bash -s -- x",
    "source /dev/stdin <<< 'cat .env'",
    ". /dev/stdin <<< 'cat .env'",
    "tcsh -c 'cat .env'",
    "mksh -c 'cat .env'",
    'sudo -nu root env',
    "echo 'cat .env' | sudo -nu root sh",
    'xargs -a .env echo',
    'xargs --arg-file=.env echo',
    'time -o .env true',
    'git -C "my dir" push -f',
    'git -c "user.name=A B" push -f',
    'git --git-dir /tmp/r reset --hard',
    'git clean --force -d',
    'git clean -d --force',
    'git commit --no-verif -m x',
    'git -C . rm tests/test_app.py',
    "find . -maxdepth 1 -name '.en*' -exec cat {} +",
    "find . -maxdepth 1 -name '.e?v' -exec cat {} +",
    "find . -maxdepth 1 -name '.[e]nv' -exec cat {} +",
    'fold .env',
    'grep -f .env README.md',
    'tar --file=.env -cf a.tar src',
    'install .env /tmp/x',
    'rm -rf "${HOME:-/}"',
    'rm --recurs --force ~',
]
# False alarms the same reviews found; these must stay allowed.
REVIEW_ALLOWED = [
    'wc -l src/*',
    'ls src/*',
    'echo $((2 * 3))',
    'x=$(( 4 * 5 )); echo $x',
    '(( 3 < 10 )) && echo ok',
    'jq .env package.json',
    "jq '.env.NODE_ENV' package.json",
    'gh pr create --title t --body "update server/.env.production handling"',
    'printenv NODE_ENV',
    'git commit -uno -m x',
    'grep -e foo -e bar README.md',
    "grep -rn -e 'process.env' src",
    'rsync -a --exclude=.env src/ out/',
    'tar --exclude=.env -czf out.tgz src',
    'cd "$BUILD_DIR" && ls',
    'curl -d \'{"a":1,"b":2}\' https://example.com',
    'git -C src status',
    'git -C src log --oneline -3',
    'sudo -u root ls',
    'sudo -nu root ls',
    'echo "$@"',
    'echo "$1" "$2"',
    'cd build && rm -rf *',
    'cd /tmp && ls',
    'ls -la {src,tests}',
    'mkdir -p out/{a,b}',
    'node -e "const {a, b} = {a: 1, b: 2}; console.log(a + b)"',
    "printf '%s\n' a b | xargs -n1 echo",
    "echo 'npm test' | sh",
    'git clean -n',
    'git reset --soft HEAD~1',
    'ls ${HOME}',
    'x=${FOO:-bar}; echo $x',
]


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
    record("done-gate | block reason calls out the false 'done' claim", "reads that way" in reason)
    record("done-gate | block reason forbids weakening tests", "Do not delete, skip or weaken tests" in reason)
    data = check("no claim in message: still blocks", "block",
                 run_hook(GATE, root, gate_event(root, "Here is a summary of the change.", "s2")))
    record("done-gate | no claim: reason does not accuse", "reads that way" not in data.get("reason", ""))

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
