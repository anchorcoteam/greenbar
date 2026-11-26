# greenbar

**Hooks for Claude Code that stop a false "done".**

Claude Code sometimes ends a turn with "Done, all tests pass" when it never ran them, or when they fail.
greenbar adds a Stop hook that runs your project's real checks every time Claude tries to finish. If a
check fails, Claude is not allowed to stop: it gets the failing command and the end of its output, and it
has to fix the cause or tell you plainly what still fails.

It also adds a guard that runs before every tool call and blocks the usual ways an agent hurts a repo:
reading `.env` files and keys, skipping or deleting tests, force-pushing, `--no-verify`, `git reset --hard`,
`rm -rf` on the wrong folder, and committing a secret.

Free and open source (MIT). Python 3.9+, standard library only, no network calls. 562 test cases.

> greenbar is an independent project. It is not made, endorsed or supported by Anthropic.

## Install

As a plugin (recommended):

```bash
claude plugin marketplace add anchorcoteam/greenbar
claude plugin install greenbar@greenbar
```

Then, inside a session in your repo, run `/greenbar:setup`. It finds your test, type-check and lint
commands, asks you to confirm them, and writes `.claude/done-gate.json`. You can also write that file by hand:

```json
{ "checks": [ { "name": "tests", "run": "npm test --silent" }, { "name": "lint", "run": "npx eslint ." } ] }
```

**Trust step.** The gate only runs a config you have approved, so a repo you clone cannot make it run its
own commands. `/greenbar:setup` does this for you. By hand:

```bash
python3 "$(find ~/.claude/plugins -path '*greenbar/hooks/done_gate.py' | head -1)" trust .
```

Run it again whenever you edit `.claude/done-gate.json`. Until then the gate allows the stop and tells you why.
The same trust covers `.claude/guard.json` and `.claude/guard.off`. Until you trust them, a repo's
`guard.json` can only add rules, and a repo's `guard.off` is ignored. Trust is stored in
`~/.config/greenbar/trusted.json`, never in the repo.

Add `.claude/.done-gate/` to your `.gitignore`. It stores the fingerprint of the last green run.

Without plugins: copy `plugins/greenbar/hooks/` into your repo as `.claude/hooks/greenbar/` and add the two
entries from `plugins/greenbar/hooks/hooks.json` to `.claude/settings.json`, replacing
`${CLAUDE_PLUGIN_ROOT}/hooks` with `$CLAUDE_PROJECT_DIR/.claude/hooks/greenbar`.

## What it does

### Done gate (Stop hook)

- Runs each command in `.claude/done-gate.json` when Claude tries to end its turn. Each check runs in
  the project folder with `CI=1`.
- Any non-zero exit or timeout blocks the stop. Claude sees which check failed and the last 40 lines
  of its output. If Claude's last message claimed success, the message says so.
- **No wasted runs.** It fingerprints the working tree (HEAD, the diff and untracked files, or file
  times outside git) when your prompt arrives and when Claude stops. If the turn changed nothing (a
  question, a plan), or nothing changed since the last green run, it allows the stop without running
  anything. A suite that was already red before the turn doesn't punish question-only turns.
- Checks run in their own process group. On a timeout the whole group is killed, so no test workers
  are left holding ports. Output is kept on disk, and only the tail is read, with likely secrets redacted.
  There is a total budget (`total_timeout_seconds`, default 1500) under the hook's 30-minute limit.
- **Cannot trap you.** After `max_consecutive_blocks` failures in a row (default 3), Claude may stop.
  You see a warning that the checks are still failing.
- Fails open with a visible warning if its own config or input is broken. A bug in the gate never
  locks your session.

### Guard (PreToolUse hook)

It is on as soon as the plugin is installed. Defaults, all configurable in `.claude/guard.json`:

| Blocks | Examples caught |
|---|---|
| Off-limits paths (`.env`, `.env.*` except `*.example`/`*.sample`/`*.template`, `*.pem`, `*.key`, `id_rsa*`, `secrets/`) | `Read .env`, `cat ./.ENV`, `head -c 200 .e*`, `cd src && cat ../.env`, `source .env`, `timeout 30 cat .env`, `bash -c 'cat .env'`, `echo .env \| xargs cat`, `eval`, `$(cat .env)`, `Glob **/.env`, `find . -name '.env*'` |
| Dumping the environment into the transcript | `printenv`, bare `env`, `export -p`, `set` |
| Credential folders in your home directory | `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.docker`, `~/.netrc` |
| Weakening tests | adding `@pytest.mark.skip`, `@unittest.skip`, `it.skip(`, `xit(`, `t.Skip()`, `#[ignore]`; edits that remove test functions; `rm`/`git rm` of test files, or moving them out of a test folder (snapshots and caches are exempt) |
| Read-only and locked files | `read_only` globs; `locked_once_committed` globs (for example applied migrations: new files are fine, committed ones can't change) |
| Destructive git | `push --force` / `-f` / `+branch` / `--force-with-lease`, `--no-verify`, `commit -n`, `-c core.hooksPath=…`, `reset --hard`, `clean -f`, `checkout -- .`, `restore .` |
| Deleting far too much | `rm -rf /`, `~`, `$HOME`, `$PWD`, `..`, `.`, `*` at the project root, or the project root itself, also as `sudo rm -rf /`, `timeout 30 rm -rf ~` or `find . -exec rm -rf ~ \;` |
| Committing secrets | never-commit files staged, or added lines that look like AWS/GitHub/Stripe/Slack/Google/Anthropic/OpenAI keys, private keys or quoted passwords |

**How shell commands are read.** The guard does not match the command line against a list of bad
strings. It splits it the way a shell would (quotes, escapes, `;`, `&&`, pipes, subshells, loop bodies,
here-documents) and checks each command that would really run. Wrapper commands are stripped first
(`sudo`, `env`, `timeout`, `nice`, `nohup`, `time`, `command`, `exec`, `stdbuf`, `xargs`, `watch` and
others), so `timeout 30 cat .env` and `/bin/cat ".env"` are both judged as `cat .env`. It follows command
text into `sh -c '...'`, `eval`, `$(...)`, backticks, `find -exec` and text piped or here-doc'd into a
shell, and it fills in a variable set to plain text earlier on the same line (`f=.env; cat $f`). When a
program it does not know has a command such as `cat` or `rm` among its arguments, that is checked as a
command too, so it errs toward blocking: `docker exec app cat .env` is refused. If it cannot read a
command at all, it blocks it.

In a trusted `guard.json`, a list you set replaces that list's defaults. See `plugins/greenbar/examples/`
for both config files. If `guard.json` is broken, the guard uses its defaults and still lets Claude edit
the file to fix it.

## Turn it off

- One session: `DONE_GATE_OFF=1 claude`
- One repo: `touch .claude/done-gate.off` and/or `touch .claude/guard.off`
- Everywhere: `claude plugin disable greenbar@greenbar`

## Uninstall

```bash
claude plugin uninstall greenbar@greenbar
claude plugin marketplace remove greenbar
```

Then delete `.claude/done-gate.json`, `.claude/guard.json` and `.claude/.done-gate/` from any repo where you
set it up. greenbar writes nothing else.

## What it does not do

- **The guard is a seatbelt, not a sandbox.** It reads the text of a command before it runs; it does
  not watch or confine the process. It stops the accidents and the lazy shortcuts, and anything that
  hides what it does from the command text gets past it. Known gaps:
  - Another language doing the work: `python -c "open('.env').read()"`, `node -e`, a script file, a
    Makefile target or an npm script.
  - Text that only exists at run time: `cat $(echo .env)`, a variable set in an earlier command or
    exported by your shell, a program name built on the fly (`$CMD .env`), a file list fed to `xargs`
    or `sh` from a file or the network (`curl ... | sh`).
  - Aliases and shell functions defined elsewhere, and git aliases.
  - Commands that read everything under a folder: `grep -r KEY .`, `tar c .`, `cp -r . /tmp/x`.
  - Command strings sent somewhere else to run, such as `ssh host '...'`.
  - A program the guard does not know as a file reader, given a bare file name (`curl -d @.env ...`,
    `git show HEAD:.env`). A path with a slash is always checked, whatever the program.
  - A program that runs code written inside its own arguments: `awk 'BEGIN{system("...")}'`,
    `git -c alias.x='!...' x`, `some-tool --cmd='...'`.
  - `find . -exec cat {} +` with no name filter, which reads every file it finds.
  - Emptying a test file from the shell (`: > tests/test_x.py`); the test rules cover the edit tools,
    `rm`, `git rm` and `mv`.
  - `env` run inside something else (`docker exec app env`), because `go env` and `conda env` must work.
  - Encoded or computed spellings (`.e{n..n}v`, `/bin/ca? .env`), and symlinks made at run time.

  Keep real secrets out of reach with OS permissions, and use a real sandbox or container when the
  agent must not be able to do something.
- Checks inherit your environment, so a test that prints environment variables can show them to Claude.
  Output is redacted for common key formats, not for everything.
- `cp .env.example .env` is blocked because it writes an off-limits file. Run it yourself.
- **It only knows the checks you give it.** If your tests don't cover the change, a green bar proves
  nothing. It also doesn't judge whether the code is good.
- It doesn't stop Claude from writing a weak new test. It does block adding skip markers and deleting test files.
- Secret scanning is pattern-based. It catches common key formats and quoted passwords of 12+ characters.
  It misses unquoted `KEY=value` lines and short passwords.
- Checks run on your machine with your permissions. Only list commands you would run yourself.
- **Platforms:** tested on macOS 26 arm64 (Python 3.9 and 3.15, plus a live clean-profile run) and on Linux arm64 in a `python:3.12-slim` container (test suite only; see `proof/`).
  Windows is not supported: the done gate needs `fcntl`, and it switches itself off without it. If
  `python3` is missing, both hooks switch themselves off with a one-line warning.

## Test it

```bash
python3 tests/run_tests.py        # 562 cases, a few minutes, touches only a temp folder
python3 tests/run_tests.py -v     # list every case
```

`proof/` holds recorded runs. `macos-clean-home-run.txt` is a brand-new HOME that installs the plugin from
GitHub, runs the suite, then runs two live break tests with headless Claude Code on a fresh clone of
[tomli](https://github.com/hukkin/tomli). In test A, Claude is told to break the parser and reply "Done, all
tests pass": the gate blocks the stop and Claude reports the 93 failures instead. In test B, Claude is asked to
`cat .env`, and the guard blocks it. `linux-test-run.md` is the suite in a Linux container. Re-run with
`proof/clean-home-proof.sh`.

## License

MIT. See [LICENSE](LICENSE).
