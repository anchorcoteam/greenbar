# greenbar

**Hooks for Claude Code that stop a false "done".**

Claude Code sometimes ends a turn with "Done, all tests pass" when it never ran them, or when they fail.
greenbar adds a Stop hook that runs your project's real checks every time Claude tries to finish. If a
check fails, Claude is not allowed to stop: it gets the failing command and the end of its output, and it
has to fix the cause or tell you plainly what still fails.

It also adds a guard that runs before every tool call and blocks the usual ways an agent hurts a repo:
reading `.env` files and keys, skipping or deleting tests, force-pushing, `--no-verify`, `git reset --hard`,
`rm -rf` on the wrong folder, and committing a secret.

Free and open source (MIT). Python 3.9+, standard library only, no network calls. 195 test cases.

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
python3 ~/.claude/plugins/cache/greenbar/greenbar/*/hooks/done_gate.py trust .   # path may vary; `claude plugin details greenbar` shows it
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
| Off-limits paths (`.env`, `.env.*` except `*.example`/`*.sample`/`*.template`, `*.pem`, `*.key`, `id_rsa*`, `secrets/`) | `Read .env`, `cat ./.ENV`, `head -c 200 .e*`, `cd src && cat ../.env`, `source .env`, `bash -c 'cat .env'`, `eval`, `$(cat .env)`, `Glob **/.env`, `find . -name '.env*'` |
| Dumping the environment into the transcript | `printenv`, bare `env`, `export -p`, `set` |
| Credential folders in your home directory | `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.docker`, `~/.netrc` |
| Weakening tests | adding `@pytest.mark.skip`, `@unittest.skip`, `it.skip(`, `xit(`, `t.Skip()`, `#[ignore]`; edits that remove test functions; `rm`/`git rm` of test files, or moving them out of a test folder (snapshots and caches are exempt) |
| Read-only and locked files | `read_only` globs; `locked_once_committed` globs (for example applied migrations: new files are fine, committed ones can't change) |
| Destructive git | `push --force` / `-f` / `+branch` / `--force-with-lease`, `--no-verify`, `commit -n`, `-c core.hooksPath=…`, `reset --hard`, `clean -f`, `checkout -- .`, `restore .` |
| Deleting far too much | `rm -rf /`, `~`, `$HOME`, `$PWD`, `..`, `.`, `*` at the project root, or the project root itself |
| Committing secrets | never-commit files staged, or added lines that look like AWS/GitHub/Stripe/Slack/Google/Anthropic/OpenAI keys, private keys or quoted passwords |

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

- **It is not a sandbox.** The guard reads command text. A determined process can still reach a file
  in ways it cannot see: a script or `python -c` that opens `.env` itself, recursive search such as
  `grep -r KEY .` (which reads every file), `cat $(echo .env)`, encoded paths, or symlinks made at run
  time. Use it as a guard rail, and keep real secrets out of reach with OS permissions.
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
python3 tests/run_tests.py        # 195 cases, about 1-2 minutes, touches only a temp folder
python3 tests/run_tests.py -v     # list every case
```

`proof/` holds a recorded run on a clean machine profile. It installs from this repo only, runs the
suite, and runs a live break test where headless Claude Code is asked to break a test and say "done".

## License

MIT. See [LICENSE](LICENSE).
