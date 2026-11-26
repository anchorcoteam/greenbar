---
name: setup
description: Set up greenbar's done gate for this repo. Finds the project's real test, type-check and lint commands, writes .claude/done-gate.json, and proves the gate works. Use when the user runs /greenbar:setup or asks to configure greenbar.
---

# Set up the greenbar done gate

The done gate does nothing until `.claude/done-gate.json` lists at least one check.

1. Find the commands this repo really uses. Look in `package.json` scripts, `pyproject.toml`,
   `Makefile`, `go.mod`, `Cargo.toml`, CI files under `.github/workflows/`, and the README.
   Prefer what CI runs. Typical picks: `npm test --silent`, `npx tsc --noEmit`, `python3 -m pytest -q`,
   `ruff check .`, `go test ./...`, `cargo test`.
2. Run each candidate once. Keep only commands that exit 0 on the current tree, or tell the user
   which already fail (the gate would block on them immediately).
3. Show the user the list and ask before writing. Then write `.claude/done-gate.json`:
   `{"checks": [{"name": "tests", "run": "<command>"}]}`. See `examples/done-gate.json` in this
   plugin for every option.
4. Add `.claude/.done-gate/` to `.gitignore` (it holds the last-green fingerprint).
5. Optional: write `.claude/guard.json` if the repo has paths beyond the defaults that Claude must
   never read (customer exports, credentials) or files that are locked once committed (migrations).
   A list you set replaces that list's defaults, so copy the defaults you still want.
6. Tell the user how to switch each part off: `touch .claude/done-gate.off`, `touch .claude/guard.off`,
   or `DONE_GATE_OFF=1` for one session.
