# Git Commit Roadmap — Interactive Mode (v1.2.0)

Incremental commit plan for the interactive wizard. Each commit leaves the repo
working and test-passing. Apply in order on top of the v1.1.0 work.

The guiding principle: interactive mode is an **addition**, never a replacement.
The flag-driven, scriptable path (used by CodeGrade, pipes, and CI) is preserved
exactly — the wizard only ever runs for a human at a real terminal.

---

## Commit 1 — Immutable key-merge helper on Config

**Goal.** Let a caller produce a new Config with extra API keys merged in,
without mutating the shared (frozen) instance.

**Files modified/added.**
- `recon/core/config.py` (add `Config.with_keys`)
- `tests/unit/test_interactive.py` (new — `TestWithKeys` portion)

**Reason.** Interactive mode needs to inject keys the user pastes at the prompt.
Config is intentionally frozen for safety, so we return a fresh copy rather than
mutate state. This keeps the immutability guarantee intact.

**Commit message.**
```
feat(config): add immutable with_keys helper for runtime key injection
```

---

## Commit 2 — Interactive wizard module

**Goal.** Add the guided prompt flow (target → mode → optional key collection →
output format) as a self-contained, testable module.

**Files added.**
- `recon/interactive.py`
- remainder of `tests/unit/test_interactive.py` (TTY gate + wizard flow tests)

**Reason.** All prompting is quarantined in one module so it can be unit-tested
(by patching `input`) and, crucially, so the rest of the framework stays
non-interactive. The `is_interactive()` TTY gate is the safety mechanism that
prevents the wizard from firing in scripts/CI/CodeGrade.

**Commit message.**
```
feat(interactive): add opt-in interactive wizard for guided runs
```

---

## Commit 3 — Wire the wizard into the CLI

**Goal.** Launch the wizard when the user passes `--interactive`, or when no
target is given *and* stdin/stdout are a real terminal. Translate its answers
into the same variables the flags set, so there is one execution path.

**Files modified.**
- `recon/cli.py` (import, `--interactive` flag, hook in `run()`, help epilog)

**Reason.** The CLI is the composition root, so the branch belongs here. The TTY
check ensures a missing target still errors cleanly (never hangs) in
non-interactive contexts — CodeGrade and pipes are unaffected.

**Commit message.**
```
feat(cli): launch interactive wizard when no target given at a TTY
```

---

## Commit 4 — Version bump & documentation

**Goal.** Bump to 1.2.0 and document interactive mode.

**Files modified.**
- `pyproject.toml`, `recon/__init__.py` (version → 1.2.0)
- `docs/USAGE.md` (interactive-mode section + options table)
- `docs/GIT_ROADMAP_INTERACTIVE.md` (this file)

**Reason.** Interactive mode is a user-facing feature warranting a minor version
bump and clear docs. Docs land last so they describe the final surface.

**Commit message.**
```
docs: document interactive mode and bump version to 1.2.0
```

---

## At a glance

| # | Commit | Leaves repo… |
|---|---|---|
| 1 | `feat(config): add immutable with_keys helper for runtime key injection` | green; helper + tests |
| 2 | `feat(interactive): add opt-in interactive wizard for guided runs` | green; wizard + tests |
| 3 | `feat(cli): launch interactive wizard when no target given at a TTY` | green; wizard reachable |
| 4 | `docs: document interactive mode and bump version to 1.2.0` | shippable v1.2.0 |

Non-interactive behaviour (flags, pipes, CodeGrade) is identical before and after
this series — verified by the existing test suite continuing to pass.
