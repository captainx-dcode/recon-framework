# Git Implementation Roadmap

You asked for the repository to be developed **incrementally** — not one massive
commit — so that debugging and regression tracking stay easy. This document is
that plan.

Each phase below is a single, self-contained commit that **leaves the repository
in a working, test-passing state**. Later phases only *add* to earlier ones; they
never require rewriting what came before. That property is what makes
`git bisect` and regression hunting straightforward: any green commit is a usable
checkpoint.

For every phase you get: **Goal**, **Files**, **Reason**, **Expected outcome**,
and a **Commit message**.

---

## How to use this

Work top to bottom. After each phase, run `pytest` (once tests exist) and a
quick manual check, then commit with the provided message. The first phase seeds
the repo exactly as GitHub's "create a new repository on the command line"
snippet expects:

```bash
git init
git branch -M main
git remote add origin https://github.com/captainx-dcode/recon-framework.git
# ... make Phase 1 changes ...
git add .
git commit -m "chore: bootstrap repository skeleton and tooling"
git push -u origin main
# ... then Phase 2 onward, one commit each ...
```

---

## Phase 1 — Repository skeleton & tooling

**Goal.** Establish a professional, empty-but-runnable project shell so every
later commit lands in a proper structure.

**Files created.**
- `README.md` (initial overview)
- `LICENSE` (MIT)
- `.gitignore`
- `requirements.txt`, `requirements-dev.txt`
- `pyproject.toml`
- `.env.example`
- `recon/__init__.py` and empty subpackage `__init__.py` files
  (`core/`, `collectors/`, `output/`, `utils/`)

**Reason.** Getting packaging, ignore rules, and the secret-handling story
(`.env.example` + git-ignored `.env`) right *before* writing code prevents two
classic mistakes: committing secrets, and refactoring the layout later.

**Expected outcome.** `pip install -e .` succeeds; the package imports; there's
nothing to run yet but the scaffold is sound.

**Commit message.**
```
chore: bootstrap repository skeleton and tooling
```

---

## Phase 2 — Core data model & exceptions

**Goal.** Define the shared vocabulary every other layer will speak.

**Files created.**
- `recon/core/models.py` (`Status`, `TargetType`, `Target`, `CollectorResult`, `ReconResult`)
- `recon/core/exceptions.py` (`ReconError` hierarchy)
- `tests/__init__.py`, `tests/unit/__init__.py`
- `tests/unit/test_models.py`

**Reason.** The models are the contract that decouples collection from
presentation; they depend on nothing, so building them first means everything
later has a stable foundation and cannot introduce import cycles.

**Expected outcome.** `pytest` runs and passes model tests. `ReconResult.to_dict()`
round-trips through `json.dumps`.

**Commit message.**
```
feat(core): add normalized data model and exception hierarchy
```

---

## Phase 3 — Logging & configuration

**Goal.** Centralized logging and environment-based, injectable configuration.

**Files created.**
- `recon/utils/__init__.py`, `recon/utils/logging.py`
- `recon/core/config.py` (`Config`, `ENV_KEYS`, `.env` loader with fallback)
- `tests/unit/test_config.py`

**Reason.** Configuration and logging are cross-cutting; establishing them early
(with keys sourced from env, never code) means every subsequent component can be
wired the right way from birth. Injecting `Config` is what will make collectors
testable without real secrets.

**Expected outcome.** Config loads from env and `.env`; missing keys are `None`;
`require_key` raises a helpful `ConfigError`. Logging is configurable via a
single call. Tests pass.

**Commit message.**
```
feat(core): add centralized logging and environment-based configuration
```

---

## Phase 4 — Validation & shared HTTP client

**Goal.** Two foundational utilities: target classification and a resilient HTTP
client.

**Files created.**
- `recon/utils/validators.py` (`classify`, `is_domain`, `is_ip`)
- `recon/utils/http.py` (`HttpClient` with timeout, retries, rate-limit, UA)
- `tests/unit/test_validators.py`

**Reason.** Both are prerequisites for collectors. Centralizing HTTP behaviour
now (DRY) means individual collectors will contain only source-specific logic;
centralizing classification means the engine can later select collectors by
target type reliably.

**Expected outcome.** Domains/IPs/emails/URLs classify correctly; garbage raises
`ValidationError`. The HTTP client retries transient failures and paces
requests. Validator tests pass.

**Commit message.**
```
feat(utils): add target validation and shared HTTP client
```

---

## Phase 5 — Collector contract

**Goal.** The keystone abstraction: `BaseCollector`.

**Files created.**
- `recon/collectors/__init__.py`, `recon/collectors/base.py`

**Reason.** This is the generalisation of the lesson's standalone functions into
a plugin contract. Its `run()` wrapper centralizes timing, applicability checks,
and error/skip handling so no collector ever repeats that logic — and so one
failing source can never crash a run. Everything after this is "just" writing
sources against the contract.

**Expected outcome.** `BaseCollector` can't be instantiated directly (it's
abstract); a trivial subclass runs and returns a `CollectorResult`. (Dedicated
tests arrive with the first real collectors in Phase 6.)

**Commit message.**
```
feat(collectors): add BaseCollector plugin contract with uniform result handling
```

---

## Phase 6 — WHOIS & DNS collectors (passive, keyless)

**Goal.** The first two real sources — both passive and requiring no API key, so
the tool is immediately useful.

**Files created.**
- `recon/collectors/whois_collector.py`
- `recon/collectors/dns_collector.py`
- `tests/conftest.py` (fake `Config`, fake HTTP client, fixtures)
- part of `tests/unit/test_collectors.py` (WHOIS via a faked `whois` module;
  base-wrapper behaviour)

**Reason.** Leading with keyless passive collectors means the framework does
something valuable before any credentials exist, and it exercises the contract
end-to-end. WHOIS also demonstrates the date-normalisation fix over the lesson.

**Expected outcome.** WHOIS returns structured registration data with ISO dates;
DNS returns record types found. Both degrade cleanly if their library is absent.
Tests pass.

**Commit message.**
```
feat(collectors): add passive WHOIS and DNS collectors
```

---

## Phase 7 — VirusTotal & Shodan collectors (API-backed)

**Goal.** Two API-backed sources, proving the config/HTTP-injection story and
multi-target support (domain vs IP).

**Files created.**
- `recon/collectors/virustotal_collector.py`
- `recon/collectors/shodan_collector.py`
- remainder of `tests/unit/test_collectors.py` (mocked API responses; 404/401
  handling; missing-key → skipped)

**Reason.** These validate the parts the passive collectors don't touch: keyed
access via `require_key` (→ SKIPPED when unset), the shared HTTP client, and
summarising large API payloads. Shodan (IP-only) vs VirusTotal (domain+IP) also
exercises applicability.

**Expected outcome.** With a fake key + fake HTTP, both return summarised data;
without a key they're SKIPPED, not errored; auth/404 map to sensible statuses.
Tests pass.

**Commit message.**
```
feat(collectors): add VirusTotal and Shodan API collectors
```

---

## Phase 8 — Registry & engine

**Goal.** Tie collectors together: discovery/selection and the orchestration
workflow.

**Files created.**
- `recon/collectors/registry.py` (`CollectorRegistry`, `build_default_registry`)
- `recon/core/engine.py` (`ReconEngine`: classify → plan → collect → aggregate)
- `tests/integration/__init__.py`, `tests/integration/test_engine.py`

**Reason.** The engine is the generalisation of `main()`. Building it *after* the
collectors and registry means it can be tested against real selection logic with
fake collectors, proving the whole passive/active/tool-filter workflow.

**Expected outcome.** The engine classifies a target, selects only applicable
collectors (respecting `--passive` and tool filters), runs them, and returns a
serialisable `ReconResult`. Integration tests pass.

**Commit message.**
```
feat(core): add collector registry and reconnaissance orchestration engine
```

---

## Phase 9 — Output formatters & storage

**Goal.** Present results in JSON, CSV, and a terminal table, and persist them.

**Files created.**
- `recon/output/__init__.py`, `recon/output/formatters.py`
- `recon/output/storage.py`
- `tests/unit/test_formatters.py`

**Reason.** Presentation is deliberately last among the library layers because it
consumes the finished model and nothing depends on it. The Strategy pattern here
makes future formats trivial; separating storage from formatting keeps "how it
looks" and "where it goes" independent.

**Expected outcome.** All three formatters render a `ReconResult`; JSON is valid,
CSV is one row per source, the table shows highlights. `ReportStore` writes files
with safe names. Formatter/registry tests pass.

**Commit message.**
```
feat(output): add JSON/CSV/table formatters and report storage
```

---

## Phase 10 — CLI & entry point

**Goal.** The composition root that wires everything into a usable command.

**Files created.**
- `recon/cli.py` (argparse, all flags, exit codes)
- `recon.py` (root entry-point shim)

**Reason.** The CLI depends on every other layer and is depended on by none, so
it comes last. Keeping wiring here — and logic in the library — is what kept all
prior phases importable and testable without a shell.

**Expected outcome.** `python recon.py --list-tools`, `--domain …`, `--output …`,
`--passive`, `--save`, `--verbose` all work end-to-end. Structured output to
stdout, logs to stderr. `pip install -e .` exposes the `recon` command.

**Commit message.**
```
feat(cli): add command-line interface and executable entry point
```

---

## Phase 11 — CI & documentation

**Goal.** Continuous integration and the full documentation set.

**Files created.**
- `.github/workflows/ci.yml`
- `docs/ARCHITECTURE.md`, `docs/INSTALL.md`, `docs/CONFIGURATION.md`,
  `docs/USAGE.md`, `docs/CONTRIBUTING.md`, `docs/ROADMAP.md`,
  `docs/GIT_ROADMAP.md`
- expanded `README.md`

**Reason.** With the code complete and green, lock in quality (tests on 3.9–3.12)
and make the project approachable. Docs land last so they describe the final,
stable surface rather than a moving target.

**Expected outcome.** CI runs the suite across Python versions and smoke-tests
the CLI on every push/PR. A newcomer can install, configure, run, and extend the
tool from the docs alone.

**Commit message.**
```
docs: add CI workflow and full documentation set
```

---

## Suggested sequence at a glance

| # | Commit | Leaves repo… |
|---|---|---|
| 1 | `chore: bootstrap repository skeleton and tooling` | installable, empty |
| 2 | `feat(core): add normalized data model and exception hierarchy` | model tested |
| 3 | `feat(core): add centralized logging and environment-based configuration` | config tested |
| 4 | `feat(utils): add target validation and shared HTTP client` | utils tested |
| 5 | `feat(collectors): add BaseCollector plugin contract with uniform result handling` | contract ready |
| 6 | `feat(collectors): add passive WHOIS and DNS collectors` | usable, keyless |
| 7 | `feat(collectors): add VirusTotal and Shodan API collectors` | API sources tested |
| 8 | `feat(core): add collector registry and reconnaissance orchestration engine` | full workflow |
| 9 | `feat(output): add JSON/CSV/table formatters and report storage` | output tested |
| 10 | `feat(cli): add command-line interface and executable entry point` | end-to-end CLI |
| 11 | `docs: add CI workflow and full documentation set` | shippable v1.0 |

Every row is green and runnable. If a regression appears at, say, commit 9, you
know the engine (commit 8) was fine and the fault is in output — the layered,
additive history does the triage for you.
