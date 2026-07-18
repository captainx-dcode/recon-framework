# Git Commit Roadmap — Lab: Reconnaissance Part 1

This is the incremental commit plan for the work done to support the OSINT lab.
Each commit is self-contained and leaves the repository in a working,
test-passing state. Apply them in order on top of the existing `main`.

The theme: **improve the framework first, then add the thin assignment file.**
Framework changes are reusable; the assignment merely orchestrates them.

---

## Commit 1 — Reusable hostname resolver

**Goal.** Add a single-responsibility utility to resolve a hostname to an IP,
usable by any collector that needs to pivot from a domain to an IP.

**Files modified/added.**
- `recon/utils/resolver.py` (new)
- `tests/unit/test_resolver.py` (new)

**Reason.** The lab's Shodan flow needs domain → IP resolution. Rather than bury
that in the Shodan collector, it belongs in a shared helper so future IP-centric
sources (Censys, reverse-DNS, GreyNoise) reuse it. DRY + Single Responsibility.

**Commit message.**
```
feat(utils): add reusable hostname resolver
```

---

## Commit 2 — Domain support in the Shodan collector

**Goal.** Let the Shodan collector accept domains as well as IPs, resolving a
domain to an IP first (Shodan `dns/resolve`, then the local resolver as
fallback) before the host lookup.

**Files modified.**
- `recon/collectors/shodan_collector.py`
- `tests/unit/test_shodan_domain_and_facade.py` (new)
- `tests/unit/test_collectors.py` (update the now-stale IP-only assertion)

**Reason.** The original collector was IP-only — a real limitation the lab
exposed, since analysts point Shodan at domains routinely. Fixing it in the
framework (not the assignment) strengthens the repo for every future consumer.

**Commit message.**
```
feat(collectors): support domain targets in Shodan via DNS resolution
```

---

## Commit 3 — Public facade API

**Goal.** Add module-level convenience functions (`whois_lookup`,
`shodan_lookup`, `investigate`) that wrap the engine/collectors so simple
consumers can call the framework in one line.

**Files modified/added.**
- `recon/api.py` (new)
- `recon/__init__.py` (export the facade; bump version to 1.1.0)

**Reason.** The engine is the right shape for applications but heavyweight for a
script. The Facade pattern gives a friendly surface without a second
implementation to drift out of sync — reusable by any consumer, not lab-specific.

**Commit message.**
```
feat(api): add public facade functions for framework consumers
```

---

## Commit 4 — Assignment orchestrator (`OSINT_final.py`)

**Goal.** Add the graded deliverable as a thin orchestration layer over the
framework, exposing the exact symbols the rubric checks for.

**Files added.**
- `OSINT_final.py` (new, at repo root)

**Reason.** The lab requires literal `import whois`, `get_whois_info`,
`get_shodan_info`, and calls to both. The file delegates to the framework
(no duplicated logic) and falls back to a self-contained mode if the package
isn't importable, so it passes CodeGrade in any environment.

**Commit message.**
```
feat(lab): add OSINT_final.py assignment orchestrator
```

---

## Commit 5 — Documentation

**Goal.** Document the facade, the lab solution, and rubric verification.

**Files added/modified.**
- `docs/LAB_SOLUTION.md` (new — approach + rubric verification table)
- `docs/GIT_ROADMAP_LAB.md` (new — this file)
- `README.md` (note domain-capable Shodan + facade API)

**Reason.** Keep the project approachable and make the grading story explicit.
Docs land last so they describe the final, stable surface.

**Commit message.**
```
docs: document facade API, lab solution, and rubric verification
```

---

## At a glance

| # | Commit | Leaves repo… |
|---|---|---|
| 1 | `feat(utils): add reusable hostname resolver` | green; new helper + tests |
| 2 | `feat(collectors): support domain targets in Shodan via DNS resolution` | green; Shodan handles domains |
| 3 | `feat(api): add public facade functions for framework consumers` | green; one-line API |
| 4 | `feat(lab): add OSINT_final.py assignment orchestrator` | green; graded file passes rubric |
| 5 | `docs: document facade API, lab solution, and rubric verification` | shippable v1.1.0 |

Every row is runnable and test-passing. If a regression appears at commit 2, you
know the resolver (commit 1) was fine — the layered history localizes the fault.
