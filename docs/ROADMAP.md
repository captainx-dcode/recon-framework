# Roadmap

The framework is intentionally built so that the items below are **additive** —
each slots into an existing seam without reworking the core. This document
doubles as a map of where those seams are.

## Status: v1.0

Shipped and tested:

- Core engine: classify → plan → collect → aggregate
- Pluggable `BaseCollector` contract with uniform error/timing handling
- Collectors: WHOIS, DNS, VirusTotal, Shodan
- Output: JSON, CSV, terminal table (Strategy pattern)
- Config from environment/`.env` with validation and injection
- Shared HTTP client (timeout, retries, rate-limiting, User-Agent)
- Centralized logging; multi-target support (domain / IP / email)
- 64 unit + integration tests, all offline

## Near term (v1.1) — more passive sources

The module names several tools not yet implemented. Each is a new collector
(one file + one registry line), proving the extension model:

- [ ] **Censys collector** — host/certificate data. `ENV_KEYS` already reserves
      `CENSYS_API_ID` / `CENSYS_API_SECRET`.
- [ ] **theHarvester-style email/subdomain collector** — aggregate emails,
      subdomains, and hosts from public sources.
- [ ] **Certificate Transparency collector** (crt.sh) — subdomain discovery with
      no API key required; a good "batteries-included" default.
- [ ] **Google Dorking helper** — generate and (optionally, within ToS) run a
      curated dork set for a domain.

## Near term (v1.2) — richer targets & chaining

- [ ] **Domain → IP chaining.** Let the DNS collector's resolved A/AAAA records
      feed IP-only collectors (Shodan) automatically within one run. The seam:
      the engine already produces a `ReconResult`; a small "expander" step can
      derive follow-up targets from it.
- [ ] **Email target enrichment** — breach/exposure lookups for `--target` emails.
- [ ] **CIDR / range input** — expand a network block into individual IP targets.

## Mid term (v2.0) — performance & scale

- [ ] **Concurrent collection.** Collectors are already isolated behind
      `run()`, so swapping the engine's sequential loop for a
      `concurrent.futures` executor is a localized change with no collector edits.
      Rate-limiting moves to a shared token bucket in `HttpClient`.
- [ ] **Batch mode** — accept a file of targets and emit one combined report.
- [ ] **Caching layer** — optional on-disk cache keyed by (source, target) to
      avoid burning API quota on repeated lookups.

## Mid term (v2.x) — output & reporting

- [ ] **HTML and Markdown formatters** — each is a single `Formatter` subclass.
- [ ] **Report diffing** — compare two runs of the same target over time to
      surface newly exposed services or changed registration.
- [ ] **SQLite storage backend** — alongside file output, for querying history.

## Longer term

- [ ] **Plugin auto-discovery** — load third-party collectors via entry points
      so they need not live in this repo.
- [ ] **Maltego export** — emit graph-friendly entities/links (the module frames
      Maltego as a visualisation layer; this is the data side of that).
- [ ] **Active-recon module (Part 2)** — a clearly-gated, authorization-required
      layer for port/service scanning, kept strictly separate from passive OSINT.

## Explicit non-goals

- **No exploitation or attack tooling.** This is a reconnaissance framework;
  weaponization is out of scope by design.
- **No scraping that violates a site's terms or `robots.txt`.** Collectors use
  official APIs and public data; anything active stays behind explicit flags and
  authorization.
- **No bundled secrets or default keys.** Ever.

## How to influence the roadmap

Open an issue describing the source or feature and the intel it provides. If
you'd like to build it, [CONTRIBUTING.md](CONTRIBUTING.md) shows that a new
collector is usually well under an hour of work.
