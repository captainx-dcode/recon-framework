# Recon Framework

A modular, extensible **reconnaissance / OSINT framework** built around the
methodology taught in *Introduction to Reconnaissance Part 1*.

It generalises the module's two teaching functions (`get_whois_info` and
`get_virustotal_info`) into a reusable engine that can investigate **any**
domain, IP, or email using a pluggable set of OSINT collectors — and it is
designed so new sources (Censys, theHarvester, Google Dorking, …) drop in
without touching the core.

> **Ethical & legal use only.** This tool automates *passive* OSINT and light
> API lookups. Only run it against assets you own or are explicitly authorised
> to assess. See [Ethics & Legality](#ethics--legality).

---

## Table of contents

- [Why this exists](#why-this-exists)
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Architecture](#architecture)
- [Extending the framework](#extending-the-framework)
- [Testing](#testing)
- [Ethics & legality](#ethics--legality)
- [Further docs](#further-docs)

---

## Why this exists

The technical lesson produces a single script that prompts for a domain, calls
WHOIS and VirusTotal, prints the results, and dumps them to JSON. That is a fine
*learning* artifact but a poor *engineering* one: the API key is hardcoded,
there is no input validation, one failing call crashes the run, dates aren't
JSON-serialisable, and adding a third source means copy-pasting the pattern.

This repository keeps the lesson's **workflow** — scope → collect → store — and
rebuilds it as production software:

| Lesson script | This framework |
|---|---|
| Hardcoded `VT_API_KEY` in source | Keys from environment / `.env`, validated, never committed |
| Two standalone functions | One `BaseCollector` contract; sources are plugins |
| `main()` hardcodes the sequence | `ReconEngine` plans & runs applicable collectors |
| Crashes on any error | Every collector failure is captured as data |
| Prints + one JSON file | JSON / CSV / table formatters, pluggable |
| No tests | 64 unit + integration tests, fully mocked |

## Features

- **Multi-target** — domains, IPv4/IPv6, and emails, auto-classified.
- **Pluggable collectors** — WHOIS, DNS, VirusTotal, Shodan out of the box.
- **Passive/active awareness** — `--passive` skips anything that touches the network actively.
- **Structured output** — `--output json|csv|table`, plus `--save` to disk.
- **Resilient** — a missing key → *skipped*; a failing source → *error*; the run always completes.
- **Configurable & safe** — timeouts, retries, rate-limiting, and a consistent `User-Agent`, all env-driven.
- **Tested & typed** — type hints throughout; CI across Python 3.9–3.12.

## Installation

```bash
git clone https://github.com/captainx-dcode/recon-framework.git
cd recon-framework

python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# optional: install as a package to get the `recon` command
pip install -e .
```

Python 3.9+ is required. See [`docs/INSTALL.md`](docs/INSTALL.md) for details and
troubleshooting.

## Configuration

API keys are **never** hardcoded. Copy the template and fill in what you have:

```bash
cp .env.example .env
# edit .env — leave any key blank to simply skip that collector
```

| Variable | Used by | Required? |
|---|---|---|
| `VT_API_KEY` | VirusTotal collector | Optional (collector skipped if unset) |
| `SHODAN_API_KEY` | Shodan collector | Optional |
| `RECON_TIMEOUT` / `RECON_RATE_LIMIT` / `RECON_MAX_RETRIES` | HTTP client | Optional (defaults provided) |

WHOIS and DNS need **no keys**, so the framework is useful immediately. Full
reference in [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md).

## Usage

```bash
# Investigate a domain (runs every applicable collector)
python recon.py --domain example.com

# An IP, as JSON, also saved to reports/
python recon.py --ip 8.8.8.8 --output json --save

# Auto-detect the target type and run only specific tools, passively
python recon.py --target example.com --tool whois --tool dns --passive

# Machine-readable CSV
python recon.py --domain example.com --output csv

# See what's available
python recon.py --list-tools
```

Key flags: `--domain/--ip/--target`, `--tool` (repeatable), `--output`,
`--passive`, `--save`, `--output-dir`, `--verbose/--quiet`. More examples in
[`docs/USAGE.md`](docs/USAGE.md).

Example terminal output:

```
Reconnaissance report for example.com (domain)
Completed in 812 ms

SOURCE      STATUS   TIME    NOTE
----------  -------  ------  ----
whois       success  240ms   -
dns         success  180ms   -
virustotal  success  392ms   -

Highlights:
  - whois: registrar=MarkMonitor Inc.
  - dns: records=A, AAAA, MX, NS, SOA, TXT
  - virustotal: flagged=False detections=0
```

## Architecture

The design maps the module's OSINT-script process onto clean layers. Data flows
one way: the CLI composes everything, the engine orchestrates, collectors gather,
and output formats present.

```
                 ┌─────────────┐
   user  ───▶    │   cli.py    │   parse args, wire dependencies (composition root)
                 └──────┬──────┘
                        │ Config.load()            Config  ◀── .env / environment
                        ▼
                 ┌─────────────┐   classify target (validators)
                 │ ReconEngine │   plan applicable collectors → run → aggregate
                 └──────┬──────┘
             plan()     │      run()
        ┌───────────────┼────────────────┐
        ▼               ▼                 ▼
 ┌────────────┐  ┌────────────┐    ┌────────────┐   each implements BaseCollector
 │ WhoisColl. │  │  DnsColl.  │ …  │ ShodanColl │   → returns CollectorResult
 └────────────┘  └────────────┘    └─────┬──────┘
        │ (shared) HttpClient ────────────┘         retries · rate-limit · UA
        ▼
 ┌──────────────────────────────────────────┐
 │            ReconResult (model)            │   normalized aggregate of all sources
 └──────────────────┬───────────────────────┘
                    ▼
          ┌───────────────────┐      ┌──────────────┐
          │    Formatter      │ ───▶ │  ReportStore │   JSON / CSV / table → stdout / disk
          │ json · csv · table│      └──────────────┘
          └───────────────────┘
```

**Package layout**

```
recon/
├── cli.py                 # composition root: argparse → engine → formatter → store
├── core/
│   ├── config.py          # env/.env loading, validation, injectable Config
│   ├── models.py          # Target, CollectorResult, ReconResult (the data contract)
│   ├── engine.py          # ReconEngine: classify → plan → collect → aggregate
│   └── exceptions.py      # one error hierarchy for consistent handling
├── collectors/
│   ├── base.py            # BaseCollector: the plugin contract + error wrapper
│   ├── registry.py        # discovery/selection of collectors
│   ├── whois_collector.py
│   ├── dns_collector.py
│   ├── virustotal_collector.py
│   └── shodan_collector.py
├── output/
│   ├── formatters.py      # Formatter strategy: JSON / CSV / table
│   └── storage.py         # ReportStore: where/how reports are written
└── utils/
    ├── logging.py         # centralized logging config
    ├── http.py            # shared HTTP client (timeout, retry, rate-limit, UA)
    └── validators.py      # target classification / input validation
```

Full rationale — including how each SOLID/DRY/KISS principle is applied and why
each boundary exists — is in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Extending the framework

Adding an OSINT source is the litmus test of the design. It takes **two edits**:

```python
# 1. recon/collectors/censys_collector.py
from recon.collectors.base import BaseCollector
from recon.core.models import Target, TargetType

class CensysCollector(BaseCollector):
    name = "censys"
    description = "Host & certificate data from Censys."
    supported_types = (TargetType.IP, TargetType.DOMAIN)
    active = True

    def _collect(self, target: Target) -> dict:
        api_id = self._config.require_key("censys_api_id")      # → SKIPPED if unset
        resp = self.http.get(f"https://search.censys.io/api/v2/hosts/{target.value}",
                             headers={"Authorization": f"Basic {api_id}"})
        return {"target": target.value, "raw": resp.json()}
```

```python
# 2. register it in recon/collectors/registry.py
_DEFAULT_COLLECTORS = (WhoisCollector, DnsCollector, VirusTotalCollector,
                       ShodanCollector, CensysCollector)
```

It now appears in `--list-tools`, is selectable with `--tool censys`, runs in
the engine, and flows into every output format — no other code changes. See
[`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md).

## Testing

```bash
pip install -r requirements-dev.txt
pytest                     # 64 tests, all offline (APIs are mocked)
pytest --cov=recon         # with coverage
```

Tests never hit the network or use real keys: the framework's dependency
injection lets each test pass a fake `Config` and a fake HTTP client.

## Ethics & legality

Reconnaissance is legal and ethical **only within authorised scope**. This
project deliberately favours passive techniques and public APIs, applies polite
rate-limiting, and sends an honest `User-Agent`. Before use, ensure you have
written authorisation for the target and comply with applicable law (e.g. GDPR,
CCPA) and each API provider's terms. The authors accept no liability for misuse.

## Further docs

- [Architecture](docs/ARCHITECTURE.md) — deep dive & design decisions
- [Installation](docs/INSTALL.md)
- [Configuration](docs/CONFIGURATION.md)
- [Usage & examples](docs/USAGE.md)
- [Contributing](docs/CONTRIBUTING.md)
- [Roadmap](docs/ROADMAP.md)

## License

MIT — see [LICENSE](LICENSE).
