# Architecture

This document explains **how** the framework is structured and, more
importantly, **why** each decision is the right one. It is the engineering
counterpart to the module's "Process: Building a Script for Collecting OSINT."

## 1. From lesson script to framework

The technical lesson's final script is one file with three responsibilities
fused together:

```python
VT_API_KEY = "your_..._here"          # configuration
def get_whois_info(domain): ...       # collection (source 1)
def get_virustotal_info(domain): ...  # collection (source 2)
def main():                           # orchestration + presentation + storage
    domain = input(...)
    ... print ...
    json.dump(...)
```

Every one of those concerns is something you'll want to change independently:
add a source without touching orchestration; change output format without
touching sources; swap the key store without touching anything. Fusing them is
what makes the script un-extensible. The framework's entire structure is the
result of **separating those concerns** into layers that depend on each other in
one direction only.

## 2. The layers and their dependency flow

```
cli  ──▶  engine  ──▶  collectors  ──▶  utils(http)
 │          │              │
 │          ├──▶ registry ─┘
 │          ▼
 └──▶  output(formatters, storage)  ──▶  core(models)
                              ▲
        everything depends on core(models) — nothing in core depends outward
```

Rules that keep this clean:

- **`core/models.py` depends on nothing** in the framework. It is the shared
  vocabulary (`Target`, `CollectorResult`, `ReconResult`) every other layer
  speaks. Because it has no dependencies, no change elsewhere can break it, and
  it can be imported anywhere without cycles.
- **Collectors depend on `core` and `utils`, never on each other.** WHOIS
  knows nothing about DNS. This is what lets you delete or add one freely.
- **Output depends only on `core` models**, never on collectors. A formatter
  renders a `ReconResult`; it neither knows nor cares that a `ShodanCollector`
  produced part of it.
- **The CLI depends on everything and is depended on by nothing.** It is the
  *composition root* — the single place where concrete objects are created and
  wired. Keeping wiring in exactly one place is what makes the rest of the code
  importable and testable without a shell.

## 3. The central abstraction: `BaseCollector`

Every OSINT source, no matter how exotic, has the same shape: *given a target,
talk to some source, return findings*. The lesson wrote that shape twice as free
functions. We capture it once as an abstract base class:

```python
class BaseCollector(ABC):
    name: str
    supported_types: tuple[TargetType, ...]
    active: bool
    def applies_to(self, target) -> bool: ...
    def _collect(self, target) -> dict: ...   # subclass fills this in
    def run(self, target) -> CollectorResult:  # framework provides this
```

Why this is the keystone:

- **Open/Closed Principle.** The engine is *closed* for modification but the set
  of collectors is *open* for extension. New behaviour arrives as new subclasses.
- **Liskov substitutability.** The engine treats every collector identically
  through this interface, so any collector works anywhere a collector is
  expected.
- **The `run()` wrapper enforces one invariant for free:** *a collector never
  crashes the run.* It times the call, checks applicability, and converts any
  exception into a `CollectorResult(status=ERROR)` — or a missing key into
  `SKIPPED`. Subclasses just implement `_collect` and raise naturally; they
  never write try/except boilerplate. This is DRY applied to error handling, and
  it's what makes running twenty sources robust.

## 4. The data contract: normalized results

A single normalized model (`core/models.py`) is what decouples collection from
presentation. Every collector returns a `CollectorResult` with the same
envelope — `source`, `status`, `data`, `error`, `duration_ms` — regardless of
what it queried. The engine aggregates these into one `ReconResult`.

Consequences:

- Formatters and storage consume **only** `ReconResult`. Adding VirusTotal never
  requires touching the CSV formatter, because the CSV formatter was written
  against the model, not against any source.
- `to_dict()` on the models guarantees JSON-serialisability. This is a concrete
  fix for a real lesson bug: `python-whois` returns `datetime` objects (and
  sometimes lists of them), which make the lesson's `json.dump` throw on many
  real domains. Normalisation to ISO strings happens once, at the collector
  boundary.

## 5. Configuration & dependency injection

`Config` is an immutable, environment-sourced object (`core/config.py`). Crucially
it is **injected** into the engine and collectors rather than read from globals:

```python
engine = ReconEngine(Config.load())      # production
engine = ReconEngine(fake_config, http=fake_http)   # a test
```

Why injection over the lesson's module global:

- **Testability.** A test constructs a `Config` with a fake key and a fake HTTP
  client and exercises a collector with zero network access and zero real
  secrets. The 64-test suite runs in <0.1s precisely because of this.
- **Security.** The key lives in the environment/`.env` (git-ignored), not in
  source. `require_key()` turns "missing key" into a clean `SKIPPED` result with
  a message telling the user which variable to set — never a leaked default or a
  cryptic 401.
- **Immutability (`frozen=True`).** No collector can mutate shared config
  mid-run, eliminating a class of spooky-action bugs.

## 6. Cross-cutting utilities (DRY)

Three concerns are identical across sources, so each lives in exactly one place:

- **`utils/http.py`** — one `HttpClient` gives every API-backed collector the
  same timeout, bounded retries with exponential backoff (honouring
  `Retry-After`), polite inter-request delay, and a consistent `User-Agent`. The
  module explicitly calls out the User-Agent and "rate limiting and delays";
  centralising them means a collector contains *only* its unique logic.
- **`utils/logging.py`** — logging is configured once. `--verbose` flips the
  global level. Logs go to **stderr** so **stdout** stays clean for piping
  JSON/CSV — a deliberate choice for tool composability and CodeGrade capture.
- **`utils/validators.py`** — target classification is centralised and unit
  tested, because getting it wrong (firing an IP collector at a domain) wastes
  API quota and confuses users.

## 7. The engine: workflow as code

`ReconEngine` is the generalisation of `main()`. It expresses the module's
workflow abstractly:

```
classify(raw)         # scope definition       (stage 1)
  → plan(target)      # reconnaissance planning (stage 2): pick applicable collectors
    → run each        # OSINT collection        (stages 3–7)
      → aggregate      # result normalization    (stage 8)
        → ReconResult  # handed to output/storage (stages 9–10)
```

`plan()` is separate from `run()` on purpose: selection logic (which tools apply
to this target type, honouring `--tool` and `--passive`) is pure and testable in
isolation, and it enables features like dry-runs without executing anything.

## 8. Output as a strategy

Formatters (`output/formatters.py`) implement a common `Formatter` interface —
the Strategy pattern. The CLI picks one by name. Adding HTML or Markdown output
is a single new subclass; the engine, collectors, and storage are untouched.
Storage (`output/storage.py`) is deliberately separate from formatting: *how a
report looks* (formatter) and *where it goes / what it's named* (store) are
different decisions, so writing a CSV to disk reuses the exact code path as
writing JSON — only the injected formatter differs.

## 9. Principle scorecard

| Principle | Where it shows up |
|---|---|
| **Single Responsibility** | Each module owns one concern: config, models, engine, one collector per source, one formatter per format, storage, http, logging, validation. |
| **Open/Closed** | New collectors and new output formats are added by subclassing + registering; core code never changes. |
| **Liskov Substitution** | The engine drives every collector purely through `BaseCollector`. |
| **Interface Segregation** | Collectors implement one tiny method (`_collect`); formatters implement one (`render`). No fat interfaces. |
| **Dependency Inversion** | High-level engine depends on the `BaseCollector` abstraction, not concrete sources; concretes are injected. |
| **DRY** | HTTP behaviour, error wrapping, logging, and the data model are each defined once and reused everywhere. |
| **KISS** | Zero-dependency table/CSV output; a hand-rolled `.env` fallback; no framework needed to run. Complexity is added only where it buys extensibility. |
| **Separation of Concerns** | The collection ↔ presentation boundary is the normalized `ReconResult`; the wiring ↔ logic boundary is the CLI. |

## 10. Deliberate trade-offs

- **Sequential collection, not concurrent.** Simpler, deterministic, and easier
  to reason about and test. Because each collector is isolated behind `run()`,
  swapping in a `concurrent.futures` executor later is a localized change in the
  engine — the roadmap notes this. KISS now; the seam is ready.
- **Lazy imports of third-party libs** (`whois`, `dns`) inside collectors. The
  core framework and its other collectors remain importable and usable even if
  one optional dependency is absent; a missing lib becomes a clean `ERROR`
  result rather than an import-time crash of the whole tool.
- **Pragmatic domain regex** rather than full RFC-1035. In practice the strict
  grammar over-matches; the chosen pattern is correct for the targets recon
  actually handles and is backed by tests.
