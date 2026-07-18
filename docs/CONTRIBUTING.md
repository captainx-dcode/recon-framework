# Contributing

Thanks for considering a contribution. This project is structured so the most
common change — **adding a new OSINT source** — is small, safe, and well-defined.
This guide walks through that and the general workflow.

## Development setup

```bash
git clone https://github.com/captainx-dcode/recon-framework.git
cd recon-framework
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pip install -e .          # optional: gives you the `recon` command
pytest                    # confirm a green baseline before you start
```

## Ground rules

- **Every change keeps the suite green.** Run `pytest` before opening a PR.
- **New behaviour ships with tests.** Collectors are tested with a fake HTTP
  client (never the real network) — see `tests/conftest.py` for the fixtures.
- **No secrets in code.** Keys come from the environment via `Config`. If your
  collector needs one, add it to `ENV_KEYS` in `core/config.py` and document it
  in `.env.example` and `docs/CONFIGURATION.md`.
- **Type hints** on public functions; **docstrings** explaining *why*, not just
  *what*.
- **Respect the layers.** Collectors depend on `core` + `utils`, never on each
  other or on `output`. Output depends only on `core` models. See
  [ARCHITECTURE.md](ARCHITECTURE.md).

## Adding a collector (the common case)

A collector is any subclass of `BaseCollector` that implements `_collect`.

### 1. Write the collector

Create `recon/collectors/<name>_collector.py`:

```python
"""<Source> collector — one-line description of what intel it gathers."""

from __future__ import annotations

from recon.collectors.base import BaseCollector
from recon.core.models import Target, TargetType


class MySourceCollector(BaseCollector):
    name = "mysource"                       # stable, lowercase; used in --tool
    description = "What this source provides."
    supported_types = (TargetType.DOMAIN,)  # which targets it handles
    active = True                            # True if it touches the network actively

    def _collect(self, target: Target) -> dict:
        # If the source needs a key, this raises ConfigError → the wrapper turns
        # it into a clean SKIPPED result. Never read os.environ directly here.
        api_key = self._config.require_key("mysource_api_key")

        # Use the shared HTTP client — you get retry/timeout/rate-limit/UA free.
        resp = self.http.get(
            f"https://api.mysource.example/v1/lookup/{target.value}",
            headers={"Authorization": f"Bearer {api_key}"},
        )

        if resp.status_code == 404:
            return {"target": target.value, "found": False}
        if resp.status_code != 200:
            # Raise on failure; the base wrapper records it as an ERROR result.
            raise RuntimeError(f"mysource request failed: HTTP {resp.status_code}")

        payload = resp.json()
        # Return JSON-serialisable primitives. Lift the useful bits into a
        # `summary`, keep the full response under `raw`.
        return {"target": target.value, "found": True, "summary": {...}, "raw": payload}
```

**Do not** write `try/except` around your own logic for expected failures —
raise, and let `BaseCollector.run()` capture it uniformly. That guarantee (one
source never crashes the run) only holds if collectors follow it.

### 2. Register it

Add the class to `_DEFAULT_COLLECTORS` in `recon/collectors/registry.py`:

```python
from recon.collectors.mysource_collector import MySourceCollector

_DEFAULT_COLLECTORS = (
    WhoisCollector, DnsCollector, VirusTotalCollector, ShodanCollector,
    MySourceCollector,          # <-- new
)
```

That's it — it now appears in `--list-tools`, is selectable with
`--tool mysource`, runs in the engine, and flows into every output format.

### 3. If it needs an API key

Add one line to `ENV_KEYS` in `recon/core/config.py`:

```python
ENV_KEYS = {
    ...,
    "mysource_api_key": "MYSOURCE_API_KEY",
}
```

Then document it in `.env.example` and `docs/CONFIGURATION.md`.

### 4. Test it

Create `tests/unit/test_mysource.py` and use the fake HTTP client:

```python
from recon.collectors.mysource_collector import MySourceCollector
from recon.core.models import Target, TargetType
from tests.conftest import FakeResponse


def _domain(v="example.com"):
    return Target(raw=v, value=v, type=TargetType.DOMAIN)


def test_success(config, fake_http_factory):
    http = fake_http_factory({"api.mysource": FakeResponse(200, {"result": "ok"})})
    result = MySourceCollector(config, http).run(_domain())
    assert result.ok
    assert result.data["found"] is True


def test_missing_key_is_skipped(config_no_keys, fake_http_factory):
    result = MySourceCollector(config_no_keys, fake_http_factory({})).run(_domain())
    assert result.status.value == "skipped"
```

## Adding an output format

Subclass `Formatter` in `recon/output/formatters.py`, set `name`/`extension`,
implement `render(result)`, and add it to the `_FORMATTERS` dict. The CLI's
`--output` choices update automatically from `available_formats()`.

## Adding a new target type

1. Add the value to `TargetType` in `core/models.py`.
2. Teach `utils/validators.classify()` to recognise it (add a test).
3. Declare `supported_types` on any collector that handles it.

## Commit & PR conventions

- Use focused commits with imperative subject lines
  (`feat: add Censys host collector`, `fix: normalise WHOIS date lists`).
- Prefixes: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`.
- Each commit should leave the repo in a working, test-passing state.
- In the PR description, note any new environment variable or dependency.

## Reporting issues

Include the command you ran, the target type (never post private data), the
observed vs expected behaviour, and your Python version. For collector failures,
`--verbose` output (with secrets redacted) is very helpful.
