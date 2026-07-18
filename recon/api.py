"""Public facade for the recon framework.

The framework's power lives in the engine + collector architecture, but that
power comes with ceremony: build a ``Config``, construct a ``ReconEngine``,
classify a target, pull results out of a ``ReconResult``. That's the right shape
for a serious application, but it's too much for a *simple* consumer — a quick
script, a notebook cell, or a course assignment — that just wants "give me the
WHOIS for this domain."

This module is the Facade pattern: a handful of module-level functions that wrap
the machinery and return plain data. It is **framework code, not assignment
code** — any consumer benefits from it, and it contains no logic that belongs to
one particular script. It exists so that thin orchestration layers can reuse the
framework in one line instead of duplicating engine wiring.

Everything here delegates to the same collectors the CLI uses, so behaviour
(config, logging, HTTP headers, retries, error capture) is identical — there is
no second implementation to drift out of sync.
"""

from __future__ import annotations

from typing import Any

from recon.collectors.shodan_collector import ShodanCollector
from recon.collectors.whois_collector import WhoisCollector
from recon.core.config import Config
from recon.core.engine import ReconEngine
from recon.core.models import ReconResult
from recon.utils.validators import classify


def whois_lookup(domain: str, config: Config | None = None) -> dict[str, Any]:
    """Return normalized WHOIS data for ``domain`` as a plain dict.

    Thin wrapper over :class:`WhoisCollector`. Never raises for an ordinary
    lookup failure — the collector captures errors into the returned structure
    (under the ``error`` key) just as it does inside a full engine run.
    """
    cfg = config or Config.load()
    target = classify(domain)
    result = WhoisCollector(cfg).run(target)
    return _unwrap(result)


def shodan_lookup(target_value: str, config: Config | None = None) -> dict[str, Any]:
    """Return Shodan data for a domain or IP as a plain dict.

    Accepts a domain (resolved to an IP first) or an IP directly, thanks to the
    upgraded :class:`ShodanCollector`. Requires a Shodan API key in config; if
    absent, the result's ``status`` is ``skipped`` with an explanatory message.
    """
    cfg = config or Config.load()
    target = classify(target_value)
    # A shared HTTP client is needed for Shodan's HTTP calls.
    engine = ReconEngine(cfg)
    try:
        collector = ShodanCollector(cfg, engine._http)  # reuse the configured client
        return _unwrap(collector.run(target))
    finally:
        engine.close()


def investigate(
    target_value: str,
    *,
    config: Config | None = None,
    only: list[str] | None = None,
    passive_only: bool = False,
) -> ReconResult:
    """Run the full multi-collector pipeline and return the ``ReconResult``.

    This is the facade over the whole engine, for consumers that want every
    applicable source at once rather than a single tool.
    """
    cfg = config or Config.load()
    with ReconEngine(cfg) as engine:
        return engine.run(target_value, only=only, passive_only=passive_only)


def _unwrap(result: Any) -> dict[str, Any]:
    """Flatten a single CollectorResult into a friendly dict.

    On success returns the collector's ``data`` directly (what a simple caller
    wants); otherwise returns a small envelope carrying the status and error so
    the caller can still see what happened without inspecting framework types.
    """
    if result.ok:
        return result.data
    return {"status": result.status.value, "error": result.error, "source": result.source}
