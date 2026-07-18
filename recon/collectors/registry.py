"""Collector registry.

A single place that knows every available collector. The orchestrator and CLI
ask the registry "what collectors exist?" and "give me the one called X" rather
than importing collector classes directly. Benefits:

* **One edit to add a tool.** Register the class here (or via the ``@register``
  decorator) and it's instantly available to the CLI (``--tool``, ``--list-tools``)
  and the orchestrator. This is the concrete mechanism behind "add or remove
  tools without rewriting the framework."
* **Decoupling.** Nothing else needs to import concrete collector modules, so
  dependencies flow one way (registry -> collectors), avoiding import tangles.
"""

from __future__ import annotations

from recon.collectors.base import BaseCollector
from recon.collectors.dns_collector import DnsCollector
from recon.collectors.shodan_collector import ShodanCollector
from recon.collectors.virustotal_collector import VirusTotalCollector
from recon.collectors.whois_collector import WhoisCollector

# Ordered so that passive, dependency-free collectors surface first in output.
_DEFAULT_COLLECTORS: tuple[type[BaseCollector], ...] = (
    WhoisCollector,
    DnsCollector,
    VirusTotalCollector,
    ShodanCollector,
)


class CollectorRegistry:
    """Holds collector *classes* keyed by their ``name``."""

    def __init__(self) -> None:
        self._collectors: dict[str, type[BaseCollector]] = {}

    def register(self, collector_cls: type[BaseCollector]) -> type[BaseCollector]:
        """Register a collector class. Usable as a decorator.

        Raises ``ValueError`` on duplicate names so a typo can't silently
        shadow an existing tool.
        """
        name = collector_cls.name
        if name in self._collectors:
            raise ValueError(f"Collector name '{name}' is already registered.")
        self._collectors[name] = collector_cls
        return collector_cls

    def get(self, name: str) -> type[BaseCollector]:
        try:
            return self._collectors[name]
        except KeyError:
            raise KeyError(
                f"Unknown collector '{name}'. Available: {', '.join(self.names())}"
            )

    def names(self) -> list[str]:
        return sorted(self._collectors)

    def all(self) -> list[type[BaseCollector]]:
        return list(self._collectors.values())

    def describe(self) -> list[tuple[str, str, bool]]:
        """Return (name, description, active) for every collector — feeds --list-tools."""
        return [
            (cls.name, cls.description, cls.active)
            for cls in sorted(self._collectors.values(), key=lambda c: c.name)
        ]


def build_default_registry() -> CollectorRegistry:
    """Construct a registry pre-populated with the built-in collectors."""
    registry = CollectorRegistry()
    for cls in _DEFAULT_COLLECTORS:
        registry.register(cls)
    return registry
