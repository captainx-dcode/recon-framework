"""Collector contract.

This is the single most important abstraction in the framework and the direct
generalisation of the technical lesson. The lesson wrote two standalone
functions — ``get_whois_info`` and ``get_virustotal_info`` — each of which
takes a domain, talks to one source, and returns data. Every OSINT source in
the world fits that same shape. So instead of a growing pile of free functions,
we define one abstract base class expressing the contract:

    "Given a validated Target and shared services (config, http), decide whether
     you apply, then produce a normalized CollectorResult."

Concrete collectors (WHOIS, VirusTotal, Shodan, DNS, ...) subclass this. The
orchestrator discovers and runs them polymorphically without knowing their
internals. Adding a source = adding a subclass, changing nothing else
(Open/Closed Principle, and the module's "add or remove tools without rewriting
the framework").
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod

from recon.core.config import Config
from recon.core.exceptions import ConfigError
from recon.core.models import CollectorResult, Status, Target, TargetType
from recon.utils.http import HttpClient
from recon.utils.logging import get_logger


class BaseCollector(ABC):
    """Abstract OSINT collector.

    Subclasses set two class attributes and implement one method:

    * ``name``            — stable identifier used in output and ``--tool``.
    * ``supported_types`` — which :class:`TargetType` values this collector
                            handles; the base ``applies_to`` uses it.
    * :meth:`_collect`    — the source-specific work, returning a plain dict.

    The public :meth:`run` wraps ``_collect`` with timing, applicability checks,
    and uniform error capture so no subclass ever has to repeat that ceremony —
    and one failing collector can never crash the whole run.
    """

    #: Stable, lowercase identifier (e.g. "whois", "virustotal").
    name: str = "base"

    #: Human-readable one-liner shown in ``--list-tools``.
    description: str = ""

    #: Target types this collector can handle.
    supported_types: tuple[TargetType, ...] = ()

    #: If True, collector talks to the network (affects --passive-only gating).
    active: bool = False

    def __init__(self, config: Config, http: HttpClient | None = None):
        # Dependency Injection: config and the HTTP client are passed in, never
        # constructed from globals. Tests inject fakes; production injects real
        # ones. Collectors that don't need HTTP simply ignore it.
        self._config = config
        self._http = http
        self._log = get_logger(f"collectors.{self.name}")

    # ---- contract methods -------------------------------------------------

    def applies_to(self, target: Target) -> bool:
        """Return True if this collector can meaningfully run against target.

        Default implementation checks ``supported_types``. Subclasses may
        override for finer control (e.g. only public IPs).
        """
        return target.type in self.supported_types

    @abstractmethod
    def _collect(self, target: Target) -> dict:
        """Do the actual source-specific collection.

        Return a JSON-serialisable dict of findings. Raise on failure; the
        wrapper converts exceptions to an ERROR result. Missing configuration
        should raise :class:`ConfigError` (wrapper converts to SKIPPED).
        """
        raise NotImplementedError

    # ---- orchestration wrapper -------------------------------------------

    def run(self, target: Target) -> CollectorResult:
        """Execute the collector, always returning a CollectorResult.

        This method never raises for expected failures — that guarantee is what
        lets the orchestrator run many collectors and aggregate their outcomes
        without defensive try/except at the call site.
        """
        if not self.applies_to(target):
            self._log.debug("Skipping %s: not applicable to %s", self.name, target.type.value)
            return CollectorResult(
                source=self.name,
                status=Status.NOT_APPLICABLE,
                error=f"{self.name} does not support target type '{target.type.value}'",
            )

        start = time.perf_counter()
        try:
            data = self._collect(target)
            duration = (time.perf_counter() - start) * 1000
            self._log.info("%s collected in %.0fms", self.name, duration)
            return CollectorResult(
                source=self.name,
                status=Status.SUCCESS,
                data=data,
                duration_ms=round(duration, 2),
            )
        except ConfigError as exc:
            # Missing key etc. — expected, recoverable; mark SKIPPED not ERROR.
            self._log.warning("%s skipped: %s", self.name, exc)
            return CollectorResult(
                source=self.name,
                status=Status.SKIPPED,
                error=str(exc),
                duration_ms=round((time.perf_counter() - start) * 1000, 2),
            )
        except Exception as exc:  # noqa: BLE001 - intentional catch-all boundary
            # The framework boundary: any collector blow-up becomes data, not a
            # crash. This is what makes the tool robust across dozens of sources.
            self._log.error("%s failed: %s", self.name, exc)
            return CollectorResult(
                source=self.name,
                status=Status.ERROR,
                error=f"{type(exc).__name__}: {exc}",
                duration_ms=round((time.perf_counter() - start) * 1000, 2),
            )

    # ---- helper -----------------------------------------------------------

    @property
    def http(self) -> HttpClient:
        """Return the injected HTTP client or raise if a collector forgot one."""
        if self._http is None:
            raise CollectorError_missing_http(self.name)
        return self._http


def CollectorError_missing_http(name: str):  # noqa: N802 - factory, kept local
    from recon.core.exceptions import CollectorError

    return CollectorError(f"Collector '{name}' requires an HttpClient but none was injected.")
