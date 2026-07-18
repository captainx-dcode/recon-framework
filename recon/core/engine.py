"""Reconnaissance orchestrator.

This is the framework's execution core — the generalisation of the lesson's
``main()``. Where ``main()`` hardcoded "call whois, then call virustotal, then
save," the engine performs the same workflow *abstractly*:

    scope (classify target)
      -> plan (select applicable collectors)
        -> collect (run each, aggregate normalized results)
          -> return one ReconResult

It knows nothing about any specific source — it only speaks the
:class:`BaseCollector` contract and the :class:`ReconResult` model. That is what
lets the same engine drive one tool or twenty, over domains or IPs, with no
change. Output and storage are deliberately *not* here; the engine's single
responsibility is producing the aggregated result (SRP).

Data flow:
    Config + Registry --build--> [Collector instances]
    Target --applies_to--> filtered collectors
    each collector.run(target) --> CollectorResult --> ReconResult.add
"""

from __future__ import annotations

from recon.collectors.base import BaseCollector
from recon.collectors.registry import CollectorRegistry, build_default_registry
from recon.core.config import Config
from recon.core.models import ReconResult, Target
from recon.utils.http import HttpClient
from recon.utils.logging import get_logger
from recon.utils.validators import classify

log = get_logger(__name__)


class ReconEngine:
    """Plans and executes a reconnaissance run for a single target."""

    def __init__(
        self,
        config: Config,
        registry: CollectorRegistry | None = None,
        http: HttpClient | None = None,
    ):
        # Dependencies are injected with sensible defaults, so a caller can do
        # ``ReconEngine(Config.load())`` for the common case, or pass a custom
        # registry/http for tests and specialised runs.
        self._config = config
        self._registry = registry or build_default_registry()
        self._http = http or HttpClient(config)

    # ---- planning ---------------------------------------------------------

    def plan(
        self,
        target: Target,
        *,
        only: list[str] | None = None,
        passive_only: bool = False,
    ) -> list[BaseCollector]:
        """Select and instantiate the collectors that should run.

        Args:
            target: the classified target.
            only: if given, restrict to these collector names (``--tool``).
            passive_only: exclude collectors that touch the network actively.

        Returns collectors that both exist in the (possibly filtered) set and
        declare themselves applicable to the target type. Selecting collectors
        here — separately from running them — keeps planning testable and makes
        ``--list-tools``/dry-run behaviour straightforward.
        """
        if only:
            classes = [self._registry.get(name) for name in only]
        else:
            classes = self._registry.all()

        collectors: list[BaseCollector] = []
        for cls in classes:
            instance = cls(self._config, self._http)
            if passive_only and cls.active:
                log.debug("Excluding active collector '%s' (passive-only mode).", cls.name)
                continue
            if instance.applies_to(target):
                collectors.append(instance)
            else:
                log.debug("Collector '%s' not applicable to %s.", cls.name, target.type.value)

        return collectors

    # ---- execution --------------------------------------------------------

    def run(
        self,
        raw_target: str,
        *,
        only: list[str] | None = None,
        passive_only: bool = False,
    ) -> ReconResult:
        """Full pipeline: classify -> plan -> collect -> aggregate.

        Accepts the *raw* user string and does classification internally so
        callers (CLI, tests, other code) have one simple entry point.
        """
        target = classify(raw_target)
        log.info("Target %r classified as %s", target.value, target.type.value)

        result = ReconResult(target=target)
        collectors = self.plan(target, only=only, passive_only=passive_only)

        if not collectors:
            log.warning("No applicable collectors for target %s.", target.value)

        for collector in collectors:
            log.info("Running collector: %s", collector.name)
            result.add(collector.run(target))

        return result.finalize()

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "ReconEngine":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
