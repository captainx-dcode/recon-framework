"""Normalized internal data model.

Every collector, regardless of the external source it queries, returns its
findings wrapped in these structures. Keeping a single canonical shape is the
backbone of the framework: output formatters, storage, and the report builder
all consume :class:`ReconResult` and never need to know which tool produced the
data. This is the Separation of Concerns boundary between *collection* and
*presentation*.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Status(str, Enum):
    """Outcome of a single collector run.

    Inherits from ``str`` so values serialise cleanly to JSON/CSV without a
    custom encoder.
    """

    SUCCESS = "success"
    ERROR = "error"
    SKIPPED = "skipped"          # collector chose not to run (e.g. missing key)
    NOT_APPLICABLE = "not_applicable"  # target type doesn't match collector


class TargetType(str, Enum):
    """The kind of thing being investigated."""

    DOMAIN = "domain"
    IP = "ip"
    EMAIL = "email"
    UNKNOWN = "unknown"


@dataclass
class Target:
    """The subject of a reconnaissance run.

    ``raw`` preserves exactly what the user supplied; ``value`` is the
    normalized/validated form; ``type`` is the classification. Collectors
    inspect ``type`` to decide whether they apply (Task 1: scope definition).
    """

    raw: str
    value: str
    type: TargetType

    def to_dict(self) -> dict[str, Any]:
        return {"raw": self.raw, "value": self.value, "type": self.type.value}


@dataclass
class CollectorResult:
    """Result of one collector querying one source about one target.

    This is deliberately generic. ``data`` holds the source-specific payload
    (already normalized to plain dict/list primitives so it is JSON-safe), while
    the surrounding fields give every result a consistent envelope: which tool
    ran, whether it worked, how long it took, and any human-readable error.
    """

    source: str
    status: Status
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["status"] = self.status.value
        return out

    @property
    def ok(self) -> bool:
        return self.status == Status.SUCCESS


@dataclass
class ReconResult:
    """Aggregate of every collector run against a single target.

    The orchestrator builds one of these per run. It is the single object handed
    to output formatters and storage, so adding a new output format never
    touches collection code (Open/Closed Principle).
    """

    target: Target
    results: list[CollectorResult] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None

    def add(self, result: CollectorResult) -> None:
        self.results.append(result)

    def finalize(self) -> "ReconResult":
        self.finished_at = time.time()
        return self

    @property
    def duration_ms(self) -> float:
        if self.finished_at is None:
            return 0.0
        return round((self.finished_at - self.started_at) * 1000, 2)

    @property
    def successful(self) -> list[CollectorResult]:
        return [r for r in self.results if r.ok]

    def to_dict(self) -> dict[str, Any]:
        """Flatten to a JSON-serialisable dict.

        Results are keyed by source for easy lookup while also retaining order
        via the ``sources`` list.
        """
        return {
            "target": self.target.to_dict(),
            "sources": [r.source for r in self.results],
            "duration_ms": self.duration_ms,
            "results": {r.source: r.to_dict() for r in self.results},
        }
