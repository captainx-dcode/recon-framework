"""Framework exception hierarchy.

A single base class (:class:`ReconError`) lets callers catch every
framework-specific failure with one ``except`` while still allowing precise
handling of individual cases. This is the "consistent error handling"
requirement made concrete. Collector-level errors are generally *not* raised out
of the framework — they are captured into a :class:`~recon.core.models.CollectorResult`
so one failing source never aborts the whole run. These exceptions are for
programmer/configuration errors that should surface loudly.
"""

from __future__ import annotations


class ReconError(Exception):
    """Base class for all framework errors."""


class ConfigError(ReconError):
    """Raised when configuration is missing or invalid (e.g. required key absent)."""


class ValidationError(ReconError):
    """Raised when a target cannot be validated or classified."""


class CollectorError(ReconError):
    """Raised for unrecoverable collector setup problems.

    Note: transient/expected collector failures (timeouts, 404s, missing API
    keys) are recorded as CollectorResult(status=ERROR/SKIPPED), not raised.
    """
