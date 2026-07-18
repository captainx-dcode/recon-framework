"""WHOIS collector.

Generalises the lesson's ``get_whois_info``. Two deliberate improvements over
the original while staying faithful to the learning objective (gather domain
registration and ownership details):

1. **Structured output, not a text blob.** The lesson returned ``w.text`` — one
   opaque string. That's fine for printing but useless for downstream analysis,
   CSV columns, or comparing domains. We extract the salient fields (registrar,
   creation/expiry dates, name servers, emails) into a normalized dict, while
   still preserving the raw text under ``raw`` for completeness.

2. **Datetime normalisation.** ``python-whois`` returns dates as ``datetime``,
   sometimes as a *list* of them. Those aren't JSON-serialisable and break the
   lesson's ``json.dump`` on many real domains. We coerce them to ISO strings.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

from recon.collectors.base import BaseCollector
from recon.core.models import Target, TargetType


def _iso(value: Any) -> Any:
    """Coerce datetimes (and lists of them) to ISO strings; pass others through."""
    if isinstance(value, _dt.datetime):
        return value.isoformat()
    if isinstance(value, list):
        return [_iso(v) for v in value]
    return value


class WhoisCollector(BaseCollector):
    """Fetch and normalize WHOIS registration data for a domain."""

    name = "whois"
    description = "Domain registration & ownership details via WHOIS."
    supported_types = (TargetType.DOMAIN,)
    active = False  # WHOIS is passive: no contact with the target's own systems.

    # Fields we lift into the normalized structure. Anything present in the
    # WHOIS record but not listed here is still available under ``raw``.
    _FIELDS = (
        "domain_name",
        "registrar",
        "creation_date",
        "expiration_date",
        "updated_date",
        "name_servers",
        "emails",
        "org",
        "country",
        "status",
    )

    def _collect(self, target: Target) -> dict:
        # Imported lazily so the framework can be imported (and its other
        # collectors used) even in an environment where python-whois isn't
        # installed. The error becomes a clean ERROR result via the wrapper.
        import whois  # type: ignore

        self._log.debug("Querying WHOIS for %s", target.value)
        record = whois.whois(target.value)

        normalized: dict[str, Any] = {}
        for field in self._FIELDS:
            value = record.get(field) if hasattr(record, "get") else getattr(record, field, None)
            if value is not None:
                normalized[field] = _iso(value)

        return {
            "domain": target.value,
            "registration": normalized,
            "raw": getattr(record, "text", None),
        }
