"""Input validation and target classification.

Corresponds to the module's first process stage ("Determine Scope") and the
"input validation" testing requirement. Given an arbitrary user string we must
decide *what* it is (domain / IP / email) so the orchestrator can select only
the collectors that apply. Getting this wrong wastes API quota and produces
misleading errors, so classification is centralised and unit-tested rather than
guessed at each call site.
"""

from __future__ import annotations

import ipaddress
import re

from recon.core.exceptions import ValidationError
from recon.core.models import Target, TargetType

# A pragmatic domain matcher: one-or-more labels of alphanumerics/hyphens
# followed by a TLD of at least two letters. Not a full RFC-1035 implementation
# (those over-match in practice) but correct for the domains recon deals with.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$"
)
_EMAIL_RE = re.compile(r"^[^@\s]+@([^@\s]+\.[A-Za-z]{2,63})$")

# Schemes/paths users often paste; we strip them before classifying so
# "https://example.com/path" still resolves to the domain "example.com".
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def _strip_url(value: str) -> str:
    """Reduce a pasted URL to its host component."""
    value = _SCHEME_RE.sub("", value.strip())
    value = value.split("/", 1)[0]      # drop path
    value = value.split("?", 1)[0]      # drop query
    value = value.split("#", 1)[0]      # drop fragment
    value = value.split("@", 1)[-1]     # drop userinfo
    value = value.split(":", 1)[0]      # drop :port
    return value.strip().strip(".")


def classify(raw: str) -> Target:
    """Classify a raw user string into a validated :class:`Target`.

    Order matters: email is checked before domain (an email contains a domain),
    and IPs are checked explicitly. Anything unrecognised raises
    :class:`ValidationError` so the CLI can report it cleanly instead of firing
    collectors at garbage.
    """
    if raw is None or not str(raw).strip():
        raise ValidationError("Empty target supplied.")

    candidate = str(raw).strip()

    # Email
    m = _EMAIL_RE.match(candidate)
    if m:
        return Target(raw=raw, value=candidate.lower(), type=TargetType.EMAIL)

    # IP address (v4 or v6) — try before URL stripping so IPv6 colons survive
    try:
        ip = ipaddress.ip_address(candidate)
        return Target(raw=raw, value=str(ip), type=TargetType.IP)
    except ValueError:
        pass

    # Domain (after removing any URL scaffolding)
    host = _strip_url(candidate)
    try:
        ip = ipaddress.ip_address(host)
        return Target(raw=raw, value=str(ip), type=TargetType.IP)
    except ValueError:
        pass

    if _DOMAIN_RE.match(host):
        return Target(raw=raw, value=host.lower(), type=TargetType.DOMAIN)

    raise ValidationError(
        f"Could not classify target {raw!r} as a domain, IP address, or email."
    )


def is_domain(value: str) -> bool:
    """Convenience predicate used in tests and quick checks."""
    return bool(_DOMAIN_RE.match(_strip_url(value)))


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
