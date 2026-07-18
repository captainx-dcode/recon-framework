"""Hostname resolution utility.

A small, single-responsibility helper: turn a hostname into an IP address. It
exists as its own module because *more than one* part of the framework needs to
pivot from a domain to an IP — the Shodan collector is the first consumer, but
any future IP-centric source (Censys hosts, GreyNoise, reverse-DNS enrichment)
will want exactly this. Centralising it here (DRY) means that logic — including
the choice of resolution strategy and its error handling — lives in one place.

Two resolution strategies are offered, tried in order of preference:

1. ``dnspython`` (already a framework dependency for the DNS collector), which
   gives us a timeout knob and consistent behaviour with the rest of the tool.
2. The stdlib ``socket.gethostbyname`` as a zero-dependency fallback, so the
   helper still works if ``dnspython`` is somehow unavailable.

The function never raises for an ordinary "couldn't resolve" — it returns
``None`` so callers can treat a missing IP as data, matching the framework's
"failures are values, not crashes" philosophy.
"""

from __future__ import annotations

from recon.utils.logging import get_logger

log = get_logger(__name__)


def resolve_hostname(hostname: str, timeout: float = 10.0) -> str | None:
    """Resolve ``hostname`` to a single IPv4/IPv6 address string.

    Args:
        hostname: the domain/host to resolve (e.g. ``"example.com"``).
        timeout: per-query timeout in seconds when dnspython is used.

    Returns:
        The first resolved IP address as a string, or ``None`` if the name
        cannot be resolved by any available method.
    """
    ip = _resolve_with_dnspython(hostname, timeout)
    if ip is not None:
        return ip
    return _resolve_with_socket(hostname)


def _resolve_with_dnspython(hostname: str, timeout: float) -> str | None:
    """Preferred path: use dnspython so we honour a timeout consistently."""
    try:
        import dns.resolver  # type: ignore
        from dns.exception import DNSException  # type: ignore
    except ImportError:
        return None

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    for record_type in ("A", "AAAA"):
        try:
            answers = resolver.resolve(hostname, record_type)
            for answer in answers:
                return answer.to_text()
        except DNSException as exc:
            log.debug("dnspython %s lookup failed for %s: %s", record_type, hostname, exc)
            continue
    return None


def _resolve_with_socket(hostname: str) -> str | None:
    """Zero-dependency fallback using the standard library."""
    import socket

    try:
        return socket.gethostbyname(hostname)
    except (socket.gaierror, socket.herror, OSError) as exc:
        log.debug("socket resolution failed for %s: %s", hostname, exc)
        return None
