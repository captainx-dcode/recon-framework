"""DNS collector.

The module repeatedly lists "WHOIS and DNS lookups" and "analyzing DNS records"
as foundational passive techniques, yet the technical lesson never implemented
DNS. Adding it here demonstrates the framework's whole point: a technique named
in the methodology becomes a self-contained plugin without touching anything
else.

Uses ``dnspython`` when available. Because a public resolver query doesn't touch
the target's own infrastructure, this is classed as passive. Records collected:
A, AAAA, MX, NS, TXT, CNAME, SOA — the set most useful for footprinting.
"""

from __future__ import annotations

from recon.collectors.base import BaseCollector
from recon.core.models import Target, TargetType

_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")


class DnsCollector(BaseCollector):
    """Resolve common DNS record types for a domain."""

    name = "dns"
    description = "A/AAAA/MX/NS/TXT/CNAME/SOA records via public DNS."
    supported_types = (TargetType.DOMAIN,)
    active = False

    def _collect(self, target: Target) -> dict:
        import dns.resolver  # type: ignore
        from dns.exception import DNSException  # type: ignore

        resolver = dns.resolver.Resolver()
        resolver.lifetime = self._config.request_timeout

        records: dict[str, list[str]] = {}
        for rtype in _RECORD_TYPES:
            try:
                answers = resolver.resolve(target.value, rtype)
                records[rtype] = sorted(r.to_text() for r in answers)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue  # absence of a record type is normal, not an error
            except DNSException as exc:
                self._log.debug("DNS %s lookup failed for %s: %s", rtype, target.value, exc)
                continue

        return {
            "domain": target.value,
            "records": records,
            "record_types_found": sorted(records.keys()),
        }
