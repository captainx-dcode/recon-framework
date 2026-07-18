"""Shodan collector.

Shodan is one of the four flagship tools the module teaches (the "search engine
for hackers" that indexes exposed services). It fits the same plugin contract as
every other source.

**Design note — why this collector now accepts domains as well as IPs.**
The original version was IP-only, on the reasoning that Shodan's host endpoint is
IP-centric and the DNS collector already produces IPs. The Reconnaissance Part 1
lab exposed that as a real limitation: analysts routinely point Shodan at a
*domain* and expect the tool to resolve it first. So the collector now supports
both target types — for a domain it resolves an IP via the reusable
``resolve_hostname`` helper, then performs the host lookup. This mirrors the
two-step flow (``dns/resolve`` → ``shodan/host``) taught in the course while
keeping resolution logic in a shared utility rather than duplicated here.
"""

from __future__ import annotations

from typing import Any

from recon.collectors.base import BaseCollector
from recon.core.models import Target, TargetType
from recon.utils.resolver import resolve_hostname

_RESOLVE_URL = "https://api.shodan.io/dns/resolve"
_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"


class ShodanCollector(BaseCollector):
    """Query Shodan for exposed ports and services on a domain or IP."""

    name = "shodan"
    description = "Open ports, banners & services for a domain/IP via Shodan."
    # Now handles both: an IP is queried directly; a domain is resolved first.
    supported_types = (TargetType.IP, TargetType.DOMAIN)
    active = True

    def _collect(self, target: Target) -> dict:
        api_key = self._config.require_key("shodan_api_key")  # -> SKIPPED if missing

        ip, resolved_from = self._resolve_target(target, api_key)
        if ip is None:
            return {
                "target": target.value,
                "found": False,
                "reason": "Could not resolve the domain to an IP address.",
            }

        response = self.http.get(_HOST_URL.format(ip=ip), params={"key": api_key})

        if response.status_code == 404:
            return {
                "target": target.value,
                "ip": ip,
                "found": False,
                "reason": "No Shodan information available for this host.",
            }
        if response.status_code == 401:
            raise PermissionError("Shodan rejected the API key (401). Check SHODAN_API_KEY.")
        if response.status_code != 200:
            raise RuntimeError(f"Shodan request failed: HTTP {response.status_code}")

        payload = response.json()
        result: dict[str, Any] = {
            "target": target.value,
            "ip": ip,
            "found": True,
            "summary": self._summarize(payload),
            "raw": payload,
        }
        if resolved_from is not None:
            # Record that we pivoted domain -> IP, useful in the report.
            result["resolved_from"] = resolved_from
        return result

    def _resolve_target(self, target: Target, api_key: str) -> tuple[str | None, str | None]:
        """Return (ip, resolved_from).

        For an IP target, ``ip`` is the target itself and ``resolved_from`` is
        ``None``. For a domain, we resolve to an IP and set ``resolved_from`` to
        the domain so the pivot is visible in output.

        Resolution prefers Shodan's own ``dns/resolve`` endpoint (consistent with
        the course material and keeping DNS answers "as Shodan sees them"), then
        falls back to the framework's local resolver if that call is unavailable.
        """
        if target.type == TargetType.IP:
            return target.value, None

        ip = self._shodan_resolve(target.value, api_key)
        if ip is None:
            ip = resolve_hostname(target.value, timeout=self._config.request_timeout)
        return ip, target.value

    def _shodan_resolve(self, domain: str, api_key: str) -> str | None:
        """Resolve a hostname using Shodan's dns/resolve endpoint."""
        try:
            response = self.http.get(_RESOLVE_URL, params={"hostnames": domain, "key": api_key})
            if response.status_code == 200:
                return response.json().get(domain)
        except Exception as exc:  # noqa: BLE001 - fall back to local resolver
            self._log.debug("Shodan dns/resolve failed for %s: %s", domain, exc)
        return None

    @staticmethod
    def _summarize(payload: dict[str, Any]) -> dict[str, Any]:
        services = [
            {
                "port": item.get("port"),
                "transport": item.get("transport"),
                "product": item.get("product"),
                "module": (item.get("_shodan") or {}).get("module"),
            }
            for item in payload.get("data", [])
        ]
        return {
            "ports": payload.get("ports", []),
            "hostnames": payload.get("hostnames", []),
            "org": payload.get("org"),
            "isp": payload.get("isp"),
            "country": payload.get("country_name"),
            "os": payload.get("os"),
            "services": services,
        }
