"""Shodan collector.

Shodan is one of the four flagship tools the module teaches (the "search engine
for hackers" that indexes exposed services). It's a natural fit for the same
plugin contract, and including it shows the framework spans the full toolset the
module cares about — not just the two functions in the technical lesson.

Shodan's host API is IP-centric, so this collector applies to IP targets. (A
production extension could resolve a domain's A record first; we keep the
responsibility boundary clean here and let the DNS collector provide IPs.)
"""

from __future__ import annotations

from typing import Any

from recon.collectors.base import BaseCollector
from recon.core.models import Target, TargetType


class ShodanCollector(BaseCollector):
    """Query Shodan's host endpoint for exposed ports and services."""

    name = "shodan"
    description = "Open ports, banners & services for an IP via Shodan."
    supported_types = (TargetType.IP,)
    active = True

    def _collect(self, target: Target) -> dict:
        api_key = self._config.require_key("shodan_api_key")  # -> SKIPPED if missing
        url = f"https://api.shodan.io/shodan/host/{target.value}"

        response = self.http.get(url, params={"key": api_key})

        if response.status_code == 404:
            return {"ip": target.value, "found": False, "reason": "No Shodan information available."}
        if response.status_code == 401:
            raise PermissionError("Shodan rejected the API key (401). Check SHODAN_API_KEY.")
        if response.status_code != 200:
            raise RuntimeError(f"Shodan request failed: HTTP {response.status_code}")

        payload = response.json()
        return {
            "ip": target.value,
            "found": True,
            "summary": self._summarize(payload),
            "raw": payload,
        }

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
