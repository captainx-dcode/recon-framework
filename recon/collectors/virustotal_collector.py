"""VirusTotal collector.

Generalises the lesson's ``get_virustotal_info`` and fixes its structural
problems:

* **No hardcoded key.** The lesson had ``VT_API_KEY = "your_..._here"`` as a
  module global. Here the key comes from injected config via
  ``config.require_key`` — absent key => a clean SKIPPED result, never a 401
  surprise or a leaked secret in source control.
* **Shared HTTP client.** Timeout, retries, rate-limiting and User-Agent come
  from the injected :class:`HttpClient`, not a bare ``requests.get``.
* **Summarised output.** The raw v3 response is large and deeply nested. We keep
  the analyst-relevant summary (reputation, last-analysis vote tallies,
  categories, registrar) at the top level and preserve the full payload under
  ``raw`` for anyone who needs it.

Works for both domains and IPs by selecting the correct endpoint — a small
generalisation the single-purpose lesson function didn't offer.
"""

from __future__ import annotations

from typing import Any

from recon.collectors.base import BaseCollector
from recon.core.models import Target, TargetType

_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalCollector(BaseCollector):
    """Query VirusTotal for domain/IP reputation and DNS data."""

    name = "virustotal"
    description = "Reputation, categories & analysis stats from VirusTotal."
    supported_types = (TargetType.DOMAIN, TargetType.IP)
    active = True  # Hits an external API about the target; treat as active-ish.

    def _endpoint(self, target: Target) -> str:
        if target.type == TargetType.IP:
            return f"{_BASE}/ip_addresses/{target.value}"
        return f"{_BASE}/domains/{target.value}"

    def _collect(self, target: Target) -> dict:
        api_key = self._config.require_key("virustotal_api_key")  # -> SKIPPED if missing
        headers = {"x-apikey": api_key}

        response = self.http.get(self._endpoint(target), headers=headers)

        if response.status_code == 404:
            return {"target": target.value, "found": False, "reason": "Not present in VirusTotal dataset."}
        if response.status_code == 401:
            # Surface auth problems distinctly rather than as generic failure.
            raise PermissionError("VirusTotal rejected the API key (401). Check VT_API_KEY.")
        if response.status_code != 200:
            raise RuntimeError(f"VirusTotal request failed: HTTP {response.status_code}")

        payload = response.json()
        attributes = payload.get("data", {}).get("attributes", {})

        return {
            "target": target.value,
            "found": True,
            "summary": self._summarize(attributes),
            "raw": payload,
        }

    @staticmethod
    def _summarize(attr: dict[str, Any]) -> dict[str, Any]:
        """Pull the fields an analyst actually reads first."""
        stats = attr.get("last_analysis_stats", {})
        summary: dict[str, Any] = {
            "reputation": attr.get("reputation"),
            "last_analysis_stats": stats,
            "categories": attr.get("categories"),
            "registrar": attr.get("registrar"),
            "asn": attr.get("asn"),
            "as_owner": attr.get("as_owner"),
            "country": attr.get("country"),
        }
        # A single, glanceable risk signal derived from the vote tallies.
        malicious = stats.get("malicious", 0) if isinstance(stats, dict) else 0
        suspicious = stats.get("suspicious", 0) if isinstance(stats, dict) else 0
        summary["flagged"] = bool(malicious or suspicious)
        summary["detections"] = malicious + suspicious
        return {k: v for k, v in summary.items() if v is not None}
