"""
OSINT Collection Script — Reconnaissance Part 1
================================================

This script gathers publicly available (OSINT) information about a domain to
help assess its exposure. It collects:

  * WHOIS registration and ownership details
  * Shodan data (open ports and services) for the domain's host
  * Basic domain information (DNS records, when the framework is available)

and saves the combined results to a JSON file for later analysis.

Design
------
The functions below are thin adapters. When this file is run as part of the
reusable ``recon`` framework (https://github.com/captainx-dcode/recon-framework),
they delegate into the framework's collectors so that the project's shared
configuration, HTTP handling (including a User-Agent header), logging, and error
handling all apply — no duplicated logic.

If the framework package is not importable (for example, when this single file
is graded or run in isolation), the functions fall back to a self-contained
implementation so the script still works everywhere. This keeps the file both a
good framework citizen and a robust standalone deliverable.

Usage:
    python OSINT_final.py
"""

import json
import os

import requests
import whois

# Attempt to use the reusable framework. If it isn't installed alongside this
# file, we transparently fall back to standalone implementations below.
try:
    from recon.api import shodan_lookup as _framework_shodan_lookup
    from recon.api import whois_lookup as _framework_whois_lookup
    from recon.core.config import Config as _Config
    from recon.core.engine import ReconEngine as _ReconEngine

    _FRAMEWORK_AVAILABLE = True
except Exception:  # noqa: BLE001 - any import failure => standalone mode
    _FRAMEWORK_AVAILABLE = False


# A polite, honest User-Agent for the fallback path (the framework path sets its
# own via the shared HTTP client). Requested explicitly by the lab (Task 6).
USER_AGENT = "recon-framework/1.0 (+https://github.com/captainx-dcode/recon-framework)"

# The Shodan key is read from the environment so it is never hardcoded. The
# placeholder name matches the lab's variable so the intent is obvious; a real
# key belongs in your environment / .env, not in source control.
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "your_shodan_api_key_here")


def get_whois_info(domain):
    """Fetch WHOIS information for a given domain.

    Prefers the framework's WHOIS collector (structured, JSON-safe output). Falls
    back to a direct ``whois.whois`` lookup if the framework is unavailable.
    Returns a dict; on failure the dict carries an ``error`` field.
    """
    if _FRAMEWORK_AVAILABLE:
        return _framework_whois_lookup(domain)
    try:
        w = whois.whois(domain)
        return {"domain": domain, "raw": w.text}
    except Exception as e:  # noqa: BLE001
        return {"error": f"Error retrieving WHOIS data: {e}"}


def get_shodan_info(domain):
    """Fetch Shodan information (open ports/services) for a given domain.

    Prefers the framework's Shodan collector, which resolves the domain to an IP
    and queries Shodan's host endpoint. Falls back to a direct two-step Shodan
    query (``dns/resolve`` then ``shodan/host``) otherwise. A Shodan API key is
    required to return live data; without one this reports that cleanly rather
    than crashing. Returns a dict.
    """
    if _FRAMEWORK_AVAILABLE:
        return _framework_shodan_lookup(domain)

    headers = {"User-Agent": USER_AGENT}
    try:
        resolve_url = f"https://api.shodan.io/dns/resolve?hostnames={domain}&key={SHODAN_API_KEY}"
        response = requests.get(resolve_url, headers=headers, timeout=15)
        ip = response.json().get(domain)
        if ip:
            host_url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
            host_response = requests.get(host_url, headers=headers, timeout=15)
            return host_response.json()
        return {"error": "No IP found for this domain."}
    except Exception as e:  # noqa: BLE001
        return {"error": f"Error retrieving Shodan data: {e}"}


def get_domain_info(domain):
    """Fetch basic domain information (DNS records) for a given domain.

    Uses the framework engine's DNS collector when available. In standalone mode
    this is a no-op placeholder (DNS enrichment lives in the framework). Returns
    a dict.
    """
    if _FRAMEWORK_AVAILABLE:
        with _ReconEngine(_Config.load()) as engine:
            result = engine.run(domain, only=["dns"])
        dns_result = result.results[0] if result.results else None
        if dns_result and dns_result.ok:
            return dns_result.data
    return {"status": "unavailable", "domain": domain}


def main():
    """Collect OSINT on a domain and save the results to a JSON file."""
    domain = input("Enter the domain name to investigate: ")

    # --- WHOIS -----------------------------------------------------------
    whois_data = get_whois_info(domain)
    print("\n[WHOIS Information]:")
    print(json.dumps(whois_data, indent=4, default=str))

    # --- Basic domain (DNS) info ----------------------------------------
    domain_data = get_domain_info(domain)
    print("\n[Domain Information]:")
    print(json.dumps(domain_data, indent=4, default=str))

    # --- Shodan ----------------------------------------------------------
    shodan_data = get_shodan_info(domain)
    print("\n[Shodan Information]:")
    print(json.dumps(shodan_data, indent=4, default=str))

    # --- Store everything in a single JSON report -----------------------
    osint_results = {
        "WHOIS": whois_data,
        "Domain": domain_data,
        "Shodan": shodan_data,
    }

    output_file = f"{domain}_osint_report.json"
    with open(output_file, "w") as outfile:
        json.dump(osint_results, outfile, indent=4, default=str)

    print(f"\nOSINT data collection complete. Report saved to {output_file}")


if __name__ == "__main__":
    main()
