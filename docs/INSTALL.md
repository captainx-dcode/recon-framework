# Installation

## Requirements

- **Python 3.9 or newer** (`python --version`)
- `pip`
- Internet access for live lookups (WHOIS/DNS/APIs); the tool still runs and
  degrades gracefully offline.

## Standard install

```bash
git clone https://github.com/captainx-dcode/recon-framework.git
cd recon-framework

# Recommended: an isolated virtual environment
python -m venv .venv
source .venv/bin/activate           # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

Run it:

```bash
python recon.py --list-tools
python recon.py --domain example.com --passive
```

## Install as a package (optional)

Installing the project gives you a first-class `recon` command:

```bash
pip install -e .        # editable install for development
# or: pip install .
recon --domain example.com
```

## Dependencies

Runtime (`requirements.txt`):

| Package | Purpose | If missing |
|---|---|---|
| `requests` | shared HTTP client | VirusTotal/Shodan collectors error cleanly |
| `python-whois` | WHOIS collector | WHOIS collector returns an error result |
| `dnspython` | DNS collector | DNS collector returns an error result |
| `python-dotenv` | `.env` loading | framework falls back to a built-in parser |

Because collectors import their third-party libraries **lazily**, a missing
optional dependency never stops the whole tool — only the collector that needs
it is affected, and it reports the problem as data.

Development (`requirements-dev.txt`): `pytest`, `pytest-cov`.

## Verifying the install

```bash
pip install -r requirements-dev.txt
pytest            # should report all tests passing, offline
```

## Troubleshooting

**`ModuleNotFoundError: No module named 'whois'`**
Install runtime deps: `pip install -r requirements.txt`. Note the correct
package is `python-whois`, not `whois`.

**WHOIS returns errors for a valid domain**
Some TLDs rate-limit or block WHOIS. Try again later, or another domain. This is
a property of the WHOIS system, not the framework.

**VirusTotal/Shodan show `skipped`**
That means no API key is configured — expected behaviour. Add the key to `.env`
(see [CONFIGURATION.md](CONFIGURATION.md)) to enable the collector.

**Corporate proxy / TLS interception**
Set `HTTPS_PROXY` in your environment; `requests` honours it. Increase
`RECON_TIMEOUT` if the proxy is slow.
