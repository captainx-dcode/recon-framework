# Configuration

All configuration comes from **environment variables**, optionally seeded from a
`.env` file in the project root. Nothing sensitive is ever stored in source
code.

## Quick start

```bash
cp .env.example .env
# open .env and fill in the keys you have; leave the rest blank
```

An unset key does **not** cause an error — the collector that needs it is simply
reported as `skipped`. So you can begin with no keys at all (WHOIS + DNS work
immediately) and enable more sources over time.

## Precedence

1. Real environment variables (highest priority)
2. Values from `.env`
3. Built-in defaults

This matches standard dotenv behaviour: an existing environment variable is
never overwritten by the file, which is what you want in CI/containers.

## API keys

| Variable | Collector | How to obtain |
|---|---|---|
| `VT_API_KEY` | `virustotal` | https://www.virustotal.com/gui/my-apikey (free tier available) |
| `SHODAN_API_KEY` | `shodan` | https://account.shodan.io |
| `CENSYS_API_ID` / `CENSYS_API_SECRET` | *(reserved for a future Censys collector)* | https://search.censys.io/account/api |

WHOIS and DNS require **no** credentials.

## Behavioural tuning

These control the shared HTTP client and are safe to leave at their defaults:

| Variable | Default | Meaning |
|---|---|---|
| `RECON_TIMEOUT` | `15` | Per-request timeout, seconds. |
| `RECON_RATE_LIMIT` | `1.0` | Minimum delay between outbound requests, seconds — polite pacing to reduce blocks. |
| `RECON_MAX_RETRIES` | `2` | Retries on transient HTTP failures (timeouts, 429, 5xx) with exponential backoff. |
| `RECON_USER_AGENT` | `recon-framework/1.0 …` | `User-Agent` sent on every request. |

Invalid numeric values fall back to the default with a warning, so a typo never
crashes a run.

## Using a non-default `.env` location

```bash
python recon.py --domain example.com --env-file /path/to/secrets.env
```

Pass `--env-file` to point at any file, or rely on environment variables alone
(the loader tolerates a missing file).

## Security notes

- `.env` and `*.env` are git-ignored (`.env.example` is the only committed one).
- Keys are held in an immutable `Config` object and never logged.
- The framework never places API keys in URLs where they might be logged by
  intermediaries — Shodan's key goes in query params only because its API
  mandates it; VirusTotal's goes in a header.
