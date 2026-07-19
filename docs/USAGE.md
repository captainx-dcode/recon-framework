# Usage

## Command reference

```
python recon.py [target] [options]
```

## Interactive mode (no flags needed)

If you run `recon.py` with **no target**, and you're at a real terminal, it drops
into a guided wizard that asks for the target, the mode, and the output format —
so you don't have to remember any flags:

```bash
python recon.py
```

```
  Recon Framework — interactive mode
  (tip: pass --domain / --ip to skip these questions)

  Target domain or IP: tryhackme.com
  Which mode?
    [1] Passive only  — WHOIS + DNS, no API keys needed (default)
    [2] Full          — also Shodan / VirusTotal (needs keys)
  Choose: 1
  Output format?
    [1] csv
    [2] json
    [3] table (default)
  Choose: 3
  Save the report to a file? [y/N]: n
```

You can also force the wizard explicitly with `--interactive` (`-i`), even when
piping would otherwise suppress it.

In **full** mode, if a collector's API key isn't configured, the wizard offers to
let you paste one or skip that source — skipping just means it reports `skipped`
and the run continues with whatever is available.

**Important:** the wizard only appears for a human at a terminal. When a target
*is* supplied, or when input is piped/redirected (scripts, CI, CodeGrade), the
flag-driven behaviour below applies unchanged and nothing ever blocks on a
prompt.

### Target (choose one)

| Flag | Example | Notes |
|---|---|---|
| `--domain` | `--domain example.com` | Explicit domain. |
| `--ip` | `--ip 8.8.8.8` | Explicit IPv4/IPv6. |
| `--target` | `--target example.com` | Auto-detects domain / IP / email. |

### Options

| Flag | Default | Description |
|---|---|---|
| `--tool NAME` | all | Run only this collector; repeat for several (`--tool whois --tool dns`). |
| `--output {json,csv,table}`, `-o` | `table` | Output format. |
| `--passive` | off | Skip collectors that actively touch the network. |
| `--save` | off | Also write the report to disk. |
| `--output-dir DIR` | `reports` | Where saved reports go. |
| `--env-file PATH` | `.env` | Location of the env file with API keys. |
| `--verbose`, `-v` | off | DEBUG-level logging (to stderr). |
| `--quiet`, `-q` | off | Only warnings/errors. |
| `--interactive`, `-i` | off | Force the interactive wizard (prompt for target/mode/output). |
| `--list-tools` | — | Print available collectors and exit. |

## Examples

### Everything applicable, human-readable

```bash
python recon.py --domain example.com
```

### JSON to stdout, and saved to `reports/example.com_recon.json`

```bash
python recon.py --domain example.com --output json --save
```

### CSV for spreadsheets

```bash
python recon.py --domain example.com --output csv --save
```

### Only WHOIS + DNS, passively, on an auto-detected target

```bash
python recon.py --target example.com --tool whois --tool dns --passive
```

### An IP through Shodan + VirusTotal

```bash
python recon.py --ip 8.8.8.8 --output json
```

### Discover what's available

```bash
python recon.py --list-tools
```

## Understanding the output

Each collector reports one of four statuses:

| Status | Meaning |
|---|---|
| `success` | Data was collected. |
| `skipped` | Collector couldn't run for a recoverable reason (usually a missing API key). |
| `error` | The source failed (timeout, auth rejected, lookup error). Details in the `error`/`NOTE` field. |
| `not_applicable` | Collector doesn't handle this target type (e.g. Shodan on a domain). |

Because failures are captured rather than fatal, **the run always completes and
you always get a report** covering whatever succeeded.

## Piping and automation

Structured output goes to **stdout**; logs and the "saved to …" notice go to
**stderr**. This keeps pipes clean:

```bash
# Extract just the VirusTotal reputation with jq
python recon.py --domain example.com -o json --quiet \
  | jq '.results.virustotal.data.summary.reputation'

# Batch several domains into CSVs
for d in example.com example.org example.net; do
  python recon.py --domain "$d" -o csv --save --quiet
done
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Ran successfully (at least one collector succeeded, or there was nothing to run). |
| `1` | A framework-level error (e.g. an invalid target). |
| `2` | Ran, but every applicable collector failed. |
| `130` | Interrupted (Ctrl-C). |

## Using the framework as a library

```python
from recon import ReconEngine, Config
from recon.output.formatters import get_formatter

with ReconEngine(Config.load()) as engine:
    result = engine.run("example.com", passive_only=True)

print(get_formatter("json").render(result))
for r in result.successful:
    print(r.source, "→", r.data)
```
