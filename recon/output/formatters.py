"""Output formatters.

The module requires structured output in JSON and CSV plus clear terminal
output, and asks for "future formats" to be easy to add. We model each format as
a strategy implementing one interface (:class:`Formatter`). The CLI picks a
strategy by name; adding a new format (HTML, Markdown, XML) means writing one
subclass and registering it — no changes to the engine or CLI logic
(Open/Closed).

Formatters consume the normalized :class:`ReconResult` only, so they are fully
decoupled from how the data was collected.
"""

from __future__ import annotations

import csv
import io
import json
from abc import ABC, abstractmethod
from typing import Any

from recon.core.models import ReconResult


class Formatter(ABC):
    """Render a ReconResult to a string in some format."""

    #: Name used on the command line (``--output <name>``).
    name: str = "base"
    #: File extension used when writing to disk.
    extension: str = "txt"

    @abstractmethod
    def render(self, result: ReconResult) -> str:
        raise NotImplementedError


class JsonFormatter(Formatter):
    """Pretty-printed JSON — the canonical machine-readable format.

    Mirrors the lesson's ``json.dump(..., indent=4)`` but over the full,
    normalized result set rather than two ad-hoc keys.
    """

    name = "json"
    extension = "json"

    def render(self, result: ReconResult) -> str:
        return json.dumps(result.to_dict(), indent=2, default=str, ensure_ascii=False)


class CsvFormatter(Formatter):
    """Flat CSV: one row per collector result.

    CSV is inherently tabular while recon data is nested, so we flatten
    deliberately: each row summarises a source's outcome and carries a compact
    JSON snippet of its data. This keeps the file spreadsheet-friendly without
    losing the payload.
    """

    name = "csv"
    extension = "csv"

    _COLUMNS = ("target", "target_type", "source", "status", "duration_ms", "error", "data")

    def render(self, result: ReconResult) -> str:
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=self._COLUMNS)
        writer.writeheader()
        for res in result.results:
            writer.writerow(
                {
                    "target": result.target.value,
                    "target_type": result.target.type.value,
                    "source": res.source,
                    "status": res.status.value,
                    "duration_ms": res.duration_ms,
                    "error": res.error or "",
                    "data": json.dumps(res.data, default=str, ensure_ascii=False),
                }
            )
        return buffer.getvalue()


class TableFormatter(Formatter):
    """Human-readable terminal summary with a lightweight ASCII table.

    Implemented with zero dependencies (no ``rich``/``tabulate`` required) so
    the framework runs anywhere, including a bare CodeGrade container. Shows the
    per-source status overview plus a short highlight line for each successful
    collector.
    """

    name = "table"
    extension = "txt"

    def render(self, result: ReconResult) -> str:
        lines: list[str] = []
        t = result.target
        lines.append(f"Reconnaissance report for {t.value} ({t.type.value})")
        lines.append(f"Completed in {result.duration_ms:.0f} ms\n")

        rows = [(r.source, r.status.value, f"{r.duration_ms:.0f}ms", r.error or "-") for r in result.results]
        lines.append(self._table(["SOURCE", "STATUS", "TIME", "NOTE"], rows))

        highlights = self._highlights(result)
        if highlights:
            lines.append("\nHighlights:")
            lines.extend(highlights)

        return "\n".join(lines)

    @staticmethod
    def _table(headers: list[str], rows: list[tuple[str, ...]]) -> str:
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                widths[i] = max(widths[i], len(str(cell)))

        def fmt_row(cells: tuple[str, ...] | list[str]) -> str:
            return "  ".join(str(c).ljust(widths[i]) for i, c in enumerate(cells))

        sep = "  ".join("-" * w for w in widths)
        out = [fmt_row(headers), sep]
        out += [fmt_row(row) for row in rows]
        return "\n".join(out)

    @staticmethod
    def _highlights(result: ReconResult) -> list[str]:
        """Extract a couple of the most useful facts per successful source."""
        notes: list[str] = []
        for res in result.successful:
            data = res.data
            if res.source == "whois":
                reg = data.get("registration", {})
                if reg.get("registrar"):
                    notes.append(f"  - whois: registrar={reg['registrar']}")
                if reg.get("creation_date"):
                    notes.append(f"  - whois: created={_first(reg['creation_date'])}")
            elif res.source == "dns":
                found = data.get("record_types_found", [])
                if found:
                    notes.append(f"  - dns: records={', '.join(found)}")
            elif res.source == "virustotal":
                summary = data.get("summary", {})
                if "detections" in summary:
                    notes.append(
                        f"  - virustotal: flagged={summary.get('flagged')} "
                        f"detections={summary.get('detections')}"
                    )
            elif res.source == "shodan":
                summary = data.get("summary", {})
                if summary.get("ports"):
                    notes.append(f"  - shodan: open_ports={summary['ports']}")
        return notes


def _first(value: Any) -> Any:
    """Return the first element if value is a list, else value itself."""
    if isinstance(value, list) and value:
        return value[0]
    return value


# Registry of built-in formatters, keyed by CLI name.
_FORMATTERS: dict[str, type[Formatter]] = {
    JsonFormatter.name: JsonFormatter,
    CsvFormatter.name: CsvFormatter,
    TableFormatter.name: TableFormatter,
}


def get_formatter(name: str) -> Formatter:
    """Instantiate a formatter by its CLI name."""
    try:
        return _FORMATTERS[name]()
    except KeyError:
        raise KeyError(f"Unknown output format '{name}'. Available: {', '.join(sorted(_FORMATTERS))}")


def available_formats() -> list[str]:
    return sorted(_FORMATTERS)
