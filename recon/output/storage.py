"""Report storage.

Generalises the lesson's single line ``with open(f"{domain}_threat_report.json")``.
Storage is separated from formatting: a :class:`Formatter` decides *how* the
result looks; :class:`ReportStore` decides *where* it goes and *what it's named*.
That split means writing a CSV to disk reuses exactly the same code path as
writing JSON — only the injected formatter differs (DRY + SRP).
"""

from __future__ import annotations

import re
from pathlib import Path

from recon.core.models import ReconResult
from recon.output.formatters import Formatter
from recon.utils.logging import get_logger

log = get_logger(__name__)

_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_slug(value: str) -> str:
    """Make a filesystem-safe slug from a target value (e.g. an IP or domain)."""
    slug = _SAFE_NAME_RE.sub("_", value).strip("_")
    return slug or "target"


class ReportStore:
    """Writes rendered reports into an output directory."""

    def __init__(self, output_dir: str | Path = "reports"):
        self._dir = Path(output_dir)

    def _ensure_dir(self) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)

    def build_filename(self, result: ReconResult, formatter: Formatter) -> Path:
        """Derive a descriptive, collision-resistant filename.

        Pattern: ``<target>_recon.<ext>`` — mirrors the lesson's
        ``<domain>_threat_report.json`` convention while supporting any format.
        """
        slug = _safe_slug(result.target.value)
        return self._dir / f"{slug}_recon.{formatter.extension}"

    def save(self, result: ReconResult, formatter: Formatter, path: str | Path | None = None) -> Path:
        """Render ``result`` with ``formatter`` and write it to disk.

        Returns the path written, so the CLI can report it to the user.
        """
        self._ensure_dir()
        target_path = Path(path) if path else self.build_filename(result, formatter)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(formatter.render(result), encoding="utf-8")
        log.info("Report written to %s", target_path)
        return target_path
