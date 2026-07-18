"""Recon Framework — a modular OSINT / reconnaissance toolkit.

Public API surface is intentionally small; most work goes through the CLI or the
:class:`recon.core.engine.ReconEngine`.
"""

__version__ = "1.1.0"

from recon.api import investigate, shodan_lookup, whois_lookup
from recon.core.config import Config
from recon.core.engine import ReconEngine
from recon.core.models import ReconResult, Target, TargetType

__all__ = [
    "Config",
    "ReconEngine",
    "ReconResult",
    "Target",
    "TargetType",
    "investigate",
    "whois_lookup",
    "shodan_lookup",
    "__version__",
]
