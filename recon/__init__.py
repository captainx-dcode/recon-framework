"""Recon Framework — a modular OSINT / reconnaissance toolkit.

Public API surface is intentionally small; most work goes through the CLI or the
:class:`recon.core.engine.ReconEngine`.
"""

__version__ = "1.0.0"

from recon.core.config import Config
from recon.core.engine import ReconEngine
from recon.core.models import ReconResult, Target, TargetType

__all__ = ["Config", "ReconEngine", "ReconResult", "Target", "TargetType", "__version__"]
