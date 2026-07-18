"""Configuration management.

The module is explicit that "API keys should never be hardcoded" — the starter
code's ``VT_API_KEY = "your_..._here"`` is exactly the anti-pattern to fix.
Configuration is loaded from environment variables (optionally seeded from a
``.env`` file), exposed through a single immutable :class:`Config` object, and
validated on demand.

Design choices:
* One config object is *injected* into collectors rather than read from globals
  (Dependency Injection). This makes collectors trivially testable — a test can
  pass a fabricated Config with a fake key and never touch the real environment.
* ``.env`` loading is optional and dependency-light: we parse it ourselves so
  the framework has no hard requirement on ``python-dotenv`` (though it is used
  if present).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from recon.core.exceptions import ConfigError
from recon.utils.logging import get_logger

log = get_logger(__name__)

# Maps a logical setting name -> environment variable name. Adding a new
# API-backed collector means adding one line here, nothing else.
ENV_KEYS: dict[str, str] = {
    "virustotal_api_key": "VT_API_KEY",
    "shodan_api_key": "SHODAN_API_KEY",
    "censys_api_id": "CENSYS_API_ID",
    "censys_api_secret": "CENSYS_API_SECRET",
}


def _load_dotenv(path: Path) -> None:
    """Populate ``os.environ`` from a ``.env`` file if one exists.

    Existing environment variables always win over the file, matching standard
    dotenv semantics. Falls back to a tiny hand-rolled parser when
    ``python-dotenv`` isn't installed so the framework stays usable with zero
    optional deps.
    """
    if not path.exists():
        return
    try:
        from dotenv import load_dotenv  # type: ignore

        load_dotenv(path, override=False)
        log.debug("Loaded .env via python-dotenv: %s", path)
        return
    except ImportError:
        pass

    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)
    log.debug("Loaded .env via builtin parser: %s", path)


@dataclass(frozen=True)
class Config:
    """Immutable snapshot of runtime configuration.

    Frozen so that no collector can mutate shared config mid-run. Behavioural
    knobs (timeout, rate limit, retries) live here too so they can be tuned from
    the environment without code changes.
    """

    api_keys: dict[str, str | None] = field(default_factory=dict)
    request_timeout: float = 15.0
    rate_limit_delay: float = 1.0     # polite delay between outbound requests
    max_retries: int = 2
    user_agent: str = "recon-framework/1.0 (+https://github.com/captainx-dcode/recon-framework)"

    @classmethod
    def load(cls, env_file: str | Path | None = ".env") -> "Config":
        """Build a Config from the environment (and optional ``.env`` file)."""
        if env_file is not None:
            _load_dotenv(Path(env_file))

        api_keys = {name: os.environ.get(var) for name, var in ENV_KEYS.items()}

        def _num(var: str, default: float, cast=float):
            raw = os.environ.get(var)
            if raw is None or raw == "":
                return default
            try:
                return cast(raw)
            except ValueError:
                log.warning("Invalid value for %s=%r; using default %s", var, raw, default)
                return default

        return cls(
            api_keys=api_keys,
            request_timeout=_num("RECON_TIMEOUT", 15.0),
            rate_limit_delay=_num("RECON_RATE_LIMIT", 1.0),
            max_retries=int(_num("RECON_MAX_RETRIES", 2, int)),
            user_agent=os.environ.get("RECON_USER_AGENT", cls.user_agent),
        )

    def get_key(self, name: str) -> str | None:
        """Return an API key by logical name, or ``None`` if unset."""
        return self.api_keys.get(name)

    def require_key(self, name: str) -> str:
        """Return an API key or raise :class:`ConfigError` if it's missing.

        Collectors that cannot function without a key call this and let the
        orchestrator convert the failure into a SKIPPED result.
        """
        value = self.get_key(name)
        if not value:
            env_var = ENV_KEYS.get(name, name.upper())
            raise ConfigError(
                f"Missing required API key '{name}'. "
                f"Set the {env_var} environment variable (see .env.example)."
            )
        return value

    def available_keys(self) -> list[str]:
        """Names of API keys that are actually configured."""
        return [name for name, value in self.api_keys.items() if value]
