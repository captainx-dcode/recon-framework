"""Shared HTTP client.

Every API-backed collector needs the same things: a sane timeout, a consistent
``User-Agent`` (the module calls this out explicitly for VirusTotal), polite
rate-limiting/delays to "mimic human behavior and reduce blocks," and retry on
transient failures. Implementing that once here (DRY) means individual
collectors contain only the logic unique to their source.

The client is a thin wrapper over ``requests`` and takes its behaviour from the
injected :class:`~recon.core.config.Config`, so timeouts and delays are
configurable from the environment with no code change.
"""

from __future__ import annotations

import time
from typing import Any

import requests

from recon.core.config import Config
from recon.utils.logging import get_logger

log = get_logger(__name__)

# Status codes worth retrying: request timeout, rate-limited, and 5xx.
_RETRYABLE = {408, 429, 500, 502, 503, 504}


class HttpClient:
    """Configurable HTTP helper shared across collectors."""

    def __init__(self, config: Config):
        self._config = config
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": config.user_agent})
        self._last_request_ts = 0.0

    def _respect_rate_limit(self) -> None:
        """Sleep just enough to honour the configured inter-request delay."""
        delay = self._config.rate_limit_delay
        if delay <= 0:
            return
        elapsed = time.monotonic() - self._last_request_ts
        if elapsed < delay:
            time.sleep(delay - elapsed)

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
    ) -> requests.Response:
        """Perform a GET with rate-limiting, timeout, and bounded retries.

        Raises the underlying ``requests`` exception only after retries are
        exhausted; collectors are expected to catch it and record an error
        result rather than let it propagate out of the framework.
        """
        attempts = self._config.max_retries + 1
        last_exc: Exception | None = None

        for attempt in range(1, attempts + 1):
            self._respect_rate_limit()
            try:
                log.debug("GET %s (attempt %d/%d)", url, attempt, attempts)
                response = self._session.get(
                    url,
                    headers=headers,
                    params=params,
                    timeout=self._config.request_timeout,
                )
                self._last_request_ts = time.monotonic()

                if response.status_code in _RETRYABLE and attempt < attempts:
                    backoff = self._backoff(attempt, response)
                    log.warning(
                        "GET %s returned %s; retrying in %.1fs",
                        url, response.status_code, backoff,
                    )
                    time.sleep(backoff)
                    continue

                return response
            except (requests.Timeout, requests.ConnectionError) as exc:
                self._last_request_ts = time.monotonic()
                last_exc = exc
                if attempt < attempts:
                    backoff = self._backoff(attempt, None)
                    log.warning("GET %s failed (%s); retrying in %.1fs", url, exc, backoff)
                    time.sleep(backoff)
                    continue
                raise

        # Should be unreachable, but guards against logic errors.
        if last_exc:
            raise last_exc
        raise RuntimeError("HTTP retry loop exited without a response")

    @staticmethod
    def _backoff(attempt: int, response: requests.Response | None) -> float:
        """Exponential backoff, honouring ``Retry-After`` when the server sends it."""
        if response is not None:
            retry_after = response.headers.get("Retry-After")
            if retry_after and retry_after.isdigit():
                return float(retry_after)
        return min(2.0 ** (attempt - 1), 10.0)

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
