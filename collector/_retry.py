"""Retry + backoff helpers for transient gh-CLI + urllib failures.

Ported from kaos-modules/scripts/check-publish-status.py — the policy is:

  - terminal errors (404, 401) → raise immediately, no retry
  - rate-limit / abuse / secondary-rate signals → 6x backoff multiplier
  - everything else (5xx, network, timeout) → standard exponential backoff

Tunables can be overridden via env var:

  KAOS_COMPLIANCE_MAX_ATTEMPTS   default 4
  KAOS_COMPLIANCE_BASE_BACKOFF   default 1.5 seconds

The kaos-compliance dashboard's claims are only as good as the data
behind them, so retry exhaustion must surface as `null` in JSON rather
than silently coerce to a default. The Methodology document calls this
out explicitly under "Stale data is loudly marked stale."
"""

from __future__ import annotations

import json
import os
import random
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

_MAX_ATTEMPTS = int(os.environ.get("KAOS_COMPLIANCE_MAX_ATTEMPTS", "4"))
_BASE_BACKOFF = float(os.environ.get("KAOS_COMPLIANCE_BASE_BACKOFF", "1.5"))
_RATE_LIMIT_MULTIPLIER = 6.0
_JITTER_FRAC = 0.3
_TERMINAL_STDERR_SIGNALS = (
    "not found",
    "404",
    "401",
    "unauthorized",
    "authentication required",
)
_RATE_LIMIT_STDERR_SIGNALS = (
    "rate limit",
    "secondary rate",
    "abuse detection",
    "abuse-rate-limits",
)


def _sleep_for(attempt: int, *, rate_limited: bool) -> float:
    base = _BASE_BACKOFF * (2 ** (attempt - 1))
    if rate_limited:
        base *= _RATE_LIMIT_MULTIPLIER
    return base + random.uniform(0, _JITTER_FRAC * base)


def gh_run(
    args: list[str],
    *,
    timeout: float = 30.0,
    max_attempts: int | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run ``gh <args>`` with exponential backoff on transient errors.

    Distinguishes terminal failures (404 / auth) from retryable ones
    (rate-limit, 5xx, network, timeout). Re-raises the final exception
    on exhaustion so callers can still detect catastrophic failure and
    write ``null`` into the JSON snapshot rather than silently absorb.
    """
    if not shutil.which("gh"):
        msg = "gh CLI not found on PATH — install from https://cli.github.com/"
        raise RuntimeError(msg)
    attempts = max_attempts or _MAX_ATTEMPTS
    last_exc: BaseException | None = None
    for attempt in range(1, attempts + 1):
        try:
            return subprocess.run(
                ["gh", *args],
                check=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "").lower()
            if any(sig in stderr for sig in _TERMINAL_STDERR_SIGNALS):
                raise
            rate_limited = any(sig in stderr for sig in _RATE_LIMIT_STDERR_SIGNALS)
            last_exc = exc
        except subprocess.TimeoutExpired as exc:
            rate_limited = False
            last_exc = exc

        if attempt < attempts:
            time.sleep(_sleep_for(attempt, rate_limited=rate_limited))

    assert last_exc is not None
    raise last_exc


def url_get_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 15.0,
    max_attempts: int | None = None,
) -> Any:
    """GET a JSON URL with the same retry policy as :func:`gh_run`.

    404 is terminal (resource doesn't exist; retry won't help). Every
    other HTTPError / URLError / TimeoutError / OSError is retried with
    exponential backoff. The final exception is re-raised on exhaustion.
    """
    if urllib.parse.urlsplit(url).scheme != "https":
        raise ValueError(f"refusing to fetch non-HTTPS URL: {url}")
    attempts = max_attempts or _MAX_ATTEMPTS
    req = urllib.request.Request(url, headers=headers or {})
    last_exc: BaseException | None = None
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise
            last_exc = exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_exc = exc

        if attempt < attempts:
            rate_limited = isinstance(last_exc, urllib.error.HTTPError) and last_exc.code in (
                403,
                429,
            )
            time.sleep(_sleep_for(attempt, rate_limited=rate_limited))

    assert last_exc is not None
    raise last_exc
