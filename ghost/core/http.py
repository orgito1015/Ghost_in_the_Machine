"""
ghost.core.http
==================

Shared request-retry/backoff wrapper, used everywhere the engine or
detection layer fires a request against the target.

httpx.TransportError (connection reset, timeout, DNS failure) is a
transient network failure — worth retrying. That's distinct from the
target legitimately blocking a request (a 4xx/5xx HTTP response),
which is a *result* for the detection layer to classify, not a
fuzzer-side failure to retry past.

429 is a special case: it's a real HTTP response, but retrying it
(honoring Retry-After when present) is the polite, engagement-safe
behavior, so it's handled here rather than surfaced as a raw 429 to
the caller.
"""

from __future__ import annotations

import logging
import time

import httpx

logger = logging.getLogger("ghost.http")


def request_with_retry(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    max_retries: int = 3,
    backoff_base: float = 0.5,
    **kwargs,
) -> httpx.Response:
    """Fire one logical request, retrying on transient transport
    failures and on 429 rate-limiting. Any other status code (2xx
    through 5xx) is returned as-is on the first attempt.
    """
    attempt = 0
    while True:
        try:
            response = client.request(method, url, **kwargs)
        except httpx.TransportError as exc:
            attempt += 1
            if attempt > max_retries:
                raise
            delay = backoff_base * (2 ** (attempt - 1))
            logger.warning(
                "transient network error on %s %s (attempt %d/%d): %s — retrying in %.1fs",
                method, url, attempt, max_retries, exc, delay,
            )
            time.sleep(delay)
            continue

        if response.status_code == 429:
            attempt += 1
            if attempt > max_retries:
                return response
            delay = _retry_after_seconds(response) or backoff_base * (2 ** (attempt - 1))
            logger.info(
                "rate-limited (429) on %s %s — backing off %.1fs (attempt %d/%d)",
                method, url, delay, attempt, max_retries,
            )
            time.sleep(delay)
            continue

        return response


def _retry_after_seconds(response: httpx.Response) -> float | None:
    header = response.headers.get("Retry-After")
    if not header:
        return None
    try:
        return float(header)
    except ValueError:
        return None  # HTTP-date form (RFC 7231) not handled — fall back to exponential backoff
