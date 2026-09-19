"""
ghost.detection.baseline
===========================

v1 flagged "vulnerability" on any 200/201 without the literal word
"error" in the body — noisy in both directions (legitimate 200s get
flagged; JSON error responses without that word get missed).

The fix: for each target state, fire ONE deliberately-invalid request
first (garbage/expired auth token) to fingerprint what "cleanly
blocked" actually looks like for THIS endpoint on THIS target — status
code, response shape, and approximate size. Real anomaly detection
then means "did the illegal-transition response deviate from this
target-specific blocked fingerprint," not a hardcoded string check.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from ghost.core.http import request_with_retry
from ghost.spec.schema import StateDefinition

_GARBAGE_TOKEN = "ghost-baseline-invalid-token-00000000"


@dataclass(frozen=True)
class BaselineFingerprint:
    status_code: int
    body_shape: tuple  # sorted tuple of top-level JSON keys, or () for non-JSON
    approx_length: int


def fingerprint_blocked_response(client: httpx.Client, state: StateDefinition) -> BaselineFingerprint:
    """Fire one clearly-unauthorized request at `state` and capture its
    shape as the "known blocked" reference point for diffing later.
    """
    response = request_with_retry(
        client,
        state.method.value,
        state.url,
        json=state.default_data,
        headers={**state.headers, "Authorization": f"Bearer {_GARBAGE_TOKEN}"},
    )
    return BaselineFingerprint(
        status_code=response.status_code,
        body_shape=_shape_of(response),
        approx_length=len(response.content),
    )


def _shape_of(response: httpx.Response) -> tuple:
    try:
        body = response.json()
    except ValueError:
        return ()
    if isinstance(body, dict):
        return tuple(sorted(body.keys()))
    return ()
