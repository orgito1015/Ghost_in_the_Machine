"""
ghost.detection.diff
=======================

Classifies an illegal-transition response by comparing it against the
target state's "known blocked" baseline fingerprint, rather than
string-matching for "error". Also folds in a timing signal (gap 3 in
the v1 review): a response that takes structurally longer than the
blocked baseline can indicate the request reached real business logic
(e.g. a DB write) instead of being rejected at an auth gate.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

import httpx

from ghost.detection.baseline import BaselineFingerprint, _shape_of

# How much a response can exceed the blocked-baseline timing before it's
# treated as a signal that real processing happened. Tune per-target;
# network jitter alone can easily be 1.5-2x on a noisy connection.
_TIMING_ANOMALY_MULTIPLIER = 3.0


class AnomalyVerdict(str, Enum):
    CLEANLY_BLOCKED = "cleanly_blocked"        # matches blocked baseline closely
    STRUCTURAL_DEVIATION = "structural_deviation"  # different shape/status than baseline
    LIKELY_BYPASS = "likely_bypass"            # 2xx, different shape than blocked baseline
    SERVER_ERROR = "server_error"              # 5xx - possible logic/leak flaw, needs triage
    TIMING_ANOMALY = "timing_anomaly"          # secondary signal, combined with above


@dataclass(frozen=True)
class AnomalyResult:
    verdict: AnomalyVerdict
    detail: str
    timing_flagged: bool = False


def classify_anomaly(
    response: httpx.Response,
    baseline: BaselineFingerprint,
    *,
    elapsed_seconds: float,
    baseline_elapsed_seconds: float | None = None,
) -> AnomalyResult:
    status = response.status_code
    shape = _shape_of(response)

    timing_flagged = (
        baseline_elapsed_seconds is not None
        and elapsed_seconds > baseline_elapsed_seconds * _TIMING_ANOMALY_MULTIPLIER
    )

    if status >= 500:
        return AnomalyResult(
            AnomalyVerdict.SERVER_ERROR,
            f"Illegal transition returned {status} — possible unhandled state, check for stack "
            f"trace / info leakage in body.",
            timing_flagged,
        )

    if status == baseline.status_code and shape == baseline.body_shape:
        return AnomalyResult(
            AnomalyVerdict.CLEANLY_BLOCKED,
            f"Response matches known-blocked fingerprint for this state (status {status}).",
            timing_flagged,
        )

    if 200 <= status < 300:
        return AnomalyResult(
            AnomalyVerdict.LIKELY_BYPASS,
            f"Got {status} with body shape {shape}, which differs from this state's blocked "
            f"baseline (status {baseline.status_code}, shape {baseline.body_shape}). The illegal "
            f"transition likely succeeded.",
            timing_flagged,
        )

    return AnomalyResult(
        AnomalyVerdict.STRUCTURAL_DEVIATION,
        f"Status {status} / shape {shape} differs from blocked baseline "
        f"(status {baseline.status_code} / shape {baseline.body_shape}) but isn't a clean 2xx — "
        f"worth manual triage.",
        timing_flagged,
    )
