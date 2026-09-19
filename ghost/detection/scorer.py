"""
ghost.detection.scorer
=========================

Converts a raw AnomalyResult into a Finding with a severity/confidence
rating, so the reporting layer and the operator can triage quickly
instead of reading every single attempted edge.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

import httpx

from ghost.core.state_graph import IllegalEdge
from ghost.detection.diff import AnomalyResult, AnomalyVerdict


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Finding:
    edge: IllegalEdge
    verdict: AnomalyVerdict
    detail: str
    severity: Severity
    status_code: int
    response_snippet: str
    is_notable: bool  # whether this should surface in the report at all


_BASE_SEVERITY = {
    AnomalyVerdict.CLEANLY_BLOCKED: Severity.INFO,
    AnomalyVerdict.STRUCTURAL_DEVIATION: Severity.LOW,
    AnomalyVerdict.SERVER_ERROR: Severity.MEDIUM,
    AnomalyVerdict.LIKELY_BYPASS: Severity.HIGH,
}


def score_finding(edge: IllegalEdge, response: httpx.Response, anomaly: AnomalyResult) -> Finding:
    severity = _BASE_SEVERITY[anomaly.verdict]

    # An auth-boundary-crossing bypass is the tool's headline finding class.
    if anomaly.verdict is AnomalyVerdict.LIKELY_BYPASS and "auth boundary" in edge.reason:
        severity = Severity.CRITICAL

    # Timing anomaly nudges severity up one notch (min HIGH) — a slow
    # response to something that should've been cleanly rejected suggests
    # real backend processing occurred.
    if anomaly.timing_flagged and severity < Severity.HIGH:
        severity = Severity(severity + 1)

    return Finding(
        edge=edge,
        verdict=anomaly.verdict,
        detail=anomaly.detail,
        severity=severity,
        status_code=response.status_code,
        response_snippet=response.text[:300],
        is_notable=anomaly.verdict is not AnomalyVerdict.CLEANLY_BLOCKED,
    )
