import httpx

from ghost.core.state_graph import IllegalEdge
from ghost.detection.diff import AnomalyResult, AnomalyVerdict
from ghost.detection.scorer import Severity, score_finding

_AUTH_EDGE = IllegalEdge("LOGIN", "ADMIN_PANEL", "crosses auth boundary (authenticated -> admin)")
_PLAIN_EDGE = IllegalEdge("LOGIN", "CONFIRM", "not in declared legal transition set")


def _response(status: int = 200, text: str = "") -> httpx.Response:
    return httpx.Response(status, text=text)


def test_cleanly_blocked_is_info_and_not_notable():
    anomaly = AnomalyResult(AnomalyVerdict.CLEANLY_BLOCKED, "matches baseline")
    finding = score_finding(_PLAIN_EDGE, _response(401), anomaly)
    assert finding.severity is Severity.INFO
    assert finding.is_notable is False


def test_likely_bypass_across_auth_boundary_is_critical():
    anomaly = AnomalyResult(AnomalyVerdict.LIKELY_BYPASS, "bypassed")
    finding = score_finding(_AUTH_EDGE, _response(200), anomaly)
    assert finding.severity is Severity.CRITICAL
    assert finding.is_notable is True


def test_likely_bypass_without_auth_boundary_is_high_not_critical():
    anomaly = AnomalyResult(AnomalyVerdict.LIKELY_BYPASS, "bypassed")
    finding = score_finding(_PLAIN_EDGE, _response(200), anomaly)
    assert finding.severity is Severity.HIGH


def test_timing_flag_bumps_severity_by_one_notch():
    anomaly = AnomalyResult(AnomalyVerdict.STRUCTURAL_DEVIATION, "deviation", timing_flagged=True)
    finding = score_finding(_PLAIN_EDGE, _response(403), anomaly)
    assert finding.severity is Severity.MEDIUM  # LOW -> MEDIUM


def test_timing_flag_does_not_push_past_critical_floor_already_at_high():
    anomaly = AnomalyResult(AnomalyVerdict.LIKELY_BYPASS, "bypassed", timing_flagged=True)
    finding = score_finding(_PLAIN_EDGE, _response(200), anomaly)
    assert finding.severity is Severity.HIGH  # already at HIGH floor for bump logic — stays HIGH


def test_response_snippet_is_truncated_to_300_chars():
    anomaly = AnomalyResult(AnomalyVerdict.LIKELY_BYPASS, "bypassed")
    finding = score_finding(_PLAIN_EDGE, _response(200, text="x" * 500), anomaly)
    assert len(finding.response_snippet) == 300
