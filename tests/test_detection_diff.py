import httpx

from ghost.detection.baseline import BaselineFingerprint
from ghost.detection.diff import AnomalyVerdict, classify_anomaly

_BASELINE = BaselineFingerprint(status_code=401, body_shape=("error",), approx_length=20)


def _response(status: int, body: dict | None = None) -> httpx.Response:
    if body is None:
        return httpx.Response(status)
    return httpx.Response(status, json=body)


def test_server_error_status_is_flagged_regardless_of_shape():
    result = classify_anomaly(_response(500), _BASELINE, elapsed_seconds=0.1)
    assert result.verdict is AnomalyVerdict.SERVER_ERROR


def test_matching_status_and_shape_is_cleanly_blocked():
    response = _response(401, {"error": "unauthorized"})
    result = classify_anomaly(response, _BASELINE, elapsed_seconds=0.1)
    assert result.verdict is AnomalyVerdict.CLEANLY_BLOCKED


def test_2xx_with_different_shape_is_likely_bypass():
    response = _response(200, {"order_id": 42, "status": "confirmed"})
    result = classify_anomaly(response, _BASELINE, elapsed_seconds=0.1)
    assert result.verdict is AnomalyVerdict.LIKELY_BYPASS


def test_non_2xx_different_shape_is_structural_deviation():
    response = _response(403, {"message": "forbidden"})
    result = classify_anomaly(response, _BASELINE, elapsed_seconds=0.1)
    assert result.verdict is AnomalyVerdict.STRUCTURAL_DEVIATION


def test_timing_anomaly_flagged_when_elapsed_exceeds_baseline_multiplier():
    response = _response(401, {"error": "unauthorized"})
    result = classify_anomaly(
        response, _BASELINE, elapsed_seconds=1.0, baseline_elapsed_seconds=0.1
    )
    assert result.timing_flagged is True


def test_timing_anomaly_not_flagged_within_normal_jitter():
    response = _response(401, {"error": "unauthorized"})
    result = classify_anomaly(
        response, _BASELINE, elapsed_seconds=0.15, baseline_elapsed_seconds=0.1
    )
    assert result.timing_flagged is False


def test_timing_not_evaluated_when_no_baseline_provided():
    response = _response(401, {"error": "unauthorized"})
    result = classify_anomaly(response, _BASELINE, elapsed_seconds=100.0, baseline_elapsed_seconds=None)
    assert result.timing_flagged is False
