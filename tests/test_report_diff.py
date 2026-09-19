from ghost.reporting.report_diff import diff_reports, render_summary, write_diff_json


def _finding(from_state, to_state, reason="not in declared legal transition set", verdict="likely_bypass", severity="HIGH"):
    return {
        "from_state": from_state,
        "to_state": to_state,
        "reason": reason,
        "verdict": verdict,
        "severity": severity,
        "status_code": 200,
        "detail": "d",
        "response_snippet": "",
    }


def test_diff_classifies_new_resolved_and_persistent():
    report_a = {"findings": [_finding("LOGIN", "CONFIRM"), _finding("LOGIN", "ADMIN")]}
    report_b = {"findings": [_finding("LOGIN", "ADMIN"), _finding("CART", "ADMIN")]}

    diff = diff_reports(report_a, report_b)

    assert [f["to_state"] for f in diff.new] == ["ADMIN"] and diff.new[0]["from_state"] == "CART"
    assert [f["to_state"] for f in diff.resolved] == ["CONFIRM"]
    assert [f["to_state"] for f in diff.persistent] == ["ADMIN"] and diff.persistent[0]["from_state"] == "LOGIN"


def test_diff_matches_on_full_key_not_just_states():
    # same from/to but a different verdict counts as a different finding
    report_a = {"findings": [_finding("LOGIN", "ADMIN", verdict="structural_deviation")]}
    report_b = {"findings": [_finding("LOGIN", "ADMIN", verdict="likely_bypass")]}

    diff = diff_reports(report_a, report_b)
    assert len(diff.new) == 1
    assert len(diff.resolved) == 1
    assert len(diff.persistent) == 0


def test_render_summary_includes_counts():
    diff = diff_reports({"findings": [_finding("A", "B")]}, {"findings": []})
    summary = render_summary(diff)
    assert "Resolved:   1" in summary
    assert "New:        0" in summary


def test_write_diff_json_round_trips(tmp_path):
    diff = diff_reports({"findings": [_finding("A", "B")]}, {"findings": [_finding("A", "B"), _finding("C", "D")]})
    path = tmp_path / "diff.json"
    write_diff_json(diff, path)

    import json

    payload = json.loads(path.read_text())
    assert len(payload["new"]) == 1
    assert len(payload["persistent"]) == 1
    assert len(payload["resolved"]) == 0
