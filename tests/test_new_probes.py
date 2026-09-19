import httpx
import pytest

from ghost.core.engine import EngineConfig, GhostEngine, ProbeSkipped
from ghost.core.session import SessionContext
from ghost.spec.schema import ApplicationSpec, HttpMethod, StateDefinition


def _engine(states: dict[str, StateDefinition], handler, config: EngineConfig | None = None) -> GhostEngine:
    spec = ApplicationSpec(name="t", base_url="https://x.test", states=states)
    engine = GhostEngine(spec, config)
    engine.client = httpx.Client(transport=httpx.MockTransport(handler))
    return engine


def test_race_condition_flags_more_than_one_success():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200 if calls["n"] <= 2 else 409)

    engine = _engine(
        {"REDEEM": StateDefinition(url="https://x.test/redeem", method=HttpMethod.POST, idempotency_expected=True)},
        handler,
    )
    finding = engine.probe_race_condition("REDEEM", SessionContext(), concurrency=5)

    assert finding.is_notable is True
    assert "expected at most 1" in finding.detail


def test_race_condition_clean_when_exactly_one_succeeds():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200 if calls["n"] == 1 else 409)

    engine = _engine({"REDEEM": StateDefinition(url="https://x.test/redeem", method=HttpMethod.POST)}, handler)
    finding = engine.probe_race_condition("REDEEM", SessionContext(), concurrency=5)

    assert finding.is_notable is False


def test_replay_probe_reuses_race_comparator_and_flags_reprocessing():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)  # every replay "succeeds" — reprocessed each time

    engine = _engine({"CLAIM": StateDefinition(url="https://x.test/claim", method=HttpMethod.POST)}, handler)
    finding = engine.probe_replay("CLAIM", SessionContext(), times=3)

    assert finding.is_notable is True


def test_diff_across_sessions_flags_leaked_field():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("X-Who") == "a":
            return httpx.Response(200, json={"name": "alice", "ssn": "123-45-6789"})
        return httpx.Response(200, json={"name": "bob"})

    engine = _engine({"PROFILE": StateDefinition(url="https://x.test/profile", method=HttpMethod.GET)}, handler)
    session_a = SessionContext(label="a", headers={"X-Who": "a"})
    session_b = SessionContext(label="b", headers={"X-Who": "b"})

    finding = engine.diff_across_sessions("PROFILE", session_a, session_b)

    assert finding.is_notable is True
    assert "ssn" in finding.detail


def test_diff_across_sessions_clean_when_identical():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"name": "bob"})

    engine = _engine({"PROFILE": StateDefinition(url="https://x.test/profile", method=HttpMethod.GET)}, handler)
    finding = engine.diff_across_sessions("PROFILE", SessionContext(label="a"), SessionContext(label="b"))

    assert finding.is_notable is False


def test_mass_assignment_flags_reflected_field():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"name": "bob", "is_admin": True})

    engine = _engine({"UPDATE": StateDefinition(url="https://x.test/update", method=HttpMethod.POST)}, handler)
    finding = engine.probe_mass_assignment("UPDATE", SessionContext(), candidate_fields=["is_admin"])

    assert finding.is_notable is True
    assert "is_admin" in finding.detail


def test_mass_assignment_clean_when_not_reflected():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"name": "bob"})

    engine = _engine({"UPDATE": StateDefinition(url="https://x.test/update", method=HttpMethod.POST)}, handler)
    finding = engine.probe_mass_assignment("UPDATE", SessionContext(), candidate_fields=["is_admin"])

    assert finding.is_notable is False


def test_mass_assignment_accepts_dict_candidate_fields_with_explicit_values():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"price": 0})

    engine = _engine({"UPDATE": StateDefinition(url="https://x.test/update", method=HttpMethod.POST)}, handler)
    finding = engine.probe_mass_assignment("UPDATE", SessionContext(), candidate_fields={"price": 0})

    assert finding.is_notable is True


def test_destructive_state_blocked_without_opt_in():
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("must not fire a request at a destructive state without opt-in")

    engine = _engine(
        {"REFUND": StateDefinition(url="https://x.test/refund", method=HttpMethod.POST, destructive=True)},
        handler,
    )
    with pytest.raises(ProbeSkipped):
        engine.probe_race_condition("REFUND", SessionContext(), concurrency=3)


def test_destructive_state_allowed_with_explicit_opt_in():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    engine = _engine(
        {"REFUND": StateDefinition(url="https://x.test/refund", method=HttpMethod.POST, destructive=True)},
        handler,
        config=EngineConfig(allow_destructive=True),
    )
    finding = engine.probe_race_condition("REFUND", SessionContext(), concurrency=2)
    assert finding is not None  # ran without raising


def test_dry_run_never_sends_a_request():
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("must not fire a request in dry-run mode")

    engine = _engine(
        {"REDEEM": StateDefinition(url="https://x.test/redeem", method=HttpMethod.POST)},
        handler,
        config=EngineConfig(dry_run=True),
    )
    with pytest.raises(ProbeSkipped):
        engine.probe_race_condition("REDEEM", SessionContext(), concurrency=3)


def test_scan_auto_probes_idempotency_expected_states():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200 if calls["n"] <= 2 else 409)

    spec = ApplicationSpec(
        name="t",
        base_url="https://x.test",
        states={"REDEEM": StateDefinition(url="https://x.test/redeem", method=HttpMethod.POST, idempotency_expected=True)},
    )
    engine = GhostEngine(spec, EngineConfig(race_concurrency=5))
    engine.client = httpx.Client(transport=httpx.MockTransport(handler))

    result = engine.scan(target_edges=[])  # no illegal-edge sweep, isolate the auto race-check

    assert any("REDEEM" in f.edge.from_state for f in result.findings)


def test_scan_records_skipped_probes_separately_from_errors():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    spec = ApplicationSpec(
        name="t",
        base_url="https://x.test",
        states={
            "LOGIN": StateDefinition(url="https://x.test/login", method=HttpMethod.POST),
            "REFUND": StateDefinition(url="https://x.test/refund", method=HttpMethod.POST, destructive=True),
        },
        transitions=[],
    )
    engine = GhostEngine(spec)
    engine.client = httpx.Client(transport=httpx.MockTransport(handler))

    result = engine.scan(target_edges=engine.graph.illegal_edges())

    assert result.skipped  # the LOGIN -> REFUND edge (and REFUND -> LOGIN) got skipped, not errored
    assert not result.errors
