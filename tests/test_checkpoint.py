import httpx

from ghost.core.checkpoint import load_checkpoint, restore_result, restore_session, save_checkpoint
from ghost.core.engine import EngineConfig, GhostEngine, ScanResult
from ghost.core.session import SessionContext
from ghost.spec.schema import ApplicationSpec, AuthContext, HttpMethod, StateDefinition


def _spec() -> ApplicationSpec:
    return ApplicationSpec(
        name="t",
        base_url="https://x.test",
        states={
            "LOGIN": StateDefinition(url="https://x.test/login", method=HttpMethod.POST, auth_context=AuthContext.ANONYMOUS),
            "CART": StateDefinition(url="https://x.test/cart", method=HttpMethod.POST),
            "ADMIN": StateDefinition(url="https://x.test/admin", method=HttpMethod.POST, auth_context=AuthContext.ADMIN),
        },
    )


def test_checkpoint_round_trips_session_and_result(tmp_path):
    session = SessionContext(headers={"X-Actor": "bob"}, extracted={"order_id": "42"})
    session.cookies.set("sid", "abc123")
    result = ScanResult(attempted_edges=3, errors=["e1"], skipped=["s1"])

    path = tmp_path / "checkpoint.json"
    save_checkpoint(path, actor_label="default", mode="edges", completed=3, result=result, session=session)

    checkpoint = load_checkpoint(path)
    assert checkpoint["completed"] == 3

    restored_session = SessionContext()
    restore_session(restored_session, checkpoint)
    assert restored_session.cookies.get("sid") == "abc123"
    assert restored_session.headers == {"X-Actor": "bob"}
    assert restored_session.extracted == {"order_id": "42"}

    restored_result = restore_result(checkpoint)
    assert restored_result.attempted_edges == 3
    assert restored_result.errors == ["e1"]
    assert restored_result.skipped == ["s1"]


def test_scan_writes_checkpoint_and_resume_skips_completed_edges(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403)

    engine = GhostEngine(_spec(), EngineConfig(timing_baseline_samples=0))
    engine.client = httpx.Client(transport=httpx.MockTransport(handler))
    edges = engine.graph.illegal_edges()

    checkpoint_path = tmp_path / "checkpoint.json"
    partial = engine.scan(target_edges=edges[:3], checkpoint_path=str(checkpoint_path), checkpoint_every=1)
    assert partial.attempted_edges == 3

    checkpoint = load_checkpoint(checkpoint_path)
    assert checkpoint["completed"] == 3

    seed = restore_result(checkpoint)
    final = engine.scan(target_edges=edges, seed_result=seed, resume_from=checkpoint["completed"])

    assert final.attempted_edges == len(edges)


def test_resume_skips_warm_up():
    calls = {"warmup": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            calls["warmup"] += 1
        return httpx.Response(403)

    engine = GhostEngine(_spec(), EngineConfig(timing_baseline_samples=0))
    engine.client = httpx.Client(transport=httpx.MockTransport(handler))

    engine.scan(target_edges=[], warm_up_states=["LOGIN"], resume_from=1)
    assert calls["warmup"] == 0  # resume_from > 0 means warm-up is skipped
