from ghost.core.state_graph import StateGraph
from ghost.spec.schema import ApplicationSpec, AuthContext, HttpMethod, StateDefinition, TransitionEdge


def _spec() -> ApplicationSpec:
    return ApplicationSpec(
        name="test",
        base_url="https://example.test",
        states={
            "LOGIN": StateDefinition(url="/login", method=HttpMethod.POST, auth_context=AuthContext.ANONYMOUS),
            "CART": StateDefinition(url="/cart", method=HttpMethod.POST, auth_context=AuthContext.AUTHENTICATED),
            "CONFIRM": StateDefinition(url="/confirm", method=HttpMethod.POST, auth_context=AuthContext.AUTHENTICATED),
            "ADMIN_PANEL": StateDefinition(url="/admin", method=HttpMethod.POST, auth_context=AuthContext.ADMIN),
        },
        transitions=[
            TransitionEdge(from_state="LOGIN", to_state="CART"),
            TransitionEdge(from_state="CART", to_state="CONFIRM"),
        ],
        entry_states=["LOGIN"],
    )


def test_legal_edge_is_not_illegal():
    graph = StateGraph(_spec())
    illegal = {(e.from_state, e.to_state) for e in graph.illegal_edges()}
    assert ("LOGIN", "CART") not in illegal
    assert ("CART", "CONFIRM") not in illegal


def test_skip_to_confirm_is_illegal():
    graph = StateGraph(_spec())
    illegal = {(e.from_state, e.to_state) for e in graph.illegal_edges()}
    assert ("LOGIN", "CONFIRM") in illegal


def test_admin_boundary_crossing_is_flagged_and_prioritized():
    graph = StateGraph(_spec())
    high_value = graph.high_value_targets()
    assert any(e.to_state == "ADMIN_PANEL" for e in high_value)
    for e in high_value:
        assert "auth boundary" in e.reason


def test_illegal_sequence_every_hop_is_illegal():
    graph = StateGraph(_spec())
    for sequence in graph.illegal_sequences(max_sequence_length=3):
        consecutive = list(zip(sequence.states, sequence.states[1:]))
        assert all(not graph.is_legal(a, b) for a, b in consecutive)


def test_illegal_sequence_excludes_walks_with_a_legal_hop():
    graph = StateGraph(_spec())
    # LOGIN -> CART is legal, so no returned sequence should walk through it.
    for sequence in graph.illegal_sequences(max_sequence_length=3):
        assert ("LOGIN", "CART") not in zip(sequence.states, sequence.states[1:])


def test_illegal_sequence_respects_max_length_cap():
    graph = StateGraph(_spec())
    assert all(len(s.states) <= 4 for s in graph.illegal_sequences(max_sequence_length=4))
    assert any(len(s.states) == 4 for s in graph.illegal_sequences(max_sequence_length=4))


def test_illegal_sequence_rejects_too_short_cap():
    graph = StateGraph(_spec())
    try:
        graph.illegal_sequences(max_sequence_length=2)
    except ValueError:
        return
    raise AssertionError("expected ValueError for max_sequence_length < 3")
