"""
ghost.core.state_graph
=========================

Turns the declarative spec's `transitions` list into an actual graph,
and — critically — computes the complement: every (from, to) pair that
is NOT declared legal. That complement is the fuzzer's real attack
surface. v1 had no such notion; illegal targets were picked by the
caller by hand, which doesn't scale and misses the fact that "illegal"
should be defined *relative to the legal graph*, not guessed per-call.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import permutations

from ghost.spec.schema import ApplicationSpec, AuthContext


@dataclass(frozen=True)
class IllegalEdge:
    from_state: str
    to_state: str
    reason: str  # e.g. "not in legal transition set", "crosses auth boundary (auth -> admin)"


@dataclass(frozen=True)
class IllegalSequence:
    """A chained walk of illegal hops attempted in one continuous
    session — e.g. skip step 2, then (using whatever that first bypass
    exposed) also skip step 4 — rather than one isolated illegal probe.
    """

    hops: tuple[IllegalEdge, ...]

    @property
    def states(self) -> tuple[str, ...]:
        return (self.hops[0].from_state,) + tuple(h.to_state for h in self.hops)


class StateGraph:
    """Wraps an ApplicationSpec with graph queries."""

    def __init__(self, spec: ApplicationSpec):
        self.spec = spec
        self._legal_edges: set[tuple[str, str]] = {
            (edge.from_state, edge.to_state) for edge in spec.transitions
        }

    def is_legal(self, from_state: str, to_state: str) -> bool:
        return (from_state, to_state) in self._legal_edges

    def legal_successors(self, from_state: str) -> list[str]:
        return [to for (frm, to) in self._legal_edges if frm == from_state]

    def illegal_edges(self, *, include_self_loops: bool = False) -> list[IllegalEdge]:
        """Every state pair not present in the legal transition set —
        the full candidate space for `inject_illegal_transition`.

        Prioritizes and tags auth-boundary crossings (e.g. an
        AUTHENTICATED state jumping to an ADMIN state) since those are
        the highest-value findings.
        """
        names = list(self.spec.states.keys())
        results: list[IllegalEdge] = []

        for from_state, to_state in permutations(names, 2):
            if not include_self_loops and from_state == to_state:
                continue
            if self.is_legal(from_state, to_state):
                continue
            results.append(IllegalEdge(from_state, to_state, self._reason_for(from_state, to_state)))

        # Auth-boundary crossings first — most likely to be real findings.
        results.sort(key=lambda e: 0 if "auth boundary" in e.reason else 1)
        return results

    def high_value_targets(self) -> list[IllegalEdge]:
        """Convenience filter: only the auth-boundary-crossing illegal
        edges, for a fast/focused scan instead of the full N*(N-1) sweep.
        """
        return [e for e in self.illegal_edges() if "auth boundary" in e.reason]

    def illegal_sequences(self, *, max_sequence_length: int = 3) -> list[IllegalSequence]:
        """Chained multi-hop illegal transitions: walks of up to
        `max_sequence_length` states where EVERY consecutive hop is
        illegal (e.g. skip step 2, then also skip step 4, in one
        session) — attempting compounded bypasses rather than one
        isolated illegal jump.

        Opt-in and separate from `illegal_edges()`: this is a
        permutation search over the state set (O(n!)), a materially
        larger space than the single-hop O(n^2) sweep, so callers must
        explicitly ask for it and cap `max_sequence_length`.
        """
        if max_sequence_length < 3:
            raise ValueError("max_sequence_length must be >= 3 (at least two chained illegal hops)")

        names = list(self.spec.states.keys())
        results: list[IllegalSequence] = []

        for length in range(3, max_sequence_length + 1):
            for combo in permutations(names, length):
                consecutive = list(zip(combo, combo[1:]))
                if any(self.is_legal(a, b) for a, b in consecutive):
                    continue  # a legal hop mid-walk isn't a chained illegal-sequence attempt
                hops = tuple(IllegalEdge(a, b, self._reason_for(a, b)) for a, b in consecutive)
                results.append(IllegalSequence(hops=hops))

        results.sort(key=lambda s: 0 if any("auth boundary" in h.reason for h in s.hops) else 1)
        return results

    def _reason_for(self, from_state: str, to_state: str) -> str:
        from_ctx = self.spec.states[from_state].auth_context
        to_ctx = self.spec.states[to_state].auth_context
        if _crosses_privilege_boundary(from_ctx, to_ctx):
            return f"crosses auth boundary ({from_ctx.value} -> {to_ctx.value})"
        return "not in declared legal transition set"


_PRIVILEGE_RANK = {
    AuthContext.ANONYMOUS: 0,
    AuthContext.AUTHENTICATED: 1,
    AuthContext.ADMIN: 2,
}


def _crosses_privilege_boundary(from_ctx: AuthContext, to_ctx: AuthContext) -> bool:
    return _PRIVILEGE_RANK[to_ctx] > _PRIVILEGE_RANK[from_ctx]
