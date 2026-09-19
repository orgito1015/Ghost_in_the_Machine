"""
ghost.detection.session_diff
================================

Structural diff between two JSON response bodies captured for the
*same legal state* under two different SessionContexts.

The state-graph/illegal-transition machinery elsewhere in this tool
answers "can session X reach a state it shouldn't." This answers a
different, equally common business-logic bug: two sessions that ARE
both legitimately allowed to hit a state, but the backend leaks one
actor's data into the other's response (IDOR-by-response-shape rather
than IDOR-by-reachability — e.g. a `/profile` response for user A
including a `ssn` field that only shows up because A's request
happened to also carry an admin-scoped cache key).

Deliberately shallow (top-level keys only), matching the same
"compare shape, not deep equality" philosophy `detection/baseline.py`
already uses elsewhere in this codebase — a full recursive diff needs
target-specific knowledge of which nested fields are expected to vary
per-user (timestamps, request IDs) that this generic tool doesn't have.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


@dataclass(frozen=True)
class FieldDiff:
    key: str
    value_a: Any
    value_b: Any


@dataclass(frozen=True)
class SessionDiffResult:
    only_in_a: tuple[str, ...]
    only_in_b: tuple[str, ...]
    differing: tuple[FieldDiff, ...]

    @property
    def flagged(self) -> bool:
        return bool(self.only_in_a or self.only_in_b or self.differing)


def diff_responses(response_a: httpx.Response, response_b: httpx.Response) -> SessionDiffResult:
    return diff_bodies(json_body(response_a), json_body(response_b))


def diff_bodies(body_a: dict, body_b: dict) -> SessionDiffResult:
    only_a = tuple(sorted(set(body_a) - set(body_b)))
    only_b = tuple(sorted(set(body_b) - set(body_a)))
    differing = tuple(
        FieldDiff(key, body_a[key], body_b[key])
        for key in sorted(set(body_a) & set(body_b))
        if body_a[key] != body_b[key]
    )
    return SessionDiffResult(only_in_a=only_a, only_in_b=only_b, differing=differing)


def json_body(response: httpx.Response) -> dict:
    try:
        body = response.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


def describe(result: SessionDiffResult, label_a: str, label_b: str) -> str:
    if not result.flagged:
        return f"No structural difference between '{label_a}' and '{label_b}' responses."
    parts = []
    if result.only_in_a:
        parts.append(f"only in {label_a}: {list(result.only_in_a)}")
    if result.only_in_b:
        parts.append(f"only in {label_b}: {list(result.only_in_b)}")
    if result.differing:
        parts.append(
            "differing values: "
            + ", ".join(f"{d.key}={d.value_a!r} vs {d.value_b!r}" for d in result.differing)
        )
    return "Cross-session response diff — " + "; ".join(parts)
