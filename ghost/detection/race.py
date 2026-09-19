"""
ghost.detection.race
=======================

Concurrent-request race-condition detection, plus the shared
"was this single-use action processed more than once" comparator used
by both the concurrent race probe and the sequential replay probe
(see ghost.core.engine.probe_race_condition / probe_replay).

Every other probe in this tool fires requests one at a time, so a
classic TOCTOU business-logic bug — two requests racing past a single
stock/balance/coupon check so the backend double-processes something
that should be single-use — is invisible to it. This module doesn't
know what "double-processed" means for any given target (that's
target-specific business logic), so it exposes a default heuristic
and lets the caller supply a custom comparator instead.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Sequence

import httpx

RaceComparator = Callable[[Sequence[httpx.Response]], bool]


@dataclass(frozen=True)
class RaceProbeResult:
    responses: tuple[httpx.Response, ...]
    flagged: bool
    detail: str


def default_comparator(responses: Sequence[httpx.Response]) -> bool:
    """More than one 2xx among N concurrent/replayed identical requests
    suggests the backend processed a single-use action more than once.
    Target-specific logic (a balance going negative, a duplicate order
    row) should be passed in as a custom comparator instead.
    """
    return sum(1 for r in responses if 200 <= r.status_code < 300) > 1


def evaluate(responses: Sequence[httpx.Response], comparator: RaceComparator | None = None) -> RaceProbeResult:
    comparator = comparator or default_comparator
    flagged = comparator(responses)
    successes = sum(1 for r in responses if 200 <= r.status_code < 300)
    detail = (
        f"{successes}/{len(responses)} identical requests succeeded (2xx) — expected at most 1 "
        f"for a single-use action."
        if flagged
        else f"{successes}/{len(responses)} identical requests succeeded — within expected bounds."
    )
    return RaceProbeResult(responses=tuple(responses), flagged=flagged, detail=detail)
