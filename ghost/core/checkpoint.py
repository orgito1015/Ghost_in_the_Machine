"""
ghost.core.checkpoint
========================

Resumable-scan support: periodically serializes scan progress (how
many edges/sequences have been attempted, the accumulated ScanResult,
and the actor's SessionContext state) to a JSON file, so `ghost scan
--resume checkpoint.json` can pick up where a long `--full` or
`--multi-hop` scan left off instead of restarting — useful for a large
state graph where a full N*(N-1) sweep or a multi-hop search can run
for hours and something (network blip, operator's laptop sleeping)
interrupts it partway through.

Deliberately not transactional: a checkpoint write is a single
`Path.write_text`, so a crash mid-write could leave a truncated file.
Good enough for "resume a long scan," not meant as a database.

Only imports from ghost.core.state_graph / ghost.detection at module
level (never ghost.core.engine) so GhostEngine can import this module
without a circular import; the ScanResult/SessionContext types it
actually operates on are duck-typed (attribute access only) and
type-hinted under `TYPE_CHECKING`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ghost.core.state_graph import IllegalEdge
from ghost.detection.diff import AnomalyVerdict
from ghost.detection.scorer import Finding, Severity

if TYPE_CHECKING:
    from ghost.core.engine import ScanResult
    from ghost.core.session import SessionContext


def save_checkpoint(
    path: str | Path,
    *,
    actor_label: str,
    mode: str,
    completed: int,
    result: "ScanResult",
    session: "SessionContext",
) -> None:
    payload = {
        "actor_label": actor_label,
        "mode": mode,  # "edges" | "sequences" — which scan() branch this resumes into
        "completed": completed,
        "result": {
            "attempted_edges": result.attempted_edges,
            "errors": result.errors,
            "skipped": result.skipped,
            "findings": [_finding_to_dict(f) for f in result.findings],
        },
        "session": {
            "cookies": dict(session.cookies.items()),
            "headers": session.headers,
            "extracted": session.extracted,
        },
    }
    Path(path).write_text(json.dumps(payload, indent=2))


def load_checkpoint(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text())


def restore_session(session: "SessionContext", checkpoint: dict[str, Any]) -> None:
    sess = checkpoint["session"]
    for name, value in sess["cookies"].items():
        session.cookies.set(name, value)
    session.headers.update(sess["headers"])
    session.extracted.update(sess["extracted"])


def restore_result(checkpoint: dict[str, Any]) -> "ScanResult":
    from ghost.core.engine import ScanResult  # runtime import here only, to avoid the module-level cycle

    r = checkpoint["result"]
    return ScanResult(
        findings=[_finding_from_dict(f) for f in r["findings"]],
        attempted_edges=r["attempted_edges"],
        errors=r["errors"],
        skipped=r["skipped"],
    )


def _finding_to_dict(f: Finding) -> dict[str, Any]:
    return {
        "from_state": f.edge.from_state,
        "to_state": f.edge.to_state,
        "reason": f.edge.reason,
        "verdict": f.verdict.value,
        "severity": f.severity.name,
        "status_code": f.status_code,
        "detail": f.detail,
        "response_snippet": f.response_snippet,
        "is_notable": f.is_notable,
    }


def _finding_from_dict(d: dict[str, Any]) -> Finding:
    return Finding(
        edge=IllegalEdge(d["from_state"], d["to_state"], d["reason"]),
        verdict=AnomalyVerdict(d["verdict"]),
        detail=d["detail"],
        severity=Severity[d["severity"]],
        status_code=d["status_code"],
        response_snippet=d["response_snippet"],
        is_notable=d["is_notable"],
    )
