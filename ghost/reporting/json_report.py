"""
ghost.reporting.json_report
==============================

Machine-readable report — feed into a CI gate, a ticketing pipeline,
or another tool. Kept schema-stable and boring on purpose.
"""

from __future__ import annotations

import json
from pathlib import Path

from ghost.reporting.models import ReportContext


def render_json(ctx: ReportContext) -> str:
    payload = {
        "target": ctx.target_name,
        "started_at": ctx.started_at.isoformat(),
        "operator_note": ctx.operator_note,
        "attempted_edges": ctx.scan_result.attempted_edges,
        "errors": ctx.scan_result.errors,
        "skipped": ctx.scan_result.skipped,
        "findings": [
            {
                "from_state": f.edge.from_state,
                "to_state": f.edge.to_state,
                "reason": f.edge.reason,
                "verdict": f.verdict.value,
                "severity": f.severity.name,
                "status_code": f.status_code,
                "detail": f.detail,
                "response_snippet": f.response_snippet,
            }
            for f in ctx.scan_result.findings
        ],
    }
    return json.dumps(payload, indent=2)


def write_json_report(ctx: ReportContext, path: str | Path) -> None:
    Path(path).write_text(render_json(ctx))
