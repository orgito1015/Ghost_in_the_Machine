"""
ghost.reporting.report_diff
==============================

Compares two JSON scan reports (ghost.reporting.json_report's output)
from the same spec/tool version and classifies each finding as new (in
B, not A), resolved (in A, not B — fixed *or* flaky, this can't tell
those apart), or persistent (in both). The standard "did this regress"
question for a scan a team runs repeatedly (nightly CI, before/after a
patch).

Findings are matched by (from_state, to_state, reason, verdict) rather
than a persistent ID, since neither the Finding model nor the JSON
report format assigns one — see ghost/detection/scorer.py.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ReportDiff:
    new: list[dict[str, Any]] = field(default_factory=list)
    resolved: list[dict[str, Any]] = field(default_factory=list)  # in A, not in B — fixed or flaky
    persistent: list[dict[str, Any]] = field(default_factory=list)  # in both


def load_report(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text())


def diff_reports(report_a: dict[str, Any], report_b: dict[str, Any]) -> ReportDiff:
    findings_a = {_key(f): f for f in report_a.get("findings", [])}
    findings_b = {_key(f): f for f in report_b.get("findings", [])}
    keys_a, keys_b = set(findings_a), set(findings_b)

    return ReportDiff(
        new=[findings_b[k] for k in sorted(keys_b - keys_a)],
        resolved=[findings_a[k] for k in sorted(keys_a - keys_b)],
        persistent=[findings_b[k] for k in sorted(keys_a & keys_b)],
    )


def _key(finding: dict[str, Any]) -> tuple[str, str, str, str]:
    return (finding["from_state"], finding["to_state"], finding["reason"], finding["verdict"])


def render_summary(diff: ReportDiff) -> str:
    lines = [
        f"New:        {len(diff.new)}",
        f"Resolved:   {len(diff.resolved)} (fixed or flaky — re-run to tell them apart)",
        f"Persistent: {len(diff.persistent)}",
    ]
    for label, findings in (("NEW", diff.new), ("RESOLVED", diff.resolved)):
        for f in findings:
            lines.append(f"  [{label}] {f['severity']:<8} {f['from_state']} -> {f['to_state']} ({f['verdict']})")
    return "\n".join(lines)


def diff_to_dict(diff: ReportDiff) -> dict[str, Any]:
    return {"new": diff.new, "resolved": diff.resolved, "persistent": diff.persistent}


def write_diff_json(diff: ReportDiff, path: str | Path) -> None:
    Path(path).write_text(json.dumps(diff_to_dict(diff), indent=2))
