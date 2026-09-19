"""
ghost.reporting.html_report
==============================

Self-contained HTML report (no external assets) for handing a scan's
results to a human for triage/write-up into the engagement report.
"""

from __future__ import annotations

from pathlib import Path

from ghost.reporting.models import ReportContext

_SEVERITY_COLOR = {
    "CRITICAL": "#b91c1c",
    "HIGH": "#c2410c",
    "MEDIUM": "#a16207",
    "LOW": "#4d7c0f",
    "INFO": "#374151",
}


def render_html(ctx: ReportContext) -> str:
    rows = "\n".join(_finding_row(f) for f in ctx.scan_result.findings) or (
        "<tr><td colspan='5'>No notable findings.</td></tr>"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Ghost In The Machine — {ctx.target_name}</title>
<style>
  body {{ font-family: -apple-system, sans-serif; margin: 2rem; color: #111; }}
  h1 {{ margin-bottom: 0.2rem; }}
  .meta {{ color: #555; margin-bottom: 1.5rem; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid #e5e5e5; vertical-align: top; }}
  th {{ background: #f5f5f5; }}
  code {{ font-size: 0.85em; background: #f5f5f5; padding: 0.1rem 0.3rem; }}
  .sev {{ font-weight: 600; }}
</style>
</head>
<body>
  <h1>Ghost In The Machine</h1>
  <div class="meta">
    Target: <strong>{ctx.target_name}</strong> &middot;
    Scanned: {ctx.started_at.isoformat()} &middot;
    Edges attempted: {ctx.scan_result.attempted_edges} &middot;
    Findings: {len(ctx.scan_result.findings)} &middot;
    Errors: {len(ctx.scan_result.errors)} &middot;
    Skipped: {len(ctx.scan_result.skipped)}
  </div>
  <table>
    <thead>
      <tr><th>Severity</th><th>Transition</th><th>Verdict</th><th>Detail</th><th>Status</th></tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>
</body>
</html>"""


def _finding_row(f) -> str:
    color = _SEVERITY_COLOR.get(f.severity.name, "#374151")
    return (
        f"<tr>"
        f"<td class='sev' style='color:{color}'>{f.severity.name}</td>"
        f"<td><code>{f.edge.from_state}</code> &rarr; <code>{f.edge.to_state}</code></td>"
        f"<td>{f.verdict.value}</td>"
        f"<td>{f.detail}</td>"
        f"<td>{f.status_code}</td>"
        f"</tr>"
    )


def write_html_report(ctx: ReportContext, path: str | Path) -> None:
    Path(path).write_text(render_html(ctx))
