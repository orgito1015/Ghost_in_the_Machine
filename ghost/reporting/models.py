"""
ghost.reporting.models
=========================

Thin wrapper tying a ScanResult to run metadata, as the shared input
for both the HTML and JSON report renderers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from ghost.core.engine import ScanResult


@dataclass
class ReportContext:
    target_name: str
    scan_result: ScanResult
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    operator_note: str = ""
