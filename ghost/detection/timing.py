"""
ghost.detection.timing
=========================

Standalone timing-baseline helper, kept separate from `baseline.py`
(response *shape* fingerprinting) since timing needs multiple samples
to be meaningful — network jitter makes a single sample unreliable.

Not yet wired into GhostEngine by default (see engine.py's
`_get_baseline`, which currently only captures shape). Planned:
sample N blocked requests, store median latency, pass it into
`classify_anomaly(..., baseline_elapsed_seconds=...)`.
"""

from __future__ import annotations

import statistics
import time

import httpx

from ghost.core.http import request_with_retry
from ghost.spec.schema import StateDefinition


def sample_blocked_latency(client: httpx.Client, state: StateDefinition, samples: int = 3) -> float:
    """Fire `samples` deliberately-unauthorized requests at `state` and
    return the median latency in seconds, as a noise-resistant timing
    baseline for `classify_anomaly`.
    """
    durations: list[float] = []
    for _ in range(samples):
        start = time.monotonic()
        request_with_retry(
            client,
            state.method.value,
            state.url,
            json=state.default_data,
            headers={**state.headers, "Authorization": "Bearer ghost-baseline-invalid-token"},
        )
        durations.append(time.monotonic() - start)
    return statistics.median(durations)
