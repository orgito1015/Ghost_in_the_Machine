"""
ghost.spec.importers.traffic_capture
========================================

Shared request-grouping, path-templating, credential-redaction, and
session-order-based transition-inference logic for turning a list of
captured HTTP requests into a draft ApplicationSpec — regardless of
where the capture came from.

`burp_proxy.py` parses a Burp "Save items" XML export into a list of
`CapturedRequest` and hands it to `build_spec_from_captures` here;
`record.py` (the `ghost record` live-proxy command) does the same with
requests captured through a running mitmproxy instance. Neither
reimplements the "how do captures become a spec" logic — it exists in
exactly one place, factored out of what was originally burp_proxy.py's
own private helpers.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from ghost.spec.schema import ApplicationSpec, HttpMethod, StateDefinition, TransitionEdge

_NUMERIC_SEGMENT = re.compile(r"^\d+$")
_UUID_SEGMENT = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_REDACTED_HEADERS = {"authorization", "cookie"}
_SESSION_COOKIE_NAMES = {"session", "sessionid", "jsessionid", "phpsessid", "sid", "auth", "token"}


@dataclass
class CapturedRequest:
    """One request as seen by a capture source (Burp export item, live
    proxy flow, ...), already reduced to the fields the spec builder
    needs — the source-specific parsing (XML/base64, mitmproxy flow
    objects, ...) stays in the importer that produces these.
    """

    base_url: str
    path: str
    method: str
    headers: dict[str, str] = field(default_factory=dict)
    body: dict[str, Any] = field(default_factory=dict)


def build_spec_from_captures(captures: list[CapturedRequest], *, name: str = "imported-traffic-spec") -> ApplicationSpec:
    """Group captures by (method, normalized path-template) into
    states, redact Authorization/Cookie headers, and propose a draft
    `transitions` list from the observed per-session request order.

    `captures` must already be in chronological order (the order they
    were seen in) — that ordering is the signal `_propose_transitions`
    uses.
    """
    if not captures:
        raise ValueError("No captured requests to build a spec from")

    states: dict[str, StateDefinition] = {}
    occurrences: dict[str, list[CapturedRequest]] = defaultdict(list)
    for item in captures:
        if item.method not in HttpMethod.__members__:
            continue
        occurrences[_state_name(item)].append(item)

    for state_name, occs in occurrences.items():
        first = occs[0]
        template_path = _templatize(first.path)
        states[state_name] = StateDefinition(
            url=first.base_url + template_path,
            method=HttpMethod(first.method),
            default_data=_merged_body(occs),
            headers=_redact_headers(first.headers),
            description=(
                f"Imported from {len(occs)} captured request(s). "
                f"Review any '{{id}}' path placeholder before scanning."
            ),
        )

    return ApplicationSpec(
        name=name,
        base_url=_common_base_url(captures),
        states=states,
        transitions=_propose_transitions(captures),
        entry_states=[],
    )


# -- grouping / templating ------------------------------------------------------


def _templatize(path: str) -> str:
    segments = path.split("/")
    return "/".join(
        "{id}" if _NUMERIC_SEGMENT.match(seg) or _UUID_SEGMENT.match(seg) else seg
        for seg in segments
    )


def _state_name(item: CapturedRequest) -> str:
    slug = _templatize(item.path).strip("/").replace("/", "_").replace("{", "").replace("}", "")
    return f"{item.method}_{slug}" if slug else f"{item.method}_root"


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k: v for k, v in headers.items() if k.lower() not in _REDACTED_HEADERS}


def _merged_body(occurrences: list[CapturedRequest]) -> dict[str, Any]:
    for occ in occurrences:
        if occ.body:
            return occ.body
    return {}


def _common_base_url(items: list[CapturedRequest]) -> str:
    return Counter(item.base_url for item in items).most_common(1)[0][0]


# -- transition inference --------------------------------------------------------


def _session_key(item: CapturedRequest) -> str:
    cookie = item.headers.get("Cookie") or item.headers.get("cookie")
    if not cookie:
        return "no-session"
    for part in cookie.split(";"):
        name, sep, value = part.strip().partition("=")
        if sep and name.strip().lower() in _SESSION_COOKIE_NAMES:
            return value.strip()
    return cookie  # fall back to the full cookie string as the session identity


def _propose_transitions(items: list[CapturedRequest]) -> list[TransitionEdge]:
    """Infer legal edges from per-session request order. `items` must
    already be in chronological (observed) order.
    """
    sessions: dict[str, list[str]] = defaultdict(list)
    for item in items:
        if item.method not in HttpMethod.__members__:
            continue
        state_name = _state_name(item)
        ordered = sessions[_session_key(item)]
        if not ordered or ordered[-1] != state_name:  # collapse consecutive repeats (polling etc.)
            ordered.append(state_name)

    edges: set[tuple[str, str]] = set()
    for ordered_states in sessions.values():
        edges.update(zip(ordered_states, ordered_states[1:]))

    return [
        TransitionEdge(
            from_state=a,
            to_state=b,
            description="Inferred from observed per-session request order — review before trusting as intended business logic.",
        )
        for a, b in sorted(edges)
    ]
