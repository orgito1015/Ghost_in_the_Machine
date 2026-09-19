"""
ghost.spec.importers.record
==============================

`ghost record`'s live-capture path: run a local MITM proxy, let the
operator manually walk a legal flow through it once (pointing a
browser or API client at `127.0.0.1:PORT`), then convert whatever got
captured into a draft spec using the same grouping/path-templating/
credential-redaction/transition-inference logic `burp_proxy.py` uses
(see ghost.spec.importers.traffic_capture) — a live capture is
functionally the same input shape as a Burp export, just gathered
in-process instead of imported after the fact from a separate tool.

mitmproxy is an OPTIONAL dependency (`pip install -e ".[record]"`),
imported lazily inside `run_recording_proxy` rather than at module
level: hand-rolling a correct TLS-intercepting proxy (per-host
certificate generation, HTTP CONNECT tunneling) is real
security-sensitive code that's easy to get subtly wrong, and mitmproxy
is the standard, actively-maintained tool for exactly that job.
Nothing else in this package needs it, so it isn't a core dependency
and its absence shouldn't break `import ghost`.
"""

from __future__ import annotations

import json
from typing import Any

from ghost.spec.importers.traffic_capture import CapturedRequest, build_spec_from_captures
from ghost.spec.schema import ApplicationSpec


class _CaptureAddon:
    """mitmproxy addon: records one CapturedRequest per completed
    request/response pair, in the order they complete (mitmproxy's own
    `response` hook fires once the full exchange is done), which is
    exactly the chronological ordering `build_spec_from_captures`'
    transition inference needs.
    """

    def __init__(self) -> None:
        self.captures: list[CapturedRequest] = []

    def response(self, flow: Any) -> None:
        request = flow.request
        port_suffix = "" if request.port in (80, 443) else f":{request.port}"
        self.captures.append(
            CapturedRequest(
                base_url=f"{request.scheme}://{request.host}{port_suffix}",
                path=request.path.split("?", 1)[0],
                method=request.method.upper(),
                headers=dict(request.headers),
                body=_json_body(request.content),
            )
        )


def _json_body(content: bytes | None) -> dict[str, Any]:
    if not content:
        return {}
    try:
        parsed = json.loads(content)
    except ValueError:
        return {}  # non-JSON body (form-encoded, etc.) — leave default_data empty for human review
    return parsed if isinstance(parsed, dict) else {}


def run_recording_proxy(port: int) -> list[CapturedRequest]:
    """Blocking call: starts a mitmproxy instance listening on `port`
    and runs until the operator interrupts it (Ctrl+C), returning
    everything it captured. Raises ImportError with an install hint if
    mitmproxy isn't installed.

    NOTE: this talks to mitmproxy's real (asyncio-based) master/addon
    API, verified against mitmproxy 12.x during development, but
    hasn't been exercised end-to-end against a live proxied client in
    this environment — treat the proxy lifecycle handling here as
    best-effort and sanity-check it against whatever mitmproxy version
    you install before relying on it for an engagement.
    """
    try:
        import asyncio

        from mitmproxy import options
        from mitmproxy.tools.dump import DumpMaster
    except ImportError as exc:
        raise ImportError(
            "`ghost record` needs mitmproxy: pip install -e '.[record]' (or `pip install mitmproxy`)."
        ) from exc

    addon = _CaptureAddon()
    opts = options.Options(listen_port=port)
    master = DumpMaster(opts, with_termlog=False, with_dumper=False)
    master.addons.add(addon)

    try:
        asyncio.run(master.run())
    except KeyboardInterrupt:
        master.shutdown()

    return addon.captures


def build_spec_from_recording(captures: list[CapturedRequest], name: str = "recorded-spec") -> ApplicationSpec:
    return build_spec_from_captures(captures, name=name)
