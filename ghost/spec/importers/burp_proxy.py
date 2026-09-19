"""
ghost.spec.importers.burp_proxy
==================================

Bootstraps a draft ApplicationSpec from a recorded proxy history
(Burp Suite XML export or a ZAP session export), which is often a
better source than OpenAPI for apps whose business logic lives in
multi-step web flows without a formal API schema.

This module only does the Burp-XML-specific part: decoding each
<item>'s base64 raw HTTP request into a `CapturedRequest`. Grouping
those into states, path-templating, credential redaction, and
session-order-based transition inference are shared with the
`ghost record` live-capture path — see
ghost.spec.importers.traffic_capture.build_spec_from_captures.
"""

from __future__ import annotations

import base64
import json
from typing import Any
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET

from ghost.spec.importers.traffic_capture import CapturedRequest, build_spec_from_captures
from ghost.spec.schema import ApplicationSpec


def import_burp_xml(xml_path: str) -> ApplicationSpec:
    """Parse a Burp Suite 'Save items' XML export into a draft spec.

    Groups captured requests into states by (method, normalized path
    template), redacts Authorization/Cookie headers, and proposes a
    draft `transitions` list from the observed per-session request
    order (items are read in the file's original, chronological order).
    """
    root = ET.parse(xml_path).getroot()
    captures = [parsed for el in root.findall("item") if (parsed := _parse_item(el)) is not None]
    if not captures:
        raise ValueError(f"No usable <item> entries found in Burp export: {xml_path}")

    return build_spec_from_captures(captures, name="imported-burp-spec")


def import_zap_session(session_path: str) -> ApplicationSpec:
    """Parse a ZAP session export into a draft spec. Not yet implemented."""
    raise NotImplementedError("ZAP session import is a planned v2 feature.")


# -- parsing ------------------------------------------------------------------


def _parse_item(item_el: ET.Element) -> CapturedRequest | None:
    url_el = item_el.find("url")
    request_el = item_el.find("request")
    if url_el is None or url_el.text is None or request_el is None:
        return None

    parsed_url = urlsplit(url_el.text.strip())
    method_el = item_el.find("method")
    method = (method_el.text or "GET").strip().upper() if method_el is not None else "GET"
    headers, body = _split_request(_decode_maybe_b64(request_el))

    return CapturedRequest(
        base_url=f"{parsed_url.scheme}://{parsed_url.netloc}",
        path=parsed_url.path or "/",
        method=method,
        headers=headers,
        body=body,
    )


def _decode_maybe_b64(el: ET.Element) -> str:
    text = el.text or ""
    if el.get("base64") == "true":
        try:
            return base64.b64decode(text).decode("utf-8", errors="replace")
        except (ValueError, UnicodeDecodeError):
            return ""
    return text


def _split_request(raw: str) -> tuple[dict[str, str], dict[str, Any]]:
    """Split a raw HTTP request into (headers, json body)."""
    if not raw:
        return {}, {}
    normalized = raw.replace("\r\n", "\n")
    head, _, body_text = normalized.partition("\n\n")

    headers: dict[str, str] = {}
    for line in head.splitlines()[1:]:
        name, sep, value = line.partition(":")
        if sep:
            headers[name.strip()] = value.strip()

    body: dict[str, Any] = {}
    body_text = body_text.strip()
    if body_text:
        try:
            parsed = json.loads(body_text)
            if isinstance(parsed, dict):
                body = parsed
        except ValueError:
            pass  # non-JSON body (form-encoded, etc.) — leave default_data empty for human review

    return headers, body
