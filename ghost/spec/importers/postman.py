"""
ghost.spec.importers.postman
===============================

Bootstraps a draft ApplicationSpec from a Postman collection (v2.x),
following the same pattern as `openapi.py`: each request becomes a
StateDefinition, named from the request's Postman item name (falling
back to `METHOD_/path/slug`).

What this importer CANNOT infer, and leaves for the operator to fill in
(same gaps as the OpenAPI importer):
  - `transitions` (the legal business-flow ordering between states)
  - `entry_states`
  - `auth_context` per state (defaults everything to AUTHENTICATED;
    operator should tag ADMIN-only endpoints)
  - `extract` / value-chaining rules between steps

Authorization/Cookie headers are stripped on import for the same
reason as the Burp importer: live credentials belong in
ghost.core.session, not baked into a spec file.
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterator
from urllib.parse import urlsplit

from ghost.spec.schema import ApplicationSpec, HttpMethod, StateDefinition

_REDACTED_HEADERS = {"authorization", "cookie"}
_VAR_RE = re.compile(r"\{\{(\w+)\}\}")


def import_postman(doc: dict, base_url: str | None = None) -> ApplicationSpec:
    """
    Parameters
    ----------
    doc : dict
        A parsed Postman collection (v2.x) document.
    base_url : str, optional
        Overrides the collection's `base_url`/`baseUrl` variable, if present.

    Returns
    -------
    ApplicationSpec
        A draft spec with `states` populated and `transitions` empty.
    """
    variables = _collection_variables(doc)
    fallback_base = base_url or variables.get("base_url") or variables.get("baseUrl") or ""

    states: dict[str, StateDefinition] = {}
    for name, request in _iter_requests(doc.get("item", [])):
        method_str = str(request.get("method", "GET")).upper()
        if method_str not in HttpMethod.__members__:
            continue

        raw_url = _resolve_vars(_url_raw(request.get("url")), variables)
        req_base, path = _split_url(raw_url)
        resolved_base = req_base or fallback_base
        template_path = _templatize_path(path)

        default_name = f"{method_str}_{template_path.strip('/').replace('/', '_')}" or method_str
        state_name = _unique_name(states, _slugify(name) or default_name)
        states[state_name] = StateDefinition(
            url=(resolved_base.rstrip("/") + template_path) if resolved_base else template_path,
            method=HttpMethod(method_str),
            default_data=_example_body(request, variables),
            headers=_non_auth_headers(request.get("header", [])),
            description=name or None,
        )

    return ApplicationSpec(
        name=doc.get("info", {}).get("name", "imported-postman-spec"),
        base_url=fallback_base,
        states=states,
        transitions=[],
        entry_states=[],
    )


def _iter_requests(items: list[dict]) -> Iterator[tuple[str, dict]]:
    """Walk a Postman item tree (folders nest arbitrarily), yielding
    (name, request) for each leaf request item.
    """
    for item in items:
        if "item" in item:
            yield from _iter_requests(item["item"])
        elif "request" in item:
            yield item.get("name", ""), item["request"]


def _collection_variables(doc: dict) -> dict[str, str]:
    return {v["key"]: v.get("value", "") for v in doc.get("variable", []) if v.get("key")}


def _resolve_vars(text: str, variables: dict[str, str]) -> str:
    if not text:
        return text
    return _VAR_RE.sub(lambda m: variables.get(m.group(1), m.group(0)), text)


def _url_raw(url: Any) -> str:
    if isinstance(url, str):
        return url
    if isinstance(url, dict):
        return url.get("raw", "")
    return ""


def _split_url(raw_url: str) -> tuple[str, str]:
    parsed = urlsplit(raw_url)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}", parsed.path or "/"
    return "", raw_url  # unresolved {{var}} prefix — best effort, needs human review


def _templatize_path(path: str) -> str:
    """Postman's `:paramName` path-variable convention -> `{paramName}`,
    to match the bracket style used elsewhere in imported specs.
    """
    return "/".join(
        f"{{{seg[1:]}}}" if seg.startswith(":") and len(seg) > 1 else seg for seg in path.split("/")
    )


def _slugify(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", name.strip()).strip("_").upper()


def _unique_name(existing: dict, base: str) -> str:
    if base not in existing:
        return base
    n = 2
    while f"{base}_{n}" in existing:
        n += 1
    return f"{base}_{n}"


def _non_auth_headers(headers: list[dict]) -> dict[str, str]:
    return {
        h["key"]: h.get("value", "")
        for h in headers or []
        if not h.get("disabled") and h.get("key", "").strip().lower() not in _REDACTED_HEADERS
    }


def _example_body(request: dict, variables: dict[str, str]) -> dict:
    """Best-effort pull of a request body from the Postman item, mirroring
    the openapi importer's `_example_body`. Returns {} if absent/unparseable.
    """
    body = request.get("body") or {}
    mode = body.get("mode")

    if mode == "raw":
        raw = _resolve_vars(body.get("raw", ""), variables).strip()
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except ValueError:
            return {}

    if mode in ("urlencoded", "formdata"):
        return {item["key"]: item.get("value", "") for item in body.get(mode, []) if not item.get("disabled")}

    return {}
