"""
ghost.spec.importers.openapi
==============================

Bootstraps a draft ApplicationSpec from an OpenAPI 3.x / Swagger 2.x
document: each operation (path + method) becomes a StateDefinition,
named from its `operationId` (falling back to `METHOD_/path/slug`).

What this importer CANNOT infer, and leaves for the operator to fill in:
  - `transitions` (the legal business-flow ordering between states)
  - `entry_states`
  - `auth_context` per state (defaults everything to AUTHENTICATED;
    operator should tag ADMIN-only endpoints)
  - `extract` / value-chaining rules between steps
"""

from __future__ import annotations

from ghost.spec.schema import ApplicationSpec, HttpMethod, StateDefinition


def import_openapi(doc: dict, base_url: str | None = None) -> ApplicationSpec:
    """
    Parameters
    ----------
    doc : dict
        A parsed OpenAPI/Swagger document (e.g. via `json.load` or
        `yaml.safe_load` on the spec file — parsing untrusted specs
        should go through a standard OpenAPI validator upstream).
    base_url : str, optional
        Overrides the `servers[0].url` in the doc, if present.

    Returns
    -------
    ApplicationSpec
        A draft spec with `states` populated and `transitions` empty.
    """
    resolved_base = base_url or (doc.get("servers", [{}])[0].get("url", ""))
    states: dict[str, StateDefinition] = {}

    for path, path_item in doc.get("paths", {}).items():
        for method_str, operation in path_item.items():
            if method_str.upper() not in HttpMethod.__members__:
                continue  # skip non-HTTP-method keys like "parameters"

            state_name = operation.get("operationId") or _slugify(method_str, path)
            states[state_name] = StateDefinition(
                url=resolved_base.rstrip("/") + path,
                method=HttpMethod(method_str.upper()),
                default_data=_example_body(operation),
                description=operation.get("summary"),
            )

    return ApplicationSpec(
        name=doc.get("info", {}).get("title", "imported-openapi-spec"),
        base_url=resolved_base,
        states=states,
        transitions=[],
        entry_states=[],
    )


def _slugify(method: str, path: str) -> str:
    return f"{method.upper()}_{path.strip('/').replace('/', '_').replace('{', '').replace('}', '')}"


def _example_body(operation: dict) -> dict:
    """Best-effort pull of an example request body from the operation,
    if the spec author provided one. Returns {} otherwise — operators
    should fill in realistic default_data for meaningful fuzzing.
    """
    try:
        content = operation["requestBody"]["content"]["application/json"]
        return content.get("example") or next(iter(content.get("examples", {}).values()), {}).get("value", {})
    except (KeyError, StopIteration):
        return {}
