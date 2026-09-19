"""
ghost.spec.importers.graphql
================================

Bootstraps a draft ApplicationSpec from a GraphQL API: either an SDL
schema document (`type Query { ... }` / `type Mutation { ... }`
blocks) or a standard introspection query result. Each query field and
each mutation becomes its own StateDefinition.

This looked, at first glance, like it would need a new
`StateDefinition` field (a GraphQL operation isn't a REST path/method
pair) — it doesn't. A GraphQL operation is just a POST to one fixed
endpoint with a `{"query": ..., "variables": {...}}` JSON body, and
`StateDefinition.default_data` is already a free-form JSON-body
container. So every generated state uses the existing `url` (the
single GraphQL endpoint, same for every state here), `method` (always
POST), and `default_data` (the query document + variables) fields
completely unchanged — no schema or engine change needed. Illegal-
transition/chaining machinery works on these states exactly like any
REST state: `render_template` already recurses into the `variables`
sub-dict, so `{{extracted_value}}` placeholders there work for free.

What this importer CANNOT infer (same gaps as the OpenAPI/Postman
importers):
  - `transitions`, `entry_states`
  - `auth_context` per state (defaults AUTHENTICATED; operator should
    tag admin-only mutations)
  - real argument values — SDL/introspection only gives argument
    *types*, so `variables` gets type-appropriate placeholders (empty
    string, 0, false, null) for the operator to fill in.

The SDL parser is a lightweight regex/brace-scanner, not a full GraphQL
grammar: it expects each field on its own line (`name(args): Type`),
which covers typical hand- or codegen-formatted schemas but not every
legal SDL layout (e.g. a field whose argument list wraps across
multiple lines). The introspection parser has no such limitation since
it's just JSON.
"""

from __future__ import annotations

import re
from typing import Any

from ghost.spec.schema import ApplicationSpec, HttpMethod, StateDefinition

_TYPE_BLOCK_RE = re.compile(r"type\s+(Query|Mutation)\s*\{")
_FIELD_RE = re.compile(r"^\s*(\w+)\s*(\(([^)]*)\))?\s*:\s*[\w\[\]!]+", re.MULTILINE)
_ARG_RE = re.compile(r"(\w+)\s*:\s*([\w\[\]!]+)")

_PLACEHOLDER_BY_SCALAR: dict[str, Any] = {"Int": 0, "Float": 0.0, "Boolean": False, "ID": "", "String": ""}


def import_graphql_sdl(sdl: str, endpoint: str) -> ApplicationSpec:
    """Parse `type Query`/`type Mutation` blocks out of a GraphQL SDL
    document. `endpoint` is the single URL every generated state POSTs
    to (GraphQL has one endpoint total, not one per operation).
    """
    states: dict[str, StateDefinition] = {}
    for match in _TYPE_BLOCK_RE.finditer(sdl):
        operation_kind = match.group(1)
        block = _extract_block(sdl, match.end() - 1)
        for field_match in _FIELD_RE.finditer(block):
            name, _, args_src = field_match.groups()
            states[name] = _state_for(endpoint, operation_kind, name, _parse_arg_types(args_src or ""))

    if not states:
        raise ValueError("No 'type Query' or 'type Mutation' block found in the given SDL")

    return _spec(endpoint, states)


def import_graphql_introspection(result: dict, endpoint: str) -> ApplicationSpec:
    """Parse a standard GraphQL introspection query result (the
    `{"data": {"__schema": {...}}}` response shape) into a draft spec.
    """
    schema = result.get("data", result).get("__schema", {})
    types_by_name = {t["name"]: t for t in schema.get("types", []) if t.get("name")}

    states: dict[str, StateDefinition] = {}
    for kind, type_ref in (("Query", schema.get("queryType")), ("Mutation", schema.get("mutationType"))):
        if not type_ref:
            continue
        type_def = types_by_name.get(type_ref.get("name"), {})
        for field in type_def.get("fields") or []:
            arg_types = {arg["name"]: _type_ref_to_str(arg["type"]) for arg in field.get("args", [])}
            states[field["name"]] = _state_for(endpoint, kind, field["name"], arg_types)

    return _spec(endpoint, states)


def _spec(endpoint: str, states: dict[str, StateDefinition]) -> ApplicationSpec:
    return ApplicationSpec(
        name="imported-graphql-spec", base_url=endpoint, states=states, transitions=[], entry_states=[]
    )


def _state_for(endpoint: str, operation_kind: str, field_name: str, arg_types: dict[str, str]) -> StateDefinition:
    keyword = "query" if operation_kind == "Query" else "mutation"
    query_doc, variables = _build_operation_doc(keyword, field_name, arg_types)
    return StateDefinition(
        url=endpoint,
        method=HttpMethod.POST,
        default_data={"query": query_doc, "variables": variables},
        description=f"Imported GraphQL {keyword} '{field_name}'.",
    )


def _build_operation_doc(keyword: str, field_name: str, arg_types: dict[str, str]) -> tuple[str, dict[str, Any]]:
    var_decls = ", ".join(f"${name}: {type_}" for name, type_ in arg_types.items())
    call_args = ", ".join(f"{name}: ${name}" for name in arg_types)
    header = f"{keyword} {field_name[0].upper()}{field_name[1:]}" + (f"({var_decls})" if var_decls else "")
    call = f"{field_name}({call_args})" if call_args else field_name
    variables = {name: _placeholder_for_type(type_) for name, type_ in arg_types.items()}
    return f"{header} {{ {call} }}", variables


def _parse_arg_types(args_src: str) -> dict[str, str]:
    return dict(_ARG_RE.findall(args_src))


def _type_ref_to_str(type_ref: dict) -> str:
    kind = type_ref.get("kind")
    if kind == "NON_NULL":
        return _type_ref_to_str(type_ref["ofType"]) + "!"
    if kind == "LIST":
        return f"[{_type_ref_to_str(type_ref['ofType'])}]"
    return type_ref.get("name") or "String"


def _placeholder_for_type(type_str: str) -> Any:
    return _PLACEHOLDER_BY_SCALAR.get(type_str.strip("[]!"))  # None for object/enum types — operator fills in


def _extract_block(text: str, brace_start: int) -> str:
    depth = 0
    for i in range(brace_start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[brace_start + 1 : i]
    return text[brace_start + 1 :]
