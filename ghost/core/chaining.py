"""
ghost.core.chaining
======================

Handles extracting values from one state's response (per its
ExtractionRule list) and substituting them into a later state's
`default_data` / `path_params` via `{{store_as}}` templating.

This is what lets the fuzzer express real business-logic attacks like:
  1. ADD_TO_CART -> extract cart_id
  2. Illegally jump straight to CONFIRM_ORDER using that cart_id,
     skipping APPLY_COUPON / ADDRESS_VERIFY / PAYMENT_AUTH in between.

v1 had no mechanism for this at all — `default_data` was static, so
any state requiring a prior-step ID simply couldn't be reached.
"""

from __future__ import annotations

import re
from typing import Any

import httpx
from jsonpath_ng import parse as jsonpath_parse

from ghost.spec.schema import ExtractionRule

_TEMPLATE_RE = re.compile(r"\{\{(\w+)\}\}")


def extract_values(response: httpx.Response, rules: list[ExtractionRule]) -> dict[str, str]:
    """Run each ExtractionRule's JSONPath against the response body.

    Raises ValueError if a `required=True` rule finds no match — callers
    should treat that as "this chain can't proceed," not a soft warning.
    """
    extracted: dict[str, str] = {}
    try:
        body = response.json()
    except ValueError:
        body = {}

    for rule in rules:
        matches = jsonpath_parse(rule.json_path).find(body)
        if not matches:
            if rule.required:
                raise ValueError(
                    f"Required extraction failed: '{rule.json_path}' had no match "
                    f"in response from {response.request.url}"
                )
            continue
        extracted[rule.store_as] = str(matches[0].value)

    return extracted


def render_template(value: Any, context: dict[str, str]) -> Any:
    """Recursively substitute `{{key}}` placeholders in strings, dict
    values, and list items using the given context. Non-string leaves
    (ints, bools, None) pass through unchanged.
    """
    if isinstance(value, str):
        def _sub(match: re.Match) -> str:
            key = match.group(1)
            if key not in context:
                raise KeyError(f"Template references unset value: '{{{{{key}}}}}'")
            return context[key]

        return _TEMPLATE_RE.sub(_sub, value)

    if isinstance(value, dict):
        return {k: render_template(v, context) for k, v in value.items()}

    if isinstance(value, list):
        return [render_template(v, context) for v in value]

    return value
