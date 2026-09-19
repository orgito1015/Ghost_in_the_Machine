import httpx
import pytest

from ghost.core.chaining import extract_values, render_template
from ghost.spec.schema import ExtractionRule


def _response(body: dict) -> httpx.Response:
    return httpx.Response(200, json=body, request=httpx.Request("GET", "https://example.test/x"))


def test_extract_values_success():
    rules = [ExtractionRule(json_path="$.data.order_id", store_as="order_id")]
    extracted = extract_values(_response({"data": {"order_id": 42}}), rules)
    assert extracted == {"order_id": "42"}


def test_extract_values_optional_miss_is_silently_skipped():
    rules = [ExtractionRule(json_path="$.data.missing", store_as="x", required=False)]
    assert extract_values(_response({"data": {}}), rules) == {}


def test_extract_values_required_miss_raises_and_aborts_chain():
    rules = [ExtractionRule(json_path="$.data.missing", store_as="x", required=True)]
    with pytest.raises(ValueError, match="Required extraction failed"):
        extract_values(_response({"data": {}}), rules)


def test_extract_values_non_json_body_treated_as_empty():
    response = httpx.Response(200, text="not json", request=httpx.Request("GET", "https://example.test/x"))
    rules = [ExtractionRule(json_path="$.x", store_as="x", required=False)]
    assert extract_values(response, rules) == {}


def test_render_template_substitutes_nested_dict_and_list():
    context = {"cart_id": "cart-1", "uid": "u-9"}
    value = {
        "order": {"cart": "{{cart_id}}", "owner": "{{uid}}"},
        "tags": ["static", "{{cart_id}}"],
        "count": 3,
        "flag": None,
    }
    rendered = render_template(value, context)
    assert rendered == {
        "order": {"cart": "cart-1", "owner": "u-9"},
        "tags": ["static", "cart-1"],
        "count": 3,
        "flag": None,
    }


def test_render_template_missing_key_raises():
    with pytest.raises(KeyError):
        render_template("{{unset_value}}", {})
