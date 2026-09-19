from types import SimpleNamespace

from ghost.spec.importers.record import _CaptureAddon, _json_body, build_spec_from_recording
from ghost.spec.importers.traffic_capture import CapturedRequest


def _fake_flow(method="GET", host="api.example.test", port=443, scheme="https", path="/orders/123", content=None, headers=None):
    request = SimpleNamespace(
        method=method, host=host, port=port, scheme=scheme, path=path,
        content=content, headers=headers or {},
    )
    return SimpleNamespace(request=request)


def test_json_body_parses_dict_and_ignores_non_json():
    assert _json_body(b'{"a": 1}') == {"a": 1}
    assert _json_body(b"not json") == {}
    assert _json_body(None) == {}
    assert _json_body(b"[1, 2]") == {}  # top-level list, not a dict body


def test_capture_addon_records_response_as_captured_request():
    addon = _CaptureAddon()
    addon.response(_fake_flow(content=b'{"item_id": 1}', headers={"Cookie": "sid=abc"}))

    assert len(addon.captures) == 1
    captured = addon.captures[0]
    assert captured.base_url == "https://api.example.test"  # standard port omitted
    assert captured.path == "/orders/123"
    assert captured.method == "GET"
    assert captured.body == {"item_id": 1}
    assert captured.headers["Cookie"] == "sid=abc"


def test_capture_addon_includes_nonstandard_port():
    addon = _CaptureAddon()
    addon.response(_fake_flow(port=8443))
    assert addon.captures[0].base_url == "https://api.example.test:8443"


def test_capture_addon_strips_query_string_from_path():
    addon = _CaptureAddon()
    addon.response(_fake_flow(path="/search?q=x"))
    assert addon.captures[0].path == "/search"


def test_build_spec_from_recording_delegates_to_shared_builder():
    captures = [CapturedRequest(base_url="https://x.test", path="/orders/123", method="GET")]
    spec = build_spec_from_recording(captures, name="my-recording")
    assert spec.name == "my-recording"
    assert spec.states["GET_orders_id"].url == "https://x.test/orders/{id}"
