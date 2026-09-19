import base64
import textwrap

from ghost.spec.importers.burp_proxy import import_burp_xml


def _b64(raw: str) -> str:
    return base64.b64encode(raw.replace("\n", "\r\n").encode()).decode()


def _item(url: str, method: str, path: str, cookie: str, body: str = "") -> str:
    request = f"{method} {path} HTTP/1.1\nHost: example.test\nCookie: {cookie}\nAuthorization: Bearer super-secret-token\nContent-Type: application/json\n\n{body}"
    return f"""
    <item>
      <url><![CDATA[{url}]]></url>
      <method><![CDATA[{method}]]></method>
      <request base64="true"><![CDATA[{_b64(request)}]]></request>
    </item>
    """


def _write_export(tmp_path, items: list[str]) -> str:
    xml = f"<items burpVersion=\"test\">{''.join(items)}</items>"
    path = tmp_path / "export.xml"
    path.write_text(xml)
    return str(path)


def test_groups_numeric_ids_into_path_template(tmp_path):
    items = [
        _item("https://example.test/orders/123", "GET", "/orders/123", "sess=aaa"),
        _item("https://example.test/orders/456", "GET", "/orders/456", "sess=bbb"),
    ]
    spec = import_burp_xml(_write_export(tmp_path, items))

    assert list(spec.states.keys()) == ["GET_orders_id"]
    assert spec.states["GET_orders_id"].url == "https://example.test/orders/{id}"


def test_redacts_auth_and_cookie_headers(tmp_path):
    items = [_item("https://example.test/orders/123", "GET", "/orders/123", "sess=aaa")]
    spec = import_burp_xml(_write_export(tmp_path, items))

    headers = spec.states["GET_orders_id"].headers
    assert "Authorization" not in headers
    assert "Cookie" not in headers


def test_proposes_transition_from_session_order(tmp_path):
    items = [
        _item("https://example.test/orders/123", "GET", "/orders/123", "sess=aaa"),
        _item("https://example.test/orders/123/confirm", "POST", "/orders/123/confirm", "sess=aaa", body="{}"),
    ]
    spec = import_burp_xml(_write_export(tmp_path, items))

    edges = {(e.from_state, e.to_state) for e in spec.transitions}
    assert ("GET_orders_id", "POST_orders_id_confirm") in edges
