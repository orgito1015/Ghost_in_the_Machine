import httpx

from ghost.core.session import SessionContext, SessionPool


def test_cookie_absorbed_and_replayed_on_next_request():
    received = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            return httpx.Response(200, headers={"Set-Cookie": "sid=abc123; Path=/"})
        received["cookie"] = request.headers.get("Cookie")
        return httpx.Response(200)

    session = SessionContext()
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        session.apply_to_client(client)
        login_response = client.request("GET", "https://example.test/login")
        session.absorb_response(login_response)

        session.apply_to_client(client)
        client.request("GET", "https://example.test/next")

    assert received["cookie"] == "sid=abc123"


def test_apply_to_client_syncs_cookies_across_a_different_client_instance():
    session = SessionContext()
    session.cookies.set("sid", "xyz")

    other_client = httpx.Client()
    session.apply_to_client(other_client)

    assert other_client.cookies.get("sid") == "xyz"
    other_client.close()


def test_request_headers_returns_a_copy_not_a_live_reference():
    session = SessionContext(headers={"X-Actor": "low_priv"})
    headers = session.request_headers()
    headers["X-Actor"] = "mutated"
    assert session.headers["X-Actor"] == "low_priv"


def test_refresh_token_updates_authorization_header():
    session = SessionContext(token_refresh=lambda: "new-token-123")
    assert session.refresh_token() is True
    assert session.headers["Authorization"] == "Bearer new-token-123"


def test_refresh_token_is_noop_without_hook():
    session = SessionContext()
    assert session.refresh_token() is False
    assert "Authorization" not in session.headers


def test_session_pool_reuses_context_per_label():
    pool = SessionPool()
    a1 = pool.get_or_create("admin")
    a2 = pool.get_or_create("admin")
    low = pool.get_or_create("low_priv")

    assert a1 is a2
    assert a1 is not low
    assert sorted(pool.labels()) == ["admin", "low_priv"]
