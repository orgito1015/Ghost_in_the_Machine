import httpx
import pytest

from ghost.core.http import request_with_retry


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_retries_transient_transport_error_then_succeeds(monkeypatch):
    monkeypatch.setattr("ghost.core.http.time.sleep", lambda _: None)
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            raise httpx.ConnectError("boom", request=request)
        return httpx.Response(200, json={"ok": True})

    with _client(handler) as client:
        response = request_with_retry(client, "GET", "https://example.test/x", max_retries=3)

    assert response.status_code == 200
    assert calls["n"] == 3


def test_gives_up_after_max_retries_on_transport_error(monkeypatch):
    monkeypatch.setattr("ghost.core.http.time.sleep", lambda _: None)

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    with _client(handler) as client, pytest.raises(httpx.ConnectError):
        request_with_retry(client, "GET", "https://example.test/x", max_retries=2)


def test_backs_off_and_retries_429_honoring_retry_after(monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr("ghost.core.http.time.sleep", sleeps.append)
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "2"})
        return httpx.Response(200)

    with _client(handler) as client:
        response = request_with_retry(client, "GET", "https://example.test/x", max_retries=3)

    assert response.status_code == 200
    assert sleeps == [2.0]


def test_non_429_error_response_is_returned_without_retry():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(403)

    with _client(handler) as client:
        response = request_with_retry(client, "GET", "https://example.test/x", max_retries=3)

    assert response.status_code == 403
    assert calls["n"] == 1
