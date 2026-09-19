"""
ghost.core.session
=====================

v1 captured `set-cookie` after a request but never re-applied it on
later requests, so every "illegal transition" attempt was effectively
unauthenticated — useless for testing the exact case that matters most
("can a logged-in low-priv user skip to an admin action?").

SessionContext fixes that: it's the single source of truth for
cookies/headers/tokens for one simulated actor, threaded through every
request the engine makes for that actor.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

import httpx


@dataclass
class SessionContext:
    """Represents one simulated actor's authentication state.

    Multiple SessionContexts let the engine simulate cross-role attacks
    directly, e.g. "take user A's session, attempt an illegal transition
    into a state scoped to user B's resources."
    """

    label: str = "default"
    cookies: httpx.Cookies = field(default_factory=httpx.Cookies)
    headers: dict[str, str] = field(default_factory=dict)
    extracted: dict[str, str] = field(default_factory=dict)  # values pulled via ExtractionRule
    token_refresh: Callable[[], str] | None = field(default=None, repr=False, compare=False)
    """Optional hook for bearer-token auth: called on a 401 during a
    legitimate step to get a fresh token, for long scans where the
    actor's token expires mid-run — cookie rotation is handled for
    free by absorb_response, but a bearer token has no such signal
    short of the caller telling us how to mint a new one.
    """

    def absorb_response(self, response: httpx.Response) -> None:
        """Update stored cookies from a response's Set-Cookie headers."""
        self.cookies.extract_cookies(response)

    def apply_to_client(self, client: httpx.Client) -> None:
        """Sync this context's cookies onto the shared httpx client
        before firing a request under this actor's identity.
        """
        client.cookies = self.cookies

    def request_headers(self) -> dict[str, str]:
        return dict(self.headers)

    def refresh_token(self) -> bool:
        """Call the configured `token_refresh` hook and update this
        session's Authorization header. Returns False (no-op) if no
        hook is configured.
        """
        if self.token_refresh is None:
            return False
        self.headers["Authorization"] = f"Bearer {self.token_refresh()}"
        return True


class SessionPool:
    """Holds named SessionContexts (e.g. "low_priv_user", "admin_user",
    "anonymous") so the engine can test transitions both within one
    actor's session and across actors.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, SessionContext] = {}

    def get_or_create(self, label: str) -> SessionContext:
        if label not in self._sessions:
            self._sessions[label] = SessionContext(label=label)
        return self._sessions[label]

    def __getitem__(self, label: str) -> SessionContext:
        return self._sessions[label]

    def labels(self) -> list[str]:
        return list(self._sessions.keys())
