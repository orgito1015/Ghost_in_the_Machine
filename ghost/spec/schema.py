"""
ghost.spec.schema
==================

Declarative schema for describing an application's behavioral state
machine: states (endpoints/steps), legal transitions between them, and
rules for extracting values from one response and chaining them into a
later request (e.g. carrying an `order_id` from ADD_TO_CART into
CONFIRM_ORDER).

This replaces v1's flat, hand-written JSON with a validated model that
can also be *produced* by the importers in ghost.spec.importers
(OpenAPI, Burp/ZAP proxy logs, Postman collections) instead of only
being hand-authored.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, model_validator


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


class AuthContext(str, Enum):
    """Which privilege level a state is expected to require.

    Used by StateGraph to flag a specific, high-value class of illegal
    transition: a low-priv session reaching a state tagged ADMIN.
    """

    ANONYMOUS = "anonymous"
    AUTHENTICATED = "authenticated"
    ADMIN = "admin"


class ExtractionRule(BaseModel):
    """A rule for pulling a value out of a state's response and
    stashing it in the engine's context bag under `store_as`, so a
    later state's `default_data` or `path_params` can reference it via
    `{{store_as}}` templating.
    """

    json_path: str = Field(..., description="JSONPath into the response body, e.g. '$.data.order_id'")
    store_as: str = Field(..., description="Key to store the extracted value under in engine context")
    required: bool = Field(default=False, description="If true, abort the step chain when extraction fails")


class StateDefinition(BaseModel):
    """One node in the application's behavioral graph — typically one
    API endpoint or one meaningful step in a multi-step flow.
    """

    url: str
    method: HttpMethod
    default_data: dict = Field(default_factory=dict)
    path_params: dict = Field(default_factory=dict, description="Templated path segments, e.g. {'user_id': '{{uid}}'}")
    headers: dict = Field(default_factory=dict)
    auth_context: AuthContext = AuthContext.AUTHENTICATED
    extract: list[ExtractionRule] = Field(default_factory=list)
    description: Optional[str] = None
    idempotency_expected: bool = Field(
        default=False,
        description="If true, this state is a single-use action (redeem, purchase, transfer) that "
        "should succeed at most once under concurrent identical requests. Enables automatic "
        "race-condition probing for this state during GhostEngine.scan() — see detection/race.py.",
    )
    destructive: bool = Field(
        default=False,
        description="If true, this state performs a real write with hard-to-reverse effects "
        "(refund, deletion, privilege grant). GhostEngine will not fire a request at it from any "
        "probe (illegal transition/sequence, race, replay, mass-assignment) unless the operator "
        "passes --i-know-what-im-doing. See docs/ethics.md.",
    )


class TransitionEdge(BaseModel):
    """A single legal edge in the state graph: `from_state` may be
    legitimately followed by `to_state`. Everything NOT declared here
    is a candidate illegal transition (see StateGraph.illegal_edges).
    """

    from_state: str
    to_state: str
    description: Optional[str] = None


class ApplicationSpec(BaseModel):
    """Top-level spec: the full behavioral map of a target application."""

    name: str
    base_url: str
    states: dict[str, StateDefinition]
    transitions: list[TransitionEdge] = Field(default_factory=list)
    entry_states: list[str] = Field(default_factory=list, description="Valid starting points for a session")

    @model_validator(mode="after")
    def _validate_references(self) -> "ApplicationSpec":
        state_names = set(self.states.keys())
        for edge in self.transitions:
            if edge.from_state not in state_names:
                raise ValueError(f"transition references unknown state: {edge.from_state}")
            if edge.to_state not in state_names:
                raise ValueError(f"transition references unknown state: {edge.to_state}")
        for entry in self.entry_states:
            if entry not in state_names:
                raise ValueError(f"entry_state references unknown state: {entry}")
        return self
