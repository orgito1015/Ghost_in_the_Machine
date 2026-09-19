"""
ghost.detection.mass_assignment
==================================

Checks whether extra fields injected into an otherwise-legal request
(mass-assignment / parameter-pollution probing) got bound and reflected
back by the target — the classic "the API model has an `is_admin`
column and the framework happily binds whatever the client sends" bug
class, distinct from anything the state-graph or timing/shape
detection layers catch (those only ever send a state's *declared*
`default_data`; nothing here previously sent fields a state never
listed).

Kept separate from the injection call site
(ghost.core.engine.probe_mass_assignment) so the "did this come back"
check and the default candidate-field list can be reused or tuned
independently of how the probe request itself gets built.
"""

from __future__ import annotations

from typing import Any

DEFAULT_CANDIDATE_FIELDS: tuple[str, ...] = (
    "is_admin",
    "isAdmin",
    "admin",
    "role",
    "roles",
    "is_staff",
    "privilege",
    "permissions",
    "price",
    "amount",
    "balance",
    "discount",
    "user_id",
    "owner_id",
    "account_id",
)


def reflected_fields(injected: dict[str, Any], response_body: dict[str, Any]) -> dict[str, Any]:
    """Return the subset of `injected` fields whose value comes back
    unchanged in `response_body` — evidence the server bound and
    accepted a field the client should never control directly.
    """
    return {k: v for k, v in injected.items() if k in response_body and response_body[k] == v}
