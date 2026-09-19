"""
Ghost In The Machine
=====================

A stateful business-logic fuzzer for authorized security engagements.

Instead of blind input fuzzing, this tool models an application's
behavioral lifecycle as a directed graph of states and legal transitions,
then systematically attempts *illegal* transitions (state-skips,
step-reordering, privilege-boundary jumps) while carrying session
context and chained values forward — the same way a human pentester
manually tests "what happens if I hit step 5 without step 3."

For authorized use only. See docs/ethics.md.
"""

from ghost.core.engine import GhostEngine
from ghost.core.state_graph import StateGraph
from ghost.spec.schema import ApplicationSpec

__version__ = "2.0.0-dev"
__all__ = ["GhostEngine", "StateGraph", "ApplicationSpec"]
