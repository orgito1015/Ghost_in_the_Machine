"""
ghost.spec.loader
===================

Loads an ApplicationSpec from disk (JSON or YAML) and validates it.
"""

from __future__ import annotations

import json
from pathlib import Path

from ghost.spec.schema import ApplicationSpec


def load_spec(path: str | Path) -> ApplicationSpec:
    """Load and validate a spec file. Supports .json and .yaml/.yml."""
    path = Path(path)
    raw = path.read_text()

    if path.suffix in (".yaml", ".yml"):
        import yaml  # local import: optional dependency, only needed for YAML specs

        data = yaml.safe_load(raw)
    else:
        data = json.loads(raw)

    return ApplicationSpec.model_validate(data)


def save_spec(spec: ApplicationSpec, path: str | Path) -> None:
    """Serialize a spec back to JSON, e.g. after generating one from an importer."""
    path = Path(path)
    path.write_text(spec.model_dump_json(indent=2))
