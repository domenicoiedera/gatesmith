"""Registry I/O shared by the gates.

One rule, applied everywhere: a registry file that is absent or empty means
"nothing declared yet" and the caller's default is used. A registry that
EXISTS but cannot be parsed is a broken instrument — it must never be read as
an empty, clear result — so it raises.

That asymmetry is the point. The dangerous failure of a gate is going quiet,
not going loud: a truncated registry that reads as "no rules" is how a guard
fails open.
"""

import json
import os


class RegistryError(Exception):
    """A registry file exists but cannot be read as a JSON object."""


def load_json(path, default):
    """Parse ``path``; return ``default`` when absent or empty.

    Unparseable content — or content that is valid JSON but not a JSON object
    — raises :class:`RegistryError` instead of silently degrading to
    ``default`` (or handing a non-mapping back for the caller to crash on).
    A registry is a mapping by contract; see the module docstring.
    """
    if not path or not os.path.exists(path) or os.path.getsize(path) == 0:
        return default
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError, ValueError) as exc:
        raise RegistryError(f"{path}: {exc}") from exc
    if not isinstance(data, dict):
        raise RegistryError(
            f"{path}: registry root must be a JSON object, got {type(data).__name__}")
    return data


def save_json(path, payload):
    """Write ``payload`` as indented JSON, creating parent directories."""
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")
