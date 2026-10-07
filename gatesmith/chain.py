"""The review registry hash chain.

Every review entry is part of a tamper-evident chain. Each entry carries a
0-based ``seq`` and the hash of its predecessor (``prev_hash``), and the hash
of the chain's head is what the detached signature seals. Editing an entry's
content without also rewriting every hash downstream is detectable, and — once
the chain head is sealed — rewriting the chain is detectable too.

Pinned definitions (these are load-bearing; do not "simplify" them):

* **Canonical entry form** — the bytes that are hashed — is
  ``json.dumps(entry, sort_keys=True, separators=(",", ":"))`` with the keys
  ``seq`` and ``prev_hash`` removed, encoded UTF-8.
* **Genesis** — ``prev_hash`` of entry 0 is 64 hex zeros; ``seq`` is 0-based.
* **Chain head** — the hash of the last canonical entry.
* **head_hash** — ``sha256`` over the newline-joined per-entry hashes. This is
  the value the seal signs.
* **Root marker** — the registry root carries ``{"gatesmith_registry":
  {"v": 2}}``. A registry with a marker but an entry missing ``seq``/
  ``prev_hash`` is a broken chain, never "legacy". A registry with no marker at
  all predates the chain and must be upgraded explicitly.

Nothing here touches :mod:`gatesmith.store`; the chain is scoped to the review
registry only, so the other gates keep the plain JSON semantics they had.
"""

import hashlib
import json

from .store import RegistryError

GENESIS = "0" * 64
MARKER_KEY = "gatesmith_registry"
CHAIN_VERSION = 2


class LegacyRegistryError(RegistryError):
    """A registry that predates the chain, or carries an unknown marker."""


class ChainStructureError(RegistryError):
    """A chained registry whose structure is malformed (missing chain fields)."""


class ChainBrokenError(RegistryError):
    """A chained registry whose recorded hashes do not link up."""


def canonical_bytes(entry):
    """The exact bytes hashed for ``entry`` — ``seq``/``prev_hash`` removed."""
    body = {k: v for k, v in entry.items() if k not in ("seq", "prev_hash")}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def entry_hash(entry):
    """``sha256`` hex of an entry's canonical form."""
    return hashlib.sha256(canonical_bytes(entry)).hexdigest()


def head_hash(entries):
    """``sha256`` over the newline-joined per-entry hashes — the sealed value."""
    joined = "\n".join(entry_hash(entry) for entry in entries)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def chain_head(entries):
    """The hash of the last canonical entry (the chain's head), or None if empty."""
    return entry_hash(entries[-1]) if entries else None


def stamp(entries):
    """Assign ``seq``/``prev_hash`` across ``entries`` in order, in place.

    Called on every write so a freshly written registry is always self-consistent.
    """
    prev = GENESIS
    for index, entry in enumerate(entries):
        entry["seq"] = index
        entry["prev_hash"] = prev
        prev = entry_hash(entry)
    return entries


def verify_chain(reg):
    """Walk the chain, raising when it does not link up.

    Returns the list of per-entry hashes (oldest first) when the chain is sound.
    """
    marker = reg.get(MARKER_KEY)
    if marker is None:
        raise LegacyRegistryError(
            "this registry predates the chain (no gatesmith_registry marker); "
            "upgrade explicitly by opening a review into a fresh registry")
    if not isinstance(marker, dict) or marker.get("v") != CHAIN_VERSION:
        raise LegacyRegistryError(
            f"unsupported registry marker {marker!r}; expected "
            f"{{'v': {CHAIN_VERSION}}}")
    entries = reg.get("reviews", [])
    if not isinstance(entries, list):
        raise ChainStructureError("registry 'reviews' must be a list")
    prev = GENESIS
    hashes = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ChainStructureError(
                f"chain broken at entry {index}: entry is not an object")
        if "seq" not in entry or "prev_hash" not in entry:
            raise ChainStructureError(
                f"chain broken at entry {index}: missing seq/prev_hash")
        if entry["seq"] != index:
            raise ChainStructureError(
                f"chain broken at entry {index}: seq {entry['seq']!r} != {index}")
        if entry["prev_hash"] != prev:
            raise ChainBrokenError(f"chain broken at entry {index}")
        prev = entry_hash(entry)
        hashes.append(prev)
    return hashes
