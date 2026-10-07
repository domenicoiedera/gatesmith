"""gatesmith — vendor-neutral verification gates for AI coding agents.

Four fail-closed gates you can wrap around any agent's work:

* ``review``   — a two-agent gate: an executor builds, an independent reviewer
  signs, and nothing advances without an explicit independent pass.
* ``evidence`` — the mechanical pre-review checks a reviewer runs before
  signing: diff-in-scope, verification note, frozen paths, auto-advance markers.
* ``lanes``    — file-set ownership and shared-tree discipline for parallel
  agents, plus a read-only worktree audit.
* ``frozen``   — frozen paths as code, not as a paragraph in a doc.

Zero dependencies, Python 3.10+ standard library only.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
