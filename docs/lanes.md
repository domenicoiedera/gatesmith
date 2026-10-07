# Two agents, one working tree, one quiet overwrite

For a while, one repository was worked by several agents at once. They shared a
single working tree and a single git index, and — this is the part that matters
— they could not see each other's writes.

The incidents came in one shape. An agent would run a command that staged "its
changes" and, because `git add <file>` stages the *file*, not *your edits to it*,
it staged another agent's unfinished change along with its own. Once, it
committed a baseline file whose corresponding test was still uncommitted, so a
clean checkout failed from a healthy repository. Another time two agents chose
the same file, edited it within the same minute, and one simply overwrote the
other. Neither noticed, because neither could.

**No amount of discipline fixes this.** The failure is structural: a mutable
resource with no lock, written by processes with no visibility of one another.
Asking agents to "be careful" is not a mechanism.

## What the guard does now

`gatesmith lanes` makes ownership explicit before work starts:

- `check` refuses a lane whose owned files overlap a file another **active**
  lane already owns, a file held **uncommitted** in the shared tree, or a
  **frozen** path.
- `start` registers the lane only after a clean `check`.
- `claim` adds files to one active lane, re-running the same tripwire.
- `manifest` records what the lane changed against its base and flags drift —
  changed files the lane never declared.
- `signoff` records a reviewer verdict on the manifest before the lane merges.

The frozen check runs **in-process**. An earlier version shelled out to a
separate script; when that path went missing the guard silently reported "no
frozen files" and its tests passed while blocking nothing. There is no path to
miss now, and a test asserts a frozen owned-file actually blocks, against a
non-frozen control that clears.

`gatesmith lanes worktrees` is a read-only audit on top: it inventories every
worktree, classifies each as active or a stale candidate, and has no delete,
prune, or reset verb. `unknown` is never treated as safe to remove.

## The receipt

```
tests/test_lanes.py::test_frozen_owned_file_blocks_check
tests/test_lanes.py::test_non_frozen_file_clears_check
tests/test_lanes.py::test_shared_tree_busy_trip
tests/test_lanes.py::test_owned_clash_tripwire
tests/test_worktree.py::test_unknown_never_safe
```
