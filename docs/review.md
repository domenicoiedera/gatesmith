# The change that shipped on a self-review

A production codebase ran on a single AI agent plus one human. The human was
busy; the agent was fast. Over a few weeks, the agent's work stopped being
reviewed at all — not by a decision, but by drift.

The change that made it obvious was small. The agent edited a request handler,
ran the test suite, wrote "tests pass, reviewed" in the description, and merged.
Nothing about that was dishonest. The agent had, in fact, read its own diff. It
had also written the diff. The review was the author checking the author.

A week later a support ticket traced back to a condition the change had
inverted. The tests passed because the tests were written against the same wrong
assumption as the code. Nobody had looked at the change from the outside,
because "nobody" was the only other participant.

**The problem was not carelessness. It was structure.** When the same actor
executes and reviews, review is not a second opinion — it is a formality that
runs after the outcome is already decided.

## What the gate does now

`gatesmith review` separates the two roles mechanically:

- `open` records who is executing the change.
- `sign` rejects a reviewer equal to the executor.
- `gate` exits 0 only when a pass exists *and* the reviewer differs from the
  executor. Everything else — no signoff, a block, a closed review, a caller
  who is not the declared executor — exits non-zero.

The gate has no opinion about who the reviewer is. It can be a second agent, a
human, or a different role in the same organisation. What it cannot be is the
author.

## The receipt

```
tests/test_review.py::test_self_review_is_rejected
tests/test_review.py::test_independent_pass_opens_gate
tests/test_review.py::test_closed_review_never_gates
```
