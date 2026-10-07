# The config only one person was allowed to touch

On the same production codebase, a handful of files were effectively frozen:
pricing constants, the payment capture path, the authentication flow. They were
frozen by convention — everyone knew, and it was written down somewhere.

An agent, asked to do an unrelated cleanup, found a constant in the pricing
module that looked unused and tidied it away. It was not unused. The change
passed the test suite, because the suite tested prices relative to each other
and not their absolute values. It passed review, because the reviewer was
reading a cleanup diff and the line looked like cleanup.

Nobody noticed until an invoice was wrong.

**A policy that lives only in a document is enforced only until someone has not
read the document.** The reviewer was not careless; the diff genuinely did not
look dangerous, and "is this file one of the special ones" was knowledge in a
person's head rather than a fact a tool could check.

## What the guard does now

`gatesmith frozen` makes frozen paths data:

```json
{"items": [
  {"id": "F1", "area": "payment capture", "owned_files": ["src/payments", "src/tax.ts"]}
]}
```

- `gatesmith frozen check <paths>` exits non-zero when any planned path is owned
  by a frozen item, and names the item.
- The same check runs inside the lane guard, so a lane cannot even *claim* a
  frozen file.
- The evidence runbook fails when a changed file is frozen.

The registry is a file you can review, diff, and put in version control. A
registry that exists but cannot be parsed is a hard error — a guard that reads a
broken file as "nothing is frozen" has failed open, which is exactly the failure
it was built to prevent.

## The receipt

```
tests/test_frozen.py::FrozenCli::test_frozen_path_blocks
tests/test_frozen.py::FrozenCli::test_clear_path_exits_zero
tests/test_frozen.py::FrozenCli::test_unreadable_registry_is_a_hard_error
```
