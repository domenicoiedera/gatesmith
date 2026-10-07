---
name: proof-standard
description: Use when a check passes and you are about to trust it. Positive control, fail-then-pass, and the rule that a validation which cannot fail is a fabrication.
---

# The proof standard

**A validation that cannot fail is a fabrication.** If a check has never gone
red, you do not know that it discriminates — you only know that it runs.

Three habits follow. Every one of them is cheap; skipping any of them is how a
green run becomes a false clear.

## 1. Positive control

No negative result is valid until the same command has been proven to find
something. Before you trust "no matches", "0 problems", or "clean", make the
command match a case you planted on purpose.

- Grepping for a banned string? Plant the string in a scratch file, run the same
  grep, and watch it match. If it does not match, your "clean" result was noise.
- A guard that reports nothing? Point it at an input it must block, and confirm
  it blocks.

Quote your arguments. An unquoted glob in a shell can expand to nothing, and
"no matches found" reads exactly like a clean negative.

## 2. Fail-then-pass

A passing suite is not evidence that a new test discriminates. To prove it:

1. Break the thing the test is about — one deliberate mutation.
2. Run it. Show the test go **red**. Name the failing test.
3. Restore it. Run it. Show it go **green**.

If you cannot make it go red, **say so**. You have learned that the guarantee
lives somewhere other than where the test points — which is itself the finding.

Keep both runs. A test shipped without its red run is a claim, not a receipt.

## 3. Check the artifact, never the label

A comment is not the code. A name is not the behavior. A status badge is not a
result.

- A comment that says "mirrors the schema" is a sentence, not a check.
- A function called `validate()` that returns `True` unconditionally validates
  nothing.
- A test whose assertion matches its own explanatory comment passes for the
  wrong reason.

Read the artifact. Run the command. Compare the output to the claim.

## Corollaries worth internalizing

- **An empty enumeration must fail.** A check that finds zero items when it
  expected many is broken, not green. A green `0 files checked` is the worst
  output a check can produce.
- **A check narrower than its name is a lie.** The command succeeds, the reader
  reads coverage into the success, and the files it never looked at are the ones
  that break.
- **Narrow the input, never the pattern.** When a check is noisy, fix what you
  feed it; do not soften what it looks for. A pattern that stops matching the
  real violation is worse than the noise.
- **Mutation-test the rule, not just the code.** A rule that has not been shown
  to catch a real violation is not yet a rule.

## When you are done

State what you broke, what went red, and what went green. If you only have the
green, you are not done.
