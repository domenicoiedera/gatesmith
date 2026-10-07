# The warning that fired on everything, and so on nothing

The pre-review checklist had a check for a specific dangerous pattern: a change
that would let work advance without a human approving it. It scanned the whole
diff.

The codebase had a written rule — *nothing advances past drafted without a
human* — and, being a well-documented project, it stated that rule in a lot of
places. Release notes, design docs, the checklist's own description. Every one
of those documents tripped the check the moment it was touched. The warning
fired on nearly every change.

A warning that fires on everything is not a warning. It is noise, and the
predictable adaptation is to stop reading it. Weeks later, a genuine config line
— an explicit auto-approve flag added "for trusted agents" — sailed through,
because it looked exactly like the two dozen warnings before it that had all
been fine.

**The check was not wrong about the pattern. It was wrong about the input.** A
document that *describes* a rule is not the same as code that *implements* a
violation.

## What the check does now

`gatesmith evidence` narrows the input, never the pattern:

- Only **added lines** are read. A deletion of a dangerous line is a fix; hunk
  headers and context are not edits.
- **Report prose is excluded.** Files under `docs/`, `reports/`, and `*.md` /
  `*.rst` cannot implement an auto-advance; they can only describe one. The
  exclusion is a configurable regex, not a hardcoded assumption.
- The pattern itself is unchanged, and a test asserts it still matches the words
  it is looking for.

Both directions are pinned, because a classifier that simply stopped firing
would pass the false-positive case and be worse than the bug.

Two checks are opt-in and ship off: a marker check driven by `--markers-file`
(any regexes your policy needs), and the report-path regex.

## The receipt

```
tests/test_evidence.py::HitlClassification::test_report_prose_is_not_a_marker
tests/test_evidence.py::HitlClassification::test_added_code_line_is_a_marker
tests/test_evidence.py::HitlClassification::test_the_pattern_itself_is_unchanged
```
