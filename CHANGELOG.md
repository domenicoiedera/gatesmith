# Changelog

All notable changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Every release also notes the failures it exposed, because a release that taught
us nothing is a release we did not verify.

## [0.1.0] - 2026-10-02

### Added

- `gatesmith review` — the fail-closed two-agent gate: `open`, `sign`, `gate`,
  plus `status`, `list`, `close`, `lookup`. Self-review is rejected by
  construction and the gate clears only on an independent pass.
- `gatesmith evidence` — the pre-review runbook: diff-in-scope, verification
  note, frozen paths, and auto-advance markers in added code. The marker check
  is opt-in via `--markers-file`; report prose is never scanned for markers.
- `gatesmith lanes` — file-set ownership, shared-tree-busy detection, manifest
  and reviewer sign-off, with an in-process frozen check, plus a read-only
  `worktrees` audit.
- `gatesmith frozen` — frozen paths as code, from a JSON registry.
- `skills/proof-standard/` — the skill-pack: positive control, fail-then-pass,
  and the rule that a validation which cannot fail is a fabrication.
- `examples/` — a Claude Code `Stop` hook, a pre-commit hook, a GitHub Actions
  snippet, and a sample `gatesmith.yaml`.

### Failures this release exposed

- The lane guard used to shell out to a separate guard script. After
  repackaging that path did not exist, so the guard returned "no frozen paths"
  and its tests passed while blocking nothing. It now calls the frozen module
  in-process, and a test asserts a frozen owned-file actually blocks against a
  non-frozen control.
- The auto-advance check used to scan the whole diff, so a report that quoted
  the rule raised the warning meant for a real violation. The pattern was not
  narrowed; the input was, and both directions are tested.
- The worktree process probe treated any non-zero `lsof` exit as "could not
  tell", which made every worktree look `unknown`. A clean exit code 1 with no
  diagnostics is now a real negative, while an ambiguous probe still becomes
  `unknown`.

## [Unreleased]

- Planned: a baseline-comparison battery, and a project config file.
