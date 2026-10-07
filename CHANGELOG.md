# Changelog

All notable changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Every release also notes the failures it exposed, because a release that taught
us nothing is a release we did not verify.

## [0.2.0] - 2026-10-08

### Changed

- **The review seal is now REQUIRED by default at the gate.** `review gate`
  exits 1 when the registry is unsealed or its seal does not verify. The only
  way to admit an unsealed registry is the explicit `--allow-unsealed`, which
  prints a loud warning naming the residual risk.
- One exit taxonomy across the verbs (D5): `gate` — 1 on a chain/structure/legacy
  integrity failure or a missing/non-verifying seal, 2 on a malformed registry
  shape (clean message, never a traceback); `verify` — 1 on a failed chain/seal
  or a missing seal, 2 on an unreadable registry/anchor; `seal` — 0/2;
  `status`/`list`/`lookup` are informational — 0 when they can report, 2 when
  the registry is unreadable or unparseable. They make no gate decision.
- `status`/`list`/`lookup` name the seal state explicitly and never print a bare
  `GATE: OPEN` — a stale seal reads `UNSEALED — NOT ENFORCED`.
- The trust-anchor warning is computed from the **anchor's own** location, so a
  repo-internal anchor is warned about even when the registry lives outside
  every repo.
- Every `ssh-keygen` call carries a 30s timeout; a hung tool is exit 2, not a
  hang. Seal sidecar I/O is fail-closed: any `OSError` is exit 2 with a message.
- The signed preimage uses a normalized registry path (`./reg.json` and
  `reg.json` produce the same preimage). Leading-dash paths are rejected before
  they reach argv.
- `tools/mutation_check.py` ships with the tree: it disables each load-bearing
  guard in turn and asserts its test goes RED, restoring byte-identically.

### Failures this release exposed

- The wave-1 gate was **fail-open against the adversary it exists to stop**:
  `_enforce_seal` admitted whenever `<registry>.sig` was absent, so a
  write-capable executor self-approved by never sealing — or by deleting the
  sidecar. A three-entry registry with a forged last entry and a deleted sidecar
  was admitted (exit 0). The seal is now required by default.
- `status` printed `GATE: OPEN` from signoff strings alone while `gate` blocked
  on the same registry — a false admitted oracle. Its text now names the seal
  state.
- The anchor warning was skipped whenever the registry sat outside any git tree,
  so a repo-writable anchor could pass unremarked. It is now derived from the
  anchor's location.
- `gate` caught only `ChainBrokenError`, so a structure/legacy failure exited 2
  instead of the documented 1; paths beginning with `-` reached `ssh-keygen` as
  options; no subprocess had a timeout; and a seal I/O error raised an uncaught
  `OSError` (exit 1, contradicting the documented 2). All fixed.
- The informational verbs kept lying in subtler shapes after the first fix: a
  `.sig` file that merely existed (with a matching digest) read as `sealed`; a
  signature that validated but did not bind the named reviewer read as
  `VERIFIED`; a verb that checked nothing still implied a verdict; and
  `verify --signer` asserted "gate will block" from a narrowed principal set
  while the unrestricted gate would admit. Each was found by an independent
  adversary *after* the previous fix had passed its own tests.

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
