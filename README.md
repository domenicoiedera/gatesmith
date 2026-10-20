# gatesmith

**Fail-closed verification gates for AI coding agents.** You bring the agent;
gatesmith brings the governance. Zero dependencies, Python 3.10+, MIT.

An agent that reviews its own work is not a second opinion. gatesmith turns
"someone else checked" into a mechanism: a change cannot advance until an
*independent* reviewer signs it, and every failure mode blocks.

## Install

Install the release wheel. No account, no registry, no publishing step in the middle:

```
pip install https://github.com/domenicoiedera/gatesmith/releases/download/v0.3.0/gatesmith-0.3.0-py3-none-any.whl
```

Pin the tag from source instead, if you prefer to read exactly what runs:

```
pip install "git+https://github.com/domenicoiedera/gatesmith.git@v0.3.0"
```

Isolated install, so `gatesmith` lands on your PATH without touching a project venv:

```
pipx install https://github.com/domenicoiedera/gatesmith/releases/download/v0.3.0/gatesmith-0.3.0-py3-none-any.whl
uv tool install https://github.com/domenicoiedera/gatesmith/releases/download/v0.3.0/gatesmith-0.3.0-py3-none-any.whl
```

From a clone, for development:

```
git clone https://github.com/domenicoiedera/gatesmith && cd gatesmith
pip install -e .
```

Any of these should end with `gatesmith --version` printing `gatesmith 0.3.0`.

**There is no `gatesmith` package on PyPI**, so `pip install gatesmith` fails with
"No matching distribution found". The lines above are the install paths that
work; each one was run on macOS with Python 3.12 before being written here.

Requires Python 3.10+. No dependencies, no accounts. The gates run fully
offline; the only optional network call in the tool is the judge classifier
(v0.3.0), which is off by default.

## The four gates

| Command | Question it answers |
|---|---|
| `gatesmith review` | Did a reviewer *other than the executor* pass this change? |
| `gatesmith evidence` | Is the diff in scope, verified, and free of frozen or auto-advance changes? |
| `gatesmith lanes` | May this agent touch these files right now, and is the shared tree free? |
| `gatesmith frozen` | Does this change touch a path only the owner may change? |

## 60 seconds: the review gate

```
# The executor opens a review and declares the change.
gatesmith review open --id bump-deps --executor claude --change "bump deps" --tier B

# An independent reviewer must sign. The executor signing its own work fails.
gatesmith review sign --id bump-deps --reviewer human --verdict pass

# Wrap the push/deploy/migrate step. Exit 0 only on an independent, sealed pass.
gatesmith review seal --key ~/.ssh/reviewer_key
gatesmith review gate --id bump-deps --target deploy --executor claude \
  --allowed-signers /outside/the/repo/reviewers
```

`gate` exits 0 only when a pass exists, the reviewer differs from the executor,
and the chain head is covered by a seal that verifies against a trust anchor you
supply from **outside** the repo. A missing signoff, a block, a closed review,
reviewer == executor, or a missing/!verifying seal all exit non-zero. A registry
that was never sealed is blocked by default; `--allow-unsealed` is the explicit,
loud opt-out that admits it on chain+signoff only. Wire it into a hook or CI and
the work stops at the door.

## Install it into your agent

Recipes, not lock-in — the same binary everywhere:

- `examples/claude-code-hook.json` — a Claude Code `Stop` hook.
- `.pre-commit-hooks.yaml` — a pre-commit hook (recipe copy in `examples/`).
- `examples/ci.yml` — a GitHub Actions snippet.
- `examples/gatesmith.yaml` — shared default registry paths.

## A second opinion, typed (v0.3.0, advisory)

gatesmith can now record a **decision classifier's** opinion beside the
gate's — yours, not ours: you point it at any endpoint (`JUDGE_URL`,
`JUDGE_MODEL`; the documented default is the OpenCode Zen free route). The
classifier is asked 3–5 typed questions — executor-vs-reviewer independence,
whether the change stays inside its declared file set, whether the recorded
evidence supports the gate decision — and every answer is a typed verdict
with a confidence, appended to a tamper-evident JSONL receipt.

```
# Standalone: classify the current registry
gatesmith judge --registry review-registry.json --id bump-deps

# Or surface one advisory line beside the gate verdict
JUDGE_URL=... JUDGE_API_KEY=... gatesmith review gate --id bump-deps \
  --target deploy --allowed-signers /outside/the/repo/reviewers --judge
```

**Advisory until calibrated.** The classifier never decides anything: the
`judge:` line is printed *after* the gate's verdict is computed and cannot
move its exit code — pinned by a mutation guard, the same way the gates
themselves are. Offline it degrades to one honest `judge: unavailable` line.
The audit receipts (`ts`, route, model, question keys, answers, confidences,
an `invocation_id`; payload digested, credentials redacted) land beside the
gate's evidence. See `docs/judge.md`.

## The proof standard

The rule this project is built on: **a validation that cannot fail is a
fabrication.** A passing test is not evidence that it discriminates — you break
the thing, watch it go red, restore it, and watch it go green.
`skills/proof-standard/SKILL.md` is the skill-pack; `tests/` is the receipts.

## War stories

Each gate exists because a specific failure got past review. The stories, with
the names removed, live in `docs/`:

- `docs/review.md` — the change that shipped on a self-review.
- `docs/evidence.md` — the warning that fired on everything, and so on nothing.
- `docs/lanes.md` — two agents, one working tree, one quiet overwrite.
- `docs/frozen.md` — the config only one person was allowed to touch.

## Fail-closed by construction

- A registry that exists but cannot be parsed is a hard error, never an empty
  result. A guard that reads a broken file as "nothing declared" is how a gate
  fails open.
- The lane guard calls the frozen guard in-process; there is no script path to
  go missing and no subprocess to fail open.
- The worktree audit has no delete, prune, or reset verb, and `unknown` is never
  treated as safe to remove.

## Every claim here is pinned by a test

`tests/` runs with the standard library only:

```
python -m unittest discover -s tests -t .
```

## License

MIT. See `LICENSE`.
