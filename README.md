# gatesmith

**Fail-closed verification gates for AI coding agents.** You bring the agent;
gatesmith brings the governance. Zero dependencies, Python 3.10+, MIT.

An agent that reviews its own work is not a second opinion. gatesmith turns
"someone else checked" into a mechanism: a change cannot advance until an
*independent* reviewer signs it, and every failure mode blocks.

## Install

```
pip install gatesmith
```

Requires Python 3.10+. No dependencies, no network, no accounts, no model calls.

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

# Wrap the push/deploy/migrate step. Exit 0 only on an independent pass.
gatesmith review gate --id bump-deps --target deploy --executor claude
```

`gate` exits 0 only when a pass exists and the reviewer differs from the
executor. A missing signoff, a block, a closed review, or reviewer == executor
all exit non-zero. Wire it into a hook or CI and the work stops at the door.

## Install it into your agent

Recipes, not lock-in — the same binary everywhere:

- `examples/claude-code-hook.json` — a Claude Code `Stop` hook.
- `.pre-commit-hooks.yaml` — a pre-commit hook (recipe copy in `examples/`).
- `examples/ci.yml` — a GitHub Actions snippet.
- `examples/gatesmith.yaml` — shared default registry paths.

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
