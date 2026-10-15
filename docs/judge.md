# The judge: bring your own decision classifier

## What it is

v0.3.0 adds a second, independent opinion to a gatesmith gate: a
**typed-decision classifier** you configure yourself. gatesmith asks it 3–5
typed questions about the change under review, records its typed answers with
confidences in a tamper-evident audit receipt, and — at the gate — prints one
advisory line beside the deterministic verdict.

It is *your* classifier, by configuration: a base URL, a model name, an API
key in the environment. The documented default is the OpenCode Zen free route
(`jev-1.13-free`, wire contract measured and pinned in `gatesmith/judge.py`):
`choice` questions need a criteria map (`allow`/`block`), `score` is refused,
`noul` returns a 0–1 scalar. Any endpoint that answers the same typed shape
works.

```
gatesmith judge --registry review-registry.json --id bump-deps
JUDGE_URL=... JUDGE_API_KEY=... gatesmith review gate --id bump-deps \
  --target deploy --judge
```

## The questions (and why these five)

1. `executor_also_reviewer` — is the executor also the reviewer? (choice)
2. `lane_bounded` — is the change bounded by its declared file set? (choice)
3. `gate_allowable` — should the gate decision be allowed? (choice)
4. `evidence_supports` — does the state hold verification, or only assertions? (choice)
5. `independence_confident` — 0–1 confidence in reviewer independence (noul)

Each is decidable from the registry state the gate already holds — the
classifier is asked to reason over the same record the deterministic gate
reads, not over anything secret: the state payload is one redactable string
(review id, tier, status, executor, change, owned files, signoff, the gate's
own verdict), digested — never stored — in the receipt.

## Advisory until calibrated (the graduation rule)

**The classifier never gates.** The `gate` exit code is computed from the
deterministic two-agent rule and the seal, and is fixed *before* the judge is
consulted; the `judge:` line is printed afterward and cannot move it. An
uncalibrated classifier that blocks everything would otherwise hold your
pipeline hostage; one that allows everything would rubber-stamp it. So it
surfaces, and the receipts are how you *calibrate* it: run it beside the gate,
compare, and only when its agreement is measured — with thresholds you can
name — consider promoting it. This is pinned by a mutation guard
(`tools/mutation_check.py`): a wiring that lets the judge move the exit code,
or deletes the surfacing call, goes RED in the suite.

## The receipts (tamper-evident by design)

Every invocation — gate hook or standalone verb — appends exactly one JSONL
line to `.gatesmith/judge-receipts.jsonl`: `ts`, `invocation_id`, `route`,
`model`, `question_keys`, `answers`, `confidences`, `verdict`, `reason`,
`elapsed_s`, `calls_used`, `state_sha256`. The state itself is never written —
only its SHA-256 — and credential-shaped strings are redacted before anything
leaves the process *or* lands in the receipt. Receipts are append-only; a
cumulative call counter (`.gatesmith/judge-counter.json`) and a per-invocation
cap bound how many classifier calls can ever be made, and exceeding a cap is a
named skip, never a silent partial state.

## Failure behaviour

- Offline, bad URL, no key, or a route that answers garbage: the verb prints
  `judge: unavailable (<reason>)` and exits **0** — informational, never a
  crash, never a traceback. At the gate, the same line appears and the exit
  code stays the gate's.
- Caps exceeded: `judge: skipped` with the named cap.
- The judge module missing entirely: the gate prints
  `judge: unavailable (gatesmith.judge module is missing)` and carries on.
- Default OFF: without `--judge` or `JUDGE_URL` the classifier is never
  contacted, no line appears, no receipt is written.

## Honest limits

- The classifier sees the registry's claims, not the repository: it can be as
  wrong as the record it reads. The receipt lets you audit *it*, too.
- Confidences are the route's self-report, not a calibrated probability.
- Receipts are append-only but not signed; they sit beside the sealed
  registry, not inside its chain. Treat them as evidence, not as proof.
