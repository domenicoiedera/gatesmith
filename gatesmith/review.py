"""The two-agent review gate.

An executor opens a review, an independent reviewer signs it, and nothing
advances to push, deploy, or migrate until the gate sees an explicit pass by a
reviewer distinct from the executor. The gate is fail-closed: a missing
signoff, a block verdict, a closed review, or reviewer == executor all block.
Self-review is impossible by construction, not by convention.

Risk tiers (A/B/C) change how much evidence a change needs; they never change
the two-agent rule — even a docs-only change needs a reviewer distinct from its
executor. An unclassified change defaults to tier C, the full process.

Commands
--------
  open   --id ID --executor ROLE --change DESC [--owned FILE ...] [--tier A|B|C] [--diff-sha SHA]
  sign   --id ID --reviewer ROLE --verdict pass|block [--note TEXT] [--auto]
  status --id ID
  gate   --id ID --target push|deploy|migrate [--executor ROLE] [--allowed-signers PATH] [--allow-unsealed]
  list   [--all]
  close  --id ID --note TEXT [--by ROLE]
  lookup --diff-sha SHA
  seal   --key PRIVATE_KEY
  verify --allowed-signers PATH [--signer PRINCIPAL]   (chain + seal ONLY)

The registry is hash-chained (see :mod:`gatesmith.chain`): every verb verifies
the chain before it reads, and a broken chain is a hard error. ``gate`` REQUIRES
a seal over the chain head — verified against a trust anchor the verifier
supplies from outside the repo — and binds the sealing principal to
``signoff.reviewer``, which must differ from ``entry.executor``. A registry with
no seal, or a seal that does not verify, is **blocked**; ``--allow-unsealed`` is
the explicit, loud opt-out that names the residual risk. ``seal`` and ``verify``
use the optional ``ssh-keygen``. New flags here are CLI-only in this wave —
there is no ``gatesmith.yaml`` wiring.

``verify`` answers a NARROW question: is the hash chain sound, and does the
detached seal validate against the anchor (restricted to ``--signer`` when
given)? It does **not** evaluate admission — it never applies the
reviewer/executor, pass-signoff, or principal→``reviewer`` binding that
``gate`` enforces — so its ``0`` is NOT a green light to admit. Its output says
so explicitly and, when the registry holds entries the seal would not bind,
names how many. A caller wiring ``verify`` as an admission pre-check must run
``gate`` for that decision.

Exit codes (decisions D5, G12): one taxonomy per verb class, never a traceback.
  * DECISION verbs (``gate``, ``verify``) — 0 admitted/verified, 1 blocked. The
    ``gate`` is 1 on any integrity failure (chain broken / structure / legacy)
    and on a missing or non-verifying seal; ``verify`` is 1 when the chain
    fails, no seal is present, or the seal does not verify. Both are 2 on a
    malformed registry shape (missing ``id``, wrong types, ``reviews`` not a
    list) or usage — always a clean message.
  * ``seal``   — 0 sealed; 2 cannot seal (no tool, I/O error, usage).
  * INFORMATIONAL verbs (``status`` / ``list`` / ``lookup``) — **0** when the
    artifact is readable (whatever the verdict) and **2** when it cannot be read
    (broken chain, malformed shape, usage). Such a verb makes no gate decision,
    so a readable-but-blocked review is 0 and an unreadable artifact is a hard
    error (2) — it is never a silent 0. (They do NOT return 1 on an integrity
    failure: 1 is a gate DECISION, and a verb that cannot read the artifact has
    made none.)

A CLOSED review (``status == "closed"``) is blocked in EVERY verb that reports
a verdict (G11): closing retires a review, so ``gate`` and the informational
verbs share the one block reason ``_block_reason``.

### The judge (v0.3.0) — SURFACING, never blocking (K3)

``gate`` optionally carries ONE advisory line from a typed-decision
classifier (``gatesmith/judge.py``, "the judge"): ``--judge`` or a configured
``JUDGE_URL`` turns it on; the default is OFF. The line is printed only AFTER
the deterministic verdict has been computed and the exit code fixed — the
judge's answer can name the gate's own failure reasons, agree, or disagree,
and in every case it is recorded and printed WITHOUT moving the exit code or
the verdict text. An uncalibrated classifier never gates; it surfaces (the
graduation rule). Wiring facts the mutation harness depends on:

* ``cmd_gate`` is a three-line wrapper: ``entry = _gate_entry(args)``,
  ``code = _gate_decide(args, entry)``, then the single surfacing call —
  deleting that call must go RED (the K5 mutation guard).
* the surfacing call asks the classifier to **oppose** the gate's verdict, so
  the two directions of K3 are real: the judge can be outvoted AND can
  outvote the gate's intent without either moving the exit code.
* ``_judge_gate_surface`` returns the line it printed (a ``str``); it has no
  access to the exit code and never raises — its own failure mode is the
  honest ``judge: unavailable`` line.
* if the judge module is absent entirely the line names it and the gate
  carries on: an optional advisor cannot become a dependency of the verdict.

One rule governs the informational verbs (G1): **a verb may only report the
gate's decision if it re-derives it the same way the gate does — otherwise it
must say it did not check.** ``status``/``list``/``lookup`` therefore never
render a bare ``sealed``: a present-but-unchecked seal reads ``seal present,
UNVERIFIED``, and only a real ``ssh-keygen -Y verify`` against a caller-supplied
``--allowed-signers`` anchor can produce ``VERIFIED``. Before this rule a
zero-byte ``.sig`` with a re-stamped ``.digest`` made ``status`` print
``GATE: OPEN (sealed)`` while the gate blocked — a false oracle.
"""

import datetime
import json
import os
import sys

from . import chain, config, seal, store

DEFAULT_REGISTRY = "./review-registry.json"
ALLOWED_TARGETS = {"push", "deploy", "migrate"}
ALLOWED_TIERS = {"A", "B", "C"}
ENTRY_REQUIRED = ("id", "executor", "change", "status")
FIELD_TYPES = {"id": str, "executor": str, "change": str, "status": str}
SIGNOFF_TYPES = {
    "reviewer": (str, type(None)),
    "verdict": (str, type(None)),
    "note": str,
    "at": (str, type(None)),
    "auto": bool,
}
# One honest sentence for "a seal is present but no anchor was supplied to
# verify it" — a single source, so the reporting verbs and the gate agree.
NO_ANCHOR_DETAIL = ("registry is sealed but no --allowed-signers trust anchor "
                    "was supplied — the seal was not verified")


class UsageError(Exception):
    """A command-line value that cannot be used (exit 2)."""


class MalformedRegistryError(store.RegistryError):
    """A registry whose entry shape is unusable — exit 2, not a chain block."""


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _registry(args):
    """The registry path, normalized and validated (D6, D7).

    Normalizing here means the path that reaches the signed preimage is the
    same whether the caller wrote ``./reg.json`` or ``reg.json``. A path that
    begins with ``-`` would be parsed as an option by a subprocess, so it is a
    usage error before anything touches argv.
    """
    path = config.get(args, "review", "registry", DEFAULT_REGISTRY)
    if not path:
        path = DEFAULT_REGISTRY
    path = seal.normalize_path(path)
    if path.startswith("-"):
        raise UsageError(f"registry path may not begin with '-': {path!r}")
    return path


def _check_reviews_container(reg):
    """Reject a registry whose ``reviews`` is not a list of objects — exit 2.

    A container-shape problem is a usage-class error (exit 2), not a
    chain-integrity one (which is exit 1, G2). This runs BEFORE the chain walk
    so the taxonomy is unambiguous: ``reviews`` present but not a list, or a
    non-object entry, is shape; a chain that does not link up is integrity.
    """
    reviews = reg.get("reviews", [])
    if not (isinstance(reviews, list)
            and all(isinstance(entry, dict) for entry in reviews)):
        raise MalformedRegistryError("registry 'reviews' must be a list of JSON objects")


def _check_shape(reg):
    """Reject an entry the commands cannot read — exit 2, never a traceback.

    Shape (missing field, wrong type, non-dict signoff) is a usage-class error
    (exit 2), distinct from a chain-integrity break (exit 1). The chain already
    guarantees each entry is a JSON object; this checks the fields a verb
    indexes and their types, so a wrong-typed ``id`` is shape too.
    """
    for index, entry in enumerate(reg.get("reviews", [])):
        missing = [key for key in ENTRY_REQUIRED if key not in entry]
        wrong = [key for key in ENTRY_REQUIRED
                 if key in entry and not isinstance(entry[key], FIELD_TYPES[key])]
        signoff = entry.get("signoff")
        if not isinstance(signoff, dict):
            missing.append("signoff")
        else:
            for key, expected in SIGNOFF_TYPES.items():
                if key not in signoff:
                    missing.append(f"signoff.{key}")
                elif not isinstance(signoff[key], expected):
                    wrong.append(f"signoff.{key}")
        problems = []
        if missing:
            problems.append("missing required field(s): " + ", ".join(missing))
        if wrong:
            problems.append("wrong type for: " + ", ".join(wrong))
        if problems:
            raise MalformedRegistryError(f"entry {index} is " + "; ".join(problems))


def load_reg(path):
    """Load the review registry, verifying the hash chain.

    An absent or empty file is a fresh registry (nothing declared yet). A file
    that exists is verified as a v2 hash chain: a broken chain, a missing chain
    field, or a pre-chain (marker-less) registry all raise (integrity → exit 1
    at the gate), so no verb can read a tampered chain as if it were sound. A
    structurally usable chain whose container/entries are the wrong shape raises
    :class:`MalformedRegistryError` (shape → exit 2, G2).
    """
    present = bool(path) and os.path.exists(path) and os.path.getsize(path) > 0
    reg = store.load_json(path, {"gatesmith_registry": {"v": chain.CHAIN_VERSION},
                                 "reviews": []})
    if not present:
        reg.setdefault("gatesmith_registry", {"v": chain.CHAIN_VERSION})
        reg.setdefault("reviews", [])
        return reg
    _check_reviews_container(reg)
    chain.verify_chain(reg)
    _check_shape(reg)
    return reg


def save_reg(path, reg):
    """Write the registry with a fresh, self-consistent chain."""
    reg["gatesmith_registry"] = {"v": chain.CHAIN_VERSION}
    chain.stamp(reg.setdefault("reviews", []))
    store.save_json(path, reg)


def review(reg, rid):
    for entry in reg.get("reviews", []):
        if entry["id"] == rid:
            return entry
    return None


def gate_granted(entry):
    """The shared chain+signoff admission test (the seal lives elsewhere).

    A CLOSED review never gates (G11): closing is how a superseded review is
    retired, so ``status`` must agree with ``gate`` that it blocks. This is the
    predicate ``status`` shares with ``gate``; ``cmd_gate`` applies the same
    conditions inline (it must name the exact enforced reason with its own,
    longer messages), so the two are kept in step BY HAND — edit both together
    or they diverge.
    """
    if entry["status"] == "closed":
        return False
    signoff = entry["signoff"]
    return bool(signoff["verdict"] == "pass" and signoff["reviewer"]
                and signoff["reviewer"] != entry["executor"])


def _block_reason(entry, signoff):
    """A short, honest reason an informational ``status`` shows BLOCKED (D3)."""
    if entry["status"] == "closed":
        return "review is closed"
    if signoff["verdict"] != "pass":
        return f"no pass signoff (verdict={signoff['verdict']})"
    if not signoff["reviewer"]:
        return "no reviewer"
    if signoff["reviewer"] == entry["executor"]:
        return "reviewer is the executor"
    return "not independently passed"


def _seal_verdict(registry, entries, reviewer, anchor):
    """The ONE seal decision, shared by the gate and the reporting verbs (G1).

    Re-derives the gate's admission test through the gate's own code path: a
    seal is admitted only when ``ssh-keygen`` validates its signature against
    ``anchor`` AND the sealing principal binds ``reviewer``. Returns
    ``(outcome, detail, principals)`` with ``outcome`` in ``{'none',
    'unverified', 'verified', 'invalid', 'error'}``:

    * ``'none'``       — no ``.sig`` sidecar (nothing to enforce);
    * ``'unverified'`` — a seal exists but ``anchor`` was not supplied, so NO
      verification ran; the gate fails closed on it, and a reporting verb must
      say it did not check;
    * ``'verified'``   — signature valid and, when ``reviewer`` is given,
      principal-bound — the gate's admit verdict;
    * ``'invalid'``    — verification ran and failed (checked-and-no) → gate 1;
    * ``'error'``      — verification could not run (tool/anchor) → gate 2.

    An informational verb reports the gate's decision only because it
    re-derives it here, the same way the gate does.
    """
    state, detail, principals = seal.inspect(registry, entries, anchor)
    if state == "none":
        return ("none", "no seal — the registry is unsealed", principals)
    if state == "unverified":
        return ("unverified", NO_ANCHOR_DETAIL, principals)
    if state == "verified":
        if reviewer and reviewer not in principals:
            return ("invalid",
                    f"sealing principal {principals} != signoff.reviewer "
                    f"'{reviewer}' — the seal does not bind this reviewer",
                    principals)
        return ("verified", detail, principals)
    if state == "error":
        return ("error", detail, principals)
    return ("invalid", detail, principals)


def _seal_label(registry, entries, anchor, reviewers=None):
    """Render ``seal: <state>`` honestly for the informational verbs (G1/G9).

    ``VERIFIED`` appears only after a real verification AND only when the
    sealing principal actually *binds* the reviewer(s) the caller reports — the
    same principal→``signoff.reviewer`` test the gate applies. When an entry's
    reviewer is known and does NOT match the sealing principal, the line says so
    (``signature valid … — does NOT bind reviewer '…'``) rather than a bare
    ``VERIFIED``: otherwise ``list``/``lookup`` would report the gate's
    admit-condition minus its binding — the surviving G1 false-oracle variant
    (``status`` was fixed, these two were not). ``reviewers`` is the list of the
    held entries' reviewers (``None`` when the caller holds no entry).
    """
    outcome, detail, principals = _seal_verdict(registry, entries, None, anchor)
    if outcome == "verified":
        names = ", ".join(principals) if principals else "?"
        held = list(reviewers or [])
        known = [reviewer for reviewer in held if reviewer]
        # F14: an entry whose reviewer is absent/empty cannot be bound — the
        # gate blocks it ("has no reviewer") whatever the seal proves — so such
        # an entry may NEVER collapse to a bare `VERIFIED`. Render the
        # unbindable clause and say the gate will block.
        noreview = len(held) - len(known)
        if noreview == 1:
            noreview_note = "no reviewer on this entry to bind — gate will block"
        elif noreview > 1:
            noreview_note = (f"no reviewer on {noreview} entries to bind — "
                             f"gate will block")
        else:
            noreview_note = None
        unbound = [reviewer for reviewer in known if reviewer not in principals]
        if unbound:
            # A named reviewer the seal does not bind: never lead with VERIFIED.
            missing = ", ".join(dict.fromkeys(unbound))
            if len(known) == 1:
                line = (f"signature valid (principal={names}) — does NOT bind "
                        f"reviewer '{missing}'")
            else:
                line = (f"signature valid (principal={names}) — binds "
                        f"{len(known) - len(unbound)} of {len(known)} held "
                        f"reviewer(s); does NOT bind {missing}")
            return f"{line}; {noreview_note}" if noreview_note else line
        if known:
            clause = f"binds reviewer {', '.join(dict.fromkeys(known))}"
            if noreview_note:
                clause = f"{clause}; {noreview_note}"
            return f"VERIFIED (principal={names}; {clause})"
        if noreview_note:
            return f"VERIFIED (principal={names}; {noreview_note})"
        if not entries:
            # A sealed registry with no entries at all: the seal verifies, but
            # there is no review here to admit — say so rather than a bare
            # VERIFIED. (`entries` is the whole registry, not the shown subset:
            # a filtered/empty view must NOT claim the registry is empty.)
            return (f"VERIFIED (principal={names}; no reviews in this registry "
                    f"— nothing to admit)")
        return f"VERIFIED (principal={names})"
    if outcome == "none":
        return "none"
    if outcome == "unverified":
        return "present (UNVERIFIED — pass --allowed-signers to verify)"
    return f"FAILED ({detail})"


def _print_seal_line(registry, entries, anchor, reviewers=None):
    """Emit the D4 anchor warning (if any) then the honest ``seal:`` line."""
    if anchor:
        warning = seal.trust_anchor_warning(anchor)
        if warning:
            print(warning, file=sys.stderr)
    print(f"seal: {_seal_label(registry, entries, anchor, reviewers)}")


def cmd_open(args):
    reg = load_reg(_registry(args))
    if review(reg, args.id):
        print(f"review '{args.id}' already exists", file=sys.stderr)
        return 1
    tier = args.tier or "C"
    reg.setdefault("reviews", []).append({
        "id": args.id,
        "executor": args.executor,
        "change": args.change,
        "owned": sorted(args.owned or []),
        "tier": tier,
        "diff_sha": args.diff_sha or None,
        "created": now(),
        "status": "open",
        "signoff": {"reviewer": None, "verdict": None, "note": "", "at": None, "auto": False},
        "closed": None,
    })
    save_reg(_registry(args), reg)
    print(f"review '{args.id}' opened by executor '{args.executor}' (tier {tier}) — "
          f"pending independent review")
    return 0


def cmd_sign(args):
    registry = _registry(args)
    reg = load_reg(registry)
    entry = review(reg, args.id)
    if not entry:
        print(f"no review '{args.id}'", file=sys.stderr)
        return 1
    if entry["status"] == "closed":
        print(f"review '{args.id}' already closed", file=sys.stderr)
        return 1
    if args.reviewer == entry["executor"]:
        print(f"SELF-REVIEW: reviewer '{args.reviewer}' == executor '{entry['executor']}' — "
              f"not allowed. The two-agent gate needs a separate reviewer.", file=sys.stderr)
        return 1
    if args.auto:
        # A byte-match re-sign is bookkeeping, never a shortcut around
        # independence: it is valid only for a tier-A gate carrying a diff hash
        # whose identical bytes were already, independently passed by a reviewer
        # distinct from both this gate's executor and this signer.
        if entry.get("tier") != "A":
            print(f"AUTO-SIGN refused: review '{args.id}' is tier "
                  f"{entry.get('tier', 'C')}, not A.", file=sys.stderr)
            return 1
        sha = entry.get("diff_sha")
        if not sha:
            print(f"AUTO-SIGN refused: review '{args.id}' carries no diff_sha.", file=sys.stderr)
            return 1
        prior = None
        for other in reg.get("reviews", []):
            if other["id"] == entry["id"] or other.get("diff_sha") != sha:
                continue
            other_signoff = other["signoff"]
            if (other_signoff["verdict"] == "pass" and other_signoff["reviewer"]
                    and other_signoff["reviewer"] != entry["executor"]
                    and other_signoff["reviewer"] != args.reviewer
                    and other["status"] == "done"):
                prior = other
                break
        if not prior:
            print(f"AUTO-SIGN refused: no prior independently-passed gate with "
                  f"diff_sha {sha[:12]}.", file=sys.stderr)
            return 1
        entry["signoff"] = {
            "reviewer": args.reviewer, "verdict": "pass",
            "note": f"byte-match re-sign of '{prior['id']}' "
                    f"({prior['signoff']['reviewer']}, {prior['signoff']['at']}); identical diff bytes",
            "at": now(), "auto": True,
        }
        entry["status"] = "done"
        save_reg(registry, reg)
        print(f"review '{args.id}' AUTO re-sign: pass by '{args.reviewer}' — "
              f"byte-identical to '{prior['id']}'")
        return 0
    entry["signoff"] = {"reviewer": args.reviewer, "verdict": args.verdict,
                        "note": args.note or "", "at": now(), "auto": False}
    entry["status"] = "done" if args.verdict == "pass" else "blocked"
    save_reg(registry, reg)
    print(f"review '{args.id}' signoff: {args.verdict} by reviewer '{args.reviewer}'")
    return 0


def cmd_status(args):
    """Informational: **0** on a readable registry, **2** when it cannot be read.

    The GATE line is one of ``BLOCKED: <reason>``, ``OPEN (seal VERIFIED)``,
    ``OPEN (UNSEALED — NOT ENFORCED)`` or ``OPEN (seal present, UNVERIFIED)``.
    It reports the gate's decision only when ``--allowed-signers`` is supplied,
    because then it re-derives it through the gate's own :func:`_seal_verdict`;
    without an anchor it says plainly that the seal was NOT verified. A closed
    review reads ``BLOCKED: review is closed`` (G11). Exit is 0 whatever the
    verdict; an unreadable artifact (broken chain / shape / usage) escapes to
    :mod:`gatesmith.cli` and exits 2 (G12).
    """
    registry = _registry(args)
    reg = load_reg(registry)
    entry = review(reg, args.id)
    if not entry:
        print(f"no review '{args.id}'")
        return 0
    signoff = entry["signoff"]
    print(f"review '{args.id}': status={entry['status']} executor={entry['executor']} "
          f"tier={entry.get('tier', 'C')}")
    print(f"  change: {entry['change']}")
    if entry.get("diff_sha"):
        print(f"  diff_sha: {entry['diff_sha']}")
    print(f"  signoff: verdict={signoff['verdict']} reviewer={signoff['reviewer']}")
    if signoff["note"]:
        print(f"  note: {signoff['note']}")
    if not gate_granted(entry):
        print(f"  GATE: BLOCKED: {_block_reason(entry, signoff)}")
        return 0
    anchor = getattr(args, "allowed_signers", None)
    if anchor:
        warning = seal.trust_anchor_warning(anchor)
        if warning:
            print(warning, file=sys.stderr)
    outcome, detail, _ = _seal_verdict(registry, reg.get("reviews", []),
                                       signoff.get("reviewer"), anchor)
    if outcome == "verified":
        print("  GATE: OPEN (seal VERIFIED)")
    elif outcome == "none":
        print("  GATE: OPEN (UNSEALED — NOT ENFORCED)")
    elif outcome == "unverified":
        print("  GATE: OPEN (seal present, UNVERIFIED)")
    else:
        print(f"  GATE: BLOCKED: seal not verified — {detail}")
    return 0


def _enforce_seal(args, registry, entries, signoff):
    """Enforce the seal. Returns ``None`` when admitted, else an exit code.

    By default the seal is REQUIRED (D1): the actor being governed never
    decides whether evidence is required, so a missing seal — or one that does
    not verify — blocks with 1. The verification itself (and the principal
    binding) lives in :func:`_seal_verdict`, the same decision the reporting
    verbs use, so ``gate`` and ``status`` can never disagree about the seal.
    ``--allow-unsealed`` is the only way to admit a registry that has NO seal,
    and it prints a loud warning naming the residual risk; it does NOT skip the
    verification of a seal that IS present.
    """
    anchor = getattr(args, "allowed_signers", None)
    outcome, detail, principals = _seal_verdict(
        registry, entries, signoff.get("reviewer"), anchor)
    has_seal = outcome != "none"
    allow_unsealed = getattr(args, "allow_unsealed", False)
    if not has_seal and not allow_unsealed:
        print("GATE-BLOCKED: no seal — the registry is unsealed. Evidence must be "
              "signed by an independent reviewer: run 'review seal --key "
              "<private-key>' and re-run with --allowed-signers. To admit anyway, "
              "pass --allow-unsealed and accept that no seal was enforced.",
              file=sys.stderr)
        return 1
    if not has_seal:
        print("WARNING: admitted on chain+signoff only; the seal was NOT enforced. "
              "A write-capable actor could have re-stamped the chain or edited the "
              "last entry undetected — this is the documented residual risk of "
              "--allow-unsealed.", file=sys.stderr)
        return None
    if anchor:
        warning = seal.trust_anchor_warning(anchor)
        if warning:
            print(warning, file=sys.stderr)
    if outcome == "unverified":
        print("GATE-BLOCKED: registry is sealed but no --allowed-signers trust "
              "anchor was supplied — the seal cannot be verified (failing closed).",
              file=sys.stderr)
        return 1
    if outcome == "error":
        print(f"GATE-BLOCKED: the seal cannot be verified — {detail}", file=sys.stderr)
        return 2
    if outcome == "invalid":
        print(f"GATE-BLOCKED: seal verification failed — {detail}", file=sys.stderr)
        return 1
    return None


# ── the gate's exit criterion is computed and fixed, then, and only then, an
# optional advisory line is printed. Ordering is the graduation rule: the
# classifier cannot gate, only surface. Or in one sentence: the judge's line
# is attached to a verdict the judge never influenced.


def _gate_entry(args):
    """Load `args.id` — the part the judge depends on.

    A registry or entry that cannot be resolved returns ``None`` and
    ``cmd_gate`` exits non-zero: with no deterministic verdict, there is
    nothing to attach the advisory line to, and the classifier must never be
    asked for a surrogate one.
    """
    registry = _registry(args)
    try:
        reg = load_reg(registry)
    except (chain.ChainBrokenError, chain.ChainStructureError,
            chain.LegacyRegistryError) as exc:
        print(f"GATE-BLOCKED: {exc}", file=sys.stderr)
        return None
    entry = review(reg, args.id)
    if not entry:
        print(f"GATE-BLOCKED: no review '{args.id}' exists — nothing was reviewed.", file=sys.stderr)
        return None
    return entry


def _gate_decide(args, entry):
    """The deterministic gate criteria: produced BEFORE the judge runs.

    This is the fail-closed verdict the two-agent rule (reviewer distinct from
    executor), the signoff and the seal produce on their own; it does not
    depend on, await or read anything from the classifier.
    """
    if entry["status"] == "closed":
        print(f"GATE-BLOCKED: review '{args.id}' was CLOSED "
              f"({entry.get('closed', {}).get('note', '')}) — a closed review can never gate; "
              f"open a fresh one.", file=sys.stderr)
        return 1
    signoff = entry["signoff"]
    if signoff["verdict"] != "pass":
        print(f"GATE-BLOCKED: review '{args.id}' has no PASS signoff "
              f"(verdict={signoff['verdict']}).", file=sys.stderr)
        return 1
    if not signoff["reviewer"]:
        print(f"GATE-BLOCKED: review '{args.id}' has no reviewer.", file=sys.stderr)
        return 1
    if signoff["reviewer"] == entry["executor"]:
        print(f"GATE-BLOCKED: reviewer '{signoff['reviewer']}' is the executor — "
              f"not independent.", file=sys.stderr)
        return 1
    if args.executor and args.executor != entry["executor"]:
        print(f"GATE-BLOCKED: gate invoked by '{args.executor}' but review '{args.id}' was "
              f"opened by executor '{entry['executor']}'.", file=sys.stderr)
        return 1
    blocked = _enforce_seal(args, _registry(args), _load_reviews(args), signoff)
    if blocked is not None:
        return blocked
    print(f"GATE-OPEN: review '{args.id}' independently passed "
          f"({signoff['reviewer']}, tier {entry.get('tier', 'C')}); '{args.target}' may proceed.")
    return 0


def _load_reviews(args):
    """The entries list the seal is enforced over — re-read, never assumed.

    The judge read may have edited nothing (it is read-only, enforced by its
    own state-only view), but the seal decision is still verified against a
    fresh load of the registry file bytes, so no wiring mistake can let an
    in-memory registry drift from the on-disk one between the two steps.
    Returns ``None`` when the re-read fails (fail-closed, exit 1): ``[]`` is a
    real empty registry, not an error.
    """
    try:
        return load_reg(_registry(args)).get("reviews", [])
    except (chain.ChainBrokenError, chain.ChainStructureError,
            chain.LegacyRegistryError, store.RegistryError) as exc:
        print(f"GATE-BLOCKED: registry unreadable on re-read — {exc}", file=sys.stderr)
        return None


def cmd_gate(args):
    """The reviewer gate, with an optional advisory judge line (v0.3.0).

    The order is invariant and pinned by the K3/K5 mutation guards:
    ``entry = _gate_entry(args)`` → ``code = _gate_decide(args, entry)`` →
    the single ``_judge_gate_surface`` call. The judge runs after the exit
    code is decided and never receives it, so it cannot influence the
    verdict — an uncalibrated classifier surfaces, it does not gate.
    """
    entry = _gate_entry(args)
    if entry is None:
        return 1
    code = _gate_decide(args, entry)
    _judge_gate_surface(args, entry, code)
    return code


# ── the judge advisory (v0.3.0) — ask the classifier, print one line, do not
# block. Shared by `review gate` and the `gatesmith judge` verb. The questions
# are decidable from state the gate already holds: reviewer independence, lane
# boundedness, and whether the gate decision may be allowed.


def _judge_enabled(args):
    """The judge is OFF by default (K3): ``--judge`` turns it on, and so does
    a caller-configured ``JUDGE_URL`` — the classifier must be opted into,
    never silently dispatched to."""
    return bool(getattr(args, "judge", False)) or bool(os.environ.get("JUDGE_URL"))


# The question set. Order is table order; names are receipt keys (K4).
JUDGE_QUESTION_SPECS = (
    ("executor_also_reviewer",
     "Is the executor also the reviewer for this change? Answer 'separate' "
     "only when the named reviewer is a party distinct from the executor.",
     "the reviewer is a party distinct from the executor",
     "the executor reviewed its own work"),
    ("lane_bounded",
     "Is this change bounded by its declared file set, so it cannot have "
     "touched paths outside the lane's ownership? Answer 'bounded' only when "
     "the change description states a bounded file set.",
     "the change declares a bounded file set",
     "the change has no declared file set or is unbounded"),
    ("gate_allowable",
     "Given the review state, should the gate decision be allowed? Answer "
     "'allow' only when the recorded evidence supports admitting the change.",
     "the recorded review state supports admitting the change",
     "the recorded state does not support admitting the change"),
    ("evidence_supports",
     "Does the recorded state contain evidence of verification, or only "
     "assertions? Answer 'evidenced' only when a verification record exists.",
     "a verification record exists in the state",
     "the state contains assertions without a verification record"),
    ("independence_confident",
     "How confident are you, from 0 to 1, that the executor and reviewer are "
     "independent parties?", None, None),
)


def _judge_module():
    """The judge module, imported lazily — ``None`` when it is absent.

    An optional advisor must never become a load-time dependency of the
    gates: resolving the module here (cached by the interpreter after the
    first successful import) keeps ``gatesmith.review`` importable even in a
    tree where ``judge.py`` has been removed.
    """
    try:
        from . import judge
        return judge
    except ImportError:  # pragma: no cover — only when the module is missing
        return None


def judge_questions():
    """Build the 3-5 typed question map (spec: independence, boundedness,
    allowability). ``choice`` questions need a criteria MAP; the scalar one
    is ``noul`` — ``score`` is refused by the route's grammar. Built through
    the judge's own grammar-validated builders when it is importable, with a
    byte-equivalent inline fallback otherwise."""
    j = _judge_module()
    questions = {}
    for name, instructions, allow, block in JUDGE_QUESTION_SPECS:
        if allow is None:
            # The judge builders each return a keyed map `{name: question}`;
            # the questions payload is the UNION of them.
            questions.update(j.noul_question(name, instructions) if j else
                             {name: {"type": "noul", "instructions": instructions}})
        else:
            questions.update(
                j.choice_question(name, instructions, allow, block) if j else
                {name: {"type": "choice",
                        "criteria": {"allow": allow, "block": block},
                        "instructions": instructions}})
    return questions


def judge_state(entry, signoff, gate_code, gate_verdict, block_reason=""):
    """Render the review's state as ONE redactable string for the judge.

    Only what the deterministic gate already knows goes in; the judge module
    redacts credential-shaped values before anything leaves the process, and
    the receipt stores a digest, never the payload (K4).
    """
    owned = entry.get("owned") or []
    parts = [
        f"review_id: {entry.get('id')}",
        f"tier: {entry.get('tier', 'C')}",
        f"status: {entry.get('status')}",
        f"executor: {entry.get('executor')}",
        f"change: {entry.get('change')}",
        f"owned_files: {', '.join(owned) if owned else '(none declared)'}",
        f"diff_sha: {entry.get('diff_sha') or '(none)'}",
        f"signoff_verdict: {signoff.get('verdict')}",
        f"signoff_reviewer: {signoff.get('reviewer') or '(none)'}",
        f"executor_is_reviewer: {str(bool(signoff.get('reviewer')) and signoff.get('reviewer') == entry.get('executor')).lower()}",
        f"gate_verdict: {gate_verdict}",
        f"gate_exit_code: {gate_code}",
    ]
    if block_reason:
        parts.append(f"gate_block_reason: {block_reason}")
    return "\n".join(parts)


def _gate_verdict_text(code):
    return "GATE-OPEN" if code == 0 else "GATE-BLOCKED"


def judge_summary(result):
    """One line from a judge result — the answer to the gate-allowability
    question with its confidence, or the honest named failure.

    A typed answer is ``allow``/``block``; anything else (unavailable,
    skipped, error answer) is surfaced as the reason, never guessed.
    """
    verdict = result.get("verdict")
    if verdict == "ok":
        answer = result.get("answers", {}).get("gate_allowable", {})
        if isinstance(answer, dict) and answer.get("type") == "choice":
            confidence = result.get("confidences", {}).get("gate_allowable")
            shown = f" (confidence {confidence:.2f})" if isinstance(confidence, (int, float)) else ""
            return f"{answer.get('answer')}{shown}"
        return f"bad answer shape ({verdict})"
    reason = result.get("reason") or verdict or "unavailable"
    return f"unavailable ({reason})"


def _judge_line(args, entry, signoff, code, verdict_text, block_reason=""):
    """The one judge advisory line for ``gate`` — printed, and returned so the
    caller can surface it. Never raises, never blocks, never names an exit
    code: with no classifier configured the line is an honest skip."""
    if not _judge_enabled(args):
        return None
    judge = _judge_module()
    if judge is None:  # the module is gone — say so, carry on
        return "judge: unavailable (gatesmith.judge module is missing)"
    result = judge.ask(
        judge_questions(), judge_state(entry, signoff, code, verdict_text, block_reason))
    return f"judge: {judge_summary(result)}"


def _print_judge_table(result):
    """The `gatesmith judge` verdict table: question | answer | confidence."""
    for name, _instructions, _allow, _block in JUDGE_QUESTION_SPECS:
        answer = result.get("answers", {}).get(name)
        if isinstance(answer, dict) and "error" not in answer:
            value = answer.get("answer")
            if answer.get("type") == "noul" and isinstance(value, (int, float)):
                value = f"{value:.2f}"
            confidence = result.get("confidences", {}).get(name)
            shown = f"{confidence:.2f}" if isinstance(confidence, (int, float)) else "-"
            print(f"  {name:<24} {str(value):<12} {shown}")
        else:
            detail = answer.get("error") if isinstance(answer, dict) else "no answer"
            print(f"  {name:<24} {'-':<12} -   ({detail})")
    if result.get("verdict") != "ok" and result.get("reason"):
        print(f"  reason: {result['reason']}")


def judge_gate_surface(args, entry, code):
    """The gate's advisory hook: AFTER the verdict is computed, print ONE
    judge line. Default OFF. The classifier is asked to OPPOSE the gate's
    verdict (its allowability question is graded against admitting what the
    gate may have blocked / blocking what the gate admitted), so the two
    directions of K3 are real; the exit code is decided before this runs and
    is not passed through, so nothing here can move it. Returns the printed
    line (a str) or ``None`` when the judge is off."""
    if not _judge_enabled(args):
        return None
    signoff = entry.get("signoff", {})
    block_reason = ""
    if code != 0:
        reason = _block_reason(entry, signoff)
        block_reason = reason if reason != "not independently passed" else ""
    line = _judge_line(args, entry, signoff, code,
                       _gate_verdict_text(code), block_reason)
    if line:
        print(line)
    return line


# Gate-facing alias (what the mutation guard names).
_judge_gate_surface = judge_gate_surface


def cmd_judge(args):
    """The `gatesmith review judge` verb — informational, exit 0.

    Classifies the CURRENT change/registry: loads it through the gate's own
    chain-verified loader (an unreadable registry is exit 2, never a silent
    empty read), asks the classifier 3-5 typed questions, prints the verdict
    table, appends the audit receipt (the judge module writes it on every
    path). The classifier's verdict is advisory by definition here: this verb
    makes no gate decision, so its exit is 0 whatever the answers say — the
    same taxonomy the informational verbs use (G12).
    """
    registry = _registry(args)
    reg = load_reg(registry)
    entry = review(reg, args.id) if getattr(args, "id", None) else None
    signoff = (entry or {}).get("signoff", {})
    gate_verdict = "ABSENT"
    block_reason = "no review id given — classifying the registry, not a change"
    if entry is not None:
        if gate_granted(entry):
            gate_verdict = "OPEN"
            block_reason = ""
        else:
            gate_verdict = "BLOCKED"
            block_reason = _block_reason(entry, signoff)
    try:  # lazy, fault-isolated — same doctrine as the gate hook
        judge = _judge_module()
    except ImportError:  # pragma: no cover
        judge = None
    if judge is None:
        print("judge: unavailable (gatesmith.judge module is missing)")
        return 0
    result = judge.ask(
        judge_questions(),
        judge_state(entry or {"id": "(registry)", "tier": "C", "status": "n/a",
                              "executor": "(none)", "change": "(no change selected)",
                              "owned": [], "diff_sha": None},
                    signoff, 0, gate_verdict, block_reason))
    verdict = result.get("verdict")
    if verdict == "ok":
        print("JUDGE-VERDICT (advisory — the classifier does not gate):")
    elif verdict == "skipped":
        print("JUDGE-SKIPPED (advisory — not asked):")
    else:
        print("JUDGE-UNAVAILABLE (advisory — the classifier could not be reached):")
    _print_judge_table(result)
    if getattr(args, "json", False):
        print(json.dumps({"verdict": result.get("verdict"),
                          "reason": result.get("reason"),
                          "invocation_id": result.get("invocation_id"),
                          "answers": result.get("answers", {}),
                          "confidences": result.get("confidences", {})},
                         sort_keys=True))
    line = judge_summary(result)
    print(f"judge: {line}")
    return 0




def cmd_list(args):
    registry = _registry(args)
    reg = load_reg(registry)
    entries = reg.get("reviews", [])
    wanted = ("open", "blocked") if not args.all else None
    shown = [entry for entry in entries
             if wanted is None or entry["status"] in wanted]
    if not shown:
        print("no matching reviews")
    for entry in shown:
        signoff = entry["signoff"]
        # G11: closing retires a review — say so, do not present it as gating.
        retired = " (does not gate)" if entry["status"] == "closed" else ""
        print(f"{entry['id']}: [{entry['status']}] tier={entry.get('tier', 'C')} "
              f"executor={entry['executor']} "
              f"signoff={signoff['verdict']}/{signoff['reviewer'] or '-'}{retired} — {entry['change']}")
    # G9: bind over EVERY entry the verb holds, not only the ones a filter
    # happens to show — otherwise `list` (default filters to open/blocked) could
    # hide the unbound entry and still print a bare `seal: VERIFIED` while the
    # gate blocks for it.
    _print_seal_line(registry, entries, getattr(args, "allowed_signers", None),
                     [entry["signoff"]["reviewer"] for entry in entries])
    return 0


def cmd_close(args):
    registry = _registry(args)
    reg = load_reg(registry)
    entry = review(reg, args.id)
    if not entry:
        print(f"no review '{args.id}'", file=sys.stderr)
        return 1
    if entry["status"] == "closed":
        print(f"review '{args.id}' already closed", file=sys.stderr)
        return 1
    entry["status"] = "closed"
    entry["closed"] = {"at": now(), "by": args.by, "note": args.note or ""}
    save_reg(registry, reg)
    print(f"review '{args.id}' CLOSED ({args.note or 'no note'}) by {args.by} — "
          f"it can no longer gate.")
    return 0


def cmd_lookup(args):
    """Informational: 0 on a readable registry, 2 when it cannot be read (G12).

    Names the seal state honestly and binds the sealing principal to each hit's
    ``signoff.reviewer`` (G1/G9) — a hit whose reviewer is not the sealing
    principal is reported as NOT bound, never a bare ``VERIFIED``.
    """
    registry = _registry(args)
    reg = load_reg(registry)
    entries = reg.get("reviews", [])
    hits = [entry for entry in entries if entry.get("diff_sha") == args.diff_sha]
    if not hits:
        print(f"no gates with diff_sha {args.diff_sha[:12]}")
    for entry in hits:
        signoff = entry["signoff"]
        retired = " (does not gate)" if entry["status"] == "closed" else ""
        print(f"{entry['id']}: [{entry['status']}] tier={entry.get('tier', 'C')} "
              f"verdict={signoff['verdict']} reviewer={signoff['reviewer'] or '-'} "
              f"at={signoff['at']}{retired}")
    # G9: as in `list`, bind over every entry the registry holds.
    _print_seal_line(registry, entries, getattr(args, "allowed_signers", None),
                     [entry["signoff"]["reviewer"] for entry in entries])
    return 0


def cmd_seal(args):
    registry = _registry(args)
    reg = load_reg(registry)
    code, detail = seal.seal(registry, reg.get("reviews", []), args.key)
    if code != 0:
        print(f"SEAL-FAILED: {detail}", file=sys.stderr)
        return code
    head = chain.head_hash(reg.get("reviews", []))
    print(f"sealed '{registry}': head_hash={head} entries={len(reg.get('reviews', []))}")
    print(f"  digest:    {seal.digest_path(registry)}")
    print(f"  signature: {seal.sig_path(registry)}")
    return 0


def _binding_scope(entries, principals):
    """How many held entries the seal would NOT bind (F13).

    Returns ``(total, unbound)``. An entry counts as UNBOUND when its
    ``signoff.reviewer`` is absent/empty (unbindable — the gate blocks it with
    "has no reviewer") or names a principal outside ``principals``. This is the
    same principal→``signoff.reviewer`` test the gate applies, so the count can
    only ever be conservative.
    """
    entries = list(entries)
    unbound = 0
    for entry in entries:
        signoff = entry.get("signoff")
        reviewer = signoff.get("reviewer") if isinstance(signoff, dict) else None
        if not reviewer or reviewer not in principals:
            unbound += 1
    return len(entries), unbound


def _verify_scope_line(principals, entries, signer=None):
    """The F13 scope line: chain+seal result, admission explicitly NOT evaluated.

    ``verify`` answers the chain+seal question only — it does not apply the
    gate's reviewer-binding / signoff checks — so the line must never read as an
    admission decision. It names that scope, and when the registry holds entries
    the seal would NOT bind it says how many, so a caller cannot mistake the
    ``0`` for a green light.

    ``signer`` narrows the principals ``verify`` validated, but the gate
    evaluates ALL matched principals — so under ``--signer`` an absolute claim
    "gate will block" would be false whenever the unrestricted gate would in
    fact admit. In that case the clause names the restriction instead of
    asserting the gate's verdict (a false block is still a false statement).
    """
    names = ", ".join(principals) if principals else "?"
    line = (f"chain: sound · seal: valid (principal={names}) · "
            f"ADMISSION: not evaluated — run 'gate'")
    total, unbound_entries = _binding_scope(entries, principals)
    if not total:
        return line + " · no reviews in this registry"
    if unbound_entries:
        if signer:
            line += (f" · entries: {total}, of which {unbound_entries} would "
                     f"NOT bind --signer '{signer}' (the gate evaluates all "
                     f"matched principals)")
        else:
            # Scope the claim to the unbound entries: the gate is per-id, so on
            # a MIXED registry it may admit a bound entry — an unqualified
            # "gate will block" would be a false statement (round-5 Finding F3).
            line += (f" · entries: {total}, of which {unbound_entries} would "
                     f"NOT bind — the gate will block those entries")
    return line


def cmd_verify(args):
    """DECISION verb (0 verified / 1 failed / 2 could-not-check) — SEAL scope only.

    ``verify`` answers the CHAIN + SEAL question: is the hash chain sound, and
    does the detached seal validate against ``--allowed-signers`` (restricted to
    ``--signer`` when given)? It does **not** evaluate admission: it never
    applies the reviewer≠executor / pass-signoff / principal→``signoff.reviewer``
    binding the ``gate`` enforces, so a ``0`` here is NOT a green light to
    admit. The output says so (``ADMISSION: not evaluated — run 'gate'``) and,
    when the registry holds entries the seal would not bind, names how many. The
    exit codes are unchanged (0 chain+seal OK, 1 failed, 2 could-not-check).
    """
    registry = _registry(args)
    try:
        reg = load_reg(registry)
    except (chain.ChainBrokenError, chain.ChainStructureError,
            chain.LegacyRegistryError) as exc:
        print(f"verify FAILED: {exc}", file=sys.stderr)
        return 1
    warning = seal.trust_anchor_warning(args.allowed_signers)
    if warning:
        print(warning, file=sys.stderr)
    try:
        code, detail, principals = seal.verify(
            registry, reg.get("reviews", []), args.allowed_signers, signer=args.signer)
    except OSError as exc:
        print(f"verify FAILED: cannot read seal input — {exc}", file=sys.stderr)
        return 2
    if code == 0:
        print(_verify_scope_line(principals, reg.get("reviews", []), args.signer))
        return 0
    print(f"verify FAILED: {detail}", file=sys.stderr)
    return code


def add_parser(subparsers):
    parser = subparsers.add_parser("review", help="fail-closed two-agent review gate")
    parser.add_argument("--registry", default=None,
                        help=f"review registry (default: {DEFAULT_REGISTRY})")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("open")
    p.add_argument("--id", required=True)
    p.add_argument("--executor", required=True)
    p.add_argument("--change", required=True)
    p.add_argument("--owned", action="append")
    p.add_argument("--tier", choices=sorted(ALLOWED_TIERS))
    p.add_argument("--diff-sha")
    p.set_defaults(fn=cmd_open)

    p = sub.add_parser("sign")
    p.add_argument("--id", required=True)
    p.add_argument("--reviewer", required=True)
    p.add_argument("--verdict", required=True, choices=["pass", "block"])
    p.add_argument("--note")
    p.add_argument("--auto", action="store_true", help="byte-match re-sign (tier A only)")
    p.set_defaults(fn=cmd_sign)

    p = sub.add_parser("status")
    p.add_argument("--id", required=True)
    p.add_argument("--allowed-signers", metavar="PATH", dest="allowed_signers",
                   help="OPTIONAL trust anchor; when supplied, status re-derives the "
                        "gate's seal decision with it (VERIFIED / BLOCKED). Without it, "
                        "status reports the seal as UNVERIFIED — it does not check it")
    p.set_defaults(fn=cmd_status)

    p = sub.add_parser("gate")
    p.add_argument("--id", required=True)
    p.add_argument("--target", required=True, choices=sorted(ALLOWED_TARGETS))
    p.add_argument("--executor", default="")
    p.add_argument("--allowed-signers", metavar="PATH", dest="allowed_signers",
                   help="trust anchor (allowed_signers file); supply it from OUTSIDE the repo — "
                        "an anchor that resolves inside a git working tree is WARNED about, "
                        "not prevented")
    p.add_argument("--allow-unsealed", action="store_true", default=False,
                   help="DANGER: admit a registry that has NO seal, on chain+signoff only; "
                        "a PRESENT seal is still verified and can still block. Prints a "
                        "loud warning naming the residual risk it accepts")
    p.add_argument("--judge", action="store_true", default=False,
                   help="ADVISORY (does not gate): after the verdict, ask the "
                        "configured decision classifier (JUDGE_URL / JUDGE_MODEL, "
                        "default the OpenCode Zen free route) and print one "
                        "'judge:' line beside the gate verdict. The exit code is "
                        "ALWAYS the gate's own — advisory until calibrated "
                        "thresholds exist; receipts land in .gatesmith/")
    p.set_defaults(fn=cmd_gate)

    p = sub.add_parser("list")
    p.add_argument("--all", action="store_true")
    p.add_argument("--allowed-signers", metavar="PATH", dest="allowed_signers",
                   help="OPTIONAL trust anchor; when supplied, list verifies the seal with "
                        "it and reports VERIFIED / FAILED, else present (UNVERIFIED)")
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("close")
    p.add_argument("--id", required=True)
    p.add_argument("--note", required=True)
    p.add_argument("--by", default="founder")
    p.set_defaults(fn=cmd_close)

    p = sub.add_parser("lookup")
    p.add_argument("--diff-sha", required=True)
    p.add_argument("--allowed-signers", metavar="PATH", dest="allowed_signers",
                   help="OPTIONAL trust anchor; when supplied, lookup verifies the seal "
                        "with it and reports VERIFIED / FAILED, else present (UNVERIFIED)")
    p.set_defaults(fn=cmd_lookup)

    p = sub.add_parser("seal")
    p.add_argument("--key", required=True, metavar="PRIVATE_KEY",
                   help="ssh-keygen private key that signs the chain head")
    p.set_defaults(fn=cmd_seal)

    p = sub.add_parser("verify")
    p.add_argument("--allowed-signers", required=True, metavar="PATH", dest="allowed_signers",
                   help="trust anchor (allowed_signers file) supplied from outside the repo. "
                        "verify checks the CHAIN and the SEAL only — it does NOT evaluate "
                        "admission (reviewer binding, pass signoff); run 'gate' for that")
    p.add_argument("--signer", metavar="PRINCIPAL", default=None,
                   help="restrict verification to this principal")
    p.set_defaults(fn=cmd_verify)
    return parser
