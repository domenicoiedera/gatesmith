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
  verify --allowed-signers PATH [--signer PRINCIPAL]

The registry is hash-chained (see :mod:`gatesmith.chain`): every verb verifies
the chain before it reads, and a broken chain is a hard error. ``gate`` REQUIRES
a seal over the chain head — verified against a trust anchor the verifier
supplies from outside the repo — and binds the sealing principal to
``signoff.reviewer``, which must differ from ``entry.executor``. A registry with
no seal, or a seal that does not verify, is **blocked**; ``--allow-unsealed`` is
the explicit, loud opt-out that names the residual risk. ``seal`` and ``verify``
use the optional ``ssh-keygen``. New flags here are CLI-only in this wave —
there is no ``gatesmith.yaml`` wiring.

Exit codes (decision D5): 0 cleared / success, 1 blocked / failure, 2 usage or
unreadable input, and one taxonomy across the verbs.
  * ``gate``   — 1 on any integrity failure (chain broken / structure / legacy)
    and on a missing or non-verifying seal; 2 on a malformed registry shape
    (missing ``id``, wrong types, ``reviews`` not a list) or usage — always a
    clean message, never a traceback.
  * ``verify`` — 1 when the chain fails, no seal is present, or the seal does
    not verify; 2 on an unreadable registry/anchor or usage.
  * ``seal``   — 0 sealed; 2 cannot seal (no tool, I/O error, usage).
  * ``status`` / ``list`` / ``lookup`` — informational, always 0.

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


def _seal_label(registry, entries, anchor):
    """Render ``seal: <state>`` honestly for the informational verbs (G1).

    ``VERIFIED`` appears only after a real verification; a present-but-unchecked
    seal reads ``present (UNVERIFIED …)`` — never a bare ``sealed``.
    """
    outcome, detail, principals = _seal_verdict(registry, entries, None, anchor)
    if outcome == "verified":
        names = ", ".join(principals) if principals else "?"
        return f"VERIFIED (principal={names})"
    if outcome == "none":
        return "none"
    if outcome == "unverified":
        return "present (UNVERIFIED — pass --allowed-signers to verify)"
    return f"FAILED ({detail})"


def _print_seal_line(registry, entries, anchor):
    """Emit the D4 anchor warning (if any) then the honest ``seal:`` line."""
    if anchor:
        warning = seal.trust_anchor_warning(anchor)
        if warning:
            print(warning, file=sys.stderr)
    print(f"seal: {_seal_label(registry, entries, anchor)}")


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
    """Informational, always exit 0, and never a bare ``GATE: OPEN`` (D3/G1).

    The GATE line is one of ``BLOCKED: <reason>``, ``OPEN (seal VERIFIED)``,
    ``OPEN (UNSEALED — NOT ENFORCED)`` or ``OPEN (seal present, UNVERIFIED)``.
    It reports the gate's decision only when ``--allowed-signers`` is supplied,
    because then it re-derives it through the gate's own :func:`_seal_verdict`;
    without an anchor it says plainly that the seal was NOT verified.
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


def cmd_gate(args):
    registry = _registry(args)
    try:
        reg = load_reg(registry)
    except (chain.ChainBrokenError, chain.ChainStructureError,
            chain.LegacyRegistryError) as exc:
        print(f"GATE-BLOCKED: {exc}", file=sys.stderr)
        return 1
    entry = review(reg, args.id)
    if not entry:
        print(f"GATE-BLOCKED: no review '{args.id}' exists — nothing was reviewed.", file=sys.stderr)
        return 1
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
    blocked = _enforce_seal(args, registry, reg.get("reviews", []), signoff)
    if blocked is not None:
        return blocked
    print(f"GATE-OPEN: review '{args.id}' independently passed "
          f"({signoff['reviewer']}, tier {entry.get('tier', 'C')}); '{args.target}' may proceed.")
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
        print(f"{entry['id']}: [{entry['status']}] tier={entry.get('tier', 'C')} "
              f"executor={entry['executor']} "
              f"signoff={signoff['verdict']}/{signoff['reviewer'] or '-'} — {entry['change']}")
    _print_seal_line(registry, entries, getattr(args, "allowed_signers", None))
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
    """Informational, always exit 0 (D5); names the seal state honestly (G1)."""
    registry = _registry(args)
    reg = load_reg(registry)
    entries = reg.get("reviews", [])
    hits = [entry for entry in entries if entry.get("diff_sha") == args.diff_sha]
    if not hits:
        print(f"no gates with diff_sha {args.diff_sha[:12]}")
    for entry in hits:
        signoff = entry["signoff"]
        print(f"{entry['id']}: [{entry['status']}] tier={entry.get('tier', 'C')} "
              f"verdict={signoff['verdict']} reviewer={signoff['reviewer'] or '-'} "
              f"at={signoff['at']}")
    _print_seal_line(registry, entries, getattr(args, "allowed_signers", None))
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


def cmd_verify(args):
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
        print(f"verify OK: chain sound; seal signed by {', '.join(principals)}")
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
                   help="trust anchor (allowed_signers file) supplied from outside the repo")
    p.add_argument("--signer", metavar="PRINCIPAL", default=None,
                   help="restrict verification to this principal")
    p.set_defaults(fn=cmd_verify)
    return parser
