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
  gate   --id ID --target push|deploy|migrate [--executor ROLE] [--allowed-signers PATH]
  list   [--all]
  close  --id ID --note TEXT [--by ROLE]
  lookup --diff-sha SHA
  seal   --key PRIVATE_KEY
  verify --allowed-signers PATH [--signer PRINCIPAL]

The registry is hash-chained (see :mod:`gatesmith.chain`): every verb verifies
the chain before it reads, and a broken chain is a hard error. ``gate`` also
verifies the seal when one is present, and binds the sealing principal to
``signoff.reviewer``, which must differ from ``entry.executor``. ``seal`` and
``verify`` use the optional ``ssh-keygen``; the trust anchor is an
``allowed_signers`` file the verifier supplies from outside the repo. New
flags here are CLI-only in this wave — there is no ``gatesmith.yaml`` wiring.

Exit codes: 0 cleared / success, 1 blocked / failure, 2 usage or unreadable
input. Chain failure is a block (1) at the gate and a usage error (2) elsewhere.
"""

import datetime
import os
import sys

from . import chain, config, seal, store

DEFAULT_REGISTRY = "./review-registry.json"
ALLOWED_TARGETS = {"push", "deploy", "migrate"}
ALLOWED_TIERS = {"A", "B", "C"}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _registry(args):
    return config.get(args, "review", "registry", DEFAULT_REGISTRY)


def load_reg(path):
    """Load the review registry, verifying the hash chain.

    An absent or empty file is a fresh registry (nothing declared yet). A file
    that exists is verified as a v2 hash chain: a broken chain, a missing chain
    field, or a pre-chain (marker-less) registry all raise, so no verb can read
    a tampered chain as if it were sound.
    """
    present = bool(path) and os.path.exists(path) and os.path.getsize(path) > 0
    reg = store.load_json(path, {"gatesmith_registry": {"v": chain.CHAIN_VERSION},
                                 "reviews": []})
    if not present:
        reg.setdefault("gatesmith_registry", {"v": chain.CHAIN_VERSION})
        reg.setdefault("reviews", [])
        return reg
    chain.verify_chain(reg)
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


def cmd_open(args):
    reg = load_reg(_registry(args))
    if review(reg, args.id):
        print(f"review '{args.id}' already exists", file=sys.stderr)
        return 1
    tier = (args.tier or "C").upper()
    if tier not in ALLOWED_TIERS:
        print(f"tier must be one of {sorted(ALLOWED_TIERS)}", file=sys.stderr)
        return 2
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
    reg = load_reg(_registry(args))
    entry = review(reg, args.id)
    if not entry:
        print(f"no review '{args.id}'", file=sys.stderr)
        return 1
    signoff = entry["signoff"]
    granted = gate_granted(entry)
    print(f"review '{args.id}': status={entry['status']} executor={entry['executor']} "
          f"tier={entry.get('tier', 'C')}")
    print(f"  change: {entry['change']}")
    if entry.get("diff_sha"):
        print(f"  diff_sha: {entry['diff_sha']}")
    print(f"  signoff: verdict={signoff['verdict']} reviewer={signoff['reviewer']}")
    if signoff["note"]:
        print(f"  note: {signoff['note']}")
    print(f"  GATE: {'OPEN (independent pass)' if granted else 'BLOCKED'}")
    return 0


def _enforce_seal(args, registry, reg, entry, signoff):
    """Verify a present seal and bind its principal; ``None`` means admitted.

    A chain-broken registry is handled by the caller (gate exit 1). Here we
    handle the seal: when a ``<registry>.sig`` sidecar exists the gate MUST
    verify it and MUST confirm the sealing principal equals ``signoff.reviewer``
    (already known to differ from the executor). No seal sidecar means the
    registry was never sealed — the chain and signoff checks stand, as before.
    """
    if not os.path.exists(seal.sig_path(registry)):
        return None
    anchor = getattr(args, "allowed_signers", None)
    if not anchor:
        print("GATE-BLOCKED: registry is sealed but no --allowed-signers trust "
              "anchor was supplied — the seal cannot be verified (failing closed).",
              file=sys.stderr)
        return 1
    warning = seal.trust_anchor_warning(anchor, registry)
    if warning:
        print(warning, file=sys.stderr)
    code, detail, principals = seal.verify(registry, reg.get("reviews", []), anchor)
    if code != 0:
        print(f"GATE-BLOCKED: seal verification failed — {detail}", file=sys.stderr)
        return 1
    if signoff["reviewer"] not in principals:
        print(f"GATE-BLOCKED: sealing principal {principals} != signoff.reviewer "
              f"'{signoff['reviewer']}' — the seal does not bind this reviewer.",
              file=sys.stderr)
        return 1
    return None


def cmd_gate(args):
    registry = _registry(args)
    try:
        reg = load_reg(registry)
    except chain.ChainBrokenError as exc:
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
    blocked = _enforce_seal(args, registry, reg, entry, signoff)
    if blocked is not None:
        return blocked
    print(f"GATE-OPEN: review '{args.id}' independently passed "
          f"({signoff['reviewer']}, tier {entry.get('tier', 'C')}); '{args.target}' may proceed.")
    return 0


def cmd_list(args):
    reg = load_reg(_registry(args))
    wanted = ("open", "blocked") if not args.all else None
    shown = [entry for entry in reg.get("reviews", [])
             if wanted is None or entry["status"] in wanted]
    if not shown:
        print("no matching reviews")
        return 0
    for entry in shown:
        signoff = entry["signoff"]
        print(f"{entry['id']}: [{entry['status']}] tier={entry.get('tier', 'C')} "
              f"executor={entry['executor']} "
              f"signoff={signoff['verdict']}/{signoff['reviewer'] or '-'} — {entry['change']}")
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
    reg = load_reg(_registry(args))
    hits = [entry for entry in reg.get("reviews", [])
            if entry.get("diff_sha") == args.diff_sha]
    if not hits:
        print(f"no gates with diff_sha {args.diff_sha[:12]}")
        return 1
    for entry in hits:
        signoff = entry["signoff"]
        print(f"{entry['id']}: [{entry['status']}] tier={entry.get('tier', 'C')} "
              f"verdict={signoff['verdict']} reviewer={signoff['reviewer'] or '-'} "
              f"at={signoff['at']}")
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
    reg = load_reg(registry)
    warning = seal.trust_anchor_warning(args.allowed_signers, registry)
    if warning:
        print(warning, file=sys.stderr)
    code, detail, principals = seal.verify(
        registry, reg.get("reviews", []), args.allowed_signers, signer=args.signer)
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
    p.set_defaults(fn=cmd_status)

    p = sub.add_parser("gate")
    p.add_argument("--id", required=True)
    p.add_argument("--target", required=True, choices=sorted(ALLOWED_TARGETS))
    p.add_argument("--executor", default="")
    p.add_argument("--allowed-signers", metavar="PATH", dest="allowed_signers",
                   help="trust anchor (allowed_signers file) supplied from outside the repo")
    p.set_defaults(fn=cmd_gate)

    p = sub.add_parser("list")
    p.add_argument("--all", action="store_true")
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("close")
    p.add_argument("--id", required=True)
    p.add_argument("--note", required=True)
    p.add_argument("--by", default="founder")
    p.set_defaults(fn=cmd_close)

    p = sub.add_parser("lookup")
    p.add_argument("--diff-sha", required=True)
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
