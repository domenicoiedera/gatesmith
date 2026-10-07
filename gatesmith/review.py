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
    (missing ``id``, wrong types) or usage — always a clean message, never a
    traceback.
  * ``verify`` — 1 when the chain fails, no seal is present, or the seal does
    not verify; 2 on an unreadable registry/anchor or usage.
  * ``seal``   — 0 sealed; 2 cannot seal (no tool, I/O error, usage).
  * ``status`` / ``list`` / ``lookup`` — informational, always 0.
"""

import datetime
import os
import sys

from . import chain, config, seal, store

DEFAULT_REGISTRY = "./review-registry.json"
ALLOWED_TARGETS = {"push", "deploy", "migrate"}
ALLOWED_TIERS = {"A", "B", "C"}
ENTRY_REQUIRED = ("id", "executor", "change", "status")
SIGNOFF_REQUIRED = ("reviewer", "verdict", "note", "at", "auto")


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


def _check_shape(reg):
    """Reject an entry the commands cannot read — exit 2, never a traceback.

    The chain guarantees an entry is a JSON object; it does not guarantee the
    fields a verb indexes. A missing ``id`` used to surface as a ``KeyError``
    traceback; here it is a clean malformed-shape error.
    """
    for index, entry in enumerate(reg.get("reviews", [])):
        missing = [key for key in ENTRY_REQUIRED if key not in entry]
        signoff = entry.get("signoff")
        if not isinstance(signoff, dict):
            missing.append("signoff")
        else:
            missing += [f"signoff.{key}" for key in SIGNOFF_REQUIRED if key not in signoff]
        if missing:
            raise MalformedRegistryError(
                f"entry {index} is missing required field(s): {', '.join(missing)}")


def load_reg(path):
    """Load the review registry, verifying the hash chain.

    An absent or empty file is a fresh registry (nothing declared yet). A file
    that exists is verified as a v2 hash chain: a broken chain, a missing chain
    field, or a pre-chain (marker-less) registry all raise, so no verb can read
    a tampered chain as if it were sound. A structurally usable chain whose
    entries are still the wrong shape raises :class:`MalformedRegistryError`.
    """
    present = bool(path) and os.path.exists(path) and os.path.getsize(path) > 0
    reg = store.load_json(path, {"gatesmith_registry": {"v": chain.CHAIN_VERSION},
                                 "reviews": []})
    if not present:
        reg.setdefault("gatesmith_registry", {"v": chain.CHAIN_VERSION})
        reg.setdefault("reviews", [])
        return reg
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


def _seal_label(registry, entries):
    """One-line seal state for the informational verbs (never a bare oracle)."""
    return {
        "fresh": "sealed",
        "stale": "UNSEALED — NOT ENFORCED (stale seal)",
        "absent": "UNSEALED — NOT ENFORCED (no seal)",
    }[seal.sidecar_state(registry, entries)]


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
    """Informational, always exit 0, and never a bare ``GATE: OPEN`` (D3)."""
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
    elif seal.sidecar_state(registry, reg.get("reviews", [])) == "fresh":
        print("  GATE: OPEN (sealed)")
    else:
        print("  GATE: OPEN (UNSEALED — NOT ENFORCED)")
    return 0


def _enforce_seal(args, registry, entries, signoff):
    """Enforce the seal. Returns ``None`` when admitted, else an exit code.

    By default the seal is REQUIRED (D1): the actor being governed never
    decides whether evidence is required, so a missing seal — or one that does
    not verify — blocks with 1. ``--allow-unsealed`` is the only way to admit
    an unsealed registry, and it prints a loud warning naming the residual risk.
    """
    has_seal = os.path.exists(seal.sig_path(registry))
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
    anchor = getattr(args, "allowed_signers", None)
    if not anchor:
        print("GATE-BLOCKED: registry is sealed but no --allowed-signers trust "
              "anchor was supplied — the seal cannot be verified (failing closed).",
              file=sys.stderr)
        return 1
    warning = seal.trust_anchor_warning(anchor)
    if warning:
        print(warning, file=sys.stderr)
    try:
        code, detail, principals = seal.verify(registry, entries, anchor)
    except OSError as exc:
        print(f"GATE-BLOCKED: cannot read seal input — {exc}", file=sys.stderr)
        return 2
    if code == 2:
        print(f"GATE-BLOCKED: the seal cannot be verified — {detail}", file=sys.stderr)
        return 2
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
    print(f"seal: {_seal_label(registry, entries)}")
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
    """Informational, always exit 0 (D5); names the seal state (D3)."""
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
    print(f"seal: {_seal_label(registry, entries)}")
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
                   help="DANGER: admit an unsealed registry on chain+signoff only; "
                        "prints a loud warning and skips the seal entirely")
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
