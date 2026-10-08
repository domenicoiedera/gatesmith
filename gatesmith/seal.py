"""Detached SSHSIG over the review chain head, via ``ssh-keygen``.

The seal is the part of a review's proof that lives *outside* the artifact
under review: a signature over the chain head, verifiable only against an
``allowed_signers`` trust anchor the verifier supplies from outside the repo.
A seal the gate does not enforce is decoration, so the enforcing lives in
:mod:`gatesmith.review`; this module only produces and checks the cryptography.

Honesty — the guarantee is deliberately narrow. A seal proves *record
integrity*: the chain head it signs has not changed since it was signed, and
the signature was made by a key the verifier's anchor trusts. It proves nothing
about whether a review actually happened, or was any good, and it is **not**
proof against a write-capable actor who also holds the trust anchor — such an
actor can re-seal any registry they can rewrite. The trust boundary is the
anchor's *location* (see :func:`trust_anchor_warning`), not the seal itself.

``ssh-keygen`` is optional. Its absence fails *closed* for ``seal``/``verify``/
``gate`` and changes nothing for the other verbs. We never shell out to a
system ``openssl``: macOS ships LibreSSL, which has no Ed25519. Every subprocess
call carries a bounded ``timeout`` (see :data:`SUB_TIMEOUT`); a hung
``ssh-keygen`` is a usage error, never a hang.

Pinned preimage (a fixed-vector test pins it):

    ``gatesmith-seal:v1:<head_hash>:<entry_count>:<registry-path>``

signed in namespace ``gatesmith`` as ``ssh-keygen -Y sign -f <key> -n gatesmith
<digest-file>``. The sidecars are ``<registry>.digest`` (the preimage) and
``<registry>.sig`` (the SSHSIG). The ``<registry-path>`` in the preimage is
normalized by :func:`normalize_path`, so ``./reg.json`` and ``reg.json`` seal
and verify identically — seal and verify must be invoked with the same relative
path.
"""

import os
import shutil
import subprocess

from . import chain, proc

NAMESPACE = "gatesmith"
DIGEST_SUFFIX = ".digest"
SIG_SUFFIX = ".sig"
SUB_TIMEOUT = 30  # seconds — every ssh-keygen call is bounded


def ssh_keygen():
    """Path to ``ssh-keygen`` on PATH, or ``None`` when OpenSSH is absent."""
    return shutil.which("ssh-keygen")


def normalize_path(path):
    """Normalize a registry path for the signed preimage.

    ``./reg.json`` and ``reg.json`` must produce the same preimage, and a
    Windows-style separator must read as ``/`` (D7), so the preimage is
    identical no matter how the path was spelled. An empty path is returned
    unchanged.
    """
    if not path:
        return path
    return os.path.normpath(path).replace("\\", "/")


def digest_path(registry_path):
    return registry_path + DIGEST_SUFFIX


def sig_path(registry_path):
    return registry_path + SIG_SUFFIX


def preimage(head, count, registry_path):
    """The exact string that is signed — pinned, do not reorder the fields."""
    return f"gatesmith-seal:v1:{head}:{count}:{registry_path}"


def _leading_dash(path):
    """True for a path that would be parsed as an option, not a value (D6)."""
    return isinstance(path, str) and path.startswith("-")


def _run(argv, stdin=None):
    """Run ``ssh-keygen`` with an argv array — never a shell.

    Delegates to :func:`gatesmith.proc.run`, which kills the direct child on
    expiry and returns without draining its pipes (a grandchild that inherited
    the stdout pipe cannot hold the call past its bound). Only the text encoding
    and the timeout are pinned; the environment is left exactly as the caller's
    so the tool sees the same PATH the user does. A hung call raises
    :class:`subprocess.TimeoutExpired` for the caller to map to a usage error
    (D8).
    """
    return proc.run(argv, stdin=stdin, timeout=SUB_TIMEOUT)


def seal(registry_path, entries, key_path):
    """Sign the chain head of ``entries``.

    Returns ``(0, preimage_text)`` on success, ``(2, message)`` when it cannot
    seal: no ``ssh-keygen``, an option-like or missing key path, an I/O error
    writing the sidecars (fail-closed, D9), ``ssh-keygen`` refused, or it timed
    out (D8).
    """
    tool = ssh_keygen()
    if not tool:
        return (2, "ssh-keygen not found on PATH — cannot seal. Install OpenSSH "
                   "client tools, or admit the unsealed registry explicitly.")
    if _leading_dash(key_path):
        return (2, f"signing key path may not begin with '-': {key_path!r}")
    if not key_path or not os.path.isfile(key_path):
        return (2, f"signing key not found: {key_path!r}")
    head = chain.head_hash(entries)
    text = preimage(head, len(entries), registry_path)
    digest_file = digest_path(registry_path)
    produced = digest_file + SIG_SUFFIX
    try:
        # newline="" — write the preimage bytes verbatim, no platform translation.
        with open(digest_file, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
        result = _run([tool, "-Y", "sign", "-f", key_path, "-n", NAMESPACE, digest_file])
        if result.returncode != 0 or not os.path.isfile(produced):
            detail = (result.stderr or result.stdout or "").strip()
            return (2, f"ssh-keygen -Y sign failed (exit {result.returncode}): {detail}")
        os.replace(produced, sig_path(registry_path))
    except subprocess.TimeoutExpired:
        return (2, f"ssh-keygen timed out after {SUB_TIMEOUT}s while sealing")
    except OSError as exc:
        return (2, f"cannot write the seal sidecars next to {registry_path!r}: {exc}")
    return (0, text)


def _candidate_principals(allowed_signers):
    """Principals named in an ``allowed_signers`` file (first field, comma-list)."""
    names = []
    with open(allowed_signers, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            for name in line.split()[0].split(","):
                name = name.strip()
                if name and name not in names:
                    names.append(name)
    return names


def _verify_as(tool, allowed_signers, principal, sig_file, data_file):
    with open(data_file, "rb") as handle:
        return _run([tool, "-Y", "verify", "-f", allowed_signers, "-I", principal,
                     "-n", NAMESPACE, "-s", sig_file], stdin=handle)


def verify(registry_path, entries, allowed_signers, signer=None):
    """Check the seal against ``allowed_signers``.

    Returns ``(code, detail, principals)``. ``code`` is 0 when a trusted
    principal validated the seal; **1** when there is no seal present (missing
    ``.sig``/``.digest``), the recorded head no longer matches the chain (a
    stale seal), or no trusted key matches; and **2** when the check could not
    run at all — an unreadable/missing anchor, an option-like path, an I/O
    error, or ``ssh-keygen`` unavailable. The rule is "checked and failed → 1;
    could not check → 2". ``principals`` is the list of principals whose key
    validated the signature — the gate binds that to ``signoff.reviewer``.
    """
    tool = ssh_keygen()
    if not tool:
        return (2, "ssh-keygen not found on PATH — cannot verify a seal", [])
    if _leading_dash(allowed_signers):
        return (2, f"trust anchor path may not begin with '-': {allowed_signers!r}", [])
    sig_file = sig_path(registry_path)
    digest_file = digest_path(registry_path)
    try:
        if not os.path.isfile(sig_file):
            return (1, f"no seal present (no {sig_file} sidecar) — the registry "
                       f"is unsealed", [])
        if not os.path.isfile(digest_file):
            return (1, f"no seal present (no {digest_file} sidecar) — the registry "
                       f"is unsealed", [])
        if not allowed_signers or not os.path.isfile(allowed_signers):
            return (2, f"allowed_signers file not found: {allowed_signers!r}", [])
        expected = preimage(chain.head_hash(entries), len(entries), registry_path)
        with open(digest_file, encoding="utf-8", errors="replace") as handle:
            sealed = handle.read()
        if sealed != expected:
            return (1, "seal does not match the current chain head — the registry "
                       "changed after it was sealed", [])
        candidates = [signer] if signer else _candidate_principals(allowed_signers)
        matched = [name for name in candidates
                   if _verify_as(tool, allowed_signers, name, sig_file,
                                 digest_file).returncode == 0]
    except subprocess.TimeoutExpired:
        return (2, f"ssh-keygen timed out after {SUB_TIMEOUT}s while verifying", [])
    except OSError as exc:
        return (2, f"cannot read seal input — {exc}", [])
    if not matched:
        return (1, "no allowed signer validates the seal", [])
    return (0, "seal verified", matched)


def inspect(registry_path, entries, allowed_signers=None, signer=None):
    """Honest, anchor-aware seal state for a *reporting* verb (G1).

    Returns ``(state, detail, principals)`` where ``state`` is one of:

    * ``'none'``       — no ``.sig`` sidecar at all (nothing to enforce);
    * ``'unverified'`` — a ``.sig`` exists but no trust anchor was supplied, so
      NO verification ran — the reporting verb must say the seal was *not*
      checked, never that it is "sealed";
    * ``'verified'``   — ``ssh-keygen`` validated the signature against
      ``allowed_signers``;
    * ``'failed'``     — verification ran and did not succeed (checked-and-no);
    * ``'error'``      — verification could not run (unreadable anchor, or
      ``ssh-keygen`` unavailable).

    This is the same cryptography the gate enforces (:func:`verify`); it is the
    one source the informational verbs render, so none of them can claim a
    verification it did not perform. ``'fresh'`` (a ``.sig`` present with a
    matching ``.digest``) is deliberately NOT a state here: it is not
    verification, and the old renderer that treated it as "sealed" was a false
    oracle — a zero-byte signature satisfied it.
    """
    if not os.path.isfile(sig_path(registry_path)):
        return ("none", "no seal present", [])
    if not allowed_signers:
        return ("unverified", "no --allowed-signers anchor supplied, so the seal "
                              "was not verified", [])
    try:
        code, detail, principals = verify(registry_path, entries, allowed_signers,
                                          signer=signer)
    except OSError as exc:
        return ("error", f"cannot read seal input — {exc}", [])
    if code == 0:
        return ("verified", detail, principals)
    if code == 2:
        return ("error", detail, principals)
    return ("failed", detail, principals)


def repo_root(start):
    """Nearest ancestor of ``start`` containing a ``.git`` entry, or ``None``.

    No subprocess and no git invocation: a plain up-walk is enough to tell
    whether a path is inside a repository tree.
    """
    current = os.path.abspath(start)
    while True:
        if os.path.exists(os.path.join(current, ".git")):
            return current
        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent


def trust_anchor_warning(allowed_signers):
    """A warning when the trust anchor sits inside ANY git working tree (D4).

    The warning is computed from the anchor's **own** location — a repo-writable
    anchor proves nothing regardless of where the registry lives, so a registry
    outside every repo no longer hides the hole. It names the risk; it never
    silently trusts the file, and it never *prevents* the run: the constraint is
    procedural, not enforced.
    """
    if not allowed_signers:
        return None
    root = repo_root(os.path.dirname(os.path.abspath(allowed_signers)) or ".")
    if root is None:
        return None
    root = os.path.realpath(root)
    target = os.path.realpath(allowed_signers)
    if target == root or target.startswith(root + os.sep) or target.startswith(root + "/"):
        return (f"WARNING: trust anchor '{allowed_signers}' is INSIDE a git working "
                f"tree ({root}). A repo-writable trust anchor does not prove "
                f"independence — supply an allowed_signers file from OUTSIDE the repo.")
    return None
