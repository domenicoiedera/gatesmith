"""Detached SSHSIG over the review chain head, via ``ssh-keygen``.

The seal is the part of a review's proof that lives *outside* the artifact
under review: a signature over the chain head, verifiable only against an
``allowed_signers`` trust anchor the verifier supplies from outside the repo.
A seal the gate does not enforce is decoration, so the enforcing lives in
:mod:`gatesmith.review`; this module only produces and checks the cryptography.

``ssh-keygen`` is optional. Its absence fails *closed* for ``seal`` and
``verify`` and changes nothing for the other verbs. We never shell out to a
system ``openssl``: macOS ships LibreSSL, which has no Ed25519.

Pinned preimage (a fixed-vector test pins it):

    ``gatesmith-seal:v1:<head_hash>:<entry_count>:<registry-path>``

signed in namespace ``gatesmith`` as ``ssh-keygen -Y sign -f <key> -n gatesmith
<digest-file>``. The sidecars are ``<registry>.digest`` (the preimage) and
``<registry>.sig`` (the SSHSIG).
"""

import os
import shutil
import subprocess

from . import chain

NAMESPACE = "gatesmith"
DIGEST_SUFFIX = ".digest"
SIG_SUFFIX = ".sig"


def ssh_keygen():
    """Path to ``ssh-keygen`` on PATH, or ``None`` when OpenSSH is absent."""
    return shutil.which("ssh-keygen")


def digest_path(registry_path):
    return registry_path + DIGEST_SUFFIX


def sig_path(registry_path):
    return registry_path + SIG_SUFFIX


def preimage(head, count, registry_path):
    """The exact string that is signed — pinned, do not reorder the fields."""
    return f"gatesmith-seal:v1:{head}:{count}:{registry_path}"


def _run(argv, stdin=None):
    """Run ``ssh-keygen`` with an argv array — never a shell.

    Only the text encoding is pinned; the environment is left exactly as the
    caller's so the tool sees the same PATH the user does.
    """
    return subprocess.run(argv, stdin=stdin, capture_output=True, shell=False,
                          encoding="utf-8", errors="replace")


def seal(registry_path, entries, key_path):
    """Sign the chain head of ``entries``.

    Returns ``(0, preimage_text)`` on success, ``(2, message)`` when it cannot
    seal (no ``ssh-keygen``, no key, or ``ssh-keygen`` refused).
    """
    tool = ssh_keygen()
    if not tool:
        return (2, "ssh-keygen not found on PATH — cannot seal. Install OpenSSH "
                   "client tools, or skip sealing; the chain is still verified.")
    if not key_path or not os.path.isfile(key_path):
        return (2, f"signing key not found: {key_path!r}")
    head = chain.head_hash(entries)
    text = preimage(head, len(entries), registry_path)
    digest_file = digest_path(registry_path)
    # newline="" — write the preimage bytes verbatim, with no platform translation.
    with open(digest_file, "w", encoding="utf-8", newline="") as handle:
        handle.write(text)
    result = _run([tool, "-Y", "sign", "-f", key_path, "-n", NAMESPACE, digest_file])
    produced = digest_file + SIG_SUFFIX
    if result.returncode != 0 or not os.path.isfile(produced):
        detail = (result.stderr or result.stdout or "").strip()
        return (2, f"ssh-keygen -Y sign failed (exit {result.returncode}): {detail}")
    os.replace(produced, sig_path(registry_path))
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
    principal validated the seal, 1 when the seal is stale or no trusted key
    matches, and 2 when an input is missing or ``ssh-keygen`` is unavailable.
    ``principals`` is the list of principals whose key validated the signature —
    the gate binds that to ``signoff.reviewer``.
    """
    tool = ssh_keygen()
    if not tool:
        return (2, "ssh-keygen not found on PATH — cannot verify a seal", [])
    sig_file = sig_path(registry_path)
    if not os.path.isfile(sig_file):
        return (2, f"no signature sidecar at {sig_file}", [])
    digest_file = digest_path(registry_path)
    if not os.path.isfile(digest_file):
        return (2, f"no digest sidecar at {digest_file}", [])
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
               if _verify_as(tool, allowed_signers, name, sig_file, digest_file).returncode == 0]
    if not matched:
        return (1, "no allowed signer validates the seal", [])
    return (0, "seal verified", matched)


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


def trust_anchor_warning(allowed_signers, registry_path):
    """A warning when the trust anchor sits inside the repo, else ``None``.

    A trust anchor the repository under review can rewrite proves nothing — the
    warning names the risk; it never silently trusts the file.
    """
    root = repo_root(os.path.dirname(os.path.abspath(registry_path)) or ".")
    if root is None or not allowed_signers:
        return None
    root = os.path.realpath(root)
    target = os.path.realpath(allowed_signers)
    if target == root or target.startswith(root + os.sep):
        return (f"WARNING: trust anchor '{allowed_signers}' is INSIDE the repository "
                f"tree ({root}). A repo-writable trust anchor does not prove "
                f"independence — supply an allowed_signers file from OUTSIDE the repo.")
    return None
