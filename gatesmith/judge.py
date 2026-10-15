"""Typed-decision classifier client — the ``judge`` behind the advisory gate.

This module is a self-contained, zero-dependency client for a typed-decision
classifier HTTP route. It is vendor-neutral by configuration: the base URL and
model come from explicit arguments or the environment (``JUDGE_URL``,
``JUDGE_MODEL``); the documented default is the OpenCode Zen free route
(``jev-1.13-free``), whose measured wire contract is:

* ``POST <url>`` with ``Authorization: Bearer <key>``,
  ``Content-Type: application/json`` and ``User-Agent: opencode-go/jev-harness``
  (the default route's bot rules reject generic client user agents);
* body ``{"model": ..., "questions": {name: question}, "state": <str>}``;
* a ``choice`` question REQUIRES a criteria MAP ``{"allow": ..., "block": ...}``
  plus ``instructions`` — a criteria string or a bare ``options`` list is
  rejected by the route (HTTP 422) and by the client-side grammar check;
* ``score`` is unsupported on the route — use ``noul`` for a 0-1 scalar;
* answers come back typed, e.g.
  ``{"type": "choice", "choice": "block", "confidence": 0.98, "probabilities": {...}}``.

Design rules (v0.3.0 spec):

* **Fail graceful, never raise.** Every failure — network, auth, shape, usage —
  is returned as a verdict (``ok`` / ``unavailable`` / ``skipped``) with a named
  ``reason``. No exception ever escapes ``ask``.
* **Redaction before transmission.** Credential-shaped values in the ``state``
  payload (``key=value``, bearer tokens, connection-string passwords, long hex
  / base64 blobs, JWTs, well-known key prefixes) are masked before anything
  leaves the process, and the same redaction is applied defensively to every
  string written to the audit receipt.
* **Caps.** A per-instance call limit and a cumulative counter file bound how
  many HTTP calls can ever be made. Exceeding a cap is a NAMED skip
  (``verdict="skipped"``), never a silent partial state.
* **Append-only receipts.** Every invocation appends exactly one JSONL line:
  ``ts, invocation_id, route, model, question_keys, answers, confidences,
  verdict, reason, elapsed_s, state_sha256``. No secrets and no absolute home
  paths are ever written.

The deterministic gate never depends on this module; the judge only ever
SURFACES its verdict beside the gate's (that wiring lives in the CLI layer).
"""

import datetime as _dt
import hashlib
import json
import os
import re
import urllib.error
import urllib.request
import uuid

DEFAULT_URL = "https://opencode.ai/zen/v1/systemone"
DEFAULT_MODEL = "jev-1.13-free"
# The default route's bot rules reject generic client user agents; this value
# is part of the route's public wire contract and is configurable like everything
# else (JUDGE_USER_AGENT / user_agent=).
DEFAULT_USER_AGENT = "opencode-go/jev-harness"
DEFAULT_RECEIPT_PATH = os.path.join(".gatesmith", "judge-receipts.jsonl")
DEFAULT_COUNTER_PATH = os.path.join(".gatesmith", "judge-counter.json")
DEFAULT_MAX_CALLS = 8          # per Judge instance (one CLI invocation)
DEFAULT_TOTAL_CAP = 500        # cumulative, via the counter file
DEFAULT_TIMEOUT_S = 15.0

_VERDICT_OK = "ok"
_VERDICT_UNAVAILABLE = "unavailable"
_VERDICT_SKIPPED = "skipped"

# --- redaction ------------------------------------------------------------
#
# Credential-shaped shapes, masked BEFORE anything is sent or recorded.
# Over-masking is acceptable; leaking is not.

_CRED_SUBSTITUTIONS = [
    # labeled assignments: api_key=..., password: ..., "secret": ... etc.
    (re.compile(
        r"(?i)\b(api[_-]?key|apikey|access[_-]?key|secret|token|password|passwd|pwd|auth|credential)s?\b"
        r"(\s*[:=]\s*)([\"']?)[^\s\"',;}]+"),
     lambda m: m.group(1) + m.group(2) + m.group(3) + "[REDACTED]"),
    # bearer / basic auth headers
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"),
     lambda m: m.group(1) + " [REDACTED]"),
    # connection strings with inline credentials: scheme://user:pass@host
    # (the whole userinfo block is masked — usernames identify secrets stores)
    (re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s/@]+:[^\s/@]+@"),
     lambda m: m.group(0).split("://", 1)[0] + "://[REDACTED]@"),
    # JWTs (three base64url segments)
    (re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}"),
     "[REDACTED-JWT]"),
    # well-known key prefixes (cloud / dev tokens)
    (re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b"), "[REDACTED-AWS-KEY]"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"), "[REDACTED-KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "[REDACTED-KEY]"),
    (re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"), "[REDACTED-KEY]"),
    # long hex runs and long base64-looking blobs
    (re.compile(r"\b[0-9a-fA-F]{20,}\b"), "[REDACTED-HEX]"),
    (re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"), "[REDACTED-B64]"),
]


def redact_text(text):
    """Mask credential-shaped substrings in ``text``; everything else passes."""
    if not isinstance(text, str):
        return text
    for pattern, replacement in _CRED_SUBSTITUTIONS:
        text = pattern.sub(replacement, text)
    return text


def _redact_json(obj):
    """Recursively redact every string in a JSON-ready structure."""
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        return {key: _redact_json(val) for key, val in obj.items()}
    if isinstance(obj, list):
        return [_redact_json(val) for val in obj]
    return obj


# --- question grammar ------------------------------------------------------

def choice_question(name, instructions, allow, block):
    """Build a typed ``choice`` question (criteria MUST be a map)."""
    return {str(name): {
        "type": "choice",
        "criteria": {"allow": str(allow), "block": str(block)},
        "instructions": str(instructions),
    }}


def noul_question(name, instructions):
    """Build a typed ``noul`` question (0-1 scalar answer)."""
    return {str(name): {"type": "noul", "instructions": str(instructions)}}


def validate_questions(questions):
    """Return ``None`` when the question map is routable, else a named reason.

    Enforces the measured grammar client-side so a malformed question is
    refused BEFORE any HTTP call: ``choice`` needs a criteria MAP with
    ``allow``/``block`` strings plus ``instructions`` (a criteria string or a
    bare ``options`` list gets HTTP 422 from the route), ``noul`` needs
    ``instructions``, and ``score`` is refused outright.
    """
    if not isinstance(questions, dict) or not questions:
        return "invalid-question: questions must be a non-empty map"
    for name, question in questions.items():
        if not isinstance(name, str) or not name:
            return "invalid-question: question names must be non-empty strings"
        if not isinstance(question, dict):
            return f"invalid-question: {name} must be a map"
        qtype = question.get("type")
        if qtype == "score":
            return (f"invalid-question: {name} uses type 'score', which is "
                    f"unsupported on this route; use 'choice' or 'noul'")
        if qtype == "choice":
            criteria = question.get("criteria")
            if "options" in question:
                return (f"invalid-question: {name} uses a bare 'options' list; "
                        f"the route needs a criteria map with allow/block")
            if not isinstance(criteria, dict):
                return (f"invalid-question: {name} criteria must be a map with "
                        f"allow/block, not a string or absent")
            if not isinstance(criteria.get("allow"), str) or not isinstance(criteria.get("block"), str):
                return f"invalid-question: {name} criteria needs 'allow' and 'block' strings"
            if not isinstance(question.get("instructions"), str) or not question.get("instructions"):
                return f"invalid-question: {name} needs non-empty instructions"
        elif qtype == "noul":
            if not isinstance(question.get("instructions"), str) or not question.get("instructions"):
                return f"invalid-question: {name} needs non-empty instructions"
        else:
            return f"invalid-question: {name} has unsupported type {qtype!r}"
    return None


# --- answer parsing ---------------------------------------------------------

def _parse_answer(name, obj):
    """Normalize one typed answer; never raises."""
    if not isinstance(obj, dict):
        return {"error": f"bad-answer: {name} is not a map"}
    qtype = obj.get("type")
    if qtype == "choice" and isinstance(obj.get("choice"), str):
        confidence = obj.get("confidence")
        out = {"type": "choice", "answer": obj["choice"],
               "confidence": confidence if isinstance(confidence, (int, float)) else None}
        if isinstance(obj.get("probabilities"), dict):
            out["probabilities"] = obj["probabilities"]
        return out
    if qtype == "noul":
        value = obj.get("noul")
        if isinstance(value, (int, float)):
            return {"type": "noul", "answer": value, "confidence": value}
        return {"error": f"bad-answer: {name} noul value is not numeric"}
    return {"error": f"bad-answer: {name} has unknown answer type {qtype!r}",
            "raw": redact_text(json.dumps(obj))[:200]}


# --- counter file ------------------------------------------------------------

def _read_counter(path):
    """Best-effort read of the cumulative call counter; unreadable -> 0."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        total = data.get("total", 0)
        return total if isinstance(total, int) and total >= 0 else 0
    except (OSError, ValueError):
        return 0


def _bump_counter(path, amount):
    """Add ``amount`` to the counter file; best-effort, never raises."""
    total = _read_counter(path) + amount
    record = {"total": total,
              "updated": _utcnow()}
    try:
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(record, fh)
    except OSError:
        pass
    return total


# --- receipts ----------------------------------------------------------------

def _utcnow():
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def append_receipt(path, record, redact=True):
    """Append one JSONL line; returns (ok, error_reason).

    With ``redact=True`` (the default for direct callers) every string in
    ``record`` is redacted defensively before it is written. Callers that have
    already applied redaction — and restored the module-generated fields that
    a blanket regex would mangle (uuids, digests, timestamps) — pass
    ``redact=False``.
    """
    try:
        line = json.dumps(_redact_json(record) if redact else record, sort_keys=True)
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return True, None
    except Exception as exc:  # noqa: BLE001 — receipts must never break a run
        return False, f"receipt-write-failed: {type(exc).__name__}"


# --- the client ---------------------------------------------------------------

class Judge:
    """One classifier client for one invocation, with caps and receipts."""

    def __init__(self, url=None, model=None, api_key=None, user_agent=None,
                 timeout_s=None, receipt_path=None, counter_path=None,
                 max_calls=None, total_cap=None):
        env = lambda name, default: os.environ.get(name) or default  # noqa: E731
        self.url = url or env("JUDGE_URL", DEFAULT_URL)
        self.model = model or env("JUDGE_MODEL", DEFAULT_MODEL)
        self.api_key = api_key or env("JUDGE_API_KEY", "")
        self.user_agent = user_agent or env("JUDGE_USER_AGENT", DEFAULT_USER_AGENT)
        self.timeout_s = self._as_float(
            timeout_s if timeout_s is not None else env("JUDGE_TIMEOUT", DEFAULT_TIMEOUT_S),
            DEFAULT_TIMEOUT_S)
        self.receipt_path = receipt_path or env("JUDGE_RECEIPT", DEFAULT_RECEIPT_PATH)
        self.counter_path = counter_path or env("JUDGE_COUNTER", DEFAULT_COUNTER_PATH)
        self.max_calls = self._as_int(
            max_calls if max_calls is not None else env("JUDGE_MAX_CALLS", DEFAULT_MAX_CALLS),
            DEFAULT_MAX_CALLS)
        self.total_cap = self._as_int(
            total_cap if total_cap is not None else env("JUDGE_TOTAL_CAP", DEFAULT_TOTAL_CAP),
            DEFAULT_TOTAL_CAP)
        self.calls_used = 0

    @staticmethod
    def _as_float(value, default):
        try:
            return float(value)
        except (TypeError, ValueError):
            return float(default)

    @staticmethod
    def _as_int(value, default):
        try:
            return int(value)
        except (TypeError, ValueError):
            return int(default)

    # -- public entry point -------------------------------------------------

    def ask(self, questions, state):
        """Ask typed questions about ``state``; returns a verdict dict, never raises.

        Result shape::

            {"verdict": "ok" | "unavailable" | "skipped",
             "reason": str | None,
             "invocation_id": str, "route": str, "model": str,
             "answers": {name: {"type", "answer", "confidence", ...} | {"error": ...}},
             "confidences": {name: float | None},
             "elapsed_s": float, "calls_used": int,
             "receipt_written": bool}
        """
        invocation_id = uuid.uuid4().hex
        started = _dt.datetime.now(_dt.timezone.utc)
        result = {
            "verdict": _VERDICT_UNAVAILABLE,
            "reason": None,
            "invocation_id": invocation_id,
            "route": self.url,
            "model": self.model,
            "answers": {},
            "confidences": {},
            "elapsed_s": 0.0,
            "calls_used": 0,
            "receipt_written": False,
        }
        try:
            self._ask_inner(questions, state, invocation_id, started, result)
        except Exception as exc:  # noqa: BLE001 — no exception ever escapes
            result["verdict"] = _VERDICT_UNAVAILABLE
            result["reason"] = f"internal: {type(exc).__name__}"
        finally:
            result["elapsed_s"] = round(
                (_dt.datetime.now(_dt.timezone.utc) - started).total_seconds(), 3)
            self._write_receipt(result, questions, state)
        return result

    # -- internals -----------------------------------------------------------

    def _ask_inner(self, questions, state, invocation_id, started, result):
        result["calls_used"] = self.calls_used
        if not isinstance(state, (str, dict)):
            result["reason"] = "invalid-state: state must be a string or a map"
            return
        if isinstance(state, dict):
            # Canonical JSON: sorted keys, compact separators — the same state
            # always hashes to the same digest and reads the same on the wire.
            try:
                state = json.dumps(state, sort_keys=True, separators=(",", ":"))
            except (TypeError, ValueError) as exc:
                result["reason"] = f"invalid-state: not JSON-serializable ({type(exc).__name__})"
                return
        grammar_error = validate_questions(questions)
        if grammar_error:
            result["reason"] = grammar_error
            return
        if self.calls_used >= self.max_calls:
            result["verdict"] = _VERDICT_SKIPPED
            result["reason"] = (f"cap: per-invocation call limit "
                                f"({self.max_calls}) reached")
            return
        total_used = _read_counter(self.counter_path)
        if total_used + 1 > self.total_cap:
            result["verdict"] = _VERDICT_SKIPPED
            result["reason"] = f"cap: total-call limit ({self.total_cap}) reached"
            return
        if not self.api_key:
            result["reason"] = "auth: no API key configured (set JUDGE_API_KEY)"
            return

        # Redact BEFORE anything leaves the process.
        safe_state = redact_text(state)
        body = json.dumps({
            "model": self.model,
            "questions": questions,
            "state": safe_state,
        }).encode("utf-8")
        request = urllib.request.Request(
            self.url, data=body, method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": "Bearer " + self.api_key,
                "User-Agent": self.user_agent,
            })

        self.calls_used += 1
        result["calls_used"] = self.calls_used
        _bump_counter(self.counter_path, 1)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_s) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8", errors="replace")[:200]
            except Exception:  # noqa: BLE001
                detail = ""
            result["reason"] = f"http-{exc.code}: {redact_text(detail)}".strip()
            return
        except urllib.error.URLError as exc:
            result["reason"] = f"connect: {exc.reason}"
            return
        except TimeoutError:
            result["reason"] = f"timeout: no answer within {self.timeout_s}s"
            return
        except OSError as exc:
            result["reason"] = f"connect: {exc}"
            return

        try:
            data = json.loads(raw)
        except ValueError:
            result["reason"] = "bad-json: response was not JSON"
            return
        answers = data.get("answers") if isinstance(data, dict) else None
        if not isinstance(answers, dict):
            result["reason"] = "bad-shape: response has no answers map"
            return

        parsed = {}
        for name in questions:
            parsed[name] = _parse_answer(name, answers.get(name, {"type": "missing"}))
        result["answers"] = parsed
        result["confidences"] = {
            name: (entry.get("confidence") if isinstance(entry, dict) else None)
            for name, entry in parsed.items()}
        result["verdict"] = _VERDICT_OK
        return

    def _write_receipt(self, result, questions, state):
        record = {
            "ts": _utcnow(),
            "invocation_id": result["invocation_id"],
            "route": result["route"],
            "model": result["model"],
            "question_keys": sorted(questions) if isinstance(questions, dict) else [],
            "answers": result["answers"],
            "confidences": result["confidences"],
            "verdict": result["verdict"],
            "reason": result["reason"],
            "elapsed_s": result["elapsed_s"],
            "calls_used": result["calls_used"],
            "state_sha256": hashlib.sha256(state.encode("utf-8")).hexdigest()
            if isinstance(state, str) else None,
        }
        # Defense-in-depth redaction, then restore the fields this module
        # generated itself (uuid/digest/timestamp) so they survive intact.
        safe = _redact_json(record)
        if isinstance(safe, dict):
            # Restore only module-generated values that a blanket regex would
            # mangle AND that cannot carry a credential: uuid, digest, timestamp,
            # the verdict word, the question names.  route/model stay REDACTED
            # if they matched a credential shape (a custom endpoint URL with
            # inline user:pass must not survive into the receipt).
            for key in ("invocation_id", "state_sha256", "ts", "verdict",
                        "question_keys"):
                safe[key] = record[key]
        ok, error = append_receipt(self.receipt_path, safe, redact=False)
        result["receipt_written"] = ok
        if error:
            result["receipt_error"] = error


def ask(questions, state, **kwargs):
    """One-shot convenience: build a Judge from kwargs/env and ask once."""
    return Judge(**kwargs).ask(questions, state)
