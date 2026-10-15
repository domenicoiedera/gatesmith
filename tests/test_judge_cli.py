"""K3/K5 wiring tests: the judge surfaces beside the gate — and nothing more.

The classifier's opinion must behave like a weather report printed on the
same page as a building inspection: it may disagree, it may be absent, but it
can never change the inspection's outcome. These tests drive the real CLI
in-process (the same ``gatesmith.cli.main`` the console script calls), so the
wiring the mutation harness mutates is the wiring that runs.

Everything is offline: ``review.py`` consults the classifier only through
``gatesmith.judge.Judge``, which is pointed at an unreachable localhost port
(no route), or a local ``http.server`` thread that answers typed questions.
No test touches the network.

Run from the repo root: ``python -m unittest -v tests.test_judge_cli``.
"""

import http.server
import io
import json
import os
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from gatesmith import cli, review  # noqa: E402

# The exact question names review.judge_questions() builds, so the fake route
# answers every question the wiring asks (name drift must fail loudly, not
# silently score "unavailable").
_Q_EXEC = "executor_also_reviewer"
_Q_LANE = "lane_bounded"
_Q_GATE = "gate_allowable"
_Q_EVID = "evidence_supports"
_Q_CONF = "independence_confident"


def _fake_answers(choice_value, conf=0.91, noul=0.8):
    return {
        _Q_EXEC: {"type": "choice", "choice": choice_value, "confidence": conf},
        _Q_LANE: {"type": "choice", "choice": "bounded", "confidence": conf},
        _Q_GATE: {"type": "choice", "choice": choice_value, "confidence": conf},
        _Q_EVID: {"type": "choice", "choice": "evidenced", "confidence": conf},
        _Q_CONF: {"type": "noul", "noul": noul},
    }


class _FakeRoute(http.server.BaseHTTPRequestHandler):
    """Answers whatever ``mode`` says, like the real typed-decision route."""

    mode = "allow"
    received = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        if _FakeRoute.mode == "allow":
            chosen = "allow"
        elif _FakeRoute.mode == "block":
            chosen = "block"
        else:
            chosen = "allow"
        payload = {"answers": _fake_answers(chosen)}
        data = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):  # stdlib signature
        pass


def _start_route():
    """A local typed-decision stand-in on an ephemeral localhost port."""
    _FakeRoute.received = []
    _FakeRoute.mode = "allow"
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _FakeRoute)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/zen"


class JudgeCLITestBase(unittest.TestCase):
    """A throwaway registry, argv plumbing, and env hygiene, per test."""

    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="judge-cli-")
        self.registry = os.path.join(self.work, "reg.json")
        self._saved_env = {}

    def tearDown(self):
        for key, value in self._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    # -- helpers ---------------------------------------------------------

    def set_env(self, **kwargs):
        for key, value in kwargs.items():
            self._saved_env[key] = os.environ.get(key)
            os.environ[key] = value

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        try:
            with redirect_stdout(out), redirect_stderr(err):
                code = cli.main(list(argv))
        except SystemExit as exc:  # argparse errors raise SystemExit(2)
            code = exc.code if isinstance(exc.code, int) else 2
        return code, out.getvalue(), err.getvalue()

    def build_review(self, executor="agent-x", reviewer="reviewer-y"):
        """An open review, signed by the named reviewer (or left unsigned)."""
        self.run_cli("review", "--registry", self.registry, "open",
                     "--id", "r1", "--executor", executor,
                     "--change", "change the deploy script",
                     "--owned", "deploy.sh")
        if reviewer is not None:
            self.run_cli("review", "--registry", self.registry, "sign",
                         "--id", "r1", "--reviewer", reviewer, "--verdict", "pass")

    def gate(self, *extra):
        return self.run_cli("review", "--registry", self.registry, "gate",
                            "--id", "r1", "--target", "deploy", *extra)

    def judge_env(self, url):
        self.set_env(JUDGE_URL=url, JUDGE_API_KEY="test-key",
                     JUDGE_RECEIPT=os.path.join(self.work, "r.jsonl"),
                     JUDGE_COUNTER=os.path.join(self.work, "c.json"),
                     JUDGE_TIMEOUT="2")

    @staticmethod
    def stop(server):
        server.shutdown()
        server.server_close()


class JudgeGateWiringTest(JudgeCLITestBase):
    """The K3/K5 wiring: the judge line never moves the gate's decision."""

    def test_K3_judge_exit_code_guard(self):
        """The judge may disagree with the gate; the exit code never moves.

        Direction 1: the gate BLOCKS (self-review refused at sign, so no pass
        signoff exists) while the classifier answers `allow`. Falsifies the
        K3 mutation (``code = 0 if _judge_enabled(args) else _gate_decide(...)``
        ): with the mutation the gate exits 0 and this test goes red.
        """
        self.build_review(executor="agent-x", reviewer="agent-x")
        server, url = _start_route()
        try:
            self.judge_env(url)
            _FakeRoute.mode = "allow"
            code, out, err = self.gate("--judge", "--allow-unsealed")
            self.assertIn("GATE-BLOCKED", err)
            self.assertIn("judge:", out)
            self.assertIn("allow", out)
            self.assertEqual(code, 1, "the judge said allow; the gate must still block")
        finally:
            self.stop(server)

    def test_K3_gate_opens_while_judge_says_block(self):
        """Direction 2: the gate OPENS while the classifier answers `block`."""
        self.build_review(executor="agent-x", reviewer="reviewer-y")
        server, url = _start_route()
        try:
            self.judge_env(url)
            _FakeRoute.mode = "block"
            code, out, err = self.gate("--judge", "--allow-unsealed")
            self.assertIn("GATE-OPEN", out)
            self.assertIn("judge:", out)
            self.assertIn("block", out)
            self.assertEqual(code, 0, "the judge said block; the gate must still open")
        finally:
            self.stop(server)

    def test_K5_gate_must_surface_judge_line(self):
        """With `--judge`, the gate MUST print exactly one judge line.

        Falsifies the K5 mutation that deletes the surfacing call in
        ``cmd_gate``: the line disappears and this test goes red.
        """
        self.build_review(executor="agent-x", reviewer="reviewer-y")
        server, url = _start_route()
        try:
            self.judge_env(url)
            code, out, err = self.gate("--judge", "--allow-unsealed")
            self.assertEqual(code, 0)
            self.assertIn("GATE-OPEN", out)
            judge_lines = [line for line in out.splitlines()
                           if line.startswith("judge:")]
            self.assertEqual(len(judge_lines), 1,
                             f"expected exactly one judge line, got {judge_lines}")
        finally:
            self.stop(server)

    def test_judge_default_off(self):
        """No --judge and no JUDGE_URL: no judge line, no classifier call."""
        self.build_review(executor="agent-x", reviewer="reviewer-y")
        receipt = os.path.join(self.work, "r.jsonl")
        self.set_env(JUDGE_RECEIPT=receipt,
                     JUDGE_COUNTER=os.path.join(self.work, "c.json"))
        with mock.patch("gatesmith.judge.Judge.ask") as ask:
            code, out, err = self.gate("--allow-unsealed")
        self.assertEqual(code, 0)
        self.assertIn("GATE-OPEN", out)
        ask.assert_not_called()
        judge_lines = [line for line in out.splitlines()
                       if line.startswith("judge:")]
        self.assertEqual(judge_lines, [], "the judge must stay silent by default")
        self.assertFalse(os.path.exists(receipt), "no classifier call, no receipt")

    def test_judge_on_via_env_without_flag(self):
        """`--judge` absent but JUDGE_URL set → the judge line DOES appear.

        The spec's switch is the flag OR the environment; a caller that
        configures an endpoint has opted in even without the flag.
        """
        self.build_review(executor="agent-x", reviewer="reviewer-y")
        server, url = _start_route()
        try:
            self.judge_env(url)
            code, out, err = self.gate("--allow-unsealed")
            self.assertEqual(code, 0)
            self.assertIn("GATE-OPEN", out)
            self.assertIn("judge:", out)
        finally:
            self.stop(server)

    def test_offline_judge_open_side(self):
        """Offline + an OPEN gate: honest unavailable line, exit stays 0."""
        self.build_review(executor="agent-x", reviewer="reviewer-y")
        self.judge_env("http://127.0.0.1:1/zen")
        code, out, err = self.gate("--judge", "--allow-unsealed")
        self.assertEqual(code, 0)
        self.assertIn("GATE-OPEN", out)
        self.assertIn("judge: unavailable", out)
        self.assertNotIn("Traceback", err + out)

    def test_offline_judge_blocked_side(self):
        """Offline + a BLOCKING gate: same honest unavailable, exit stays 1."""
        self.build_review(executor="agent-x", reviewer="agent-x")
        self.judge_env("http://127.0.0.1:1/zen")
        code, out, err = self.gate("--judge", "--allow-unsealed")
        self.assertEqual(code, 1)
        self.assertIn("GATE-BLOCKED", err)
        self.assertIn("judge: unavailable", out)
        self.assertNotIn("Traceback", err + out)

    def test_missing_judge_module_degrades_to_a_line(self):
        """Even with the module gone, the gate prints a line and keeps its code."""
        self.build_review(executor="agent-x", reviewer="reviewer-y")
        self.judge_env("http://127.0.0.1:1/zen")
        with mock.patch.object(review, "_judge_module", return_value=None):
            code, out, err = self.gate("--judge", "--allow-unsealed")
        self.assertEqual(code, 0)
        self.assertIn("judge: unavailable (gatesmith.judge module is missing)", out)
        self.assertIn("GATE-OPEN", out)
        self.assertNotIn("Traceback", err + out)

    def test_gate_registry_unreadable_is_exit_2(self):
        """Same taxonomy at the gate: unreadable registry → 2, no judge line."""
        with open(self.registry, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        self.judge_env("http://127.0.0.1:1/zen")
        code, out, err = self.gate("--judge")
        self.assertEqual(code, 2, "a malformed registry must stay a usage error")
        self.assertNotIn("judge:", out)
        self.assertNotIn("Traceback", err + out)


class JudgeVerbTest(JudgeCLITestBase):
    """The `gatesmith judge` verb: verdict table, exit taxonomy, receipts."""

    def test_table_renders_and_exits_0(self):
        self.build_review()
        server, url = _start_route()
        try:
            self.judge_env(url)
            code, out, err = self.run_cli("judge", "--registry", self.registry,
                                          "--id", "r1")
            self.assertEqual(code, 0)
            self.assertIn("JUDGE-VERDICT", out)
            for name in (_Q_EXEC, _Q_LANE, _Q_GATE, _Q_EVID, _Q_CONF):
                self.assertIn(name, out)
            self.assertIn("0.91", out)
            self.assertIn("0.80", out)
            self.assertIn("allow", out)
            # The receipt: one JSONL line per call, append-only, keyed.
            with open(os.path.join(self.work, "r.jsonl"), encoding="utf-8") as fh:
                lines = [line for line in fh.read().splitlines() if line.strip()]
            self.assertEqual(len(lines), 1)
            record = json.loads(lines[0])
            for key in ("ts", "invocation_id", "route", "model", "question_keys",
                        "answers", "confidences", "verdict"):
                self.assertIn(key, record)
            self.assertEqual(record["question_keys"],
                              sorted([_Q_EXEC, _Q_LANE, _Q_GATE, _Q_EVID, _Q_CONF]))
        finally:
            self.stop(server)

    def test_offline_exit_0_with_unavailable(self):
        self.build_review()
        self.judge_env("http://127.0.0.1:1/zen")
        code, out, err = self.run_cli("judge", "--registry", self.registry,
                                      "--id", "r1")
        self.assertEqual(code, 0, "offline is informational, never an error")
        self.assertIn("JUDGE-UNAVAILABLE", out)
        self.assertIn("judge: unavailable", out)
        self.assertNotIn("Traceback", err + out)
        with open(os.path.join(self.work, "r.jsonl"), encoding="utf-8") as fh:
            lines = [line for line in fh.read().splitlines() if line.strip()]
        self.assertEqual(len(lines), 1, "exactly one receipt line, even offline")

    def test_usage_error_is_exit_2(self):
        code, out, err = self.run_cli("judge", "--not-a-flag")
        self.assertEqual(code, 2)
        self.assertNotIn("Traceback", err + out)

    def test_version_pin_still_holds(self):
        from gatesmith import __version__
        self.assertEqual(__version__, "0.3.0")
        with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as fh:
            self.assertIn('version = "0.3.0"', fh.read())


if __name__ == "__main__":
    unittest.main()
