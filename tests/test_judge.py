"""Tests for gatesmith.judge — the typed-decision classifier client.

Everything runs offline against stdlib primitives: a local ``http.server``
thread stands in for the classifier route, and an unreachable localhost port
stands in for "offline". No test touches the network.

Run from the repo root: ``python -m unittest -v tests.test_judge``.
"""

import http.server
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from gatesmith import judge  # noqa: E402

FAKE_SECRET = "sk-FAKEPLANTEDKEY0123456789abcdef"
FAKE_BEARER = "bearer BqZ7xKp2mN9wRtY4uV6sX8aQ1eF3hG5j"
FAKE_CONN = "postgres://svc_admin:s3cr3t-pw@db.internal.example:5432/prod"
FAKE_HEX = "deadbeefcafebabe0123456789abcdef01234567"
FAKE_AWS = "AKIAIOSFODNN7EXAMPLE"

STATE_WITH_SECRETS = (
    "rotate staging deploy key. api_key=" + FAKE_SECRET
    + "; auth header was " + FAKE_BEARER
    + "; dsn " + FAKE_CONN
    + "; old hash " + FAKE_HEX
    + "; aws key " + FAKE_AWS
)

CHOICE_OK = {"type": "choice", "choice": "block", "confidence": 0.98,
             "probabilities": {"allow": 0.01, "block": 0.99}}
NOUL_OK = {"type": "noul", "noul": 0.47}


def _choice_questions():
    return judge.choice_question(
        "separation_of_duties",
        "Decide whether the change violates separation of duties.",
        "executor and reviewer are independent",
        "the executor also reviewed its own diff")


class _FakeRoute(http.server.BaseHTTPRequestHandler):
    """Records the request bodies it receives; answers like the real route."""

    received = []
    mode = "ok"
    delay = 0.0

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")
        _FakeRoute.received.append({"body": body,
                                    "auth": self.headers.get("Authorization"),
                                    "ua": self.headers.get("User-Agent")})
        if _FakeRoute.delay:
            time.sleep(_FakeRoute.delay)
        if _FakeRoute.mode == "ok":
            payload = {"model": "jev-1.13-free",
                       "answers": {"separation_of_duties": CHOICE_OK,
                                   "risk": NOUL_OK},
                       "usage": {"input_tokens": 10, "output_tokens": 2}}
            code = 200
        elif _FakeRoute.mode == "http422":
            payload = {"error": {"type": "server_error",
                                 "message": "Endpoint is unavailable."}}
            code = 422
        else:
            payload = {"not": "answers"}
            code = 200
        data = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):  # stdlib signature  # keep the test output clean
        pass


class _NoulsRoute(http.server.BaseHTTPRequestHandler):
    """Answers a question key that was not asked (shape-drift probe)."""

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        data = json.dumps({"answers": {"someone_else": CHOICE_OK}}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):  # stdlib signature
        pass


class JudgeHTTPTestCase(unittest.TestCase):
    """The happy path and HTTP error paths, served by a local fake route."""

    @classmethod
    def setUpClass(cls):
        _FakeRoute.received = []
        _FakeRoute.mode = "ok"
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _FakeRoute)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="judge-")
        self.receipt = os.path.join(self.work, "receipts.jsonl")
        self.counter = os.path.join(self.work, "counter.json")
        _FakeRoute.received = []
        _FakeRoute.mode = "ok"
        _FakeRoute.delay = 0.0

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def _judge(self, **kwargs):
        kwargs.setdefault("url", f"http://127.0.0.1:{self.port}/systemone")
        kwargs.setdefault("api_key", "test-key-not-a-real-credential")
        kwargs.setdefault("receipt_path", self.receipt)
        kwargs.setdefault("counter_path", self.counter)
        return judge.Judge(**kwargs)

    def test_ok_choice_and_noul_typed_answers(self):
        result = self._judge().ask(
            dict(_choice_questions(), **judge.noul_question("risk", "How risky?")),
            "executor also reviewed its own diff")
        self.assertEqual(result["verdict"], "ok")
        self.assertIsNone(result["reason"])
        self.assertEqual(result["answers"]["separation_of_duties"]["answer"], "block")
        self.assertAlmostEqual(result["answers"]["separation_of_duties"]["confidence"], 0.98)
        self.assertAlmostEqual(result["answers"]["risk"]["answer"], 0.47)
        self.assertEqual(result["confidences"]["risk"], 0.47)
        self.assertEqual(result["calls_used"], 1)

    def test_wire_shape_model_questions_state_and_ua(self):
        self._judge().ask(_choice_questions(), "some state")
        sent = json.loads(_FakeRoute.received[0]["body"])
        self.assertEqual(sent["model"], "jev-1.13-free")
        self.assertIn("questions", sent)
        self.assertEqual(sent["state"], "some state")
        self.assertIn("separation_of_duties", sent["questions"])
        question = sent["questions"]["separation_of_duties"]
        self.assertEqual(question["type"], "choice")
        self.assertIsInstance(question["criteria"], dict)
        self.assertIn("allow", question["criteria"])
        self.assertIn("block", question["criteria"])
        self.assertEqual(_FakeRoute.received[0]["ua"], "opencode-go/jev-harness")

    def test_state_is_redacted_before_transmission(self):
        self._judge().ask(_choice_questions(), STATE_WITH_SECRETS)
        body = _FakeRoute.received[0]["body"]
        for secret in (FAKE_SECRET, FAKE_BEARER, FAKE_CONN, FAKE_HEX, FAKE_AWS,
                       "s3cr3t-pw", "svc_admin"):
            self.assertNotIn(secret, body)
        self.assertIn("[REDACTED", body)

    def test_http_error_is_named_not_raised(self):
        _FakeRoute.mode = "http422"
        result = self._judge().ask(_choice_questions(), "state")
        self.assertEqual(result["verdict"], "unavailable")
        self.assertTrue(result["reason"].startswith("http-422"))
        self.assertEqual(result["answers"], {})

    def test_bad_shape_is_named_not_raised(self):
        _FakeRoute.mode = "badshape"
        result = self._judge().ask(_choice_questions(), "state")
        self.assertEqual(result["verdict"], "unavailable")
        self.assertEqual(result["reason"], "bad-shape: response has no answers map")

    def test_missing_answer_key_is_reported_per_question(self):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _NoulsRoute)
        try:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            result = self._judge(url=f"http://127.0.0.1:{server.server_address[1]}/s") \
                .ask(_choice_questions(), "state")
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(result["verdict"], "ok")
        self.assertIn("error", result["answers"]["separation_of_duties"])
        self.assertIn("bad-answer", result["answers"]["separation_of_duties"]["error"])

    def test_timeout_is_named_not_raised(self):
        _FakeRoute.delay = 5.0
        result = self._judge(timeout_s=0.4).ask(_choice_questions(), "state")
        self.assertEqual(result["verdict"], "unavailable")
        self.assertTrue(result["reason"].startswith(("connect", "timeout")))

    def test_auth_header_is_sent_but_never_recorded(self):
        self._judge().ask(_choice_questions(), "state")
        self.assertTrue(_FakeRoute.received[0]["auth"].startswith("Bearer "))
        self._judge().ask(_choice_questions(), "state")
        receipt = open(self.receipt, encoding="utf-8").read()
        self.assertNotIn("test-key-not-a-real-credential", receipt)


class JudgeOfflineTestCase(unittest.TestCase):
    """K2: unreachable route -> verdict unavailable, exit-able, one receipt."""

    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="judge-offline-")
        self.receipt = os.path.join(self.work, "receipts.jsonl")
        self.counter = os.path.join(self.work, "counter.json")

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def _judge(self, url):
        return judge.Judge(url=url, api_key="k", receipt_path=self.receipt,
                           counter_path=self.counter, timeout_s=2.0)

    def test_connection_refused_is_unavailable_with_reason(self):
        result = self._judge("http://127.0.0.1:1/systemone") \
            .ask(_choice_questions(), "state")
        self.assertEqual(result["verdict"], "unavailable")
        self.assertTrue(result["reason"])
        self.assertEqual(result["answers"], {})

    def test_offline_writes_exactly_one_receipt_line(self):
        self._judge("http://127.0.0.1:1/systemone").ask(_choice_questions(), "state")
        lines = open(self.receipt, encoding="utf-8").read().splitlines()
        self.assertEqual(len(lines), 1)
        record = json.loads(lines[0])
        self.assertEqual(record["verdict"], "unavailable")
        self.assertIn("invocation_id", record)
        self.assertIn("ts", record)

    def test_missing_api_key_is_named(self):
        result = judge.Judge(url="http://127.0.0.1:1/systemone", api_key="",
                             receipt_path=self.receipt, counter_path=self.counter) \
            .ask(_choice_questions(), "state")
        self.assertEqual(result["verdict"], "unavailable")
        self.assertTrue(result["reason"])
        self.assertIn("auth", result["reason"])

    def test_ask_never_raises_on_garbage_input(self):
        result = self._judge("http://127.0.0.1:1/systemone").ask(None, None)
        self.assertEqual(result["verdict"], "unavailable")
        self.assertIn("invalid", result["reason"])
        self.assertEqual(open(self.receipt, encoding="utf-8").read().count("\n"), 1)


class JudgeCapsTestCase(unittest.TestCase):
    """Caps: per-invocation and cumulative; exceeding is a NAMED skip."""

    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="judge-caps-")
        self.receipt = os.path.join(self.work, "receipts.jsonl")
        self.counter = os.path.join(self.work, "counter.json")

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def _judge(self, **kwargs):
        kwargs.setdefault("url", "http://127.0.0.1:1/systemone")
        kwargs.setdefault("api_key", "k")
        kwargs.setdefault("receipt_path", self.receipt)
        kwargs.setdefault("counter_path", self.counter)
        return judge.Judge(**kwargs)

    def test_per_invocation_cap_names_the_skip(self):
        client = self._judge(max_calls=1)
        first = client.ask(_choice_questions(), "state")
        second = client.ask(_choice_questions(), "state")
        self.assertEqual(first["verdict"], "unavailable")  # refused URL, not cap
        self.assertEqual(second["verdict"], "skipped")
        self.assertIn("cap:", second["reason"])
        self.assertIn("per-invocation", second["reason"])
        self.assertEqual(second["calls_used"], 1)

    def test_total_cap_names_the_skip_and_never_calls(self):
        with open(self.counter, "w", encoding="utf-8") as fh:
            json.dump({"total": 500}, fh)
        result = self._judge(total_cap=500).ask(_choice_questions(), "state")
        self.assertEqual(result["verdict"], "skipped")
        self.assertIn("total-call limit", result["reason"])
        self.assertEqual(result["calls_used"], 0)

    def test_counter_file_counts_calls(self):
        self._judge(url="http://127.0.0.1:1/systemone").ask(_choice_questions(), "s")
        with open(self.counter, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["total"], 1)

    def test_unwritable_counter_does_not_break_the_run(self):
        result = self._judge(counter_path=os.path.join(self.work, "no", "dir",
                                                       "counter.json")) \
            .ask(_choice_questions(), "state")
        self.assertIn(result["verdict"], ("unavailable", "skipped"))
        self.assertTrue(result["reason"])


class RedactionTestCase(unittest.TestCase):
    """K4: credential-shaped values are masked before anything is sent/kept."""

    def test_planted_fake_key_is_masked(self):
        out = judge.redact_text(STATE_WITH_SECRETS)
        for secret in (FAKE_SECRET, FAKE_BEARER, FAKE_CONN, FAKE_HEX, FAKE_AWS,
                       "s3cr3t-pw", "svc_admin"):
            self.assertNotIn(secret, out)
        self.assertIn("[REDACTED", out)

    def test_benign_text_survives(self):
        text = "executor also reviewed its own diff on 2026-10-15, file a/b.py"
        self.assertEqual(judge.redact_text(text), text)

    def test_short_hex_and_words_are_not_masked(self):
        text = "deadbeef and add layout to the deck"
        self.assertEqual(judge.redact_text(text), text)

    def test_recursion_covers_nested_containers(self):
        out = judge._redact_json({"a": [STATE_WITH_SECRETS], "b": {"c": FAKE_SECRET}})
        self.assertNotIn(FAKE_SECRET, json.dumps(out))

    def test_non_string_passthrough(self):
        self.assertEqual(judge.redact_text(42), 42)
        self.assertIsNone(judge.redact_text(None))


class GrammarTestCase(unittest.TestCase):
    """The route rejects malformed questions with 422; we refuse them first."""

    def test_score_is_refused(self):
        reason = judge.validate_questions({"q": {"type": "score", "criteria": {},
                                                 "instructions": "x"}})
        self.assertIn("score", reason)

    def test_criteria_string_is_refused(self):
        reason = judge.validate_questions(
            {"q": {"type": "choice", "criteria": "bad own review",
                   "instructions": "decide"}})
        self.assertIn("criteria", reason)

    def test_bare_options_list_is_refused(self):
        reason = judge.validate_questions(
            {"q": {"type": "choice", "options": ["ok", "block"],
                   "instructions": "pick one"}})
        self.assertIn("options", reason)

    def test_missing_instructions_is_refused(self):
        reason = judge.validate_questions(
            {"q": {"type": "choice", "criteria": {"allow": "a", "block": "b"}}})
        self.assertIn("instructions", reason)

    def test_valid_choice_and_noul_pass(self):
        self.assertIsNone(judge.validate_questions(
            dict(_choice_questions(), **judge.noul_question("risk", "How risky?"))))

    def test_empty_questions_refused(self):
        self.assertIn("invalid-question", judge.validate_questions({}))

    def test_builders_produce_routable_questions(self):
        questions = dict(_choice_questions(), **judge.noul_question("risk", "How risky?"))
        self.assertEqual(sorted(questions), ["risk", "separation_of_duties"])


class ReceiptTestCase(unittest.TestCase):
    """K4: append-only JSONL with the required fields and no leaked secrets."""

    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="judge-receipt-")
        self.receipt = os.path.join(self.work, "receipts.jsonl")
        self.counter = os.path.join(self.work, "counter.json")

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def _ask_twice_offline(self):
        for _ in range(2):
            judge.Judge(url="http://127.0.0.1:1/systemone", api_key="k",
                        receipt_path=self.receipt, counter_path=self.counter,
                        timeout_s=2.0).ask(_choice_questions(), STATE_WITH_SECRETS)

    def test_append_only_two_lines_two_records(self):
        self._ask_twice_offline()
        with open(self.receipt, encoding="utf-8") as fh:
            lines = [line for line in fh.read().splitlines() if line]
        self.assertEqual(len(lines), 2)
        for line in lines:
            record = json.loads(line)  # every line is valid JSON
            for field in ("ts", "invocation_id", "route", "model",
                          "question_keys", "answers", "confidences",
                          "verdict", "reason", "state_sha256"):
                self.assertIn(field, record)
        self.assertNotEqual(json.loads(lines[0])["invocation_id"],
                            json.loads(lines[1])["invocation_id"])

    def test_no_secrets_and_no_state_in_receipt(self):
        self._ask_twice_offline()
        receipt = open(self.receipt, encoding="utf-8").read()
        for secret in (FAKE_SECRET, FAKE_BEARER, FAKE_CONN, FAKE_HEX, FAKE_AWS,
                       "rotate staging deploy key"):
            self.assertNotIn(secret, receipt)

    def test_state_is_only_a_digest(self):
        self._ask_twice_offline()
        record = json.loads(open(self.receipt, encoding="utf-8").read().splitlines()[0])
        self.assertEqual(record["state_sha256"],
                         __import__("hashlib").sha256(
                             STATE_WITH_SECRETS.encode("utf-8")).hexdigest())

    def test_no_absolute_home_paths_in_receipt(self):
        self._ask_twice_offline()
        receipt = open(self.receipt, encoding="utf-8").read()
        self.assertNotIn(os.path.expanduser("~"), receipt)
        self.assertNotIn("/Users/", receipt)

    def test_receipt_error_is_reported_not_raised(self):
        ok, error = judge.append_receipt(
            os.path.join(self.work, "missing-dir", "sub", "r.jsonl"),
            {"verdict": "ok"})
        self.assertTrue(ok)  # parent dirs are created on demand


class CounterAndDefaultsTestCase(unittest.TestCase):
    def test_counter_survives_unreadable_file(self):
        work = tempfile.mkdtemp(prefix="judge-counter-")
        try:
            path = os.path.join(work, "counter.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("not json{")
            self.assertEqual(judge._read_counter(path), 0)
            self.assertEqual(judge._bump_counter(path, 1), 1)
            self.assertEqual(judge._read_counter(path), 1)
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def test_env_defaults_are_picked_up(self):
        work = tempfile.mkdtemp(prefix="judge-env-")
        old = {key: os.environ.get(key) for key in
               ("JUDGE_URL", "JUDGE_MODEL", "JUDGE_API_KEY")}
        try:
            os.environ["JUDGE_URL"] = "http://127.0.0.1:1/zen"
            os.environ["JUDGE_MODEL"] = "other-model"
            os.environ["JUDGE_API_KEY"] = "envkey"
            client = judge.Judge(receipt_path=os.path.join(work, "r.jsonl"),
                                 counter_path=os.path.join(work, "c.json"))
            self.assertEqual(client.url, "http://127.0.0.1:1/zen")
            self.assertEqual(client.model, "other-model")
            self.assertEqual(client.api_key, "envkey")
        finally:
            for key, value in old.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()


class DictStateAndRouteRedactionTest(JudgeHTTPTestCase):
    """F-A1/F-A2 (CTO, 2026-10-15): state as a map, and the receipt's own
    route/model must NOT bypass redaction."""

    def test_FA1_state_may_be_a_dict(self):
        """A dict state is canonicalized (sorted keys) and answered, not refused."""
        j = self._judge(max_calls=2)
        r = j.ask(_choice_questions(), {"actor": "agent-1", "reviewer": "human-1"})
        self.assertEqual(r["verdict"], "ok", r["reason"])
        body = json.loads(_FakeRoute.received[0]["body"])
        self.assertEqual(body["state"], '{"actor":"agent-1","reviewer":"human-1"}')

    def test_FA2_receipt_redacts_credential_shaped_route(self):
        """A custom endpoint with inline user:pass must not survive into the receipt.

        The call itself may fail (urllib refuses userinfo URLs) — the receipt is
        written on every path, and THAT is where the credential must never appear.
        """
        leaky = self._judge(max_calls=2)
        leaky.url = leaky.url.replace("http://127.0.0.1", "http://svc:topsecret@127.0.0.1")
        r = leaky.ask(_choice_questions(), "state")
        line = open(self.receipt, encoding="utf-8").readlines()[-1]
        self.assertNotIn("topsecret", line, "credential leaked into the receipt")
