#!/usr/bin/env python3
"""K3 probe: run the gate with a scripted classifier, print the receipts.

Direction 1: the gate blocks (no pass signoff) while the judge says allow.
Direction 2: the gate opens (independent pass) while the judge says block.
In BOTH directions the gate's exit code must be the gate's own. Also probes
the default-OFF behaviour: no --judge and no JUDGE_URL, no classifier call.

Stdlib only. Run from the repo root: python3.12 probes/k3_probe.py
"""

import http.server
import io
import json
import os
import shutil
import sys
import tempfile
import threading
from contextlib import redirect_stderr, redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from gatesmith import cli  # noqa: E402


class _Scripted(http.server.BaseHTTPRequestHandler):
    answer = "allow"

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        names = ("executor_also_reviewer", "lane_bounded", "gate_allowable",
                 "evidence_supports")
        payload = {"answers": {name: {"type": "choice", "choice": _Scripted.answer,
                                      "confidence": 0.91} for name in names}}
        payload["answers"]["independence_confident"] = {"type": "noul", "noul": 0.8}
        data = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        pass


def run(argv, work):
    out, err = io.StringIO(), io.StringIO()
    env = {}
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def direction(answer, executor, reviewer):
    work = tempfile.mkdtemp(prefix="k3-probe-")
    registry = os.path.join(work, "reg.json")
    receipt = os.path.join(work, "r.jsonl")
    counter = os.path.join(work, "c.json")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Scripted)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}/zen"
    _Scripted.answer = answer
    saved = {k: os.environ.get(k) for k in
             ("JUDGE_URL", "JUDGE_API_KEY", "JUDGE_RECEIPT", "JUDGE_COUNTER",
              "JUDGE_TIMEOUT")}
    os.environ.update({"JUDGE_URL": url, "JUDGE_API_KEY": "probe-key",
                       "JUDGE_RECEIPT": receipt, "JUDGE_COUNTER": counter,
                       "JUDGE_TIMEOUT": "5"})
    try:
        for argv in (["review", "--registry", registry, "open", "--id", "r1",
                      "--executor", executor, "--change", "probe change"],
                     ["review", "--registry", registry, "sign", "--id", "r1",
                      "--reviewer", reviewer, "--verdict", "pass"]):
            run(argv, work)
        code, out, err = run(["review", "--registry", registry, "gate",
                              "--id", "r1", "--target", "deploy",
                              "--allow-unsealed", "--judge"], work)
        receipt_line = ""
        if os.path.exists(receipt):
            with open(receipt, encoding="utf-8") as fh:
                receipt_line = fh.read().strip()
        return {"answer": answer, "exit": code, "out": out, "err": err,
                "receipt": receipt_line}
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        server.shutdown()
        server.server_close()
        shutil.rmtree(work, ignore_errors=True)


def default_off():
    work = tempfile.mkdtemp(prefix="k3-off-")
    registry = os.path.join(work, "reg.json")
    for key in ("JUDGE_URL", "JUDGE_API_KEY", "JUDGE_RECEIPT", "JUDGE_COUNTER"):
        os.environ.pop(key, None)
    try:
        for argv in (["review", "--registry", registry, "open", "--id", "r1",
                      "--executor", "agent-x", "--change", "probe change"],
                     ["review", "--registry", registry, "sign", "--id", "r1",
                      "--reviewer", "reviewer-y", "--verdict", "pass"]):
            run(argv, work)
        code, out, err = run(["review", "--registry", registry, "gate",
                              "--id", "r1", "--target", "deploy",
                              "--allow-unsealed"], work)
        return code, out, err
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    print("K3 probe — the judge line never moves the gate's exit code.\n")
    blocked = direction("allow", "agent-x", "agent-x")   # gate blocks, judge allows
    print("Direction 1 — gate BLOCKS, judge says allow:")
    print(f"  gate stderr: {blocked['err'].strip().splitlines()[0] if blocked['err'].strip() else '(empty)'}")
    judge_line = [line for line in blocked["out"].splitlines()
                  if line.startswith("judge:")]
    print(f"  judge line: {judge_line[0] if judge_line else '(MISSING)'}")
    print(f"  gate exit code: {blocked['exit']}  (must be 1)")
    record = json.loads(blocked["receipt"])
    print(f"  receipt: verdict={record['verdict']} "
          f"answers_recorded={sorted(record['answers'])} "
          f"state_sha256={'state_sha256' in record} "
          f"state_payload_stored={'review_id' in json.dumps(record['answers'])}")
    opened = direction("block", "agent-x", "reviewer-y")  # gate opens, judge blocks
    print("\nDirection 2 — gate OPENS, judge says block:")
    print(f"  gate stdout: {opened['out'].strip().splitlines()[0]}")
    judge_line = [line for line in opened["out"].splitlines()
                  if line.startswith("judge:")]
    print(f"  judge line: {judge_line[0] if judge_line else '(MISSING)'}")
    print(f"  gate exit code: {opened['exit']}  (must be 0)")
    ok = blocked["exit"] == 1 and opened["exit"] == 0
    print(f"\nK3 PROBE: {'PASS' if ok else 'FAIL'} — "
          f"exit codes are the gate's own in both directions.")
    code, out, err = default_off()
    judge_lines = [line for line in out.splitlines() if line.startswith("judge:")]
    print(f"Default-OFF probe: exit={code}, judge lines={judge_lines or 'none'} "
          f"(no endpoint configured, classifier never contacted)")
    return 0 if ok and not judge_lines and code == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
