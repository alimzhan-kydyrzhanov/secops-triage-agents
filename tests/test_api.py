import json, threading, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import pytest
from secops.api import serve
from secops.data import generate
from secops.pipeline import Pipeline


@pytest.fixture
def api():
    p = Pipeline(generate()[1])
    srv = serve(p, host="127.0.0.1", port=0, token="secret")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", p
    srv.shutdown()


def call(url, body=None, token="secret"):
    req = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(),
                                 headers={"authorization": f"Bearer {token}", "content-type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


FINDING = {"finding_id": "F-900", "asset_id": "A-03", "title": "Default credentials on admin panel",
           "category": "iam", "cvss": 9.8, "detected_at": "2026-11-05T09:00:00"}


def test_webhook_ingest_then_approve(api):
    base, p = api
    status, case = call(base + "/webhooks/scanner", FINDING)
    assert status == 201 and case["priority"] == "P1" and case["status"] == "awaiting_approval"
    status, case = call(base + "/approvals/F-900", {"approver": "lead", "approved": True})
    assert status == 200 and case["status"] == "remediated"
    assert call(base + "/approvals/F-900", {"approved": True})[0] == 409  # cannot approve twice
    assert call(base + "/cases?priority=P1")[1][0]["case_id"] == "F-900"
    assert call(base + "/kpis")[1]["closed_cases"] == 1
    html = urllib.request.urlopen(base + "/dashboard").read().decode()
    assert "closed_cases" in html and "refresh" in html and "&rarr;" in html


def test_bad_input_and_auth(api):
    base, _ = api
    assert call(base + "/webhooks/scanner", {**FINDING, "cvss": 42})[0] == 422
    assert call(base + "/webhooks/scanner", FINDING, token="wrong")[0] == 401
    assert call(base + "/health")[1] == {"status": "ok"}


def test_outbound_webhook_notification():
    received = []

    class Sink(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers["content-length"]))))
            self.send_response(204); self.end_headers()
        def log_message(self, *a): pass

    sink = ThreadingHTTPServer(("127.0.0.1", 0), Sink)
    threading.Thread(target=sink.serve_forever, daemon=True).start()
    p = Pipeline([], webhook_url=f"http://127.0.0.1:{sink.server_address[1]}/hook")
    p.handle(FINDING)
    sink.shutdown()
    assert received[0]["ticket"] == "SEC-1" and p.notifier.sent == 1
