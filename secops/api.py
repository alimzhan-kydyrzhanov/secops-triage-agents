"""REST API + inbound webhook (standard library only, so it runs anywhere).
GET  /health                     liveness probe (for Docker / Cloud Run)
GET  /cases?priority=P1          list cases
GET  /kpis                       process mining KPIs
GET  /dashboard                  live HTML KPI dashboard (auto-refresh every 5 s)
POST /webhooks/scanner           a scanner pushes a new finding (JSON)
POST /approvals/<case_id>        human approves/rejects a remediation {"approver": "...", "approved": true}
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from html import escape

from .mining import bottlenecks, event_log_df, kpis


def case_json(c):
    return {"case_id": c.case_id, "asset": c.asset["name"], "title": c.finding["title"], "priority": c.priority,
            "risk_score": c.risk_score, "status": c.status, "action": c.action, "evidence": c.evidence,
            "summary": c.summary}


def dashboard_html(pipeline):
    """Real-time view: recomputed from the event log on every request, page refreshes itself."""
    k = kpis(pipeline.event_log, pipeline.cases) if pipeline.cases else {}
    rows = "".join(f"<tr><td>{escape(str(a))}</td><td>{escape(str(b))}</td></tr>"
                   for a, b in k.items() if a not in ("top_bottleneck", "data_quality_issues"))
    bn = bottlenecks(event_log_df(pipeline.event_log)).head(3) if pipeline.cases else []
    bn_rows = "".join(f"<tr><td>{escape(r.activity)} &rarr; {escape(r.next_activity)}</td><td>{r.mean:.1f} h</td></tr>"
                      for r in getattr(bn, "itertuples", lambda **_: [])(index=False))
    return (f"<!doctype html><meta http-equiv='refresh' content='5'><title>SecOps KPIs</title>"
            f"<h1>SecOps process KPIs</h1><table border=1>{rows}</table>"
            f"<h2>Top bottlenecks</h2><table border=1>{bn_rows}</table>")


def make_handler(pipeline, token=None):
    class Handler(BaseHTTPRequestHandler):
        def send(self, code, body):
            data = json.dumps(body, default=str).encode()
            self.send_response(code)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def authorized(self):  # simple bearer token for write endpoints
            return token is None or self.headers.get("authorization") == f"Bearer {token}"

        def do_GET(self):
            url = urlparse(self.path)
            if url.path == "/health":
                return self.send(200, {"status": "ok"})
            if url.path == "/cases":
                prio = parse_qs(url.query).get("priority", [None])[0]
                return self.send(200, [case_json(c) for c in pipeline.cases.values() if prio in (None, c.priority)])
            if url.path == "/kpis":
                return self.send(200, kpis(pipeline.event_log, pipeline.cases))
            if url.path == "/dashboard":
                data = dashboard_html(pipeline).encode()
                self.send_response(200)
                self.send_header("content-type", "text/html; charset=utf-8")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                return self.wfile.write(data)
            self.send(404, {"error": "not found"})

        def do_POST(self):
            if not self.authorized():
                return self.send(401, {"error": "unauthorized"})
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
            except json.JSONDecodeError:
                return self.send(400, {"error": "invalid JSON"})
            if self.path == "/webhooks/scanner":
                case = pipeline.handle(body)
                if case is None:
                    return self.send(422, {"error": pipeline.quarantine[-1]["reason"]})
                return self.send(201, case_json(case))
            if self.path.startswith("/approvals/"):
                case_id = self.path.rsplit("/", 1)[-1]
                if case_id not in pipeline.cases:
                    return self.send(404, {"error": "unknown case"})
                try:
                    case = pipeline.approve(case_id, body.get("approver", "unknown"), bool(body.get("approved")))
                except ValueError as e:
                    return self.send(409, {"error": str(e)})
                return self.send(200, case_json(case))
            self.send(404, {"error": "not found"})

        def log_message(self, *args):  # keep test output quiet
            pass

    return Handler


def serve(pipeline, host="0.0.0.0", port=8080, token=None):
    return ThreadingHTTPServer((host, port), make_handler(pipeline, token))
