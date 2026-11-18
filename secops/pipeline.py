"""Orchestrator: scanner findings -> event bus -> agents -> actions,
writing every step to an event log (case_id, activity, timestamp, resource) for process mining."""
import random
import sqlite3
from datetime import datetime, timedelta

from .actions import TicketingSystem, WebhookNotifier
from .agents import Case, InvestigationAgent, RemediationAgent, TriageAgent
from .bus import EventBus
from .data import ASSETS, IAM_BINDINGS

TOPIC, GROUP = "scanner.findings", "triage-agents"


def validate_finding(f, seen_ids):
    """Data quality checks. Returns a rejection reason or None."""
    for key in ("finding_id", "asset_id", "title", "category", "cvss", "detected_at"):
        if f.get(key) in (None, ""):
            return f"missing {key}"
    if f["finding_id"] in seen_ids:
        return "duplicate finding_id"
    if f["asset_id"] not in ASSETS:
        return "unknown asset_id"
    if not isinstance(f["cvss"], (int, float)) or not 0 <= f["cvss"] <= 10:
        return "cvss out of range 0-10"
    if f["category"] not in ("web", "server", "network", "iam"):
        return "unknown category"
    try:
        datetime.fromisoformat(f["detected_at"])
    except ValueError:
        return "invalid detected_at"
    return None


class Pipeline:
    def __init__(self, siem_alerts, llm=None, webhook_url=None, seed=1):
        self.bus = EventBus()
        self.agents = [TriageAgent(), InvestigationAgent(siem_alerts, IAM_BINDINGS, llm), RemediationAgent()]
        self.tickets = TicketingSystem()
        self.notifier = WebhookNotifier(webhook_url)
        self.cases, self.quarantine, self.event_log = {}, [], []
        self.seen_ids = set()
        self.rng = random.Random(seed)  # simulates how long each step takes

    def log(self, case_id, activity, ts, resource):
        self.event_log.append({"case_id": case_id, "activity": activity, "timestamp": ts.isoformat(), "resource": resource})

    def ingest(self, findings):
        for f in findings:
            self.bus.publish(TOPIC, f)

    def process(self, batch_size=50):
        while self.bus.lag(TOPIC, GROUP):
            batch = self.bus.consume(TOPIC, GROUP, batch_size)
            for f in batch:
                self.handle(f)
            self.bus.commit(TOPIC, GROUP, len(batch))  # commit only after processing = at-least-once

    def handle(self, f):
        reason = validate_finding(f, self.seen_ids)
        if reason:
            self.quarantine.append({**f, "reason": reason})
            return None
        self.seen_ids.add(f["finding_id"])
        case = Case(finding=f, asset=ASSETS[f["asset_id"]])
        ts = datetime.fromisoformat(f["detected_at"])
        self.log(case.case_id, "Finding received", ts, "scanner")
        for agent in self.agents:
            ts += timedelta(minutes=self.rng.randint(1, 30))
            agent.run(case)
            self.log(case.case_id, agent.name.replace("-agent", "").title() + " done", ts, agent.name)
        key = self.tickets.create(case)
        ts += timedelta(minutes=1)
        self.log(case.case_id, "Ticket created", ts, "ticketing")
        self.notifier.notify({"case_id": case.case_id, "ticket": key, "priority": case.priority, "status": case.status})
        if case.status == "auto_remediated":
            ts += timedelta(hours=self.rng.randint(1, 48))
            self.log(case.case_id, "Fix applied", ts, "automation")
            self.log(case.case_id, "Case closed", ts + timedelta(minutes=5), "automation")
        self.cases[case.case_id] = case
        return case

    def approve(self, case_id, approver, approved=True, at=None):
        """Human-in-the-loop decision for a governed remediation."""
        case = self.cases[case_id]
        if case.status != "awaiting_approval":
            raise ValueError(f"case {case_id} is {case.status}")
        last = max(datetime.fromisoformat(e["timestamp"]) for e in self.event_log if e["case_id"] == case_id)
        ts = at or last + timedelta(hours=self.rng.randint(2, 96))
        if approved:
            case.action["dry_run"] = False
            case.status = "remediated"
            self.log(case_id, "Approved", ts, approver)
            self.log(case_id, "Fix applied", ts + timedelta(hours=self.rng.randint(1, 24)), "automation")
        else:
            case.status = "risk_accepted"
            self.log(case_id, "Rejected", ts, approver)
        self.log(case_id, "Case closed", ts + timedelta(hours=25), approver)
        return case

    def to_sqlite(self, path=":memory:"):
        con = sqlite3.connect(path)
        with con:  # one transaction
            con.execute("DROP TABLE IF EXISTS event_log")
            con.execute("DROP TABLE IF EXISTS cases")
            con.execute("CREATE TABLE event_log(case_id TEXT, activity TEXT, timestamp TEXT, resource TEXT)")
            con.execute("CREATE TABLE cases(case_id TEXT PRIMARY KEY, asset TEXT, priority TEXT, risk REAL, status TEXT)")
            con.executemany("INSERT INTO event_log VALUES (:case_id,:activity,:timestamp,:resource)", self.event_log)
            con.executemany("INSERT INTO cases VALUES (?,?,?,?,?)", [
                (c.case_id, c.asset["name"], c.priority, c.risk_score, c.status) for c in self.cases.values()])
        return con
