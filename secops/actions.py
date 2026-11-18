"""Automated actions (like Celonis Action Flows / a SOAR playbook step):
create a ticket in the ticketing system and notify a webhook."""
import json
import urllib.request


class TicketingSystem:
    """Minimal Jira-like ticket store (SEC-1, SEC-2, ...)."""

    def __init__(self):
        self.tickets = {}

    def create(self, case):
        key = f"SEC-{len(self.tickets) + 1}"
        self.tickets[key] = {"key": key, "case_id": case.case_id, "priority": case.priority,
                             "title": f"[{case.priority}] {case.finding['title']} - {case.asset['name']}",
                             "action": case.action["type"], "status": "Open"}
        return key


class WebhookNotifier:
    """POSTs a JSON event to a URL (e.g. Slack / Teams / SIEM). Failures never stop the pipeline."""

    def __init__(self, url=None, retries=2, timeout=3):
        self.url, self.retries, self.timeout = url, retries, timeout
        self.sent, self.failed = 0, 0

    def notify(self, event):
        if not self.url:
            return False
        for _ in range(self.retries + 1):
            try:
                req = urllib.request.Request(self.url, data=json.dumps(event).encode(),
                                             headers={"content-type": "application/json"})
                urllib.request.urlopen(req, timeout=self.timeout).close()
                self.sent += 1
                return True
            except OSError:
                continue
        self.failed += 1
        return False
