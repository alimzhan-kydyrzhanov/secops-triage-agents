"""Three cooperating AI agents: Triage -> Investigation -> Remediation.
Each agent has one job, reads the shared Case and adds to it (a simple multi-agent
"pipeline" pattern, the same idea as a sequential crew in CrewAI or LangChain)."""
import json
import os
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta

CRIT_WEIGHT = {"low": 0.5, "medium": 1.0, "high": 1.5, "critical": 2.0}
SLA_HOURS = {"P1": 24, "P2": 72, "P3": 168, "P4": 720}
PRIORITIES = ["P1", "P2", "P3", "P4"]


@dataclass
class Case:
    finding: dict
    asset: dict
    risk_score: float = 0.0
    priority: str = "P4"
    evidence: list = field(default_factory=list)
    summary: str = ""
    action: dict = field(default_factory=dict)
    status: str = "new"

    @property
    def case_id(self):
        return self.finding["finding_id"]


class TriageAgent:
    """Scores risk = CVSS x asset criticality x exposure, then maps it to a priority."""
    name = "triage-agent"

    def run(self, case):
        exposure = 1.3 if case.asset["internet_facing"] else 1.0
        case.risk_score = round(case.finding["cvss"] * CRIT_WEIGHT[case.asset["criticality"]] * exposure, 1)
        s = case.risk_score
        case.priority = "P1" if s >= 15 else "P2" if s >= 10 else "P3" if s >= 5 else "P4"
        case.status = "triaged"
        return case


class LLMClient:
    """Optional Generative AI step: asks Claude for a short analyst summary.
    The answer must be valid JSON with the expected keys, otherwise we fall back."""

    def __init__(self, api_key=None, model="claude-haiku-4-5"):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.model = model

    def ask(self, prompt):  # separated so tests can replace it
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=json.dumps({"model": self.model, "max_tokens": 300,
                             "messages": [{"role": "user", "content": prompt}]}).encode(),
            headers={"x-api-key": self.api_key, "anthropic-version": "2023-06-01",
                     "content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read())["content"][0]["text"]

    def summarize(self, case):
        if not self.api_key:
            return None
        prompt = ("You are a SOC analyst. Reply ONLY with JSON {\"summary\": str, \"likely_exploited\": bool}.\n"
                  f"Finding: {json.dumps(case.finding)}\nEvidence: {json.dumps(case.evidence)}")
        try:
            return validate_llm_output(self.ask(prompt))
        except Exception:
            return None


def validate_llm_output(text):
    """Guardrail: never trust raw model output."""
    data = json.loads(text)
    if not isinstance(data.get("summary"), str) or not isinstance(data.get("likely_exploited"), bool):
        raise ValueError("LLM output does not match schema")
    data["summary"] = data["summary"][:500]
    return data


class InvestigationAgent:
    """Correlates the finding with SIEM alerts and IAM bindings; may escalate priority."""
    name = "investigation-agent"

    def __init__(self, siem_alerts, iam_bindings, llm=None, window_days=7):
        self.alerts, self.iam, self.llm = siem_alerts, iam_bindings, llm or LLMClient()
        self.window = timedelta(days=window_days)

    def run(self, case):
        detected = datetime.fromisoformat(case.finding["detected_at"])
        related = [a for a in self.alerts if a["asset_id"] == case.finding["asset_id"]
                   and abs(datetime.fromisoformat(a["ts"]) - detected) <= self.window]
        for a in related:
            case.evidence.append(f"SIEM {a['alert_id']}: {a['rule']} ({a['severity']})")
        admins = [who for who, role in self.iam.get(case.finding["asset_id"], []) if role == "admin"]
        if len(admins) > 1 or "everyone" in admins:
            case.evidence.append(f"IAM: too many admins {admins} (least privilege violated)")
        if any(a["severity"] == "high" for a in related):  # active attack signal -> escalate
            idx = PRIORITIES.index(case.priority)
            case.priority = PRIORITIES[max(idx - 1, 0)]
            case.evidence.append("Escalated: high-severity SIEM alert on same asset")
        llm = self.llm.summarize(case)
        case.summary = llm["summary"] if llm else (
            f"{case.finding['title']} on {case.asset['name']} (CVSS {case.finding['cvss']}, "
            f"risk {case.risk_score}); {len(related)} related SIEM alerts.")
        case.status = "investigated"
        return case


PLAYBOOK = {
    "web": ("create_patch_ticket", "low"),
    "server": ("apply_os_patch", "medium"),
    "network": ("restrict_firewall_rule", "high"),
    "iam": ("revoke_admin_role_and_rotate_credentials", "high"),
}


class RemediationAgent:
    """Proposes a fix from the playbook. Governance: only low-risk actions on
    non-critical assets run automatically; everything else waits for a human."""
    name = "remediation-agent"

    def run(self, case):
        action, risk = PLAYBOOK[case.finding["category"]]
        needs_approval = risk == "high" or case.asset["criticality"] == "critical" or case.priority == "P1"
        case.action = {"type": action, "risk": risk, "requires_approval": needs_approval, "dry_run": needs_approval}
        case.status = "awaiting_approval" if needs_approval else "auto_remediated"
        return case
