import json
import pytest
from secops.agents import Case, InvestigationAgent, LLMClient, RemediationAgent, TriageAgent, validate_llm_output
from secops.data import ASSETS, IAM_BINDINGS


def make_case(asset_id="A-03", category="web", cvss=9.1, ts="2026-11-03T10:00:00"):
    f = {"finding_id": "F-1", "asset_id": asset_id, "title": "t", "category": category, "cvss": cvss, "detected_at": ts}
    return Case(finding=f, asset=ASSETS[asset_id])


class FakeLLM(LLMClient):
    def __init__(self, reply): super().__init__(api_key="test"); self.reply = reply
    def ask(self, prompt): return self.reply


def test_triage_internet_facing_critical_is_p1():
    c = TriageAgent().run(make_case("A-03", cvss=9.1))
    assert c.risk_score == 23.7 and c.priority == "P1"


def test_triage_low_asset_low_cvss_is_p4():
    assert TriageAgent().run(make_case("A-05", cvss=3.1)).priority == "P4"


def test_investigation_escalates_on_high_siem_alert():
    case = TriageAgent().run(make_case("A-04", cvss=5.3))  # 5.3*1.0*1.3 = 6.9 -> P3
    alerts = [{"alert_id": "S-1", "asset_id": "A-04", "rule": "Outbound traffic spike", "severity": "high",
               "ts": "2026-11-04T10:00:00"}]
    InvestigationAgent(alerts, IAM_BINDINGS, llm=LLMClient(api_key="")).run(case)
    assert case.priority == "P2" and any("Escalated" in e for e in case.evidence)


def test_investigation_flags_iam_least_privilege():
    case = TriageAgent().run(make_case("A-03"))
    InvestigationAgent([], IAM_BINDINGS, llm=LLMClient(api_key="")).run(case)
    assert any(e.startswith("IAM:") for e in case.evidence)


def test_llm_summary_used_when_valid():
    reply = json.dumps({"summary": "Likely exploited SQLi", "likely_exploited": True})
    case = InvestigationAgent([], IAM_BINDINGS, llm=FakeLLM(reply)).run(TriageAgent().run(make_case()))
    assert case.summary == "Likely exploited SQLi"


@pytest.mark.parametrize("bad", ["not json", '{"summary": 1}', '{"summary": "x"}'])
def test_llm_bad_output_falls_back(bad):
    with pytest.raises(Exception):
        validate_llm_output(bad)
    case = InvestigationAgent([], IAM_BINDINGS, llm=FakeLLM(bad)).run(TriageAgent().run(make_case()))
    assert "CVSS" in case.summary  # rule-based fallback


def test_governance_iam_change_needs_human_approval():
    case = RemediationAgent().run(TriageAgent().run(make_case("A-05", category="iam", cvss=3.0)))
    assert case.status == "awaiting_approval" and case.action["dry_run"]


def test_low_risk_on_non_critical_asset_is_automated():
    case = RemediationAgent().run(TriageAgent().run(make_case("A-05", category="web", cvss=3.1)))
    assert case.status == "auto_remediated" and not case.action["requires_approval"]
