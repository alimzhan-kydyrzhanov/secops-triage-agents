from secops.bus import EventBus
from secops.data import generate
from secops.mining import check_event_log, event_log_df, kpis, sql_kpis, variants
from secops.pipeline import Pipeline


def run():
    findings, alerts = generate()
    p = Pipeline(alerts)
    p.ingest(findings)
    p.process(batch_size=7)
    return p


def test_bus_offsets_and_lag():
    bus = EventBus()
    for i in range(5):
        bus.publish("t", i)
    assert bus.consume("t", "g", 2) == [0, 1]
    assert bus.lag("t", "g") == 5  # nothing committed yet -> at-least-once
    bus.commit("t", "g", 2)
    assert bus.lag("t", "g") == 3 and bus.lag("t", "other") == 5


def test_invalid_findings_are_quarantined_with_reason():
    p = run()
    reasons = {q["finding_id"]: q["reason"] for q in p.quarantine}
    assert reasons == {"F-004": "unknown asset_id", "F-008": "cvss out of range 0-10",
                       "F-012": "invalid detected_at", "F-001": "duplicate finding_id"}
    assert len(p.cases) == 37 and p.bus.lag("scanner.findings", "triage-agents") == 0


def test_every_case_gets_a_ticket_and_valid_event_log():
    p = run()
    assert len(p.tickets.tickets) == len(p.cases)
    df = event_log_df(p.event_log)
    assert check_event_log(df) == []
    assert variants(df)["cases"].sum() == len(p.cases)


def test_approval_closes_case_and_kpis():
    p = run()
    waiting = [c for c in p.cases.values() if c.status == "awaiting_approval"]
    p.approve(waiting[0].case_id, "lead", approved=True)
    p.approve(waiting[1].case_id, "lead", approved=False)
    k = kpis(p.event_log, p.cases)
    assert k["closed_cases"] == len(p.cases) - len(waiting) + 2
    assert 0 <= k["sla_breach_rate"] <= 1 and 0 < k["automation_rate"] < 1


def test_sql_kpis_use_index():
    rows, before, after = sql_kpis(run().to_sqlite())
    assert {r[0] for r in rows} <= {"P1", "P2", "P3", "P4"}
    assert any("ix_log_case_ts" in step for step in after) and not any("ix_log_case_ts" in s for s in before)
