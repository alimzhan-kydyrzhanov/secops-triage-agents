"""python -m secops run    -> run the whole pipeline on synthetic data and print a report
python -m secops serve  -> run, then start the REST API on $PORT (default 8080)"""
import json
import os
import sys

from .data import generate
from .mining import bottlenecks, event_log_df, kpis, sql_kpis, variants
from .pipeline import Pipeline


def build():
    findings, alerts = generate()
    p = Pipeline(alerts, webhook_url=os.getenv("WEBHOOK_URL"))
    p.ingest(findings)
    p.process()
    # simulate the security lead approving most P1/P2 actions and rejecting one
    waiting = [c for c in p.cases.values() if c.status == "awaiting_approval"]
    for i, c in enumerate(waiting[: len(waiting) - 3]):
        p.approve(c.case_id, "security-lead", approved=(i != 0))
    return p


def main(cmd):
    p = build()
    if cmd == "serve":
        from .api import serve
        port = int(os.getenv("PORT", "8080"))
        print(f"API on :{port}")
        serve(p, port=port, token=os.getenv("API_TOKEN")).serve_forever()
        return
    print("Quarantined:", [(q["finding_id"], q["reason"]) for q in p.quarantine])
    print("KPIs:", json.dumps(kpis(p.event_log, p.cases), indent=2, default=str))
    df = event_log_df(p.event_log)
    print("\nTop variants:\n", variants(df).head(3).to_string(index=False))
    print("\nBottlenecks:\n", bottlenecks(df).head(3).round(1).to_string(index=False))
    rows, before, after = sql_kpis(p.to_sqlite("secops.db"))
    print("\nSQL KPI by priority:", rows)
    print("Query plan before index:", before, "\nQuery plan after index:", after)
    print("\nTickets:", list(p.tickets.tickets.values())[:3])


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "run")
