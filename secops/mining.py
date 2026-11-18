"""Process mining on the event log (the same idea Celonis uses: case id + activity + timestamp).
Computes KPIs: throughput time, SLA breaches, variants, bottlenecks, automation rate."""
import pandas as pd

from .agents import SLA_HOURS


def event_log_df(event_log):
    df = pd.DataFrame(event_log)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df.sort_values(["case_id", "timestamp"]).reset_index(drop=True)


def check_event_log(df):
    """Data quality checks for the event log itself."""
    problems = []
    if df[["case_id", "activity", "timestamp"]].isna().any().any():
        problems.append("null values in key columns")
    starts = df.groupby("case_id")["activity"].first()
    if (starts != "Finding received").any():
        problems.append("cases that do not start with 'Finding received'")
    return problems


def variants(df):
    """A variant = the exact sequence of activities a case went through."""
    seq = df.groupby("case_id")["activity"].agg(" > ".join)
    return seq.value_counts().rename_axis("variant").reset_index(name="cases")


def throughput(df, cases):
    t = df.groupby("case_id")["timestamp"].agg(["min", "max"])
    t["hours"] = (t["max"] - t["min"]).dt.total_seconds() / 3600
    t["closed"] = df[df["activity"] == "Case closed"].groupby("case_id").size().reindex(t.index).notna()
    t["priority"] = [cases[c].priority for c in t.index]
    t["sla_hours"] = t["priority"].map(SLA_HOURS)
    t["sla_breached"] = t["closed"] & (t["hours"] > t["sla_hours"])
    return t


def bottlenecks(df):
    """Average waiting time between two consecutive activities (where cases get stuck)."""
    d = df.copy()
    d["next_activity"] = d.groupby("case_id")["activity"].shift(-1)
    d["wait_h"] = (d.groupby("case_id")["timestamp"].shift(-1) - d["timestamp"]).dt.total_seconds() / 3600
    d = d.dropna(subset=["next_activity"])
    out = d.groupby(["activity", "next_activity"])["wait_h"].agg(["mean", "count"]).reset_index()
    return out.sort_values("mean", ascending=False)


def kpis(event_log, cases):
    df = event_log_df(event_log)
    t = throughput(df, cases)
    closed = t[t["closed"]]
    auto = sum(c.status == "auto_remediated" for c in cases.values())
    return {
        "cases": len(t),
        "closed_cases": int(len(closed)),
        "open_awaiting_approval": sum(c.status == "awaiting_approval" for c in cases.values()),
        "avg_throughput_hours": round(float(closed["hours"].mean()), 1) if len(closed) else None,
        "sla_breach_rate": round(float(closed["sla_breached"].mean()), 2) if len(closed) else None,
        "automation_rate": round(auto / len(cases), 2) if cases else 0,
        "by_priority": t["priority"].value_counts().sort_index().to_dict(),
        "top_bottleneck": bottlenecks(df).head(1)[["activity", "next_activity", "mean"]].round(1).to_dict("records"),
        "variants": int(len(variants(df))),
        "data_quality_issues": check_event_log(df),
    }


KPI_SQL = """
WITH durations AS (
  SELECT case_id, (julianday(MAX(timestamp)) - julianday(MIN(timestamp))) * 24 AS hours
  FROM event_log GROUP BY case_id)
SELECT c.priority, COUNT(*) AS cases, ROUND(AVG(d.hours), 1) AS avg_hours,
       RANK() OVER (ORDER BY AVG(d.hours) DESC) AS slowest_rank
FROM cases c JOIN durations d USING (case_id)
GROUP BY c.priority ORDER BY c.priority
"""


def sql_kpis(con):
    """Same KPI in SQL; an index on (case_id, timestamp) lets SQLite avoid a full sort/scan."""
    plan_before = con.execute("EXPLAIN QUERY PLAN " + KPI_SQL).fetchall()
    con.execute("CREATE INDEX IF NOT EXISTS ix_log_case_ts ON event_log(case_id, timestamp)")
    plan_after = con.execute("EXPLAIN QUERY PLAN " + KPI_SQL).fetchall()
    rows = con.execute(KPI_SQL).fetchall()
    return rows, [p[-1] for p in plan_before], [p[-1] for p in plan_after]
