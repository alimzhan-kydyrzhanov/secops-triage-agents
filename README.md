# SecOps Triage Agents

A multi-agent AI system that automates a small security operations (SecOps) workflow, from vulnerability triage through investigation to **governed remediation**, and measures the whole process with **process mining** KPIs.

All data is synthetic (fake clinic / hotel / payment systems, vulnerability ids start with `SYN-`).

```
scanner findings ──► event bus (Kafka-style topic, offsets, at-least-once)
                         │
                         ▼
   data validation ──► quarantine (reason per row)
                         │
     ┌───────────────────┼────────────────────┐
     ▼                   ▼                    ▼
 Triage agent ──► Investigation agent ──► Remediation agent
 (CVSS x asset     (SIEM alerts, IAM,        (playbook + governance:
  criticality x     optional LLM summary      high-risk = human approval)
  exposure)         with output validation)
                         │
                         ▼
     ticketing (SEC-n) + outbound webhook + REST API (/approvals)
                         │
                         ▼
     event log (case_id, activity, timestamp) ──► process mining KPIs
     (throughput, SLA breaches, variants, bottlenecks, automation rate; SQL + index)
```

## Run

```bash
pip install -r requirements.txt
python -m secops run          # full pipeline + KPI report
pytest -q                     # 18 tests
python -m secops serve        # REST API on :8080 (API_TOKEN protects POST endpoints)
docker build -t secops-triage-agents . && docker run -p 8080:8080 secops-triage-agents
```

Optional: `ANTHROPIC_API_KEY` enables the LLM summary (Claude API); `WEBHOOK_URL` enables outbound notifications.

## API

| Method | Path | What |
|---|---|---|
| GET | `/health` | liveness probe |
| GET | `/cases?priority=P1` | cases with priority, evidence, proposed action |
| GET | `/kpis` | process mining KPIs |
| GET | `/dashboard` | live HTML KPI dashboard (auto-refresh) |
| POST | `/webhooks/scanner` | a scanner pushes one finding (JSON) |
| POST | `/approvals/<case_id>` | `{"approver": "lead", "approved": true}` |

## Layout

| Path | Purpose |
|---|---|
| `secops/data.py` | synthetic assets, IAM bindings, findings, SIEM alerts |
| `secops/bus.py` | Kafka-style event bus (topics, consumer-group offsets, lag) |
| `secops/agents.py` | Triage, Investigation, Remediation agents + LLM client |
| `secops/actions.py` | ticketing system + webhook notifier |
| `secops/pipeline.py` | orchestrator, data validation, approvals, event log, SQLite |
| `secops/mining.py` | process mining KPIs (pandas) + SQL KPI with query tuning |
| `secops/api.py` | REST API and inbound webhook |
| `infra/main.tf` | Terraform for GCP Cloud Run (not applied yet) |
| `.github/workflows/ci.yml` | CI: tests, demo run, Docker build |
