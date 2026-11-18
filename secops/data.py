"""Synthetic data: assets, IAM bindings, vulnerability scanner findings and SIEM alerts.
Everything here is fake - no real systems, no real CVEs (ids start with SYN-)."""
import random
from datetime import datetime, timedelta

ASSETS = {
    "A-01": {"name": "clinic-patient-db", "type": "database", "criticality": "high", "internet_facing": False},
    "A-02": {"name": "hotel-access-control", "type": "server", "criticality": "high", "internet_facing": False},
    "A-03": {"name": "payment-gateway", "type": "api", "criticality": "critical", "internet_facing": True},
    "A-04": {"name": "booking-website", "type": "web", "criticality": "medium", "internet_facing": True},
    "A-05": {"name": "staff-wiki", "type": "web", "criticality": "low", "internet_facing": False},
}

# Identity and Access Management (IAM): which identities hold which role on each asset
IAM_BINDINGS = {
    "A-01": [("svc-backup", "admin"), ("dr-novak", "reader")],
    "A-02": [("reception", "operator")],
    "A-03": [("svc-payments", "admin"), ("ci-bot", "admin"), ("analyst", "reader")],
    "A-04": [("web-deployer", "editor")],
    "A-05": [("everyone", "admin")],
}

VULN_CATALOG = [  # title, category, CVSS base score
    ("SQL injection in login form", "web", 9.1),
    ("Outdated OpenSSL library", "server", 7.5),
    ("RDP port 3389 open to the internet", "network", 8.8),
    ("Weak TLS configuration", "network", 5.3),
    ("Over-privileged service account", "iam", 7.2),
    ("Missing HTTP security headers", "web", 3.1),
    ("Default credentials on admin panel", "iam", 9.8),
]

SIEM_RULES = [("Multiple failed logins", "medium"), ("Outbound traffic spike", "high"),
              ("Privilege escalation attempt", "high"), ("New admin user created", "low")]

START = datetime(2026, 11, 2, 8, 0)


def generate(n_findings=40, n_alerts=25, seed=7):
    """Return (findings, siem_alerts). A few findings are deliberately broken
    so the data validation step has something to quarantine."""
    rng = random.Random(seed)
    findings = []
    for i in range(1, n_findings + 1):
        title, category, cvss = rng.choice(VULN_CATALOG)
        findings.append({
            "finding_id": f"F-{i:03d}", "asset_id": rng.choice(list(ASSETS)),
            "title": title, "category": category, "cvss": cvss,
            "vuln_id": f"SYN-2026-{rng.randint(1000, 9999)}", "scanner": "synthetic-scanner",
            "detected_at": (START + timedelta(hours=rng.randint(0, 96))).isoformat(),
        })
    findings[3]["asset_id"] = "A-99"           # unknown asset
    findings[7]["cvss"] = 12.0                 # CVSS outside 0-10
    findings[11]["detected_at"] = "yesterday"  # invalid timestamp
    findings.append(dict(findings[0]))         # duplicate finding_id
    alerts = []
    for i in range(1, n_alerts + 1):
        rule, sev = rng.choice(SIEM_RULES)
        alerts.append({"alert_id": f"S-{i:03d}", "asset_id": rng.choice(list(ASSETS)), "rule": rule,
                       "severity": sev, "ts": (START + timedelta(hours=rng.randint(0, 96))).isoformat()})
    return findings, alerts
