# SOC Dashboard & Analyst Workflow

A complete, lightweight Security Operations Center (SOC) system built with **OpenSearch** — covering log ingestion, detection rules, interactive dashboards, MITRE ATT&CK mapping, alert triage, and a scripted attack demo.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        SOC Dashboard System                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐    ┌───────────────┐    ┌──────────────────┐  │
│  │  Log Sources │──▶│  Python ETL   │──▶ │   OpenSearch     │  │
│  │  (Synthetic) │    │  (Ingest +    │    │   (9200)         │  │
│  │              │    │   Enrich)     │    │                  │  │
│  └──────────────┘    └───────────────┘    └────────┬─────────┘  │
│                                                    │            │
│  ┌──────────────┐    ┌───────────────┐             │            │
│  │  Detection   │──▶│  soc-alerts-*  │◀───────────┘            │
│  │  Engine      │    │  (Alerts)     │                          │
│  └──────────────┘    └───────┬───────┘                          │
│                              │                                  │
│                    ┌─────────▼─────────┐                        │
│                    │   OpenSearch      │                        │
│                    │   Dashboards(5601)│                        │
│                    │   ┌─────────────┐ │                        │
│                    │   │SOC Overview │ │                        │
│                    │   │MITRE Heatmap│ │                        │
│                    │   │Alert Triage │ │                        │
│                    │   └─────────────┘ │                        │
│                    └───────────────────┘                        │
└─────────────────────────────────────────────────────────────────┘

```

---

## Prerequisites

- **Docker** & **Docker Compose** (v2.x+)
- **Python 3.8+** with pip
- ~2 GB free RAM for OpenSearch
- (Optional) `curl` for health checks

---

## Quick Start

### 1. Start the Cluster

```bash
docker-compose up -d
```

Wait for health check to pass (~30-60 seconds).

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 3. Bootstrap (Index Templates + Dashboards)

```bash
chmod +x setup.sh
./setup.sh
```

### 4. Generate & Ingest Synthetic Logs

```bash
python scripts/generate_logs.py
python scripts/ingest_logs.py
```

### 5. Run Detection Engine

```bash
python scripts/detection_engine.py
```

### 6. Open Dashboards

Navigate to **http://localhost:5601** and explore:
- **SOC Analyst Overview** — alert volume, severity breakdown, top hosts/users
- **MITRE ATT&CK Coverage** — technique heatmap and tag cloud
- **Alert Triage & Investigation** — drill-down table, timeline, pivot panels

### 7. Run Attack Simulation (Optional)

```bash
python scripts/simulate_attack.py
python scripts/detection_engine.py  # re-run to generate alerts
```

Then follow the investigation playbook: [`docs/SOC_PLAYBOOK.md`](docs/SOC_PLAYBOOK.md)

---

## File Structure

```
SOC Dashboard/
├── .env                           # Environment variables
├── docker-compose.yml             # OpenSearch + Dashboards
├── setup.sh                       # Bootstrap script
├── requirements.txt               # Python dependencies
│
├── schemas/
│   ├── log_schema.json            # ECS-aligned index template (security-logs-*)
│   └── alert_schema.json          # Alert index template (soc-alerts-*)
│
├── scripts/
│   ├── generate_logs.py           # Synthetic log generator (1200+ events)
│   ├── ingest_logs.py             # Bulk indexer with GeoIP enrichment
│   ├── detection_engine.py        # Rule-based detection → alerts
│   └── simulate_attack.py         # 5-stage attack chain injection
│
├── rules/
│   └── detection_rules.json       # 6 detection rules with MITRE mappings
│
├── dashboards/
│   ├── soc_overview.ndjson        # SOC Analyst Overview dashboard
│   ├── mitre_heatmap.ndjson       # MITRE ATT&CK Coverage dashboard
│   └── alert_triage.ndjson        # Alert Triage & Investigation dashboard
│
├── data/                          # Generated data (gitignored)
│   └── synthetic_logs.ndjson
│
├── docs/
│   └── SOC_PLAYBOOK.md            # Investigation walkthrough
│
└── README.md                      # This file
```

---

## Detection Rules

| ID | Rule Name | Severity | MITRE Technique |
|----|-----------|----------|-----------------|
| RULE-001 | Suspicious PowerShell Execution | High | T1059.001 |
| RULE-002 | Brute-Force Login Attempt | Medium | T1110.001 |
| RULE-003 | New Admin Account Created | Critical | T1136.001 |
| RULE-004 | Rare Outbound Network Connection | High | T1071.001 |
| RULE-005 | Certutil Abuse for File Download | High | T1140 |
| RULE-006 | Suspicious Script Host Execution | Medium | T1059.005 |

---

## Dashboards

### SOC Analyst Overview
- Alert Volume Over Time (line chart)
- Alerts by Severity (donut chart)
- Top Affected Hosts (horizontal bar)
- Top Affected Users (horizontal bar)
- Alert Summary Table (noisy vs high-risk)

### MITRE ATT&CK Coverage
- Tactic × Technique Heatmap
- Technique Tag Cloud
- Coverage Data Table

### Alert Triage & Investigation
- Alert Detail Table (drill-down)
- Alert Event Timeline (by severity)
- Investigation Pivot: By Host
- Investigation Pivot: By User
- Investigation Pivot: By IP

---

## Attack Simulation Scenario

The `simulate_attack.py` script injects a realistic 5-stage attack chain:

1. **Brute-Force** — 15 failed logins from external IP (Germany)
2. **Initial Access** — Successful login after brute-force
3. **Execution** — PowerShell download cradle + encoded commands
4. **C2 Communication** — Outbound TCP to Russia on port 4444
5. **Persistence** — New admin account `svc_support` created

All events share the same attacker IP, victim user, and target host for realistic pivot analysis.

---

## Tear Down

```bash
docker-compose down -v  # Removes containers and data volumes
```

---

## License

## VIEW all logs

docker-compose logs -f



## VIEW logs for the dashbord

docker-compose logs -f opensearch-dashboards




## VIEW logs for the opensearch

docker-compose logs -f opensearch
