# 🛡️ FedVM-Tracker

**Federal Vulnerability Management Tracking & Reporting Framework**

Federal vulnerability management programs face a consistent operational gap: scan tools generate findings, but translating those findings into prioritized, SLA-tracked, audit-ready remediation workflows is largely manual. FedVM-Tracker bridges that gap by ingesting Nessus scan exports, applying a Federal-context risk prioritization model, auto-generating POA&M entries, and producing leadership-ready reporting — all aligned to NIST SP 800-53 Rev 5 (SI-2, RA-5), FISMA continuous monitoring requirements, and CISA BOD 19-02.

---

## The Problem This Solves

In a typical Federal VM program, these systems don't talk to each other:

```
Tenable Nessus  →  raw CSV findings (noisy, unprioritized)
ServiceNow      →  remediation tickets (manually created)
POA&M tracker   →  spreadsheet (manually updated)
Leadership deck →  manually assembled from all of the above
```

Every week, VM analysts spend hours doing data entry instead of doing vulnerability management. Finding prioritization is inconsistent — CVSS scores alone don't account for asset criticality or active exploitation. Overdue findings accumulate invisibly until an audit surfaces them.

**FedVM-Tracker automates the entire pipeline** from scan output to audit-ready POA&M and executive dashboard in a single command.

---

## Pipeline Overview

```
Nessus CSV Export
      │
      ▼
┌─────────────────────┐
│  nessus_csv_parser  │  Normalize, deduplicate, enrich findings
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│   priority_scorer   │  CVSS + Asset Tier + CISA KEV + Exploit → Score 0-100
└─────────┬───────────┘
          │
          ├──────────────────────────────────────┐
          ▼                                      ▼
┌─────────────────────┐              ┌─────────────────────┐
│   poam_generator    │              │     sla_tracker     │
│  Excel + CSV POA&M  │              │  Compliance, Aging, │
│  NIST 800-53 mapped │              │  Owner Accountability│
└─────────────────────┘              └──────────┬──────────┘
                                                │
                                                ▼
                                     ┌─────────────────────┐
                                     │      dashboard      │
                                     │  HTML Executive     │
                                     │  Briefing Report    │
                                     └─────────────────────┘
```

---

## Prioritization Model

FedVM-Tracker goes beyond raw CVSS scoring with a four-factor weighted model:

| Factor | Weight | Rationale |
|--------|--------|-----------|
| CVSS v3 Base Score | 35% | Technical severity baseline |
| Asset Criticality Tier | 30% | Context: same CVE ≠ same risk on every host |
| CISA KEV Match | 20% | Confirmed active exploitation in the wild |
| Exploit Availability | 15% | Public exploit code lowers attacker bar |

**Composite score (0–100) drives four remediation tiers:**

| Tier | Score | SLA Window | Alignment |
|------|-------|-----------|-----------|
| P1 | ≥ 75 | **15 days** | CISA BOD 19-02 Critical |
| P2 | 50–74 | **30 days** | CISA BOD 19-02 High |
| P3 | 25–49 | **90 days** | Agency ISCM Policy |
| P4 | < 25 | **180 days** | Agency ISCM Policy |

> **Non-negotiable escalation:** Any Critical + CISA KEV finding is forced to P1 (minimum score 90) regardless of asset tier. Active exploitation is active exploitation.

---

## Federal Alignment

| Standard | FedVM-Tracker Coverage |
|----------|----------------------|
| NIST SP 800-53 Rev 5 — SI-2 (Flaw Remediation) | Core control; every module contributes to SI-2 compliance |
| NIST SP 800-53 Rev 5 — RA-5 (Vulnerability Scanning) | Parser ingests scan data; KEV integration fulfills RA-5(5) |
| FISMA Continuous Monitoring | Ongoing scan ingestion, POA&M maintenance, dashboard reporting |
| CISA BOD 19-02 | P1/P2 SLA windows map directly to Critical (15d) / High (30d) |
| CISA KEV Catalog | Live integration; KEV hits escalate to P1 automatically |
| OMB M-02-01 | POA&M format and required fields comply with OMB guidance |
| NIST RMF — Monitor Step | Dashboard and SLA reporting support AO continuous monitoring |

See [`docs/federal_alignment.md`](docs/federal_alignment.md) for full control mapping.

---

## Outputs

### 1. POA&M (Excel + CSV)
Auto-generated Plan of Action & Milestones with:
- Weakness ID in FY-Severity-Sequence format
- NIST 800-53 Rev 5 control mapping per finding
- Milestone steps per remediation tier
- Scheduled completion dates driven by SLA
- Color-coded risk ratings (Very High → Low)
- System metadata sheet

### 2. SLA Compliance Report (stdout + CSV)
- Overdue findings sorted by days past due
- Per-owner compliance rates
- Aging distribution (0-7d, 8-30d, 31-90d, 91d+)
- Repeat offender identification (3+ overdue per owner)
- Top 10 oldest unmitigated criticals/highs

### 3. Leadership Dashboard (HTML)
- Executive KPI summary (total, critical, high, KEV hits, overdue)
- SLA compliance meter with target indicator
- Remediation tier breakdown
- Owner accountability table
- NIST 800-53 control exposure heatmap
- Top 10 priority findings table
- Aging distribution visualization

---

## Quick Start

### Prerequisites
- Python 3.10+
- Nessus scan exported to CSV format

### Installation

```bash
git clone https://github.com/yourusername/fedvm-tracker.git
cd fedvm-tracker
pip install -r requirements.txt
```

### Run with sample data

```bash
python run.py
```

### Run with your own Nessus export

```bash
python run.py \
  --scan   /path/to/nessus_export.csv \
  --system "AGENCY-SYSTEM-NAME" \
  --owner  "System Owner Name" \
  --org    "Your Organization"
```

### Run individual modules

```bash
# Parse only
python parsers/nessus_csv_parser.py data/sample_nessus_export.csv

# Score and prioritize
python scoring/priority_scorer.py data/sample_nessus_export.csv

# Generate POA&M
python poam/poam_generator.py data/sample_nessus_export.csv

# SLA analysis
python sla/sla_tracker.py data/sample_nessus_export.csv

# Full dashboard
python reporting/dashboard.py data/sample_nessus_export.csv
```

---

## Configuration

### Asset Inventory (`data/asset_inventory.json`)

Map IP addresses to asset criticality tiers for accurate prioritization:

```json
{
  "10.0.0.15": "internet_facing",
  "10.0.0.22": "mission_critical",
  "10.0.0.33": "internal_server",
  "10.0.0.44": "workstation",
  "10.0.0.55": "dev_test"
}
```

Available tiers: `internet_facing`, `mission_critical`, `internal_server`, `workstation`, `dev_test`

### System Owner Map (`data/system_owners.json`)

Map IP addresses to system/application owner names for accountability tracking:

```json
{
  "10.0.0.15": "John Smith — OIT Infrastructure",
  "10.0.0.22": "Jane Doe — Application Team",
  "10.0.0.33": "Bob Johnson — Network Operations"
}
```

### CLI Options

```
--scan    Path to Nessus CSV export (default: data/sample_nessus_export.csv)
--system  Information system name   (default: DOT-OCIO-PROD)
--owner   System owner name         (default: System Owner)
--org     Organization name         (default: Department of Transportation)
--assets  Path to asset inventory JSON
--owners  Path to system owner map JSON
--offline Skip live CISA KEV fetch (use cached data)
```

---

## Repository Structure

```
fedvm-tracker/
├── run.py                          # Main pipeline entry point
├── requirements.txt
├── README.md
├── data/
│   └── sample_nessus_export.csv    # Sanitized mock scan data (12 findings)
├── parsers/
│   └── nessus_csv_parser.py        # Nessus CSV ingestion & normalization
├── scoring/
│   └── priority_scorer.py          # 4-factor Federal risk prioritization model
├── poam/
│   └── poam_generator.py           # Federal POA&M generator (Excel + CSV)
├── sla/
│   └── sla_tracker.py              # SLA compliance & aging analysis
├── reporting/
│   └── dashboard.py                # Leadership HTML dashboard
├── docs/
│   ├── methodology.md              # Prioritization model explained
│   └── federal_alignment.md        # NIST / FISMA / CISA control mapping
└── reports/                        # Generated output (gitignored)
```

---

## Planned Enhancements

- [ ] **EPSS Integration** — NIST NVD Exploit Prediction Scoring System for richer exploit probability
- [ ] **ServiceNow Export** — Direct ticket creation via ServiceNow REST API
- [ ] **Tenable.sc / Tenable.io API** — Pull scan data directly without CSV export
- [ ] **Cortex XDR Correlation** — Cross-reference VM findings with EDR telemetry
- [ ] **Trend Analysis** — Month-over-month MTTR and compliance rate tracking
- [ ] **Multi-System Rollup** — Aggregate reporting across multiple system boundaries
- [ ] **Automated POA&M Diff** — Compare successive scans and flag new/closed/changed findings

---

## Documentation

- [Prioritization Methodology](docs/methodology.md)
- [Federal Control Alignment](docs/federal_alignment.md)

---

## License

MIT License — see `LICENSE` for details.

---

*Built to solve real Federal VM program pain points. Aligned to NIST SP 800-53 Rev 5, FISMA, CISA BOD 19-02, and OMB M-02-01.*
