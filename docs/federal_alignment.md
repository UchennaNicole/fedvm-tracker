# Federal Alignment — FedVM-Tracker

## Overview

FedVM-Tracker is built ground-up to support Federal vulnerability management
programs operating under FISMA continuous monitoring requirements. Every
component maps directly to a published Federal standard or directive.

---

## NIST SP 800-53 Rev 5 Control Mapping

### SI-2 — Flaw Remediation (Primary Control)

**Control Statement:** The organization identifies, reports, and corrects
information system flaws; tests software and firmware updates related to
flaw remediation for effectiveness and potential side effects; installs
security-relevant software updates within an organizationally defined
time period; and incorporates flaw remediation into the organizational
configuration management process.

**FedVM-Tracker Implementation:**

| Module | SI-2 Contribution |
|--------|------------------|
| `nessus_csv_parser.py` | Identifies flaws from authenticated endpoint scans |
| `priority_scorer.py` | Prioritizes flaws by exploitability and asset impact |
| `poam_generator.py` | Documents flaws in POA&M with scheduled completion dates |
| `sla_tracker.py` | Enforces remediation timelines per SI-2(2) time constraints |
| `dashboard.py` | Provides leadership visibility into flaw remediation status |

**Enhancement SI-2(2) — Automated Flaw Remediation Status:**
The SLA tracker and dashboard fulfill the automated tracking requirement
by generating continuous visibility into open, overdue, and closed findings
without manual report compilation.

---

### RA-5 — Vulnerability Monitoring and Scanning

**Control Statement:** The organization scans for vulnerabilities in the
information system and hosted applications at defined frequencies and
when new vulnerabilities potentially affecting the system are identified.

**FedVM-Tracker Implementation:**

- Parser ingests Nessus scan output from scheduled scans (weekly/monthly per
  ISCM strategy)
- KEV integration ensures newly identified exploited vulnerabilities are
  immediately flagged regardless of scan schedule
- Findings are timestamped with scan date for RA-5(3) coverage analysis

**Enhancement RA-5(4) — Discoverable Information:**
Asset tier classification identifies internet-facing assets for more
aggressive scanning cadence.

**Enhancement RA-5(5) — Privileged Access:**
Parser handles both credentialed and uncredentialed scan outputs; credentialed
scan findings are prioritized as they reflect true installed software state.

---

### CM-7 — Least Functionality

**Control Statement:** The organization configures the information system to
provide only essential capabilities, prohibiting or restricting the use of
functions, ports, protocols, and services not required.

**FedVM-Tracker Contribution:**
Findings for Telnet (port 23), SNMP with default strings, and unnecessary
services (AJP connector, mod_status) are automatically mapped to CM-7 in
the POA&M. This creates an audit trail linking vulnerability findings to
the least-functionality control family.

---

### SC-8 — Transmission Confidentiality and Integrity

**Control Statement:** The information system implements cryptographic
mechanisms to prevent unauthorized disclosure of information during
transmission.

**FedVM-Tracker Contribution:**
Weak cipher suite and expired certificate findings map to SC-8 and SC-17.
POA&M entries for these findings include solution guidance to enforce
TLS 1.2+ and remove weak ciphers.

---

## FISMA Continuous Monitoring Alignment

### OMB Memorandum M-14-03 / NIST SP 800-137

FedVM-Tracker supports the FISMA continuous monitoring (ISCM) requirement
that agencies maintain ongoing awareness of information security,
vulnerabilities, and threats.

**Frequency Alignment:**

| Asset Category | Scan Frequency | SLA Window | Standard |
|---------------|---------------|-----------|---------|
| Internet-facing | Weekly | 15 days (P1) | CISA BOD 19-02 |
| Internal servers | Bi-weekly | 30 days (P2) | Agency ISCM |
| Workstations | Monthly | 90 days (P3) | Agency ISCM |
| Dev/Test | Monthly | 180 days (P4) | Agency ISCM |

---

## CISA Binding Operational Directive (BOD) 19-02

**Directive:** Agencies must remediate Critical vulnerabilities within
15 days and High vulnerabilities within 30 days of identification.

**FedVM-Tracker Enforcement:**
- P1 tier (15-day SLA) is applied to all Critical findings
- P1 tier is also applied to High findings with CISA KEV match
- SLA tracker flags overdue items against these BOD windows
- Dashboard displays days past due for accountability

---

## CISA Known Exploited Vulnerabilities (KEV) Catalog

FedVM-Tracker integrates with the live CISA KEV JSON feed:
`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

**KEV Integration Logic:**
1. CVE IDs from Nessus findings are matched against the full KEV catalog
2. KEV matches trigger automatic P1 tier assignment
3. KEV status is surfaced in the dashboard, POA&M, and SLA reports
4. CISA KEV findings are treated as active exploitation risk regardless
   of CVSS score

**Rationale:** A CVE with a CVSS score of 6.5 that appears on the KEV
list represents higher real-world risk than a CVSS 9.8 with no known
exploitation. The KEV integration operationalizes this distinction.

---

## POA&M Federal Standard Compliance

The POA&M generated by `poam_generator.py` conforms to:

- **OMB Memorandum M-02-01** — Guidance for Preparing and Submitting
  Security Plans of Action and Milestones
- **NIST SP 800-53A Rev 5** — Assessing Security and Privacy Controls
- **FedRAMP POA&M Template** — Adapted for civilian agency FISMA reporting

**Required POA&M Fields (all populated by generator):**

| Field | Source |
|-------|--------|
| Weakness ID | Auto-generated (FY-Severity-Sequence) |
| Weakness Description | Nessus finding synopsis |
| NIST Control | Keyword-mapped from vulnerability name |
| Point of Contact | System owner (configurable) |
| Scheduled Completion Date | Calculated from SLA tier |
| Milestone | Tier-specific remediation steps |
| Status | Open / In Progress / Closed |
| Risk Rating | Derived from remediation tier |

---

## Relationship to NIST Risk Management Framework (RMF)

FedVM-Tracker supports the **Monitor** step of the RMF lifecycle:

```
Categorize → Select → Implement → Assess → Authorize → MONITOR
                                                             ↑
                                                    FedVM-Tracker operates here
```

The tool provides:
- Ongoing control effectiveness assessment (SI-2 flaw remediation)
- Continuous security status reporting
- POA&M maintenance aligned to ATO conditions
- Risk posture visibility for the Authorizing Official (AO)
