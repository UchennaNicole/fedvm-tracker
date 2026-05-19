# Prioritization Methodology — FedVM-Tracker

## The Problem with CVSS-Only Prioritization

CVSS (Common Vulnerability Scoring System) scores are the industry standard
for vulnerability severity, but using CVSS alone to drive remediation priority
leads to systematic misallocation of resources:

- A CVSS 9.8 on an air-gapped development server is low operational risk
- A CVSS 6.5 on an internet-facing webserver with active exploitation in
  the wild is an emergency

Federal VM programs that sort their queues by CVSS score alone consistently
fail to close the findings that matter most. FedVM-Tracker addresses this
with a four-factor weighted scoring model.

---

## Scoring Model

### Factor 1 — CVSS v3 Base Score (Weight: 35%)

CVSS remains a meaningful baseline signal. It captures technical severity
including attack vector, complexity, privileges required, and scope.
Normalized from 0–10 to 0–100 for the composite calculation.

```
cvss_component = (cvss_score / 10.0) * 100
```

**Why 35% weight:** CVSS is technical severity, not operational risk.
Giving it less than half the weight prevents high-CVSS, low-exposure
findings from dominating the queue.

---

### Factor 2 — Asset Criticality Tier (Weight: 30%)

The same vulnerability on different assets represents different risk.
Asset tiers reflect the mission criticality and exposure of the host.

| Tier | Score | Examples |
|------|-------|---------|
| `internet_facing` | 100 | Public web servers, VPN endpoints, DMZ hosts |
| `mission_critical` | 90 | SCADA/ICS, core databases, authentication servers |
| `internal_server` | 70 | Internal application servers, file shares |
| `workstation` | 50 | Standard end-user endpoints |
| `dev_test` | 20 | Development and test environments |
| `unknown` | 50 | Default for unclassified assets |

Asset tiers are assigned via the `data/asset_inventory.json` file. Unclassified
assets default to 50 (workstation-equivalent) to avoid suppressing unknown risk.

**Operational note:** In a mature Federal VM program, asset tier maps to the
FIPS 199 system categorization. Internet-facing assets typically carry High
confidentiality/integrity impact; dev/test may be Moderate or Low.

---

### Factor 3 — CISA KEV Match (Weight: 20%)

The CISA Known Exploited Vulnerabilities catalog represents confirmed,
active exploitation in the wild. A KEV match is the strongest single
signal that a vulnerability needs immediate remediation.

```
kev_component = 100 if cve in kev_catalog else 0
```

**Why KEV beats CVSS:** Ransomware operators and nation-state actors
exploit KEV vulnerabilities regardless of CVSS score. CISA BOD 22-01
requires Federal agencies to remediate KEV vulnerabilities on defined
timelines, making this a compliance driver as well as a risk signal.

KEV data is fetched live from:
`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

A local cache is maintained for offline operation.

---

### Factor 4 — Exploit Availability (Weight: 15%)

Beyond the KEV list, exploit availability captures whether public
exploit code exists for a vulnerability — lowering the bar for
opportunistic attackers.

Currently derived from:
- KEV catalog match (inherits from Factor 3)
- CVSS score ≥ 9.0 (high probability of weaponized exploit)

**Planned enhancement:** Integration with NVD EPSS (Exploit Prediction
Scoring System) for more granular exploit probability scoring.

---

## Composite Score Formula

```
Risk Priority Score =
    (cvss_component    × 0.35) +
    (asset_component   × 0.30) +
    (kev_component     × 0.20) +
    (exploit_component × 0.15)
```

Score range: 0–100 (capped)

**Non-negotiable escalation rule:** Any finding that is both Critical severity
AND present on the CISA KEV list is assigned a minimum score of 90, regardless
of asset tier. These represent the highest-confidence, highest-severity risk
in any Federal environment.

---

## Remediation Tier Assignment

| Tier | Score Threshold | SLA Window | Basis |
|------|----------------|-----------|-------|
| P1 | ≥ 75 | 15 days | CISA BOD 19-02 (Critical) |
| P2 | 50–74 | 30 days | CISA BOD 19-02 (High) |
| P3 | 25–49 | 90 days | Agency ISCM policy |
| P4 | < 25 | 180 days | Agency ISCM policy |

---

## Worked Examples

### Example 1: High CVSS, Low Risk
- Finding: Apache Log4Shell (CVE-2021-44228), CVSS 10.0
- Host: Internal dev server (`dev_test` tier)
- KEV: YES
- Composite: (100×0.35) + (20×0.30) + (100×0.20) + (100×0.15) = **76.0 → P1**
- Note: Even on a dev server, an active KEV hit pushes this to P1.
  Dev systems are often on the same network segments as production.

### Example 2: Medium CVSS, High Risk
- Finding: SSL Certificate Expired, CVSS 4.3
- Host: Internet-facing DOT web portal (`internet_facing` tier)
- KEV: NO
- Composite: (43×0.35) + (100×0.30) + (0×0.20) + (0×0.15) = **45.1 → P3**
- Note: Expired certs on public-facing systems cause browser warnings
  and erode public trust. P3 is appropriate; expedite if user-facing.

### Example 3: Critical CVSS, Low Real-World Risk
- Finding: EternalBlue SMBv1 RCE (CVE-2017-0144), CVSS 9.8
- Host: Air-gapped test system (`dev_test` tier)
- KEV: YES (non-negotiable escalation applies)
- Composite forced to 90 → **P1**
- Note: Air-gapped status should be documented as a compensating control
  in the POA&M, but it does not eliminate the finding from the queue.

---

## Assumptions and Limitations

1. **Asset inventory accuracy:** The model is only as good as the asset
   classification data. Unclassified assets default to workstation-tier.
   Invest in maintaining the asset inventory.

2. **Scan coverage:** The parser only sees what Nessus scans. Blind spots
   (unscanned subnets, agentless hosts) are not reflected in the output.
   Coverage gaps should be tracked separately.

3. **False positive rate:** Nessus findings are not verified exploits.
   High-priority findings should be validated before emergency remediation
   actions. Plugin output review is essential for P1 findings.

4. **CVSS base vs. environmental score:** FedVM-Tracker uses CVSS base
   scores from Nessus. Organizations with CVSS environmental scoring
   capability can substitute environmental scores for more precise
   asset-context weighting.
