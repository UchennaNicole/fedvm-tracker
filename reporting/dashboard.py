"""
dashboard.py
------------
Generates a leadership-ready HTML vulnerability management dashboard from
scored findings and SLA tracker output. Designed for Federal program managers,
ISSOs, and AO briefings — clear risk posture at a glance without requiring
the audience to interpret raw scan data.

Dashboard sections:
    1. Executive Summary        — Overall posture, compliance rate, trend
    2. Severity Distribution    — Visual breakdown by severity tier
    3. Remediation Tier Counts  — P1/P2/P3/P4 with SLA windows
    4. SLA Compliance by Owner  — Owner accountability table
    5. KEV Exposure             — CISA Known Exploited Vulnerabilities hits
    6. Top 10 Priority Findings — Highest-risk findings requiring immediate action
    7. Aging Analysis           — Findings bucketed by time open
    8. NIST Control Heatmap     — Which controls are generating the most findings

Usage:
    from reporting.dashboard import Dashboard
    dash = Dashboard(system_name="DOT-OCIO-PROD")
    dash.generate(scored_findings, sla_report, output_path="reports/dashboard.html")
"""

import logging
from collections import defaultdict, Counter
from datetime import date
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


class Dashboard:
    """
    Generates an HTML vulnerability management dashboard.

    Args:
        system_name:   Name of the information system.
        organization:  Organization name shown in the header.
    """

    def __init__(
        self,
        system_name:  str = "Information System",
        organization: str = "Department of Transportation",
    ):
        self.system_name  = system_name
        self.organization = organization

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def generate(
        self,
        findings:   list[dict],
        sla_report: Optional[dict] = None,
        output_path: str = "reports/dashboard.html",
    ) -> str:
        """
        Generate the HTML dashboard.

        Args:
            findings:     Scored findings from PriorityScorer.
            sla_report:   Optional report dict from SLATracker.analyze().
            output_path:  Output path for the HTML file.

        Returns:
            Path to generated HTML file.
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        metrics      = self._compute_metrics(findings, sla_report)
        html_content = self._render_html(metrics, findings, sla_report)

        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html_content)

        log.info(f"Dashboard generated: {path}")
        return str(path)

    # ------------------------------------------------------------------
    # Metrics computation
    # ------------------------------------------------------------------

    def _compute_metrics(self, findings: list[dict], sla_report: Optional[dict]) -> dict:
        sev_counts  = Counter(f.get("severity", "unknown") for f in findings)
        tier_counts = Counter(f.get("remediation_tier", "P4") for f in findings)
        kev_hits    = sum(1 for f in findings if f.get("kev_match"))

        control_counter = Counter()
        for f in findings:
            # Pull controls from score_breakdown or map from name
            name = f.get("name", "").lower()
            for keyword in ["si-2", "ra-5", "cm-7", "sc-8", "ac-17", "ia-5"]:
                if any(k in name for k in [keyword.replace("-", ""), keyword.lower()]):
                    control_counter[keyword.upper()] += 1
        # Default if no matches
        if not control_counter:
            control_counter = Counter({"SI-2": len(findings), "RA-5": len(findings)})

        compliance_rate = sla_report["summary"]["compliance_rate"] if sla_report else 0
        overdue_count   = sla_report["summary"]["overdue"] if sla_report else 0

        return {
            "total":           len(findings),
            "critical":        sev_counts.get("critical", 0),
            "high":            sev_counts.get("high", 0),
            "medium":          sev_counts.get("medium", 0),
            "low":             sev_counts.get("low", 0),
            "p1":              tier_counts.get("P1", 0),
            "p2":              tier_counts.get("P2", 0),
            "p3":              tier_counts.get("P3", 0),
            "p4":              tier_counts.get("P4", 0),
            "kev_hits":        kev_hits,
            "overdue":         overdue_count,
            "compliance_rate": compliance_rate,
            "control_counts":  dict(control_counter.most_common(8)),
            "generated":       date.today().strftime("%B %d, %Y"),
        }

    # ------------------------------------------------------------------
    # HTML rendering
    # ------------------------------------------------------------------

    def _render_html(
        self,
        m:          dict,
        findings:   list[dict],
        sla_report: Optional[dict],
    ) -> str:
        top_findings = findings[:10]
        owner_rows   = self._render_owner_table(sla_report)
        finding_rows = self._render_finding_rows(top_findings)
        aging_bars   = self._render_aging_bars(sla_report)
        control_bars = self._render_control_bars(m["control_counts"])

        posture_color = (
            "#c00000" if m["compliance_rate"] < 60 else
            "#ff8c00" if m["compliance_rate"] < 80 else
            "#107c10"
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>FedVM-Tracker | {self.system_name} Dashboard</title>
<style>
  :root {{
    --critical: #C00000; --high: #FF4444; --medium: #FFC000;
    --low: #92D050; --info: #0070C0; --bg: #F3F4F6;
    --card: #FFFFFF; --border: #E5E7EB; --text: #1F2937;
    --header: #1F3864; --accent: #2E75B6;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: var(--bg); color: var(--text); font-size: 14px; }}
  header {{ background: var(--header); color: white; padding: 20px 32px; display: flex; justify-content: space-between; align-items: center; }}
  header h1 {{ font-size: 20px; font-weight: 700; }}
  header .meta {{ font-size: 12px; opacity: 0.8; text-align: right; }}
  .container {{ max-width: 1400px; margin: 0 auto; padding: 24px 32px; }}
  .section-title {{ font-size: 14px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; color: var(--accent); margin-bottom: 16px; padding-bottom: 6px; border-bottom: 2px solid var(--accent); }}
  .grid-4 {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }}
  .grid-2 {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; margin-bottom: 24px; }}
  .grid-3 {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 24px; }}
  .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }}
  .stat-card {{ text-align: center; border-top: 4px solid var(--accent); }}
  .stat-card .value {{ font-size: 36px; font-weight: 800; line-height: 1; margin: 8px 0 4px; }}
  .stat-card .label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: #6B7280; }}
  .stat-card.critical {{ border-top-color: var(--critical); }}
  .stat-card.critical .value {{ color: var(--critical); }}
  .stat-card.high {{ border-top-color: var(--high); }}
  .stat-card.high .value {{ color: var(--high); }}
  .stat-card.medium {{ border-top-color: var(--medium); }}
  .stat-card.medium .value {{ color: #B45309; }}
  .stat-card.low {{ border-top-color: var(--low); }}
  .stat-card.low .value {{ color: #166534; }}
  .stat-card.kev {{ border-top-color: #7C3AED; }}
  .stat-card.kev .value {{ color: #7C3AED; }}
  .stat-card.overdue {{ border-top-color: #DC2626; }}
  .stat-card.overdue .value {{ color: #DC2626; }}
  .stat-card.compliance .value {{ color: {posture_color}; }}
  .bar-row {{ display: flex; align-items: center; margin-bottom: 10px; gap: 10px; }}
  .bar-label {{ width: 120px; font-size: 12px; font-weight: 600; text-align: right; flex-shrink: 0; }}
  .bar-track {{ flex: 1; background: #F3F4F6; border-radius: 4px; height: 22px; overflow: hidden; }}
  .bar-fill {{ height: 100%; border-radius: 4px; display: flex; align-items: center; padding-left: 8px; font-size: 11px; font-weight: 700; color: white; transition: width 0.3s; }}
  .bar-count {{ width: 40px; font-size: 12px; font-weight: 700; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ background: var(--header); color: white; padding: 10px 12px; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }}
  td {{ padding: 9px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }}
  tr:hover td {{ background: #F9FAFB; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 700; }}
  .badge-critical {{ background: #FEE2E2; color: var(--critical); }}
  .badge-high {{ background: #FFE4E4; color: #C0392B; }}
  .badge-medium {{ background: #FEF3C7; color: #92400E; }}
  .badge-low {{ background: #D1FAE5; color: #065F46; }}
  .badge-p1 {{ background: #FEE2E2; color: #991B1B; }}
  .badge-p2 {{ background: #FEF3C7; color: #92400E; }}
  .badge-p3 {{ background: #DBEAFE; color: #1E40AF; }}
  .badge-p4 {{ background: #F3F4F6; color: #374151; }}
  .badge-kev {{ background: #EDE9FE; color: #5B21B6; }}
  .compliance-bar {{ width: 100%; height: 12px; background: #E5E7EB; border-radius: 6px; overflow: hidden; }}
  .compliance-fill {{ height: 100%; border-radius: 6px; background: {posture_color}; width: {m["compliance_rate"]}%; }}
  footer {{ text-align: center; padding: 20px; font-size: 11px; color: #9CA3AF; border-top: 1px solid var(--border); margin-top: 24px; }}
</style>
</head>
<body>

<header>
  <div>
    <h1>🛡️ FedVM-Tracker — Vulnerability Management Dashboard</h1>
    <div style="font-size:13px; margin-top:4px; opacity:0.9">{self.organization} | {self.system_name}</div>
  </div>
  <div class="meta">
    Generated: {m["generated"]}<br/>
    NIST SP 800-53 Rev 5 Aligned<br/>
    FISMA Continuous Monitoring
  </div>
</header>

<div class="container">

  <!-- Executive Summary KPIs -->
  <div class="section-title">Executive Summary</div>
  <div class="grid-4" style="grid-template-columns: repeat(7, 1fr);">
    <div class="card stat-card"><div class="value">{m["total"]}</div><div class="label">Total Open</div></div>
    <div class="card stat-card critical"><div class="value">{m["critical"]}</div><div class="label">Critical</div></div>
    <div class="card stat-card high"><div class="value">{m["high"]}</div><div class="label">High</div></div>
    <div class="card stat-card medium"><div class="value">{m["medium"]}</div><div class="label">Medium</div></div>
    <div class="card stat-card low"><div class="value">{m["low"]}</div><div class="label">Low</div></div>
    <div class="card stat-card kev"><div class="value">{m["kev_hits"]}</div><div class="label">KEV Hits</div></div>
    <div class="card stat-card overdue"><div class="value">{m["overdue"]}</div><div class="label">Overdue</div></div>
  </div>

  <!-- Compliance Meter -->
  <div class="card" style="margin-bottom: 24px;">
    <div class="section-title">Overall SLA Compliance Rate</div>
    <div style="display:flex; align-items:center; gap:16px;">
      <div style="font-size:42px; font-weight:800; color:{posture_color}; width:80px;">{m["compliance_rate"]}%</div>
      <div style="flex:1;">
        <div class="compliance-bar"><div class="compliance-fill"></div></div>
        <div style="font-size:11px; color:#6B7280; margin-top:6px;">
          Target: ≥ 90% | Status: {"✅ Meeting Target" if m["compliance_rate"] >= 90 else "⚠️ Below Target — Escalation Required" if m["compliance_rate"] < 70 else "🔶 Approaching Target"}
        </div>
      </div>
    </div>
  </div>

  <!-- Remediation Tiers & Aging -->
  <div class="grid-2">
    <div class="card">
      <div class="section-title">Remediation Tiers (SLA Windows)</div>
      {self._render_tier_bars(m)}
    </div>
    <div class="card">
      <div class="section-title">Finding Age Distribution</div>
      {aging_bars}
    </div>
  </div>

  <!-- Top Priority Findings -->
  <div class="card" style="margin-bottom: 24px;">
    <div class="section-title">Top 10 Priority Findings — Immediate Action Required</div>
    <table>
      <thead><tr>
        <th>Tier</th><th>Score</th><th>Severity</th><th>Host</th>
        <th>Vulnerability</th><th>CVE</th><th>KEV</th><th>SLA Due</th>
      </tr></thead>
      <tbody>{finding_rows}</tbody>
    </table>
  </div>

  <!-- Owner Compliance & Control Heatmap -->
  <div class="grid-2">
    <div class="card">
      <div class="section-title">SLA Compliance by System Owner</div>
      <table>
        <thead><tr><th>Owner</th><th>Total</th><th>Overdue</th><th>Rate</th></tr></thead>
        <tbody>{owner_rows}</tbody>
      </table>
    </div>
    <div class="card">
      <div class="section-title">NIST 800-53 Control Exposure (Top 8)</div>
      {control_bars}
    </div>
  </div>

</div>

<footer>
  FedVM-Tracker | Aligned to NIST SP 800-53 Rev 5 (SI-2, RA-5) | FISMA Continuous Monitoring | CISA BOD 19-02
</footer>
</body>
</html>"""

    # ------------------------------------------------------------------
    # Sub-renderers
    # ------------------------------------------------------------------

    def _render_tier_bars(self, m: dict) -> str:
        tiers = [
            ("P1 — 15 Days (Critical/KEV)", m["p1"],  "#C00000", "p1"),
            ("P2 — 30 Days (High Risk)",    m["p2"],  "#FF8C00", "p2"),
            ("P3 — 90 Days (Moderate)",     m["p3"],  "#0070C0", "p3"),
            ("P4 — 180 Days (Low)",         m["p4"],  "#92D050", "p4"),
        ]
        total  = max(m["total"], 1)
        html   = ""
        for label, count, color, _ in tiers:
            pct = round((count / total) * 100)
            html += f"""
            <div class="bar-row">
              <div class="bar-label">{label.split(" — ")[0]}</div>
              <div class="bar-track">
                <div class="bar-fill" style="width:{pct}%; background:{color};">{label.split(" — ")[1]}</div>
              </div>
              <div class="bar-count">{count}</div>
            </div>"""
        return html

    def _render_aging_bars(self, sla_report: Optional[dict]) -> str:
        if not sla_report:
            return "<p style='color:#9CA3AF; font-size:13px;'>No SLA data available.</p>"
        aging  = sla_report.get("aging_distribution", {})
        total  = max(sum(aging.values()), 1)
        colors = {"0-7 days": "#92D050", "8-30 days": "#FFC000", "31-90 days": "#FF8C00", "91+ days": "#C00000"}
        html   = ""
        for bucket, count in aging.items():
            pct   = round((count / total) * 100)
            color = colors.get(bucket, "#0070C0")
            html += f"""
            <div class="bar-row">
              <div class="bar-label">{bucket}</div>
              <div class="bar-track">
                <div class="bar-fill" style="width:{pct}%; background:{color};">{pct}%</div>
              </div>
              <div class="bar-count">{count}</div>
            </div>"""
        return html or "<p style='color:#9CA3AF;'>No aging data.</p>"

    def _render_control_bars(self, control_counts: dict) -> str:
        if not control_counts:
            return "<p style='color:#9CA3AF; font-size:13px;'>No control data available.</p>"
        max_val = max(control_counts.values(), default=1)
        html    = ""
        for control, count in sorted(control_counts.items(), key=lambda x: -x[1]):
            pct = round((count / max_val) * 100)
            html += f"""
            <div class="bar-row">
              <div class="bar-label">{control}</div>
              <div class="bar-track">
                <div class="bar-fill" style="width:{pct}%; background:#1F3864;">{count} findings</div>
              </div>
              <div class="bar-count">{count}</div>
            </div>"""
        return html

    @staticmethod
    def _render_finding_rows(findings: list[dict]) -> str:
        rows = ""
        for f in findings:
            sev   = f.get("severity", "unknown")
            tier  = f.get("remediation_tier", "P4")
            kev   = f.get("kev_match", False)
            score = f.get("risk_priority_score", 0)
            rows += f"""
            <tr>
              <td><span class="badge badge-{tier.lower()}">{tier}</span></td>
              <td><strong>{score}</strong></td>
              <td><span class="badge badge-{sev}">{sev.capitalize()}</span></td>
              <td style="font-family:monospace;">{f.get("host","")}</td>
              <td>{f.get("name","")[:55]}</td>
              <td style="font-size:11px;">{f.get("cve","N/A")}</td>
              <td>{"<span class='badge badge-kev'>KEV</span>" if kev else "—"}</td>
              <td style="font-size:11px;">{f.get("sla_due_date","")}</td>
            </tr>"""
        return rows or "<tr><td colspan='8' style='text-align:center;color:#9CA3AF;'>No findings.</td></tr>"

    @staticmethod
    def _render_owner_table(sla_report: Optional[dict]) -> str:
        if not sla_report:
            return "<tr><td colspan='4' style='color:#9CA3AF;'>No SLA data.</td></tr>"
        rows = ""
        for owner, stats in sorted(
            sla_report.get("owner_compliance", {}).items(),
            key=lambda x: x[1]["compliance_rate"]
        ):
            rate  = stats["compliance_rate"]
            color = "#C00000" if rate < 60 else "#FF8C00" if rate < 80 else "#107C10"
            rows += f"""
            <tr>
              <td>{owner}</td>
              <td style="text-align:center;">{stats["total"]}</td>
              <td style="text-align:center; color:#C00000; font-weight:700;">{stats["overdue"]}</td>
              <td style="color:{color}; font-weight:700;">{rate}%</td>
            </tr>"""
        return rows or "<tr><td colspan='4' style='color:#9CA3AF;'>No owner data.</td></tr>"


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))

    from parsers.nessus_csv_parser import NessusParser
    from scoring.priority_scorer   import PriorityScorer
    from sla.sla_tracker           import SLATracker

    filepath = sys.argv[1] if len(sys.argv) > 1 else "data/sample_nessus_export.csv"

    findings   = NessusParser(filepath).parse()
    scored     = PriorityScorer(offline_mode=True).score_all(findings)
    sla_report = SLATracker().analyze(scored)

    dash = Dashboard(system_name="DOT-OCIO-PROD", organization="Department of Transportation OCIO")
    out  = dash.generate(scored, sla_report, output_path="reports/dashboard.html")
    print(f"\nDashboard generated: {out}")
