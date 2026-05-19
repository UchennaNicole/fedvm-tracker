"""
sla_tracker.py
--------------
Tracks vulnerability findings against Federal SLA windows, identifies
overdue items, calculates aging metrics, and surfaces repeat offenders
by system owner — the operational data a VM team actually needs to
manage remediation accountability.

SLA Windows (aligned to CISA BOD 19-02 and agency-defined timelines):
    P1 (Critical+KEV or Score ≥ 75):  15 days
    P2 (Score 50–74):                  30 days
    P3 (Score 25–49):                  90 days
    P4 (Score < 25):                  180 days

Key outputs:
    - Overdue findings list with days past due
    - SLA compliance rate by system owner
    - Aging buckets (0-7d, 8-30d, 31-90d, 90d+)
    - Mean Time to Remediate (MTTR) placeholder
    - Repeat offender report (system owners with 3+ overdue)

Usage:
    from sla.sla_tracker import SLATracker
    tracker = SLATracker(system_owner_map="data/system_owners.json")
    report  = tracker.analyze(scored_findings)
    tracker.print_report(report)
"""

import json
import logging
from collections import defaultdict
from datetime import date, datetime
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Aging bucket definitions (days open)
# ---------------------------------------------------------------------------

AGING_BUCKETS = {
    "0-7 days":    (0,  7),
    "8-30 days":   (8,  30),
    "31-90 days":  (31, 90),
    "91+ days":    (91, 99999),
}


# ---------------------------------------------------------------------------
# SLA Tracker
# ---------------------------------------------------------------------------

class SLATracker:
    """
    Analyzes scored findings for SLA compliance, aging, and owner accountability.

    Args:
        system_owner_map:  Optional path to JSON mapping host IP → system owner name.
                           Format: {"10.0.0.15": "John Smith (OIT)", ...}
                           Falls back to finding["point_of_contact"] if not provided.
    """

    def __init__(self, system_owner_map: Optional[str] = None):
        self.owner_map = self._load_owner_map(system_owner_map)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def analyze(self, findings: list[dict]) -> dict:
        """
        Run full SLA analysis on scored findings.

        Returns a report dict with:
            summary             – Overall counts and compliance rate
            overdue             – List of overdue findings (sorted worst first)
            aging_distribution  – Findings bucketed by days open
            owner_compliance    – Per-owner SLA compliance stats
            repeat_offenders    – Owners with 3+ overdue findings
            top_aged_criticals  – Top 10 oldest unmitigated critical/high findings
        """
        today = date.today()

        overdue            = []
        on_track           = []
        aging_distribution = defaultdict(list)
        owner_stats        = defaultdict(lambda: {"total": 0, "overdue": 0, "on_track": 0, "findings": []})

        for f in findings:
            # Resolve owner
            owner = self.owner_map.get(f.get("host", ""), "Unassigned")
            f["assigned_owner"] = owner

            # Calculate days open and days past due
            days_open, days_past_due, is_overdue = self._calc_sla_status(f, today)
            f["days_open"]     = days_open
            f["days_past_due"] = days_past_due
            f["is_overdue"]    = is_overdue

            # Bucket by aging
            bucket = self._get_aging_bucket(days_open)
            aging_distribution[bucket].append(f)

            # Owner stats
            owner_stats[owner]["total"]    += 1
            owner_stats[owner]["findings"].append(f)
            if is_overdue:
                owner_stats[owner]["overdue"] += 1
                overdue.append(f)
            else:
                owner_stats[owner]["on_track"] += 1
                on_track.append(f)

        # Sort overdue by days past due (worst first)
        overdue.sort(key=lambda f: f["days_past_due"], reverse=True)

        # Compute compliance rates per owner
        owner_compliance = {}
        for owner, stats in owner_stats.items():
            total = stats["total"]
            compliance_rate = round(((total - stats["overdue"]) / total) * 100, 1) if total else 0
            owner_compliance[owner] = {
                "total":           total,
                "overdue":         stats["overdue"],
                "on_track":        stats["on_track"],
                "compliance_rate": compliance_rate,
            }

        # Repeat offenders — owners with 3+ overdue findings
        repeat_offenders = {
            owner: data
            for owner, data in owner_compliance.items()
            if data["overdue"] >= 3
        }

        # Top 10 oldest unmitigated critical/high
        top_aged = sorted(
            [f for f in findings if f.get("severity") in ("critical", "high")],
            key=lambda f: f.get("days_open", 0),
            reverse=True,
        )[:10]

        # Overall summary
        total         = len(findings)
        total_overdue = len(overdue)
        compliance    = round(((total - total_overdue) / total) * 100, 1) if total else 0

        report = {
            "generated":          date.today().isoformat(),
            "summary": {
                "total_findings":     total,
                "overdue":            total_overdue,
                "on_track":           len(on_track),
                "compliance_rate":    compliance,
                "critical_overdue":   sum(1 for f in overdue if f.get("severity") == "critical"),
                "high_overdue":       sum(1 for f in overdue if f.get("severity") == "high"),
            },
            "overdue":             overdue,
            "aging_distribution":  {k: len(v) for k, v in aging_distribution.items()},
            "owner_compliance":    owner_compliance,
            "repeat_offenders":    repeat_offenders,
            "top_aged_criticals":  top_aged,
        }

        log.info(
            f"SLA Analysis complete — "
            f"Total: {total} | Overdue: {total_overdue} | "
            f"Compliance Rate: {compliance}%"
        )
        return report

    def print_report(self, report: dict) -> None:
        """Print a formatted SLA report to stdout."""
        s = report["summary"]
        print("\n" + "=" * 70)
        print("  FEDVM-TRACKER — SLA COMPLIANCE REPORT")
        print(f"  Generated: {report['generated']}")
        print("=" * 70)

        print(f"\n{'OVERALL SUMMARY':─^70}")
        print(f"  Total Open Findings   : {s['total_findings']}")
        print(f"  On Track              : {s['on_track']}")
        print(f"  Overdue               : {s['overdue']}")
        print(f"  SLA Compliance Rate   : {s['compliance_rate']}%")
        print(f"  Critical Overdue      : {s['critical_overdue']}")
        print(f"  High Overdue          : {s['high_overdue']}")

        print(f"\n{'AGING DISTRIBUTION':─^70}")
        for bucket, count in report["aging_distribution"].items():
            bar = "█" * min(count * 3, 40)
            print(f"  {bucket:15} | {bar} {count}")

        print(f"\n{'OWNER SLA COMPLIANCE':─^70}")
        for owner, stats in sorted(
            report["owner_compliance"].items(),
            key=lambda x: x[1]["compliance_rate"]
        ):
            rate   = stats["compliance_rate"]
            status = "✓" if rate >= 80 else "⚠" if rate >= 50 else "✗"
            print(
                f"  {status} {owner:30} | "
                f"Compliance: {rate:5.1f}% | "
                f"Overdue: {stats['overdue']:3} / {stats['total']}"
            )

        if report["repeat_offenders"]:
            print(f"\n{'⚠ REPEAT OFFENDERS (3+ overdue)':─^70}")
            for owner, stats in report["repeat_offenders"].items():
                print(f"  {owner:35} → {stats['overdue']} overdue findings")

        print(f"\n{'TOP AGED CRITICALS / HIGHS':─^70}")
        for f in report["top_aged_criticals"][:5]:
            print(
                f"  [{f.get('severity','').upper():8}] "
                f"Age: {f.get('days_open', 0):4}d | "
                f"Host: {f.get('host', ''):15} | "
                f"{f.get('name', '')[:45]}"
            )

        print(f"\n{'OVERDUE FINDINGS':─^70}")
        for f in report["overdue"][:10]:
            print(
                f"  [{f.get('remediation_tier','--')}] "
                f"{f.get('days_past_due', 0):4}d past due | "
                f"Host: {f.get('host', ''):15} | "
                f"Owner: {f.get('assigned_owner', 'Unassigned'):20} | "
                f"{f.get('name', '')[:35]}"
            )
        if len(report["overdue"]) > 10:
            print(f"  ... and {len(report['overdue']) - 10} more overdue findings.")

        print("=" * 70 + "\n")

    def export_overdue_csv(self, report: dict, output_path: str = "reports/overdue_findings.csv") -> str:
        """Export overdue findings to CSV for ServiceNow ticket creation or leadership briefing."""
        import csv
        overdue = report.get("overdue", [])
        if not overdue:
            log.info("No overdue findings to export.")
            return ""

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        fieldnames = [
            "finding_id", "name", "cve", "cvss_score", "severity",
            "remediation_tier", "host", "assigned_owner",
            "sla_due_date", "days_open", "days_past_due",
            "kev_match", "risk_priority_score",
        ]

        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(overdue)

        log.info(f"Overdue findings exported: {path} ({len(overdue)} rows)")
        return str(path)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _calc_sla_status(finding: dict, today: date) -> tuple:
        """
        Returns (days_open, days_past_due, is_overdue).
        days_past_due is 0 if on track, positive if overdue.
        """
        scan_date_str = finding.get("scan_date", "")
        sla_due_str   = finding.get("sla_due_date", "")

        try:
            scan_date = date.fromisoformat(scan_date_str)
            days_open = (today - scan_date).days
        except (ValueError, TypeError):
            days_open = 0

        try:
            sla_due      = date.fromisoformat(sla_due_str)
            is_overdue   = today > sla_due
            days_past_due = max(0, (today - sla_due).days)
        except (ValueError, TypeError):
            is_overdue    = False
            days_past_due = 0

        return days_open, days_past_due, is_overdue

    @staticmethod
    def _get_aging_bucket(days_open: int) -> str:
        for label, (low, high) in AGING_BUCKETS.items():
            if low <= days_open <= high:
                return label
        return "91+ days"

    @staticmethod
    def _load_owner_map(path: Optional[str]) -> dict:
        if not path:
            return {}
        p = Path(path)
        if not p.exists():
            log.warning(f"System owner map not found: {path}")
            return {}
        with open(p, encoding="utf-8") as fh:
            return json.load(fh)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))

    from parsers.nessus_csv_parser import NessusParser
    from scoring.priority_scorer   import PriorityScorer

    filepath = sys.argv[1] if len(sys.argv) > 1 else "data/sample_nessus_export.csv"

    findings = NessusParser(filepath).parse()
    scored   = PriorityScorer(offline_mode=True).score_all(findings)

    tracker = SLATracker()
    report  = tracker.analyze(scored)
    tracker.print_report(report)
    tracker.export_overdue_csv(report)
