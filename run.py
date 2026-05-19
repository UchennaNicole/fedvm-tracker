"""
run.py
------
FedVM-Tracker — Main entry point.

Executes the full vulnerability management pipeline:
    1. Parse Nessus CSV export
    2. Score and prioritize findings
    3. Generate POA&M (Excel + CSV)
    4. Run SLA compliance analysis
    5. Generate leadership dashboard (HTML)

Usage:
    python run.py
    python run.py --scan data/my_nessus_export.csv
    python run.py --scan data/export.csv --system "DOT-OCIO-PROD" --owner "Jane Smith"
    python run.py --offline   # Skip live CISA KEV fetch
"""

import argparse
import logging
import sys
from datetime import date
from pathlib import Path

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt= "%H:%M:%S",
)
log = logging.getLogger("fedvm-tracker")


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def run_pipeline(
    scan_file:    str  = "data/sample_nessus_export.csv",
    system_name:  str  = "DOT-OCIO-PROD",
    system_owner: str  = "System Owner",
    organization: str  = "Department of Transportation",
    asset_map:    str  = None,
    owner_map:    str  = None,
    kev_cache:    str  = "data/kev_cache.json",
    offline:      bool = False,
) -> dict:
    """
    Execute the full FedVM-Tracker pipeline and return output paths.
    """
    from parsers.nessus_csv_parser import NessusParser
    from scoring.priority_scorer   import PriorityScorer
    from poam.poam_generator       import POAMGenerator
    from sla.sla_tracker           import SLATracker
    from reporting.dashboard       import Dashboard

    today = date.today().strftime("%Y%m%d")

    log.info("=" * 60)
    log.info("  FedVM-Tracker — Federal Vulnerability Management Pipeline")
    log.info("=" * 60)

    # ------------------------------------------------------------------
    # Step 1: Parse
    # ------------------------------------------------------------------
    log.info("STEP 1/5 — Parsing Nessus scan export...")
    parser   = NessusParser(scan_file)
    findings = parser.parse()

    if not findings:
        log.error("No findings parsed. Check your CSV file and try again.")
        sys.exit(1)

    # ------------------------------------------------------------------
    # Step 2: Score & Prioritize
    # ------------------------------------------------------------------
    log.info("STEP 2/5 — Scoring and prioritizing findings...")
    scorer = PriorityScorer(
        asset_inventory = asset_map,
        kev_cache_path  = kev_cache,
        offline_mode    = offline,
    )
    scored = scorer.score_all(findings)

    # ------------------------------------------------------------------
    # Step 3: Generate POA&M
    # ------------------------------------------------------------------
    log.info("STEP 3/5 — Generating POA&M...")
    poam_path = f"reports/poam_{today}.xlsx"
    gen = POAMGenerator(
        system_name  = system_name,
        system_owner = system_owner,
        organization = organization,
    )
    gen.generate(scored, output_path=poam_path)

    # ------------------------------------------------------------------
    # Step 4: SLA Analysis
    # ------------------------------------------------------------------
    log.info("STEP 4/5 — Running SLA compliance analysis...")
    tracker    = SLATracker(system_owner_map=owner_map)
    sla_report = tracker.analyze(scored)
    tracker.print_report(sla_report)

    overdue_csv = tracker.export_overdue_csv(
        sla_report,
        output_path=f"reports/overdue_{today}.csv"
    )

    # ------------------------------------------------------------------
    # Step 5: Dashboard
    # ------------------------------------------------------------------
    log.info("STEP 5/5 — Generating leadership dashboard...")
    dash_path = f"reports/dashboard_{today}.html"
    dash = Dashboard(system_name=system_name, organization=organization)
    dash.generate(scored, sla_report, output_path=dash_path)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    s = sla_report["summary"]
    log.info("=" * 60)
    log.info("  PIPELINE COMPLETE")
    log.info("=" * 60)
    log.info(f"  Total Findings    : {s['total_findings']}")
    log.info(f"  Overdue           : {s['overdue']}")
    log.info(f"  Compliance Rate   : {s['compliance_rate']}%")
    log.info(f"  KEV Hits          : {sum(1 for f in scored if f.get('kev_match'))}")
    log.info(f"  POA&M             : {poam_path}")
    log.info(f"  Overdue CSV       : {overdue_csv or 'None (no overdue findings)'}")
    log.info(f"  Dashboard         : {dash_path}")
    log.info("=" * 60)

    return {
        "findings":    scored,
        "sla_report":  sla_report,
        "poam_path":   poam_path,
        "overdue_csv": overdue_csv,
        "dash_path":   dash_path,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="FedVM-Tracker — Federal Vulnerability Management Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py
  python run.py --scan data/nessus_export.csv
  python run.py --scan data/export.csv --system "DOT-OCIO-PROD" --owner "Jane Smith"
  python run.py --offline
        """
    )
    parser.add_argument("--scan",    default="data/sample_nessus_export.csv", help="Path to Nessus CSV export")
    parser.add_argument("--system",  default="DOT-OCIO-PROD",                 help="Information system name")
    parser.add_argument("--owner",   default="System Owner",                  help="System owner name")
    parser.add_argument("--org",     default="Department of Transportation",   help="Organization name")
    parser.add_argument("--assets",  default=None,                             help="Path to asset inventory JSON")
    parser.add_argument("--owners",  default=None,                             help="Path to system owner map JSON")
    parser.add_argument("--offline", action="store_true",                      help="Skip live CISA KEV fetch")
    args = parser.parse_args()

    run_pipeline(
        scan_file    = args.scan,
        system_name  = args.system,
        system_owner = args.owner,
        organization = args.org,
        asset_map    = args.assets,
        owner_map    = args.owners,
        offline      = args.offline,
    )


if __name__ == "__main__":
    main()
