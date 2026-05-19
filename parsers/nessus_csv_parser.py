"""
nessus_csv_parser.py
--------------------
Ingests raw Nessus .csv exports, normalizes findings, deduplicates by
Plugin ID + Host, and enriches each record with metadata needed for
downstream prioritization and reporting.

Usage:
    from parsers.nessus_csv_parser import NessusParser
    parser = NessusParser("data/sample_nessus_export.csv")
    findings = parser.parse()
"""

import csv
import hashlib
import logging
from datetime import datetime, date
from pathlib import Path
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_MAP = {
    "critical": 4,
    "high":     3,
    "medium":   2,
    "low":      1,
    "none":     0,
    "info":     0,
}

# Federal patch SLA windows (days) by severity — aligned to CISA BOD 19-02
# and common agency-defined remediation timelines.
FEDERAL_SLA_DAYS = {
    "critical": 15,
    "high":     30,
    "medium":   90,
    "low":      180,
    "none":     365,
    "info":     365,
}

REQUIRED_COLUMNS = {
    "Plugin ID", "Risk", "Host", "Name", "Synopsis",
    "Description", "Solution", "CVSS v3.0 Base Score",
}


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class NessusParser:
    """
    Parses a Nessus CSV export into a normalized list of finding dicts.

    Each finding dict contains:
        finding_id      – SHA-256 hash of plugin_id + host (dedup key)
        plugin_id       – Nessus plugin identifier
        cve             – CVE ID(s) if present
        cvss_score      – CVSS v3 base score (float)
        severity        – Normalized severity string (critical/high/medium/low/none)
        severity_rank   – Integer rank for sorting (4=critical → 0=none)
        host            – Target IP or hostname
        protocol        – Network protocol
        port            – Port number
        name            – Vulnerability name
        synopsis        – One-line description
        description     – Full description
        solution        – Remediation guidance
        see_also        – Reference URLs
        plugin_output   – Raw scanner output
        sla_days        – Federal SLA window in days
        sla_due_date    – Date by which remediation must be completed
        scan_date       – Date this finding was parsed (today)
        days_open       – Days since scan date (0 on first parse)
        asset_tier      – Placeholder; enriched by priority_scorer
        kev_match       – Placeholder; enriched by priority_scorer
    """

    def __init__(self, filepath: str):
        self.filepath = Path(filepath)
        self.findings: list[dict] = []
        self._seen: set[str] = set()  # dedup tracking

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def parse(self) -> list[dict]:
        """Parse the CSV and return normalized findings list."""
        if not self.filepath.exists():
            raise FileNotFoundError(f"Nessus export not found: {self.filepath}")

        log.info(f"Parsing Nessus export: {self.filepath}")
        raw_rows = self._load_csv()
        self._validate_columns(raw_rows[0] if raw_rows else {})

        for row in raw_rows:
            finding = self._normalize_row(row)
            if finding is None:
                continue
            fid = finding["finding_id"]
            if fid in self._seen:
                log.debug(f"Duplicate skipped: {finding['plugin_id']} on {finding['host']}")
                continue
            self._seen.add(fid)
            self.findings.append(finding)

        log.info(
            f"Parsed {len(raw_rows)} rows → "
            f"{len(self.findings)} unique findings after deduplication."
        )
        self._log_severity_summary()
        return self.findings

    def to_summary(self) -> dict:
        """Return a high-level count summary by severity."""
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        for f in self.findings:
            sev = f["severity"]
            summary[sev] = summary.get(sev, 0) + 1
            summary["total"] += 1
        return summary

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_csv(self) -> list[dict]:
        rows = []
        with open(self.filepath, newline="", encoding="utf-8-sig") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                rows.append({k.strip(): v.strip() for k, v in row.items()})
        return rows

    def _validate_columns(self, sample_row: dict) -> None:
        missing = REQUIRED_COLUMNS - set(sample_row.keys())
        if missing:
            raise ValueError(
                f"Nessus CSV is missing expected columns: {missing}\n"
                f"Found columns: {list(sample_row.keys())}"
            )

    def _normalize_row(self, row: dict) -> Optional[dict]:
        """Convert a raw CSV row into a normalized finding dict."""
        plugin_id = row.get("Plugin ID", "").strip()
        host      = row.get("Host", "").strip()
        risk      = row.get("Risk", "none").strip().lower()

        # Skip informational/none findings — they're noise, not vulnerabilities
        if risk in ("none", "info", ""):
            return None

        severity      = risk if risk in SEVERITY_MAP else "none"
        severity_rank = SEVERITY_MAP[severity]
        cvss_score    = self._parse_cvss(row.get("CVSS v3.0 Base Score", ""))
        sla_days      = FEDERAL_SLA_DAYS.get(severity, 365)
        scan_date     = date.today()
        sla_due_date  = date.fromordinal(scan_date.toordinal() + sla_days)

        return {
            "finding_id":    self._make_id(plugin_id, host),
            "plugin_id":     plugin_id,
            "cve":           row.get("CVE", "").strip() or "N/A",
            "cvss_score":    cvss_score,
            "severity":      severity,
            "severity_rank": severity_rank,
            "host":          host,
            "protocol":      row.get("Protocol", "").strip(),
            "port":          row.get("Port", "").strip(),
            "name":          row.get("Name", "").strip(),
            "synopsis":      row.get("Synopsis", "").strip(),
            "description":   row.get("Description", "").strip(),
            "solution":      row.get("Solution", "").strip(),
            "see_also":      row.get("See Also", "").strip(),
            "plugin_output": row.get("Plugin Output", "").strip(),
            "sla_days":      sla_days,
            "sla_due_date":  sla_due_date.isoformat(),
            "scan_date":     scan_date.isoformat(),
            "days_open":     0,
            # Enriched downstream by priority_scorer.py
            "asset_tier":    "unknown",
            "kev_match":     False,
            "exploit_available": False,
            "risk_priority_score": None,
            "remediation_tier": None,
        }

    @staticmethod
    def _parse_cvss(raw: str) -> float:
        try:
            score = float(raw)
            return round(max(0.0, min(10.0, score)), 1)
        except (ValueError, TypeError):
            return 0.0

    @staticmethod
    def _make_id(plugin_id: str, host: str) -> str:
        return hashlib.sha256(f"{plugin_id}::{host}".encode()).hexdigest()[:16]

    def _log_severity_summary(self) -> None:
        summary = self.to_summary()
        log.info(
            f"Severity breakdown → "
            f"Critical: {summary['critical']} | "
            f"High: {summary['high']} | "
            f"Medium: {summary['medium']} | "
            f"Low: {summary['low']}"
        )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json
    import sys

    filepath = sys.argv[1] if len(sys.argv) > 1 else "data/sample_nessus_export.csv"
    parser   = NessusParser(filepath)
    findings = parser.parse()

    print("\n=== PARSED FINDINGS (first 3) ===")
    for f in findings[:3]:
        print(json.dumps(f, indent=2, default=str))

    print(f"\nTotal unique findings: {len(findings)}")
