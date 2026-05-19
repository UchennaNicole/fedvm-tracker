"""
priority_scorer.py
------------------
Applies a Federal-context risk prioritization model to normalized Nessus
findings. Goes beyond raw CVSS by layering in:

    1. CVSS v3 Base Score       (weighted 35%)
    2. Asset Criticality Tier   (weighted 30%)
    3. CISA KEV List Match      (weighted 20%)
    4. Exploit Availability     (weighted 15%)

Findings are scored 0–100 and bucketed into remediation tiers aligned
to Federal SLA frameworks (CISA BOD 19-02, NIST SP 800-40r4):

    P1 — Remediate within 15 days  (score ≥ 75 or Critical+KEV)
    P2 — Remediate within 30 days  (score 50–74)
    P3 — Remediate within 90 days  (score 25–49)
    P4 — Remediate within 180 days (score < 25)

CISA KEV data is pulled live from:
    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Usage:
    from parsers.nessus_csv_parser import NessusParser
    from scoring.priority_scorer import PriorityScorer

    parser   = NessusParser("data/sample_nessus_export.csv")
    findings = parser.parse()

    scorer   = PriorityScorer(asset_inventory="data/asset_inventory.json")
    scored   = scorer.score_all(findings)
"""

import json
import logging
import urllib.request
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants & Weights
# ---------------------------------------------------------------------------

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

# Scoring weights — must sum to 1.0
WEIGHT_CVSS    = 0.35
WEIGHT_ASSET   = 0.30
WEIGHT_KEV     = 0.20
WEIGHT_EXPLOIT = 0.15

# Asset tier definitions — map system classification to criticality score
# Tier assignments come from your asset inventory or manual tagging.
ASSET_TIER_SCORES = {
    "internet_facing": 100,   # Public-facing systems — highest exposure
    "mission_critical": 90,   # Core mission systems (OT, SCADA, key servers)
    "internal_server":  70,   # Internal servers with sensitive data
    "workstation":      50,   # Standard end-user endpoints
    "dev_test":         20,   # Development / test environments
    "unknown":          50,   # Default when asset tier is unclassified
}

# Remediation tier thresholds
TIER_THRESHOLDS = {
    "P1": 75,   # 15-day SLA
    "P2": 50,   # 30-day SLA
    "P3": 25,   # 90-day SLA
    "P4": 0,    # 180-day SLA
}

TIER_SLA_DAYS = {"P1": 15, "P2": 30, "P3": 90, "P4": 180}


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------

class PriorityScorer:
    """
    Scores and tiers vulnerability findings using a weighted Federal-context
    risk model. Enriches each finding dict in-place with:

        risk_priority_score  – 0–100 composite score
        remediation_tier     – P1 / P2 / P3 / P4
        tier_sla_days        – SLA window in days for this tier
        kev_match            – True if CVE is on CISA KEV list
        exploit_available    – True if known exploit flagged
        asset_tier           – Resolved asset tier string
        score_breakdown      – Dict showing per-component score contribution
    """

    def __init__(
        self,
        asset_inventory: Optional[str] = None,
        kev_cache_path: Optional[str]  = None,
        offline_mode: bool = False,
    ):
        """
        Args:
            asset_inventory:  Path to JSON file mapping IP → asset tier.
                              Format: {"10.0.0.15": "internet_facing", ...}
            kev_cache_path:   Path to locally cached CISA KEV JSON.
                              If None, fetches live from CISA.
            offline_mode:     If True, skip live KEV fetch and use cache only.
        """
        self.asset_map   = self._load_asset_inventory(asset_inventory)
        self.kev_cves    = self._load_kev(kev_cache_path, offline_mode)
        log.info(f"KEV list loaded: {len(self.kev_cves)} CVEs indexed.")
        log.info(f"Asset inventory loaded: {len(self.asset_map)} hosts mapped.")

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def score_all(self, findings: list[dict]) -> list[dict]:
        """Score and tier all findings. Returns sorted list (highest risk first)."""
        for finding in findings:
            self._score_finding(finding)

        findings.sort(key=lambda f: (
            f["risk_priority_score"] or 0,
            f["severity_rank"],
        ), reverse=True)

        log.info(f"Scored {len(findings)} findings.")
        self._log_tier_summary(findings)
        return findings

    def score_one(self, finding: dict) -> dict:
        """Score a single finding in-place and return it."""
        self._score_finding(finding)
        return finding

    # ------------------------------------------------------------------
    # Core scoring logic
    # ------------------------------------------------------------------

    def _score_finding(self, finding: dict) -> None:
        """Enrich finding dict with scores, tier, and metadata."""
        # 1. Resolve asset tier
        host       = finding.get("host", "")
        asset_tier = self.asset_map.get(host, finding.get("asset_tier", "unknown"))
        finding["asset_tier"] = asset_tier

        # 2. Check CISA KEV
        cve = finding.get("cve", "")
        kev_match = any(c.strip() in self.kev_cves for c in cve.split(",") if c.strip())
        finding["kev_match"] = kev_match

        # 3. Exploit availability — inferred from KEV hit or CVSS ≥ 9.0
        #    In production, integrate with NVD or Exploit-DB for richer signal.
        cvss_score = finding.get("cvss_score", 0.0)
        exploit_available = kev_match or cvss_score >= 9.0
        finding["exploit_available"] = exploit_available

        # 4. Compute component scores (each normalized to 0–100)
        cvss_component    = self._score_cvss(cvss_score)
        asset_component   = ASSET_TIER_SCORES.get(asset_tier, 50)
        kev_component     = 100 if kev_match else 0
        exploit_component = 100 if exploit_available else 0

        # 5. Weighted composite score
        composite = (
            cvss_component    * WEIGHT_CVSS    +
            asset_component   * WEIGHT_ASSET   +
            kev_component     * WEIGHT_KEV     +
            exploit_component * WEIGHT_EXPLOIT
        )
        composite = round(min(100.0, max(0.0, composite)), 1)

        # 6. Force P1 for Critical + KEV — non-negotiable escalation
        if finding.get("severity") == "critical" and kev_match:
            composite = max(composite, 90.0)

        # 7. Assign remediation tier
        tier = self._assign_tier(composite)

        # 8. Write enriched fields back to finding
        finding["risk_priority_score"] = composite
        finding["remediation_tier"]    = tier
        finding["tier_sla_days"]       = TIER_SLA_DAYS[tier]
        finding["score_breakdown"]     = {
            "cvss_component":    round(cvss_component    * WEIGHT_CVSS,    1),
            "asset_component":   round(asset_component   * WEIGHT_ASSET,   1),
            "kev_component":     round(kev_component     * WEIGHT_KEV,     1),
            "exploit_component": round(exploit_component * WEIGHT_EXPLOIT, 1),
            "total":             composite,
        }

    @staticmethod
    def _score_cvss(score: float) -> float:
        """Normalize CVSS 0–10 to 0–100."""
        return round((score / 10.0) * 100, 1)

    @staticmethod
    def _assign_tier(score: float) -> str:
        if score >= TIER_THRESHOLDS["P1"]:
            return "P1"
        elif score >= TIER_THRESHOLDS["P2"]:
            return "P2"
        elif score >= TIER_THRESHOLDS["P3"]:
            return "P3"
        return "P4"

    # ------------------------------------------------------------------
    # Data loaders
    # ------------------------------------------------------------------

    def _load_asset_inventory(self, path: Optional[str]) -> dict:
        """Load IP-to-tier mapping from JSON file."""
        if not path:
            log.warning("No asset inventory provided. All hosts will default to 'unknown' tier.")
            return {}
        p = Path(path)
        if not p.exists():
            log.warning(f"Asset inventory file not found: {path}")
            return {}
        with open(p, encoding="utf-8") as fh:
            return json.load(fh)

    def _load_kev(self, cache_path: Optional[str], offline_mode: bool) -> set:
        """
        Load CISA KEV CVE list. Tries live fetch first, falls back to cache.
        Returns a set of CVE IDs (e.g. {'CVE-2021-44228', ...}).
        """
        # Try live fetch
        if not offline_mode:
            try:
                cves = self._fetch_kev_live()
                if cache_path:
                    self._save_kev_cache(cves, cache_path)
                return cves
            except Exception as e:
                log.warning(f"Live KEV fetch failed ({e}). Falling back to cache.")

        # Fall back to local cache
        if cache_path and Path(cache_path).exists():
            return self._load_kev_cache(cache_path)

        log.warning("No KEV data available. KEV matching will be disabled.")
        return set()

    @staticmethod
    def _fetch_kev_live() -> set:
        log.info("Fetching CISA KEV list...")
        with urllib.request.urlopen(CISA_KEV_URL, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        cves = {v["cveID"] for v in data.get("vulnerabilities", [])}
        log.info(f"KEV fetch successful: {len(cves)} entries.")
        return cves

    @staticmethod
    def _load_kev_cache(path: str) -> set:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return {v["cveID"] for v in data.get("vulnerabilities", [])}

    @staticmethod
    def _save_kev_cache(cves: set, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"vulnerabilities": [{"cveID": c} for c in cves]}, fh)
        log.info(f"KEV cache saved to {path}")

    @staticmethod
    def _log_tier_summary(findings: list[dict]) -> None:
        counts = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
        for f in findings:
            t = f.get("remediation_tier", "P4")
            counts[t] = counts.get(t, 0) + 1
        log.info(
            f"Remediation tiers → "
            f"P1 (15d): {counts['P1']} | "
            f"P2 (30d): {counts['P2']} | "
            f"P3 (90d): {counts['P3']} | "
            f"P4 (180d): {counts['P4']}"
        )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from parsers.nessus_csv_parser import NessusParser

    filepath = sys.argv[1] if len(sys.argv) > 1 else "data/sample_nessus_export.csv"
    parser   = NessusParser(filepath)
    findings = parser.parse()

    scorer  = PriorityScorer(offline_mode=True)
    scored  = scorer.score_all(findings)

    print("\n=== TOP 5 PRIORITY FINDINGS ===")
    for f in scored[:5]:
        print(
            f"[{f['remediation_tier']}] Score: {f['risk_priority_score']:>5} | "
            f"CVSS: {f['cvss_score']} | "
            f"KEV: {'YES' if f['kev_match'] else 'no'} | "
            f"{f['severity'].upper():8} | "
            f"{f['host']:15} | {f['name']}"
        )
