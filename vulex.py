
import argparse
import logging
import os
import sqlite3
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("vulnscan")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_DB       = "scans.db"
DEFAULT_MAX_CVES = 5
DEFAULT_DELAY    = 6.0
AUTHED_DELAY     = 0.6
NVD_URL          = "https://services.nvd.nist.gov/rest/json/cves/2.0"

VALID_RISK_LEVELS    = {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}
VALID_EXPLOIT_VALUES = {"Yes", "No", "Unknown"}

# Heuristic: flag CVEs whose descriptions mention public exploit indicators
EXPLOIT_KEYWORDS = {
    "exploit", "poc", "proof-of-concept", "metasploit",
    "weaponized", "actively exploited", "in the wild",
}

SEVERITY_RISK_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH":     "HIGH",
    "MEDIUM":   "MEDIUM",
    "LOW":      "LOW",
    "UNKNOWN":  "UNKNOWN",
}

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ScanRow:
    ip:      str
    port:    int
    service: str
    product: str
    version: str


@dataclass
class CVERecord:
    cve_id:      str
    cvss_score:  float
    severity:    str
    description: str


@dataclass
class ExploitRecord:
    cve_id:            str
    exploit_available: str
    risk_level:        str
    remediation:       str
    reference_url:     str
    created_at:        str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class EnrichedFinding:
    scan:    ScanRow
    cve:     CVERecord
    exploit: ExploitRecord


# ---------------------------------------------------------------------------
# HTTP session
# ---------------------------------------------------------------------------

def build_session(api_key: Optional[str]) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=4,
        backoff_factor=2,
        status_forcelist={429, 500, 502, 503, 504},
        respect_retry_after_header=True,
        allowed_methods=["GET"],
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.headers["User-Agent"] = "VulnScan/1.0"
    if api_key:
        session.headers["apiKey"] = api_key
    return session


# ---------------------------------------------------------------------------
# CVE fetcher
# ---------------------------------------------------------------------------

class CVEFetcher:
    def __init__(self, session: requests.Session, delay: float, max_cves: int,
                 severity_filter: Optional[str]):
        self._session        = session
        self._delay          = delay
        self._max_cves       = max_cves
        self._severity_filter = severity_filter.upper() if severity_filter else None
        self._cache: dict[str, list[CVERecord]] = {}
        self._last_request   = 0.0

    def _throttle(self) -> None:
        wait = self._delay - (time.monotonic() - self._last_request)
        if wait > 0:
            time.sleep(wait)
        self._last_request = time.monotonic()

    def fetch(self, product: str, version: str = "") -> list[CVERecord]:
        key = f"{product} {version}".strip()
        if key in self._cache:
            return self._cache[key]

        self._throttle()
        try:
            resp = self._session.get(
                NVD_URL,
                params={"keywordSearch": key, "resultsPerPage": self._max_cves},
                timeout=20,
            )
            resp.raise_for_status()
        except requests.exceptions.HTTPError as exc:
            log.warning("HTTP error for %r: %s", key, exc)
            return []
        except requests.exceptions.RequestException as exc:
            log.error("Network error for %r: %s", key, exc)
            return []

        records: list[CVERecord] = []
        for item in resp.json().get("vulnerabilities", []):
            cve = item["cve"]
            severity, score = self._extract_cvss(cve.get("metrics", {}))

            if self._severity_filter and severity != self._severity_filter:
                continue

            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                "No description available.",
            )
            records.append(CVERecord(
                cve_id=cve["id"],
                cvss_score=score,
                severity=severity,
                description=desc,
            ))

        self._cache[key] = records
        log.info("  Found %d CVE(s) for %r", len(records), key)
        return records

    @staticmethod
    def _extract_cvss(metrics: dict) -> tuple[str, float]:
        for key in ("cvssMetricV31", "cvssMetricV30"):
            if key in metrics:
                d = metrics[key][0]
                return d["cvssData"]["baseSeverity"], d["cvssData"]["baseScore"]
        if "cvssMetricV2" in metrics:
            d = metrics["cvssMetricV2"][0]
            return d["baseSeverity"], d["cvssData"]["baseScore"]
        return "UNKNOWN", 0.0


# ---------------------------------------------------------------------------
# Exploit enrichment (heuristic — extend with ExploitDB / EPSS as needed)
# ---------------------------------------------------------------------------

def enrich_exploit(cve: CVERecord) -> ExploitRecord:
    desc_lower = cve.description.lower()
    exploit_available = (
        "Yes" if any(kw in desc_lower for kw in EXPLOIT_KEYWORDS) else "Unknown"
    )
    risk_level  = SEVERITY_RISK_MAP.get(cve.severity, "UNKNOWN")
    remediation = _remediation_hint(cve)

    return ExploitRecord(
        cve_id=cve.cve_id,
        exploit_available=exploit_available,
        risk_level=risk_level,
        remediation=remediation,
        reference_url=f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}",
    )


def _remediation_hint(cve: CVERecord) -> str:
    desc = cve.description.lower()
    if "upgrade" in desc or "update" in desc:
        return "Apply the vendor-recommended upgrade or patch as described in the CVE advisory."
    if "configuration" in desc or "misconfigur" in desc:
        return "Review and harden the affected service configuration per vendor guidelines."
    if "authentication" in desc or "auth" in desc:
        return "Enforce strong authentication controls and review access policies."
    if "inject" in desc or "xss" in desc or "script" in desc:
        return "Apply input validation and output encoding patches from the vendor."
    return "Review the NVD advisory and apply the latest vendor patch or mitigation."


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def get_connection(db_path: str) -> sqlite3.Connection:
    path = Path(db_path)
    if not path.parent.exists():
        raise FileNotFoundError(f"Directory not found: {path.parent}")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip          TEXT    NOT NULL,
            port        INTEGER NOT NULL,
            service     TEXT,
            product     TEXT,
            version     TEXT,
            cve_id      TEXT    NOT NULL,
            cvss_score  REAL    DEFAULT 0.0,
            severity    TEXT    CHECK(severity IN ('LOW','MEDIUM','HIGH','CRITICAL','UNKNOWN')),
            description TEXT,
            UNIQUE(ip, port, cve_id)
        );

        CREATE TABLE IF NOT EXISTS exploit_info (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id            TEXT    NOT NULL,
            exploit_available TEXT    CHECK(exploit_available IN ('Yes','No','Unknown')),
            risk_level        TEXT    CHECK(risk_level IN ('LOW','MEDIUM','HIGH','CRITICAL','UNKNOWN')),
            remediation       TEXT,
            reference_url     TEXT,
            created_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(cve_id)
        );
    """)
    conn.commit()


def load_scans(conn: sqlite3.Connection) -> list[ScanRow]:
    try:
        rows = conn.execute(
            "SELECT ip, port, service, product, version FROM scans"
        ).fetchall()
        return [ScanRow(*r) for r in rows]
    except sqlite3.OperationalError:
        log.error("'scans' table not found. Run the scanner first.")
        sys.exit(1)


def save_findings(conn: sqlite3.Connection, findings: list[EnrichedFinding]) -> tuple[int, int]:
    vuln_rows = [
        (
            f.scan.ip, f.scan.port, f.scan.service, f.scan.product, f.scan.version,
            f.cve.cve_id, f.cve.cvss_score, f.cve.severity, f.cve.description,
        )
        for f in findings
    ]
    exploit_rows = [
        (
            f.exploit.cve_id, f.exploit.exploit_available, f.exploit.risk_level,
            f.exploit.remediation, f.exploit.reference_url, f.exploit.created_at,
        )
        for f in findings
    ]

    cur_v = conn.executemany(
        """INSERT OR IGNORE INTO vulnerabilities
           (ip, port, service, product, version, cve_id, cvss_score, severity, description)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        vuln_rows,
    )
    conn.executemany(
        """INSERT INTO exploit_info
           (cve_id, exploit_available, risk_level, remediation, reference_url, created_at)
           VALUES (?,?,?,?,?,?)
           ON CONFLICT(cve_id) DO UPDATE SET
               exploit_available = excluded.exploit_available,
               risk_level        = excluded.risk_level,
               remediation       = excluded.remediation,
               reference_url     = excluded.reference_url""",
        exploit_rows,
    )
    conn.commit()
    return cur_v.rowcount, len({r[0] for r in exploit_rows})


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def print_report(conn: sqlite3.Connection) -> None:
    rows = conn.execute("""
        SELECT
            v.ip,
            v.port,
            v.service,
            v.product,
            v.version,
            v.cve_id,
            v.cvss_score,
            v.severity,
            e.exploit_available,
            e.risk_level,
            e.remediation,
            e.reference_url,
            v.description
        FROM vulnerabilities v
        LEFT JOIN exploit_info e ON v.cve_id = e.cve_id
        ORDER BY v.cvss_score DESC, v.ip, v.port
    """).fetchall()

    if not rows:
        log.info("No findings to report.")
        return

    divider   = "=" * 100
    subdiv    = "-" * 100

    print(f"\n{divider}")
    print(f"{'VULNSCAN — COMBINED VULNERABILITY & EXPLOIT REPORT':^100}")
    print(f"{'Generated: ' + datetime.now().strftime('%Y-%m-%d %H:%M:%S'):^100}")
    print(divider)

    for r in rows:
        print(f"\n  CVE ID       : {r['cve_id']}")
        print(f"  Host         : {r['ip']}:{r['port']}  ({r['service'] or '—'})")
        print(f"  Product      : {r['product']} {r['version'] or ''}")
        print(f"  CVSS Score   : {r['cvss_score']:.1f}  |  Severity : {r['severity']}")
        print(f"  Risk Level   : {r['risk_level'] or '—'}")
        print(f"  Exploit      : {r['exploit_available'] or '—'}")
        print(f"  Remediation  : {r['remediation'] or '—'}")
        print(f"  Reference    : {r['reference_url'] or '—'}")
        print(f"  Description  : {r['description'][:120]}{'...' if len(r['description'] or '') > 120 else ''}")
        print(subdiv)

    critical = sum(1 for r in rows if r["severity"] == "CRITICAL")
    high     = sum(1 for r in rows if r["severity"] == "HIGH")
    exploits = sum(1 for r in rows if r["exploit_available"] == "Yes")

    print(f"\n  SUMMARY  |  Total findings: {len(rows)}  |  "
          f"Critical: {critical}  |  High: {high}  |  With known exploit: {exploits}")
    print(f"{divider}\n")


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run(args: argparse.Namespace) -> None:
    api_key = os.getenv("NVD_API_KEY")
    delay   = AUTHED_DELAY if api_key else args.delay

    if api_key:
        log.info("NVD API key detected — delay %.1fs", delay)
    else:
        log.info("No NVD_API_KEY — unauthenticated delay %.1fs", delay)

    session = build_session(api_key)
    fetcher = CVEFetcher(session, delay, args.max_cves, args.severity)

    try:
        conn = get_connection(args.db)
    except FileNotFoundError as exc:
        log.error("%s", exc)
        sys.exit(1)

    with conn:
        ensure_schema(conn)
        scans = load_scans(conn)
        log.info("Loaded %d scan row(s) from %s", len(scans), args.db)

        findings: list[EnrichedFinding] = []
        for scan in scans:
            if not scan.product:
                continue
            log.info("[*] %s:%s — %s %s", scan.ip, scan.port, scan.product, scan.version)
            for cve in fetcher.fetch(scan.product, scan.version):
                exploit = enrich_exploit(cve)
                findings.append(EnrichedFinding(scan=scan, cve=cve, exploit=exploit))

        vuln_saved, exploit_saved = save_findings(conn, findings)
        log.info("[+] Saved %d vulnerability row(s), %d exploit record(s).",
                 vuln_saved, exploit_saved)

        print_report(conn)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Unified CVE vulnerability + exploit mapper.")
    p.add_argument("--db",       default=DEFAULT_DB,       help="Path to SQLite DB")
    p.add_argument("--delay",    type=float, default=DEFAULT_DELAY,
                   help="Seconds between NVD requests (default: 6)")
    p.add_argument("--max-cves", type=int,   default=DEFAULT_MAX_CVES,
                   help="Max CVEs to fetch per product (default: 5)")
    p.add_argument("--severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                   default=None, help="Filter CVEs by minimum severity")
    p.add_argument("--verbose",  action="store_true", help="Enable DEBUG logging")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)
    try:
        run(args)
    except KeyboardInterrupt:
        log.warning("Interrupted. Partial results may have been saved.")
        sys.exit(130)
