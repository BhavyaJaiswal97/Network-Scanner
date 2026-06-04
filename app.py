import json
import logging
import os
import queue
import re
import socket
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Optional

import requests
from flask import Flask, Response, jsonify, render_template, request, stream_with_context
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import nmap
except ImportError:
    raise SystemExit("[!] python-nmap not installed: pip install python-nmap")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
DB_PATH        = "vulndash.db"
NVD_URL        = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DELAY      = float(os.getenv("NVD_DELAY", "6.5"))
AUTHED_DELAY   = 0.6
MAX_CVES       = 5
OS_MIN_ACC     = 85
EXPLOIT_KW     = {"exploit","poc","proof-of-concept","metasploit",
                  "weaponized","actively exploited","in the wild"}
SEVERITY_ORDER = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1,"UNKNOWN":0}

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("vulndash")

app = Flask(__name__)

# Per-scan SSE queues: scan_id -> Queue
_sse_queues: dict[str, queue.Queue] = {}
_sse_lock   = threading.Lock()

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class PortResult:
    ip: str; protocol: str; port: int; state: str
    service: str; product: str; version: str
    extra: str; os_name: str
    scan_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

@dataclass
class CVERecord:
    cve_id: str; cvss_score: float; severity: str; description: str

@dataclass
class ExploitRecord:
    cve_id: str; exploit_available: str; risk_level: str
    remediation: str; reference_url: str

@dataclass
class Finding:
    port: PortResult; cve: CVERecord; exploit: ExploitRecord

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

@contextmanager
def get_conn(db: str = DB_PATH) -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def ensure_schema() -> None:
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scan_jobs (
                id         TEXT PRIMARY KEY,
                domain     TEXT NOT NULL,
                status     TEXT DEFAULT 'running',
                started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                ended_at   DATETIME
            );
            CREATE TABLE IF NOT EXISTS scans (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id   TEXT NOT NULL,
                ip        TEXT NOT NULL,
                protocol  TEXT NOT NULL,
                port      INTEGER NOT NULL,
                state     TEXT,
                service   TEXT,
                product   TEXT,
                version   TEXT,
                extra     TEXT,
                os_name   TEXT,
                scan_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(scan_id, ip, protocol, port)
            );
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     TEXT NOT NULL,
                ip          TEXT NOT NULL,
                port        INTEGER NOT NULL,
                service     TEXT,
                product     TEXT,
                version     TEXT,
                cve_id      TEXT NOT NULL,
                cvss_score  REAL DEFAULT 0.0,
                severity    TEXT,
                description TEXT,
                UNIQUE(scan_id, ip, port, cve_id)
            );
            CREATE TABLE IF NOT EXISTS exploit_info (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id            TEXT NOT NULL UNIQUE,
                exploit_available TEXT,
                risk_level        TEXT,
                remediation       TEXT,
                reference_url     TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_scans_scan_id   ON scans(scan_id);
            CREATE INDEX IF NOT EXISTS idx_vuln_scan_id    ON vulnerabilities(scan_id);
            CREATE INDEX IF NOT EXISTS idx_vuln_severity   ON vulnerabilities(severity);
        """)


# ---------------------------------------------------------------------------
# HTTP session (shared)
# ---------------------------------------------------------------------------

def _build_session() -> requests.Session:
    s = requests.Session()
    retry = Retry(total=4, backoff_factor=2,
                  status_forcelist={429,500,502,503,504},
                  respect_retry_after_header=True,
                  allowed_methods=["GET"])
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.headers["User-Agent"] = "VulnDash/1.0"
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        s.headers["apiKey"] = api_key
    return s

_http = _build_session()
_cve_cache: dict[str, list[CVERecord]] = {}
_last_nvd = 0.0


def _nvd_throttle() -> None:
    global _last_nvd
    delay = AUTHED_DELAY if os.getenv("NVD_API_KEY") else NVD_DELAY
    wait  = delay - (time.monotonic() - _last_nvd)
    if wait > 0:
        time.sleep(wait)
    _last_nvd = time.monotonic()


def fetch_cves(product: str, version: str = "") -> list[CVERecord]:
    key = f"{product} {version}".strip()
    if key in _cve_cache:
        return _cve_cache[key]
    _nvd_throttle()
    try:
        resp = _http.get(NVD_URL,
                         params={"keywordSearch": key, "resultsPerPage": MAX_CVES},
                         timeout=20)
        resp.raise_for_status()
    except requests.exceptions.RequestException as exc:
        log.warning("NVD error for %r: %s", key, exc)
        return []

    records: list[CVERecord] = []
    for item in resp.json().get("vulnerabilities", []):
        cve      = item["cve"]
        severity, score = _extract_cvss(cve.get("metrics", {}))
        desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                    "No description available.")
        records.append(CVERecord(cve_id=cve["id"], cvss_score=score,
                                 severity=severity, description=desc))
    _cve_cache[key] = records
    return records


def _extract_cvss(metrics: dict) -> tuple[str, float]:
    for k in ("cvssMetricV31", "cvssMetricV30"):
        if k in metrics:
            d = metrics[k][0]
            return d["cvssData"]["baseSeverity"], d["cvssData"]["baseScore"]
    if "cvssMetricV2" in metrics:
        d = metrics["cvssMetricV2"][0]
        return d["baseSeverity"], d["cvssData"]["baseScore"]
    return "UNKNOWN", 0.0


def enrich_exploit(cve: CVERecord) -> ExploitRecord:
    desc_lower = cve.description.lower()
    exploit    = "Yes" if any(kw in desc_lower for kw in EXPLOIT_KW) else "Unknown"
    risk       = cve.severity if cve.severity in SEVERITY_ORDER else "UNKNOWN"

    desc = cve.description.lower()
    if "upgrade" in desc or "update" in desc:
        rem = "Apply vendor-recommended upgrade or patch per the CVE advisory."
    elif "config" in desc or "misconfigur" in desc:
        rem = "Review and harden affected service configuration per vendor guidelines."
    elif "auth" in desc:
        rem = "Enforce strong authentication controls and review access policies."
    elif "inject" in desc or "xss" in desc:
        rem = "Apply input validation and output encoding patches from the vendor."
    else:
        rem = "Review the NVD advisory and apply the latest vendor patch or mitigation."

    return ExploitRecord(
        cve_id=cve.cve_id, exploit_available=exploit,
        risk_level=risk, remediation=rem,
        reference_url=f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}",
    )


# ---------------------------------------------------------------------------
# DNS + nmap
# ---------------------------------------------------------------------------

def resolve_domain(domain: str) -> list[str]:
    domain = domain.strip().lstrip("https://").lstrip("http://").split("/")[0]
    ips: list[str] = []
    try:
        results = socket.getaddrinfo(domain, None)
        for r in results:
            ip = r[4][0]
            if ip not in ips:
                ips.append(ip)
    except socket.gaierror as exc:
        raise ValueError(f"DNS resolution failed for {domain!r}: {exc}")
    return ips


def nmap_scan(ip: str, scan_id: str, emit) -> list[PortResult]:
    nm = nmap.PortScanner()
    emit(f"[nmap] Scanning {ip} ...")
    try:
        nm.scan(hosts=ip, arguments="-sV -T4 --top-ports 100 -O --osscan-guess")
    except nmap.PortScannerError as exc:
        emit(f"[!] nmap error on {ip}: {exc}")
        return []

    ports: list[PortResult] = []
    scan_time = datetime.now(timezone.utc).isoformat()

    for host in nm.all_hosts():
        os_name = _resolve_os(nm, host)
        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                d = nm[host][proto][port]
                ports.append(PortResult(
                    ip=host, protocol=proto, port=port,
                    state=d.get("state",""), service=d.get("name",""),
                    product=d.get("product",""), version=d.get("version",""),
                    extra=d.get("extrainfo",""), os_name=os_name,
                    scan_time=scan_time,
                ))
    emit(f"[nmap] {ip} → {len(ports)} port(s) found")
    return ports


def _resolve_os(nm, host: str) -> str:
    try:
        matches = nm[host].get("osmatch", [])
        if not matches:
            return "Unknown"
        best = matches[0]
        acc  = int(best.get("accuracy", 0))
        return best["name"] if acc >= OS_MIN_ACC else f"Possible: {best['name']} ({acc}%)"
    except Exception:
        return "Unknown"


# ---------------------------------------------------------------------------
# Full scan pipeline (runs in background thread)
# ---------------------------------------------------------------------------

def run_scan(scan_id: str, domain: str) -> None:
    def emit(msg: str) -> None:
        log.info("[%s] %s", scan_id, msg)
        with _sse_lock:
            q = _sse_queues.get(scan_id)
            if q:
                q.put({"type": "log", "msg": msg})

    emit(f"Starting scan for domain: {domain}")

    try:
        ips = resolve_domain(domain)
    except ValueError as exc:
        emit(f"[!] {exc}")
        _finish_scan(scan_id, "error")
        return

    emit(f"Resolved {len(ips)} IP(s): {', '.join(ips)}")

    all_findings: list[Finding] = []

    for ip in ips:
        ports = nmap_scan(ip, scan_id, emit)
        _save_ports(scan_id, ports)

        open_ports = [p for p in ports if p.state == "open" and p.product]
        for p in open_ports:
            emit(f"[nvd] Fetching CVEs for {p.product} {p.version} ...")
            cves = fetch_cves(p.product, p.version)
            emit(f"[nvd]  → {len(cves)} CVE(s) found")
            for cve in cves:
                exploit  = enrich_exploit(cve)
                finding  = Finding(port=p, cve=cve, exploit=exploit)
                all_findings.append(finding)
                _save_finding(scan_id, finding)
                with _sse_lock:
                    q = _sse_queues.get(scan_id)
                    if q:
                        q.put({"type": "finding", "data": _finding_dict(finding)})

    emit(f"Scan complete. {len(all_findings)} finding(s) total.")
    _finish_scan(scan_id, "done")

    with _sse_lock:
        q = _sse_queues.get(scan_id)
        if q:
            q.put({"type": "done"})


def _save_ports(scan_id: str, ports: list[PortResult]) -> None:
    rows = [(scan_id, p.ip, p.protocol, p.port, p.state,
             p.service, p.product, p.version, p.extra, p.os_name, p.scan_time)
            for p in ports]
    with get_conn() as conn:
        conn.executemany(
            """INSERT OR IGNORE INTO scans
               (scan_id,ip,protocol,port,state,service,product,version,extra,os_name,scan_time)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""", rows)


def _save_finding(scan_id: str, f: Finding) -> None:
    with get_conn() as conn:
        conn.execute(
            """INSERT OR IGNORE INTO vulnerabilities
               (scan_id,ip,port,service,product,version,cve_id,cvss_score,severity,description)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (scan_id, f.port.ip, f.port.port, f.port.service,
             f.port.product, f.port.version, f.cve.cve_id,
             f.cve.cvss_score, f.cve.severity, f.cve.description))
        conn.execute(
            """INSERT INTO exploit_info
               (cve_id,exploit_available,risk_level,remediation,reference_url)
               VALUES(?,?,?,?,?)
               ON CONFLICT(cve_id) DO UPDATE SET
                 exploit_available=excluded.exploit_available,
                 risk_level=excluded.risk_level,
                 remediation=excluded.remediation,
                 reference_url=excluded.reference_url""",
            (f.exploit.cve_id, f.exploit.exploit_available,
             f.exploit.risk_level, f.exploit.remediation, f.exploit.reference_url))


def _finish_scan(scan_id: str, status: str) -> None:
    with get_conn() as conn:
        conn.execute("UPDATE scan_jobs SET status=?, ended_at=CURRENT_TIMESTAMP WHERE id=?",
                     (status, scan_id))


def _finding_dict(f: Finding) -> dict:
    return {
        "ip": f.port.ip, "port": f.port.port, "protocol": f.port.protocol,
        "service": f.port.service, "product": f.port.product,
        "version": f.port.version, "os_name": f.port.os_name,
        "cve_id": f.cve.cve_id, "cvss_score": f.cve.cvss_score,
        "severity": f.cve.severity, "description": f.cve.description,
        "exploit_available": f.exploit.exploit_available,
        "risk_level": f.exploit.risk_level,
        "remediation": f.exploit.remediation,
        "reference_url": f.exploit.reference_url,
    }


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def start_scan():
    domain = (request.json or {}).get("domain", "").strip()
    if not domain:
        return jsonify({"error": "domain required"}), 400

    scan_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    with get_conn() as conn:
        conn.execute("INSERT INTO scan_jobs (id, domain) VALUES (?,?)", (scan_id, domain))

    with _sse_lock:
        _sse_queues[scan_id] = queue.Queue()

    thread = threading.Thread(target=run_scan, args=(scan_id, domain), daemon=True)
    thread.start()
    return jsonify({"scan_id": scan_id})


@app.route("/api/stream/<scan_id>")
def stream(scan_id: str):
    with _sse_lock:
        q = _sse_queues.get(scan_id)
    if q is None:
        return jsonify({"error": "scan not found"}), 404

    @stream_with_context
    def generate():
        while True:
            try:
                event = q.get(timeout=30)
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("type") == "done":
                    break
            except queue.Empty:
                yield "data: {\"type\":\"ping\"}\n\n"

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/report/<scan_id>")
def report(scan_id: str):
    with get_conn() as conn:
        job = conn.execute("SELECT * FROM scan_jobs WHERE id=?", (scan_id,)).fetchone()
        if not job:
            return jsonify({"error": "scan not found"}), 404

        rows = conn.execute("""
            SELECT v.*, e.exploit_available, e.risk_level, e.remediation, e.reference_url
            FROM vulnerabilities v
            LEFT JOIN exploit_info e ON v.cve_id = e.cve_id
            WHERE v.scan_id = ?
            ORDER BY v.cvss_score DESC
        """, (scan_id,)).fetchall()

        hosts = conn.execute("""
            SELECT DISTINCT ip, os_name,
                   COUNT(*) FILTER(WHERE state='open') AS open_ports
            FROM scans WHERE scan_id=? GROUP BY ip
        """, (scan_id,)).fetchall()

    findings = [dict(r) for r in rows]
    summary = {
        "total":    len(findings),
        "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high":     sum(1 for f in findings if f["severity"] == "HIGH"),
        "medium":   sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "low":      sum(1 for f in findings if f["severity"] == "LOW"),
        "exploitable": sum(1 for f in findings if f["exploit_available"] == "Yes"),
    }
    return jsonify({
        "job":      dict(job),
        "hosts":    [dict(h) for h in hosts],
        "findings": findings,
        "summary":  summary,
    })


@app.route("/api/scans")
def list_scans():
    with get_conn() as conn:
        jobs = conn.execute(
            "SELECT * FROM scan_jobs ORDER BY started_at DESC LIMIT 50"
        ).fetchall()
    return jsonify([dict(j) for j in jobs])


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    ensure_schema()
    log.info("VulnDash running on http://127.0.0.1:5000")
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)
