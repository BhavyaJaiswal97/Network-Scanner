import logging
import nmap
import time
import socket
import ipaddress
import uuid
import requests
import urllib.parse
import sqlite3
from contextlib import contextmanager
from zapv2 import ZAPv2
from collections import deque
from datetime import datetime, timezone
from dataclasses import dataclass, field
from flask import Flask, render_template, request
from packaging.version import Version, InvalidVersion
from typing import Generator, Optional

# ---------------------------------------------------------------------------
# Initialization & Configuration
# ---------------------------------------------------------------------------
app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

DB_PATH = "scans.db"
OS_MIN_ACCURACY = 85

# --- PERSISTENT STORAGE (In-Memory Web Session) ---
history_store = {}
scan_history_order = deque(maxlen=10)

# --- Dynamic NVD API Cache ---
API_CACHE = {}

def get_history_summary():
    """Generates a summary list of past scans for the sidebar view."""
    return [history_store[uid] for uid in scan_history_order if uid in history_store]

# ---------------------------------------------------------------------------
# Dataclasses (UI Models)
# ---------------------------------------------------------------------------
@dataclass
class ScanRow:
    target_ip: str
    target_domain: str
    port: int
    protocol: str
    state: str
    service: str
    version: str
    extra: str

@dataclass
class CVERecord:
    cve_id: str
    cvss_score: float
    severity: str
    description: str

@dataclass
class ExploitRecord:
    cve_id: str
    exploit_available: str
    risk_level: str
    remediation: str
    reference_url: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

@dataclass
class PatchStatus:
    is_vulnerable: bool
    patch_available: bool
    fixed_version: str
    status_message: str

@dataclass
class EnrichedFinding:
    scan: ScanRow
    cve: CVERecord = None
    exploit: ExploitRecord = None
    patch_status: PatchStatus = None

# ---------------------------------------------------------------------------
# SQLite Database Setup (Persistence)
# ---------------------------------------------------------------------------
@contextmanager
def get_conn(db_path: str) -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(db_path)
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

def ensure_schema(db_path: str) -> None:
    with get_conn(db_path) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ip        TEXT    NOT NULL,
                protocol  TEXT    NOT NULL,
                port      INTEGER NOT NULL,
                state     TEXT,
                service   TEXT,
                version   TEXT,
                extra     TEXT,
                os_name   TEXT,
                scan_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(ip, protocol, port, scan_time)
            );
            CREATE INDEX IF NOT EXISTS idx_scans_ip        ON scans(ip);
            CREATE INDEX IF NOT EXISTS idx_scans_port      ON scans(port);
            
            CREATE TABLE IF NOT EXISTS os_detections (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ip         TEXT    NOT NULL,
                os_name    TEXT,
                accuracy   INTEGER,
                os_family  TEXT,
                os_gen     TEXT,
                scan_time  DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)

def save_port_to_db(db_path: str, row: ScanRow, os_name: str, scan_time: str):
    with get_conn(db_path) as conn:
        conn.execute(
            """INSERT OR IGNORE INTO scans 
               (ip, protocol, port, state, service, version, extra, os_name, scan_time) 
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (row.target_ip, row.protocol, row.port, row.state, row.service, row.version, row.extra, os_name, scan_time)
        )

def save_os_to_db(db_path: str, ip: str, match: dict, scan_time: str):
    with get_conn(db_path) as conn:
        conn.execute(
            """INSERT INTO os_detections (ip, os_name, accuracy, os_family, os_gen, scan_time)
               VALUES (?,?,?,?,?,?)""",
            (
                ip,
                match.get("name", "Unknown"),
                int(match.get("accuracy", 0)),
                next((c.get("osfamily", "") for c in match.get("osclass", [])), ""),
                next((c.get("osgen", "")    for c in match.get("osclass", [])), ""),
                scan_time,
            )
        )

# ---------------------------------------------------------------------------
# Core Scanner Logic & Helpers
# ---------------------------------------------------------------------------
def resolve_os(host_data: dict) -> tuple[str, dict]:
    """Advanced OS Fingerprinting with accuracy checks."""
    try:
        matches = host_data.get("osmatch", [])
        if not matches:
            return "Unknown", {}
        best = matches[0]
        accuracy = int(best.get("accuracy", 0))
        if accuracy >= OS_MIN_ACCURACY:
            label = best["name"]
        else:
            label = f"Possible: {best['name']} ({accuracy}%)"
        return label, best
    except Exception:
        return "Unknown", {}

def clean_version_string(version_str: str) -> str:
    parts = version_str.split()
    for part in parts:
        clean_part = part.split('p')[0].split('-')[0].strip()
        if any(char.isdigit() for char in clean_part):
            return clean_part
    return version_str

def get_domain_name(ip_address: str) -> str:
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except (socket.herror, socket.gaierror):
        return "Unknown Domain"

def resolve_and_validate_target(target_input):
    cleaned = target_input.strip()
    if not cleaned:
        raise ValueError("Target input cannot be empty.")
    try:
        ipaddress.ip_network(cleaned, strict=False)
        return cleaned
    except ValueError:
        pass
    try:
        return socket.gethostbyname(cleaned)
    except socket.gaierror:
        raise ValueError(f"Could not resolve or validate domain: '{target_input}'")

def analyze_patch_and_vuln(scan_row: ScanRow) -> tuple[CVERecord | None, ExploitRecord | None, PatchStatus]:
    service = scan_row.service.lower()
    raw_version = scan_row.version

    if not raw_version or raw_version == "Unknown":
        return None, None, PatchStatus(False, False, "N/A", "Service version unknown. Cannot query API.")

    detected_ver_str = clean_version_string(raw_version)
    search_query = f"{service} {detected_ver_str}"
    
    if search_query in API_CACHE:
        return API_CACHE[search_query]

    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.parse.quote(search_query)}&resultsPerPage=1"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if data.get("totalResults", 0) > 0:
                vuln = data["vulnerabilities"][0]["cve"]
                cve_id = vuln["id"]
                description = vuln["descriptions"][0]["value"]
                
                cvss_score, severity = 0.0, "Unknown"
                metrics = vuln.get("metrics", {})
                
                if "cvssMetricV31" in metrics:
                    cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                    cvss_score, severity = float(cvss_data.get("baseScore", 0.0)), cvss_data.get("baseSeverity", "Unknown")
                elif "cvssMetricV2" in metrics:
                    cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                    cvss_score, severity = float(cvss_data.get("baseScore", 0.0)), metrics["cvssMetricV2"][0].get("baseSeverity", "Unknown")

                cve_record = CVERecord(cve_id, cvss_score, severity, description)
                exploit_record = ExploitRecord(cve_id, "Check Exploit-DB", severity, "Upgrade to latest vendor release.", f"https://nvd.nist.gov/vuln/detail/{cve_id}")
                patch_status = PatchStatus(True, True, "Latest", f"Vulnerable! Detected {cve_id} (CVSS: {cvss_score})")
                
                result = (cve_record, exploit_record, patch_status)
                API_CACHE[search_query] = result
                return result

    except requests.exceptions.RequestException as e:
        logging.error(f"NVD API request failed: {e}")

    clean_result = (None, None, PatchStatus(False, False, "N/A", "Service appears clean or API unreachable."))
    API_CACHE[search_query] = clean_result
    return clean_result

def run_zap_scan(target: str):
    logging.info(f"Starting ZAP scan against {target}")
    try:
        zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
        zap.urlopen(target)
        scan_id = zap.ascan.scan(target)

        timeout = 0
        while int(zap.ascan.status(scan_id)) < 100 and timeout < 60: 
            time.sleep(2)
            timeout += 1

        return zap.core.alerts(baseurl=target)
    except Exception as e:
        logging.error(f"ZAP integration failed: {e}")
        return [{"alert": "ZAP Connection Failed", "risk": "Info", "url": target, "confidence": "Low"}]

# ---------------------------------------------------------------------------
# Flask Routing
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    global history_store, scan_history_order

    # --- GET REQUEST: VIEW HISTORICAL SCAN RESULTS ---
    if request.method == "GET" and "scan_id" in request.args:
        req_id = request.args.get("scan_id")
        if req_id in history_store:
            past_scan = history_store[req_id]
            return render_template(
                "index.html",
                findings=past_scan["findings"],
                zap_alerts=past_scan["zap_alerts"],
                messages=[("info", f"Viewing historical scan data for {past_scan['target']}.")],
                history=get_history_summary(),
                last_target=past_scan["target"],
                scan_time=past_scan["time"],
                elapsed=past_scan["elapsed"],
                detected_os=past_scan["detected_os"],
                os_details=past_scan.get("os_details", {})
            )
        else:
            return render_template("index.html", findings=[], zap_alerts=[], messages=[("error", "Log not found.")], history=get_history_summary(), last_target="", scan_time=None, elapsed=0.0, detected_os="Unknown")

    enriched_findings = []
    messages = []
    zap_alerts = []
    web_targets = []
    last_target = ""
    scan_time = None
    elapsed = 0.0
    detected_os = "Unknown"
    os_details_dict = {}

    # --- POST REQUEST: RUN & TRACK NEW SCAN ---
    if request.method == "POST":
        target_input = request.form.get("target", "").strip()
        last_target = target_input
        timing = request.form.get("timing", "4")
        custom_ports = request.form.get("ports", "").strip()
        udp_scan = "udp" in request.form
        os_detect = "os_detect" in request.form

        try:
            scan_target = resolve_and_validate_target(target_input)
            start_time = time.time()
            iso_scan_time = datetime.now(timezone.utc).isoformat()
            scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            nmap_args = f"-sV -Pn -T{timing} "
            if udp_scan: nmap_args += "-sU "
            if os_detect: nmap_args += "-O --osscan-guess "
            nmap_args += f"-p {custom_ports} " if custom_ports else "-F "

            messages.append(("info", f"Starting Network scan on {target_input}..."))
            scanner = nmap.PortScanner()
            scanner.scan(hosts=scan_target, arguments=nmap_args)

            # PARSE NMAP & WRITE TO SQLITE
            for host in scanner.all_hosts():
                domain_name = scanner[host].hostname() or get_domain_name(host)
                
                # 1. Resolve and Save Advanced OS Details
                if os_detect:
                    detected_os, os_match = resolve_os(scanner[host])
                    if os_match:
                        os_details_dict = {
                            "Accuracy": f"{os_match.get('accuracy')}%",
                            "Family": next((c.get("osfamily", "N/A") for c in os_match.get("osclass", [])), "N/A"),
                            "Generation": next((c.get("osgen", "N/A") for c in os_match.get("osclass", [])), "N/A")
                        }
                        save_os_to_db(DB_PATH, host, os_match, iso_scan_time)

                # 2. Iterate Ports and Evaluate States
                for proto in scanner[host].all_protocols():
                    for port in scanner[host][proto].keys():
                        port_data = scanner[host][proto][port]
                        state = port_data.get('state', '')
                        service_name = port_data.get('name', 'unknown')
                        version_info = port_data.get('version', '') or "Unknown"
                        extra_info = port_data.get('extrainfo', '')

                        scan_row = ScanRow(
                            target_ip=host, target_domain=domain_name,
                            port=int(port), protocol=proto.upper(), state=state,
                            service=service_name, version=version_info, extra=extra_info
                        )

                        # Write ALL ports to the background SQLite Database for auditing
                        save_port_to_db(DB_PATH, scan_row, detected_os, iso_scan_time)

                        # Process Actionable Open Ports for the UI Dashboard
                        if state == 'open':
                            if service_name in ["http", "http-alt"]:
                                web_targets.append(f"http://{host}:{port}")
                            elif service_name in ["https", "ssl/http", "https-alt"]:
                                web_targets.append(f"https://{host}:{port}")

                            cve, exploit, patch = analyze_patch_and_vuln(scan_row)
                            enriched_findings.append(EnrichedFinding(scan_row, cve, exploit, patch))

            # ZAP SCANS ON WEB SERVICES
            if web_targets:
                web_targets = list(set(web_targets))
                for web_target in web_targets:
                    alerts = run_zap_scan(web_target)
                    if alerts:
                        zap_alerts.extend(alerts)

            elapsed = round(time.time() - start_time, 2)
            messages.append(("success", f"Scan & DB logging complete in {elapsed} seconds."))

            scan_id = str(uuid.uuid4())
            history_store[scan_id] = {
                "id": scan_id, "target": target_input, "time": scan_time,
                "elapsed": elapsed, "detected_os": detected_os, "os_details": os_details_dict,
                "findings": enriched_findings, "zap_alerts": zap_alerts,
                "findings_count": len(enriched_findings), "zap_alerts_count": len(zap_alerts)
            }
            scan_history_order.appendleft(scan_id)

        except Exception as e:
            logging.exception("Scan execution error.")
            messages.append(("error", f"System error: {str(e)}"))

    return render_template(
        "index.html",
        findings=enriched_findings,
        zap_alerts=zap_alerts,
        messages=messages,
        history=get_history_summary(),
        last_target=last_target,
        scan_time=scan_time,
        elapsed=elapsed,
        detected_os=detected_os,
        os_details=os_details_dict
    )

@app.route("/repository")
def repository():
    repo_entries = []
    for search_query, (cve, exploit, patch) in API_CACHE.items():
        if cve: 
            repo_entries.append({"service": search_query.upper(), "fixed_version": "Latest", "cve": cve, "exploit": exploit})
    return render_template("repository.html", repo_entries=repo_entries)

if __name__ == "__main__":
    ensure_schema(DB_PATH) # Initialize SQLite database
    logging.info(f"SQLite DB initialized at {DB_PATH}")
    app.run(host="127.0.0.1", port=5000, debug=True)
