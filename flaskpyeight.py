import logging
import nmap
import time
import socket
import ipaddress
import uuid
import requests
import urllib.parse
from zapv2 import ZAPv2
from collections import deque
from datetime import datetime, timezone
from dataclasses import dataclass, field
from flask import Flask, render_template, request
from packaging.version import Version, InvalidVersion

# Initialize Flask App
app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- PERSISTENT STORAGE (In-Memory) ---
history_store = {}
scan_history_order = deque(maxlen=10)

# --- Dynamic NVD API Cache ---
# Stores results during runtime to prevent hitting API rate limits on repeated services
API_CACHE = {}

def get_history_summary():
    """Generates a summary list of past scans for the sidebar view."""
    return [history_store[uid] for uid in scan_history_order if uid in history_store]

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------
@dataclass
class ScanRow:
    target_ip: str
    target_domain: str
    port: int
    protocol: str
    service: str
    version: str

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
# Helper Functions
# ---------------------------------------------------------------------------
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
        raise ValueError(f"Could not resolve or validate domain/IP range: '{target_input}'")

def analyze_patch_and_vuln(scan_row: ScanRow) -> tuple[CVERecord | None, ExploitRecord | None, PatchStatus]:
    service = scan_row.service.lower()
    raw_version = scan_row.version

    # If Nmap couldn't detect the version, we can't query the API accurately
    if not raw_version or raw_version == "Unknown":
        return None, None, PatchStatus(False, False, "N/A", "Service version unknown. Cannot query API.")

    detected_ver_str = clean_version_string(raw_version)
    search_query = f"{service} {detected_ver_str}"
    
    # Check if we already queried this exact service+version in this session
    if search_query in API_CACHE:
        return API_CACHE[search_query]

    try:
        # Query the official NIST NVD API v2 via keyword search
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.parse.quote(search_query)}&resultsPerPage=1"
        
        # Note: Get a free API key at nvd.nist.gov/developers to raise your rate limits.
        # If you have one, pass it here: headers={"apiKey": "YOUR_KEY"}
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if data.get("totalResults", 0) > 0:
                # Extract the top vulnerability returned by NVD
                vuln = data["vulnerabilities"][0]["cve"]
                cve_id = vuln["id"]
                description = vuln["descriptions"][0]["value"]
                
                # Safely parse the CVSS Score from NVD's nested JSON metrics
                cvss_score = 0.0
                severity = "Unknown"
                metrics = vuln.get("metrics", {})
                
                if "cvssMetricV31" in metrics:
                    cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                    cvss_score = float(cvss_data.get("baseScore", 0.0))
                    severity = cvss_data.get("baseSeverity", "Unknown")
                elif "cvssMetricV30" in metrics:
                    cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                    cvss_score = float(cvss_data.get("baseScore", 0.0))
                    severity = cvss_data.get("baseSeverity", "Unknown")
                elif "cvssMetricV2" in metrics:
                    cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                    cvss_score = float(cvss_data.get("baseScore", 0.0))
                    severity = metrics["cvssMetricV2"][0].get("baseSeverity", "Unknown")

                cve_record = CVERecord(cve_id, cvss_score, severity, description)
                
                # Build dynamic exploit/patch records since NVD provided the CVE
                exploit_record = ExploitRecord(
                    cve_id=cve_id, 
                    exploit_available="Check Exploit-DB/Metasploit", 
                    risk_level=severity, 
                    remediation="Upgrade to latest vendor release.", 
                    reference_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                )
                
                patch_status = PatchStatus(True, True, "Latest", f"Vulnerable! Detected {cve_id} (CVSS: {cvss_score})")
                
                # Save to cache and return the dataclasses to the Flask app
                result = (cve_record, exploit_record, patch_status)
                API_CACHE[search_query] = result
                return result

    except requests.exceptions.RequestException as e:
        logging.error(f"NVD API request failed for '{search_query}': {e}")

    # Fallback if API fails, times out, or no vulnerabilities are found
    clean_result = (None, None, PatchStatus(False, False, "N/A", "Service appears clean or API unreachable."))
    API_CACHE[search_query] = clean_result
    return clean_result


def run_zap_scan(target: str):
    """Executes an OWASP ZAP Active Scan against the target web application."""
    logging.info(f"Starting ZAP scan against {target}")
    try:
        zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
        zap.urlopen(target)
        scan_id = zap.ascan.scan(target)

        timeout = 0
        while int(zap.ascan.status(scan_id)) < 100 and timeout < 60: # 60 loop timeout
            time.sleep(2)
            timeout += 1

        return zap.core.alerts(baseurl=target)
    except Exception as e:
        logging.error(f"ZAP integration failed: {e}")
        # Return fallback error formatted identically to ZAP native alerts
        return [{
            "alert": f"ZAP API Connection Failed: Ensure ZAP is running locally on port 8080.",
            "risk": "Info",
            "url": target,
            "confidence": "Low"
        }]

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
                detected_os=past_scan["detected_os"]
            )
        else:
            return render_template(
                "index.html",
                findings=[],
                zap_alerts=[],
                messages=[("error", "Requested scan history log not found or session expired.")],
                history=get_history_summary(),
                last_target="",
                scan_time=None,
                elapsed=0.0,
                detected_os="Unknown"
            )

    # --- DEFAULT INITIAL HOISTED STATE ---
    enriched_findings = []
    messages = []
    zap_alerts = []
    web_targets = []
    last_target = ""
    scan_time = None
    elapsed = 0.0
    detected_os = "Unknown"

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
            scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # 1. RUN NMAP SCAN
            nmap_args = f"-sV -Pn -T{timing} "
            if udp_scan: nmap_args += "-sU "
            if os_detect: nmap_args += "-O "
            nmap_args += f"-p {custom_ports} " if custom_ports else "-F "

            messages.append(("info", f"Starting Nmap scan on {target_input}..."))
            scanner = nmap.PortScanner()
            scanner.scan(hosts=scan_target, arguments=nmap_args)

            # 2. PARSE NMAP RESULTS
            for host in scanner.all_hosts():
                domain_name = scanner[host].hostname() or get_domain_name(host)
                if os_detect and 'osmatch' in scanner[host] and len(scanner[host]['osmatch']) > 0:
                    detected_os = scanner[host]['osmatch'][0]['name']

                for proto in scanner[host].all_protocols():
                    for port in scanner[host][proto].keys():
                        port_data = scanner[host][proto][port]
                        if port_data['state'] == 'open':
                            service_name = port_data.get('name', 'unknown')
                            scan_row = ScanRow(
                                target_ip=host, target_domain=domain_name,
                                port=int(port), protocol=proto.upper(),
                                service=service_name, version=port_data.get('version', '') or "Unknown"
                            )

                            if service_name in ["http", "http-alt"]:
                                web_targets.append(f"http://{host}:{port}")
                            elif service_name in ["https", "ssl/http", "https-alt"]:
                                web_targets.append(f"https://{host}:{port}")

                            cve, exploit, patch = analyze_patch_and_vuln(scan_row)
                            enriched_findings.append(EnrichedFinding(scan_row, cve, exploit, patch))

            # 3. RUN ZAP SCANS ON WEB SERVICES
            if web_targets:
                web_targets = list(set(web_targets)) # Deduplicate
                for web_target in web_targets:
                    alerts = run_zap_scan(web_target)
                    if alerts:
                        zap_alerts.extend(alerts)

            elapsed = round(time.time() - start_time, 2)
            messages.append(("success", f"Scan complete in {elapsed} seconds."))

            # 4. ROBUST VULN COUNTING & HISTORY SAVE
            try:
                findings_count = len([f for f in enriched_findings if f.patch_status.is_vulnerable])
            except AttributeError:
                findings_count = len(enriched_findings)

            scan_id = str(uuid.uuid4())
            scan_data = {
                "id": scan_id,
                "target": target_input,
                "time": scan_time,
                "elapsed": elapsed,
                "detected_os": detected_os,
                "findings": enriched_findings,
                "zap_alerts": zap_alerts,
                "findings_count": findings_count,
                "zap_alerts_count": len(zap_alerts)
            }

            history_store[scan_id] = scan_data
            scan_history_order.appendleft(scan_id)

        except Exception as e:
            logging.exception("Scan execution error.")
            messages.append(("error", f"System error: {str(e)}"))

    # --- DEFAULT DASHBOARD RENDER ---
    return render_template(
        "index.html",
        findings=enriched_findings,
        zap_alerts=zap_alerts,
        messages=messages,
        history=get_history_summary(),
        last_target=last_target,
        scan_time=scan_time,
        elapsed=elapsed,
        detected_os=detected_os
    )

@app.route("/repository")
def repository():
    """Displays the live vulnerabilities dynamically fetched from NVD this session."""
    repo_entries = []
    for search_query, (cve, exploit, patch) in API_CACHE.items():
        if cve: # Only append entries that actually registered a CVE
            repo_entries.append({
                "service": search_query.upper(),
                "fixed_version": "Latest", 
                "cve": cve,
                "exploit": exploit,
            })
    return render_template("repository.html", repo_entries=repo_entries)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
