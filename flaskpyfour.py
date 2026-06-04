import logging
import nmap
import time
import socket
import ipaddress
from zapv2 import ZAPv2
from collections import deque
from datetime import datetime, timezone
from dataclasses import dataclass, field
from flask import Flask, render_template, request
from packaging.version import Version, InvalidVersion

# Initialize Flask App
app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

scan_history = deque(maxlen=10)

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
# Dynamic Vulnerability & Patch Engine
# ---------------------------------------------------------------------------
VULN_DB = {
    "ssh": {
        "fixed_version": "9.8p1",
        "cve": CVERecord("CVE-2024-6387", 8.1, "High", "regreSSHion: RCE vulnerability in OpenSSH."),
        "exploit": ExploitRecord("CVE-2024-6387", "Yes (Public)", "Critical", "Upgrade OpenSSH to 9.8p1.", "https://www.qualys.com/regresshion")
    },
    "http": {
        "fixed_version": "2.4.51",
        "cve": CVERecord("CVE-2021-41773", 7.5, "High", "Apache HTTP Server path traversal."),
        "exploit": ExploitRecord("CVE-2021-41773", "Yes (Metasploit)", "High", "Update Apache HTTP Server to 2.4.51.", "https://nvd.nist.gov/vuln/detail/CVE-2021-41773")
    },
    "https": {
        "fixed_version": "1.0.1g",
        "cve": CVERecord("CVE-2014-0160", 7.5, "High", "Heartbleed: OpenSSL memory leak."),
        "exploit": ExploitRecord("CVE-2014-0160", "Yes (Metasploit)", "High", "Patch OpenSSL to 1.0.1g or newer.", "https://heartbleed.com/")
    }
}

# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------
def clean_version_string(version_str: str) -> str:
    """Helper to extract a clean semantic version from messy Nmap text."""
    parts = version_str.split()
    for part in parts:
        clean_part = part.split('p')[0].split('-')[0].strip()
        if any(char.isdigit() for char in clean_part):
            return clean_part
    return version_str

def get_domain_name(ip_address: str) -> str:
    """Attempts to resolve an IP address to a full domain name."""
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except (socket.herror, socket.gaierror):
        return "Unknown Domain"

def resolve_and_validate_target(target_input):
    cleaned = target_input.strip()
    if not cleaned: 
        raise ValueError("Target input cannot be empty.")
    try:
        # Check if it's a valid IP or Subnet
        ipaddress.ip_network(cleaned, strict=False)
        return cleaned
    except ValueError:
        pass
    try:
        # Check if it's a resolvable domain
        return socket.gethostbyname(cleaned)
    except socket.gaierror:
        raise ValueError(f"Could not resolve or validate domain/IP range: '{target_input}'")

def analyze_patch_and_vuln(scan_row: ScanRow) -> tuple[CVERecord | None, ExploitRecord | None, PatchStatus]:
    service = scan_row.service.lower()
    raw_version = scan_row.version

    if service not in VULN_DB or not raw_version or raw_version == "Unknown":
        return None, None, PatchStatus(False, False, "N/A", "No vulnerability data available or version unknown.")

    db_entry = VULN_DB[service]
    fixed_ver_str = db_entry["fixed_version"]
    detected_ver_str = clean_version_string(raw_version)

    try:
        if Version(detected_ver_str) < Version(clean_version_string(fixed_ver_str)):
            return db_entry["cve"], db_entry["exploit"], PatchStatus(True, True, fixed_ver_str, f"Vulnerable! Upgrade to v{fixed_ver_str}.")
        else:
            return None, None, PatchStatus(False, False, fixed_ver_str, "Up-to-date.")
    except InvalidVersion:
        if detected_ver_str != fixed_ver_str:
            return db_entry["cve"], db_entry["exploit"], PatchStatus(True, True, fixed_ver_str, "Potential vulnerability. Dynamic version match failed.")

    return None, None, PatchStatus(False, False, "N/A", "Service version clean.")

def run_zap_scan(target: str):
    """Executes an OWASP ZAP Active Scan against the target web application."""
    logging.info(f"Starting ZAP scan against {target}")
    try:
        zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
        zap.urlopen(target)
        scan_id = zap.ascan.scan(target)
        
        while int(zap.ascan.status(scan_id)) < 100:
            time.sleep(2) # Polling interval
            
        return zap.core.alerts(baseurl=target)
    except Exception as e:
        logging.error(f"ZAP integration failed: {e}")
        return [{"alert": f"ZAP Scan Failed: Ensure ZAP API is running on port 8080. Error: {e}"}]

# ---------------------------------------------------------------------------
# Flask Routing
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    enriched_findings = []
    messages = []
    zap_alerts = []
    web_targets = []
    
    last_target = ""
    scan_time = None
    elapsed = 0.0
    detected_os = "Unknown"

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
                
                # Try to get hostname from Nmap, fallback to local resolution
                domain_name = scanner[host].hostname() 
                if not domain_name:
                    domain_name = get_domain_name(host)

                if os_detect and 'osmatch' in scanner[host] and len(scanner[host]['osmatch']) > 0:
                    detected_os = scanner[host]['osmatch'][0]['name']

                for proto in scanner[host].all_protocols():
                    for port in scanner[host][proto].keys():
                        port_data = scanner[host][proto][port]

                        if port_data['state'] == 'open':
                            service_name = port_data.get('name', 'unknown')
                            
                            scan_row = ScanRow(
                                target_ip=host,
                                target_domain=domain_name,
                                port=int(port),
                                protocol=proto.upper(),
                                service=service_name,
                                version=port_data.get('version', '') or "Unknown"
                            )
                            
                            # Identify web targets for ZAP (Handle HTTP and HTTPS)
                            if service_name in ["http", "http-alt"]:
                                web_targets.append(f"http://{host}:{port}")
                            elif service_name in ["https", "ssl/http", "https-alt"]: 
                                web_targets.append(f"https://{host}:{port}")

                            # Check internal patch dictionary
                            cve, exploit, patch = analyze_patch_and_vuln(scan_row)
                            enriched_findings.append(EnrichedFinding(scan_row, cve, exploit, patch))

            # 3. RUN ZAP SCANS ON DISCOVERED WEB SERVICES
            if web_targets:
                # Remove duplicates in case multiple IPs resolve to the same target
                web_targets = list(set(web_targets))
                for web_target in web_targets:
                    messages.append(("info", f"Running active ZAP analysis on {web_target}..."))
                    alerts = run_zap_scan(web_target)
                    if alerts:
                        zap_alerts.extend(alerts)

            if not enriched_findings:
                messages.append(("info", f"Scan finished. No open ports identified on {target_input}."))

            # 4. FINALIZE
            elapsed = round(time.time() - start_time, 2)
            scan_history.append({
                "target": target_input,
                "time": scan_time,
                "findings_count": len([f for f in enriched_findings if f.patch_status.is_vulnerable]),
                "zap_alerts": len(zap_alerts)
            })
            messages.append(("success", f"Scan complete in {elapsed} seconds."))

        except Exception as e:
            logging.exception("Scan execution error.")
            messages.append(("error", str(e)))

    # 5. RENDER DASHBOARD
    return render_template(
        "index.html",
        findings=enriched_findings,
        zap_alerts=zap_alerts,
        messages=messages,
        history=reversed(scan_history),
        last_target=last_target,
        scan_time=scan_time,
        elapsed=elapsed,
        detected_os=detected_os
    )

if __name__ == "__main__":
    # Note: Port scanning and OS detection (-O) may require running via sudo
    app.run(host="127.0.0.1", port=5000, debug=True)
