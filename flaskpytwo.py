import logging
import nmap
import time
import ipaddress
from collections import deque
from datetime import datetime
from flask import Flask, render_template, request

# Initialize Flask App
app = Flask(__name__)

# Configure Logging (writes errors to the console)
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

# Efficient history storage (only keeps the last 5 scans in memory)
scan_history = deque(maxlen=5)

@app.route("/", methods=["GET", "POST"])
def index():
    # Default variables
    hosts = []
    messages = []
    last_network = ""
    port_scan = False
    resolve_hostnames = False
    scan_time = None
    elapsed = 0.0

    if request.method == "POST":
        # 1. Grab form data
        network = request.form.get("network", "").strip()
        last_network = network
        port_scan = "port_scan" in request.form
        resolve_hostnames = "resolve_hostnames" in request.form

        # 2. Validate Input (Crucial for security before passing to Nmap)
        try:
            # This ensures the input is a valid IP or CIDR (e.g., 192.168.1.1 or 192.168.1.0/24)
            ipaddress.ip_network(network, strict=False)
        except ValueError:
            messages.append(("error", "Invalid IP address or CIDR notation. Please check your input."))
            return render_template("index.html", messages=messages, history=reversed(scan_history))

        # 3. Setup Scan Parameters
        start_time = time.time()
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Build Nmap arguments
        # -sn: Ping scan (no port scan) | -F: Fast mode (scans fewer ports)
        nmap_args = "-F" if port_scan else "-sn" 
        if not resolve_hostnames:
            nmap_args += " -n" # -n disables DNS resolution

        # 4. Execute Scan with Error Handling
        try:
            scanner = nmap.PortScanner()
            scanner.scan(hosts=network, arguments=nmap_args)

            # Parse results
            for host in scanner.all_hosts():
                host_info = {
                    "ip": host,
                    "state": scanner[host].state(),
                    "name": scanner[host].hostname() if resolve_hostnames else "N/A",
                    "ports": []
                }
                # If a port scan was requested and TCP ports were found
                if port_scan and 'tcp' in scanner[host]:
                    for port in scanner[host]['tcp']:
                        state = scanner[host]['tcp'][port]['state']
                        host_info["ports"].append(f"{port} ({state})")
                
                hosts.append(host_info)

            if not hosts:
                messages.append(("warn", f"Scan complete — no hosts responded on {network}."))

            # Calculate time and save history
            elapsed = round(time.time() - start_time, 2)
            scan_history.append({
                "network": network,
                "time": scan_time,
                "found": len(hosts)
            })

        except nmap.PortScannerError as e:
            logging.error(f"Nmap PortScannerError: {e}")
            messages.append(("error", "Nmap execution failed. Ensure Nmap is installed and accessible."))
        except PermissionError as e:
            logging.error(f"PermissionError: {e}")
            messages.append(("error", "Permission denied. Some scan types require elevated privileges (run as root/sudo)."))
        except Exception as e:
            logging.exception("An unexpected error occurred during the scan.")
            messages.append(("error", f"Unexpected error during scan: {type(e).__name__}"))

    # Render template using external file
    return render_template(
        "index.html",
        hosts=hosts,
        messages=messages,
        history=reversed(scan_history),
        last_network=last_network,
        port_scan=port_scan,
        resolve_hostnames=resolve_hostnames,
        scan_time=scan_time,
        elapsed=elapsed,
    )

if __name__ == "__main__":
    # DEVELOPMENT ONLY. For production, use Gunicorn or Waitress.
    app.run(host="127.0.0.1", port=5000, debug=False)
