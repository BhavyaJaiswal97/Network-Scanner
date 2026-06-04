from flask import Flask, request, render_template_string
import nmap

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Network Scanner</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f4f6f9; }
        input, button { padding: 8px; margin-bottom: 20px; }
        table { border-collapse: collapse; width: 100%; background: white; margin-bottom: 40px; box-shadow: 0 0 8px rgba(0,0,0,0.1); }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
        th { background: #1f2937; color: white; }
        pre { white-space: pre-wrap; word-wrap: break-word; background: #eee; padding: 10px; border-radius: 5px; }
    </style>
</head>
<body>

    <h2>Live Network & Exploit Scanner</h2>

    <form method="POST">
        <input name="target" placeholder="e.g., domain.com OR 192.168.1.0/24" style="width:300px" required>
        <button type="submit">Start Scan</button>
    </form>

    {% if target %}
        <h3>Scan Results for: {{ target }}</h3>
    {% endif %}

    {% if scans %}
        <h4>Open Ports & Services</h4>
        <table>
            <tr>
                <th>Target (Domain/IP)</th>
                <th>Port</th>
                <th>State</th>
                <th>Service</th>
                <th>Product</th>
            </tr>
            {% for r in scans %}
            <tr>
                <td>{{ r['target_name'] }}</td>
                <td>{{ r['port'] }}</td>
                <td>{{ r['state'] }}</td>
                <td>{{ r['service'] }}</td>
                <td>{{ r['product'] }}</td>
            </tr>
            {% endfor %}
        </table>
    {% endif %}

    {% if exploits %}
        <h4>Vulnerabilities & Exploits Found</h4>
        <table>
            <tr>
                <th>Target (Domain/IP)</th>
                <th>Port</th>
                <th>Vulnerability Script</th>
                <th>Output / Details</th>
            </tr>
            {% for e in exploits %}
            <tr>
                <td>{{ e['target_name'] }}</td>
                <td>{{ e['port'] }}</td>
                <td><strong>{{ e['script_name'] }}</strong></td>
                <td><pre>{{ e['output'] }}</pre></td>
            </tr>
            {% endfor %}
        </table>
    {% elif target and not exploits %}
        <p><em>No prominent vulnerabilities/exploits found by Nmap scripts for this target.</em></p>
    {% endif %}

</body>
</html>
"""

def scan_network(target):
    nm = nmap.PortScanner()
    
    # --script vuln triggers the vulnerability/exploit detection scripts
    # Removed -O (OS detection) to speed it up slightly and prevent root-requirement errors
    scan_args = "-sV -T4 --top-ports 100 --script vuln"
    
    print(f"Scanning {target} with args: {scan_args}")
    nm.scan(hosts=target, arguments=scan_args)

    scan_results = []
    exploit_results = []

    for host in nm.all_hosts():
        # Extract the domain name if Nmap found one, otherwise fallback to just IP
        hostname = nm[host].hostname()
        target_display = f"{hostname} ({host})" if hostname else host

        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                port_data = nm[host][proto][port]

                # 1. Standard Port Data
                scan_results.append({
                    "target_name": target_display,
                    "port": port,
                    "state": port_data.get("state", "unknown"),
                    "service": port_data.get("name", "unknown"),
                    "product": port_data.get("product", "")
                })

                # 2. Exploit / Script Data
                # If Nmap's vulnerability scripts found anything on this port, it's stored under 'script'
                if "script" in port_data:
                    for script_name, script_output in port_data["script"].items():
                        exploit_results.append({
                            "target_name": target_display,
                            "port": port,
                            "script_name": script_name,
                            "output": script_output
                        })

    return scan_results, exploit_results


@app.route("/", methods=["GET", "POST"])
def index():
    scans = []
    exploits = []
    target = ""

    if request.method == "POST":
        target = request.form["target"].strip()
        
        # We pass the domain or IP directly into our scanning function
        scans, exploits = scan_network(target)

    return render_template_string(
        HTML, 
        scans=scans, 
        exploits=exploits, 
        target=target
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
