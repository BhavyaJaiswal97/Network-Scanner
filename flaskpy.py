from flask import Flask, render_template_string, request, jsonify
import nmap
import ipaddress
import time
from datetime import datetime
from collections import deque

app = Flask(__name__)
app.secret_key = "secure_random_key_here"

# Simple in-memory rate limiter: max 5 scans per IP per minute
_rate_limit: dict[str, deque] = {}
RATE_LIMIT_MAX = 5
RATE_LIMIT_WINDOW = 60  # seconds

# Cap network size to prevent abuse (max /16 = 65536 hosts, use /24 = 256 as safe default)
MAX_PREFIX_LENGTH_IPV4 = 24
MAX_PREFIX_LENGTH_IPV6 = 120

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetScan // Network Scanner</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Barlow:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #090e14;
            --surface: #0d1520;
            --surface2: #111d2e;
            --border: #1e3a5f;
            --accent: #00d4ff;
            --accent2: #00ff9d;
            --danger: #ff4757;
            --warn: #ffa502;
            --text: #c8d8e8;
            --text-dim: #5a7a9a;
            --mono: 'Share Tech Mono', monospace;
            --sans: 'Barlow', sans-serif;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            background: var(--bg);
            color: var(--text);
            font-family: var(--sans);
            min-height: 100vh;
            overflow-x: hidden;
        }

        /* Animated grid background */
        body::before {
            content: '';
            position: fixed;
            inset: 0;
            background-image:
                linear-gradient(rgba(0,212,255,0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0,212,255,0.03) 1px, transparent 1px);
            background-size: 40px 40px;
            pointer-events: none;
            z-index: 0;
        }

        .container {
            position: relative;
            z-index: 1;
            max-width: 900px;
            margin: 0 auto;
            padding: 2rem 1.5rem 4rem;
        }

        /* Header */
        .header {
            display: flex;
            align-items: flex-end;
            gap: 1rem;
            margin-bottom: 2.5rem;
            padding-bottom: 1.5rem;
            border-bottom: 1px solid var(--border);
        }

        .logo {
            font-family: var(--mono);
            font-size: 2rem;
            color: var(--accent);
            letter-spacing: 0.05em;
            text-shadow: 0 0 20px rgba(0,212,255,0.4);
        }

        .logo span { color: var(--accent2); }

        .tagline {
            font-size: 0.75rem;
            color: var(--text-dim);
            letter-spacing: 0.15em;
            text-transform: uppercase;
            margin-bottom: 0.25rem;
        }

        .status-dot {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--accent2);
            margin-right: 6px;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; box-shadow: 0 0 0 0 rgba(0,255,157,0.4); }
            50% { opacity: 0.7; box-shadow: 0 0 0 6px rgba(0,255,157,0); }
        }

        /* Scan form */
        .scan-panel {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.75rem;
            margin-bottom: 1.5rem;
            position: relative;
            overflow: hidden;
        }

        .scan-panel::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 2px;
            background: linear-gradient(90deg, var(--accent), var(--accent2));
        }

        .panel-label {
            font-family: var(--mono);
            font-size: 0.7rem;
            color: var(--accent);
            letter-spacing: 0.2em;
            text-transform: uppercase;
            margin-bottom: 1.25rem;
        }

        .input-row {
            display: flex;
            gap: 0.75rem;
            flex-wrap: wrap;
            align-items: center;
        }

        .input-group {
            flex: 1;
            min-width: 220px;
            position: relative;
        }

        .input-group label {
            display: block;
            font-size: 0.7rem;
            color: var(--text-dim);
            letter-spacing: 0.1em;
            text-transform: uppercase;
            margin-bottom: 0.4rem;
        }

        input[type="text"] {
            width: 100%;
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 4px;
            color: var(--accent);
            font-family: var(--mono);
            font-size: 1rem;
            padding: 0.65rem 1rem;
            outline: none;
            transition: border-color 0.2s, box-shadow 0.2s;
        }

        input[type="text"]:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(0,212,255,0.1);
        }

        input[type="text"]::placeholder { color: var(--text-dim); }

        .options-row {
            display: flex;
            gap: 1.5rem;
            flex-wrap: wrap;
            margin-top: 1rem;
        }

        .checkbox-label {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.85rem;
            color: var(--text-dim);
            cursor: pointer;
            user-select: none;
        }

        .checkbox-label input[type="checkbox"] {
            accent-color: var(--accent);
            width: 14px;
            height: 14px;
        }

        .btn-scan {
            background: transparent;
            border: 1px solid var(--accent);
            color: var(--accent);
            font-family: var(--mono);
            font-size: 0.9rem;
            letter-spacing: 0.1em;
            padding: 0.65rem 1.75rem;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.2s;
            white-space: nowrap;
            align-self: flex-end;
        }

        .btn-scan:hover {
            background: var(--accent);
            color: var(--bg);
            box-shadow: 0 0 20px rgba(0,212,255,0.3);
        }

        .btn-scan:disabled {
            opacity: 0.4;
            cursor: not-allowed;
        }

        /* Progress bar */
        .progress-wrap {
            display: none;
            margin-top: 1.25rem;
        }

        .progress-wrap.active { display: block; }

        .progress-bar {
            height: 3px;
            background: var(--border);
            border-radius: 2px;
            overflow: hidden;
            margin-bottom: 0.5rem;
        }

        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--accent), var(--accent2));
            width: 0%;
            transition: width 0.3s;
            animation: scan-progress 3s ease-in-out infinite;
        }

        @keyframes scan-progress {
            0% { width: 5%; }
            50% { width: 80%; }
            100% { width: 95%; }
        }

        .progress-text {
            font-family: var(--mono);
            font-size: 0.75rem;
            color: var(--text-dim);
        }

        .progress-text .blink {
            animation: blink 1s step-end infinite;
        }

        @keyframes blink { 50% { opacity: 0; } }

        /* Alert / error */
        .alert {
            display: flex;
            align-items: flex-start;
            gap: 0.75rem;
            padding: 0.85rem 1.25rem;
            border-radius: 6px;
            margin-bottom: 1.25rem;
            font-size: 0.9rem;
        }

        .alert-error {
            background: rgba(255,71,87,0.08);
            border: 1px solid rgba(255,71,87,0.3);
            color: var(--danger);
        }

        .alert-warn {
            background: rgba(255,165,2,0.08);
            border: 1px solid rgba(255,165,2,0.3);
            color: var(--warn);
        }

        .alert-icon { font-size: 1rem; flex-shrink: 0; }

        /* Results */
        .results-panel {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
        }

        .results-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border);
            background: var(--surface2);
        }

        .results-title {
            font-family: var(--mono);
            font-size: 0.75rem;
            color: var(--accent);
            letter-spacing: 0.15em;
            text-transform: uppercase;
        }

        .results-meta {
            font-family: var(--mono);
            font-size: 0.75rem;
            color: var(--text-dim);
        }

        .results-meta span { color: var(--accent2); }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        thead tr {
            background: var(--surface2);
        }

        th {
            font-family: var(--mono);
            font-size: 0.7rem;
            color: var(--text-dim);
            letter-spacing: 0.15em;
            text-transform: uppercase;
            padding: 0.75rem 1.25rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
            font-weight: 400;
        }

        td {
            padding: 0.85rem 1.25rem;
            font-size: 0.9rem;
            border-bottom: 1px solid rgba(30,58,95,0.5);
            vertical-align: middle;
        }

        tr:last-child td { border-bottom: none; }

        tr:hover td { background: rgba(0,212,255,0.03); }

        .ip-addr {
            font-family: var(--mono);
            color: var(--accent);
            font-size: 0.9rem;
        }

        .badge {
            display: inline-block;
            padding: 0.2rem 0.6rem;
            border-radius: 3px;
            font-family: var(--mono);
            font-size: 0.75rem;
            font-weight: 600;
        }

        .badge-up {
            background: rgba(0,255,157,0.1);
            color: var(--accent2);
            border: 1px solid rgba(0,255,157,0.25);
        }

        .badge-down {
            background: rgba(255,71,87,0.1);
            color: var(--danger);
            border: 1px solid rgba(255,71,87,0.25);
        }

        .ports {
            display: flex;
            flex-wrap: wrap;
            gap: 4px;
        }

        .port-tag {
            font-family: var(--mono);
            font-size: 0.72rem;
            padding: 0.15rem 0.45rem;
            border-radius: 3px;
            background: rgba(0,212,255,0.08);
            border: 1px solid rgba(0,212,255,0.2);
            color: var(--text-dim);
        }

        .port-tag.open {
            background: rgba(0,255,157,0.08);
            border-color: rgba(0,255,157,0.2);
            color: var(--accent2);
        }

        .no-results {
            text-align: center;
            padding: 3rem 1rem;
            color: var(--text-dim);
            font-family: var(--mono);
            font-size: 0.85rem;
        }

        /* Scan history */
        .history-panel {
            margin-top: 1.5rem;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
        }

        .history-header {
            padding: 0.85rem 1.25rem;
            border-bottom: 1px solid var(--border);
            font-family: var(--mono);
            font-size: 0.7rem;
            color: var(--text-dim);
            letter-spacing: 0.15em;
            text-transform: uppercase;
            background: var(--surface2);
        }

        .history-list {
            padding: 0.5rem 0;
        }

        .history-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0.55rem 1.25rem;
            font-size: 0.85rem;
            border-bottom: 1px solid rgba(30,58,95,0.3);
            cursor: pointer;
            transition: background 0.15s;
        }

        .history-item:last-child { border-bottom: none; }

        .history-item:hover { background: rgba(0,212,255,0.04); }

        .history-network { font-family: var(--mono); color: var(--accent); font-size: 0.85rem; }

        .history-info { font-size: 0.75rem; color: var(--text-dim); font-family: var(--mono); }

        footer {
            margin-top: 3rem;
            text-align: center;
            font-size: 0.75rem;
            color: var(--text-dim);
            font-family: var(--mono);
            letter-spacing: 0.05em;
        }
    </style>
</head>
<body>
<div class="container">

    <div class="header">
        <div>
            <div class="logo">NET<span>SCAN</span></div>
        </div>
        <div>
            <div class="tagline"><span class="status-dot"></span>System ready</div>
        </div>
    </div>

    {% for category, message in messages %}
    <div class="alert alert-{{ category }}">
        <span class="alert-icon">{{ '⚠' if category == 'warn' else '✖' }}</span>
        <span>{{ message }}</span>
    </div>
    {% endfor %}

    <div class="scan-panel">
        <div class="panel-label">// Scan Configuration</div>
        <form id="scan-form" method="post">
            <div class="input-row">
                <div class="input-group">
                    <label for="network">Target Network (CIDR)</label>
                    <input type="text" id="network" name="network"
                           placeholder="e.g. 192.168.1.0/24"
                           value="{{ last_network or '' }}"
                           autocomplete="off"
                           required>
                </div>
                <button type="submit" class="btn-scan" id="scan-btn">▶ SCAN</button>
            </div>

            <div class="options-row">
                <label class="checkbox-label">
                    <input type="checkbox" name="port_scan" value="1" {{ 'checked' if port_scan else '' }}>
                    Port scan (common ports)
                </label>
                <label class="checkbox-label">
                    <input type="checkbox" name="resolve_hostnames" value="1" {{ 'checked' if resolve_hostnames else '' }}>
                    Resolve hostnames
                </label>
            </div>

            <div class="progress-wrap" id="progress">
                <div class="progress-bar"><div class="progress-fill"></div></div>
                <div class="progress-text">Scanning network<span class="blink">_</span></div>
            </div>
        </form>
    </div>

    {% if hosts is not none %}
    <div class="results-panel">
        <div class="results-header">
            <div class="results-title">// Discovered Hosts</div>
            <div class="results-meta">
                <span>{{ hosts | length }}</span> host{{ 's' if hosts|length != 1 else '' }} found
                &nbsp;·&nbsp; {{ scan_time }}
                &nbsp;·&nbsp; {{ elapsed }}s
            </div>
        </div>
        {% if hosts %}
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Status</th>
                    <th>Hostname</th>
                    {% if port_scan %}<th>Open Ports</th>{% endif %}
                </tr>
            </thead>
            <tbody>
                {% for host in hosts %}
                <tr>
                    <td><span class="ip-addr">{{ host.ip }}</span></td>
                    <td>
                        <span class="badge {{ 'badge-up' if host.state == 'up' else 'badge-down' }}">
                            {{ host.state | upper }}
                        </span>
                    </td>
                    <td style="color: var(--text-dim); font-size:0.88rem;">{{ host.hostname or '—' }}</td>
                    {% if port_scan %}
                    <td>
                        <div class="ports">
                            {% for p in host.open_ports %}
                            <span class="port-tag open">{{ p }}</span>
                            {% else %}
                            <span style="color:var(--text-dim); font-size:0.8rem; font-family:var(--mono);">none</span>
                            {% endfor %}
                        </div>
                    </td>
                    {% endif %}
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% else %}
        <div class="no-results">// No hosts responded on {{ last_network }}</div>
        {% endif %}
    </div>
    {% endif %}

    {% if history %}
    <div class="history-panel">
        <div class="history-header">// Recent Scans</div>
        <div class="history-list">
            {% for entry in history %}
            <div class="history-item" onclick="document.getElementById('network').value='{{ entry.network }}'">
                <span class="history-network">{{ entry.network }}</span>
                <span class="history-info">{{ entry.count }} hosts · {{ entry.time }}</span>
            </div>
            {% endfor %}
        </div>
    </div>
    {% endif %}

    <footer>NETSCAN // LOCAL NETWORK DISCOVERY TOOL // USE RESPONSIBLY</footer>
</div>

<script>
    document.getElementById('scan-form').addEventListener('submit', function() {
        document.getElementById('scan-btn').disabled = true;
        document.getElementById('scan-btn').textContent = '⏳ SCANNING...';
        document.getElementById('progress').classList.add('active');
    });
</script>
</body>
</html>
"""

# In-memory scan history (last 5 scans)
scan_history: list[dict] = []


def is_valid_network(network_str: str) -> tuple[bool, str]:
    """Validate and check network size. Returns (valid, error_message)."""
    try:
        net = ipaddress.ip_network(network_str, strict=False)
    except ValueError:
        return False, "Invalid IP address or CIDR notation."

    if net.version == 4 and net.prefixlen < MAX_PREFIX_LENGTH_IPV4:
        return False, (
            f"Network too large. IPv4 prefix must be /{MAX_PREFIX_LENGTH_IPV4} or smaller "
            f"(e.g. /24). You entered /{net.prefixlen}."
        )
    if net.version == 6 and net.prefixlen < MAX_PREFIX_LENGTH_IPV6:
        return False, (
            f"Network too large. IPv6 prefix must be /{MAX_PREFIX_LENGTH_IPV6} or smaller."
        )
    return True, ""


def check_rate_limit(ip: str) -> bool:
    """Return True if the request is allowed, False if rate-limited."""
    now = time.time()
    timestamps = _rate_limit.setdefault(ip, deque())
    # Remove timestamps outside the window
    while timestamps and now - timestamps[0] > RATE_LIMIT_WINDOW:
        timestamps.popleft()
    if len(timestamps) >= RATE_LIMIT_MAX:
        return False
    timestamps.append(now)
    return True


@app.route("/", methods=["GET", "POST"])
def index():
    hosts = None
    messages: list[tuple[str, str]] = []
    last_network = ""
    port_scan = False
    resolve_hostnames = False
    scan_time = ""
    elapsed = ""

    if request.method == "POST":
        client_ip = request.remote_addr or "unknown"

        if not check_rate_limit(client_ip):
            messages.append(("error", f"Rate limit exceeded. Max {RATE_LIMIT_MAX} scans per minute."))
            return render_template_string(
                HTML,
                hosts=None,
                messages=messages,
                history=scan_history[-5:][::-1],
                last_network="",
                port_scan=False,
                resolve_hostnames=False,
                scan_time="",
                elapsed="",
            )

        network = request.form.get("network", "").strip()
        port_scan = bool(request.form.get("port_scan"))
        resolve_hostnames = bool(request.form.get("resolve_hostnames"))
        last_network = network

        valid, err = is_valid_network(network)
        if not valid:
            messages.append(("error", err))
        else:
            try:
                nm = nmap.PortScanner()

                # Build nmap arguments
                args = "-sn"  # ping scan (host discovery only) by default
                if port_scan:
                    args = "-sV --open -F"  # fast port scan, common ports
                if not resolve_hostnames:
                    args += " -n"  # skip DNS resolution for speed

                start = time.time()
                nm.scan(hosts=network, arguments=args)
                elapsed = f"{time.time() - start:.1f}"
                scan_time = datetime.now().strftime("%H:%M:%S")
                hosts = []

                for host in nm.all_hosts():
                    open_ports = []
                    if port_scan:
                        for proto in nm[host].all_protocols():
                            for port, info in nm[host][proto].items():
                                if info.get("state") == "open":
                                    service = info.get("name", "")
                                    label = f"{port}/{proto}"
                                    if service:
                                        label += f" ({service})"
                                    open_ports.append(label)

                    hosts.append({
                        "ip": host,
                        "state": nm[host].state(),
                        "hostname": nm[host].hostname() if resolve_hostnames else "",
                        "open_ports": open_ports,
                    })

                # Sort by IP address numerically
                hosts.sort(key=lambda h: ipaddress.ip_address(h["ip"]))

                # Update history
                scan_history.append({
                    "network": network,
                    "count": len(hosts),
                    "time": scan_time,
                })
                if len(scan_history) > 10:
                    scan_history.pop(0)

                if not hosts:
                    messages.append(("warn", f"Scan complete — no hosts responded on {network}."))

            except nmap.PortScannerError as e:
                messages.append(("error", "Nmap execution failed. Ensure Nmap is installed and accessible."))
            except PermissionError:
                messages.append(("error", "Permission denied. Some scan types require elevated privileges (run as root/sudo)."))
            except Exception as e:
                messages.append(("error", f"Unexpected error during scan: {type(e).__name__}"))

    return render_template_string(
        HTML,
        hosts=hosts,
        messages=messages,
        history=scan_history[-5:][::-1],
        last_network=last_network,
        port_scan=port_scan,
        resolve_hostnames=resolve_hostnames,
        scan_time=scan_time,
        elapsed=elapsed,
    )


if __name__ == "__main__":
    # Debug=False in production; host binding should be restricted in real deployments
    app.run(host="127.0.0.1", port=5000, debug=False)
