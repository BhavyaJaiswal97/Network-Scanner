from flask import Flask, request, render_template
import nmap
import sqlite3
import os

app = Flask(__name__)
DB_FILE = "scans.db"

def init_db():
    """Creates the necessary database tables if they do not exist."""
    with sqlite3.connect(DB_FILE) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS hosts (
                ip TEXT PRIMARY KEY, 
                hostname TEXT, 
                mac TEXT, 
                state TEXT, 
                os_name TEXT
            );
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT, 
                proto TEXT, 
                port INTEGER, 
                state TEXT, 
                service TEXT, 
                product TEXT
            );
            CREATE TABLE IF NOT EXISTS exploits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT, 
                port INTEGER, 
                script_name TEXT, 
                output TEXT
            );
        """)

def scan_and_save(target):
    """Runs Nmap, extracts all data, and saves it to the SQLite database."""
    nm = nmap.PortScanner()
    
    # -sV (Version), -sU (UDP), -O (OS Detect), --script vuln (Exploits)
    # WARNING: -sU and -O require the script to be run with 'sudo'
    scan_args = "-sV -sU -T4 -O --top-ports 100 --script vuln"
    print(f"[*] Starting intense scan on {target}... This may take a few minutes.")
    
    try:
        nm.scan(hosts=target, arguments=scan_args)
    except Exception as e:
        print(f"[!] Scan error: {e}")
        return

    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        
        for host in nm.all_hosts():
            # 1. Parse and Save Host Information
            hostname = nm[host].hostname()
            mac = nm[host].get('addresses', {}).get('mac', 'Unknown')
            state = nm[host].state()
            
            os_name = "Unknown"
            if 'osmatch' in nm[host] and len(nm[host]['osmatch']) > 0:
                os_name = nm[host]['osmatch'][0]['name']

            cur.execute("""
                INSERT OR REPLACE INTO hosts (ip, hostname, mac, state, os_name) 
                VALUES (?, ?, ?, ?, ?)
            """, (host, hostname, mac, state, os_name))

            # 2. Parse and Save Ports and Protocols
            for proto in nm[host].all_protocols():
                for port in nm[host][proto]:
                    port_data = nm[host][proto][port]
                    p_state = port_data.get("state", "unknown")
                    p_service = port_data.get("name", "unknown")
                    p_product = port_data.get("product", "")

                    cur.execute("""
                        INSERT INTO scans (ip, proto, port, state, service, product) 
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (host, proto.upper(), port, p_state, p_service, p_product))

                    # 3. Parse and Save Exploits/Vulnerabilities
                    if "script" in port_data:
                        for script_name, output in port_data["script"].items():
                            cur.execute("""
                                INSERT INTO exploits (ip, port, script_name, output) 
                                VALUES (?, ?, ?, ?)
                            """, (host, port, script_name, output))
        conn.commit()
        print(f"[*] Scan complete and saved to database for {target}.")

@app.route("/", methods=["GET", "POST"])
def dashboard():
    # If a user submits a domain/IP via the web form, scan it first
    if request.method == "POST":
        target = request.form.get("target").strip()
        if target:
            scan_and_save(target)

    # Fetch all historical data from the database to display on the page
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        # Fetch stats
        cur.execute("SELECT COUNT(*) FROM hosts")
        total_hosts = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) FROM scans")
        total_ports = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) FROM exploits")
        total_exploits = cur.fetchone()[0]

        # Fetch table data
        cur.execute("SELECT * FROM hosts ORDER BY ip DESC")
        hosts = cur.fetchall()

        cur.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 100")
        scans = cur.fetchall()

        cur.execute("SELECT * FROM exploits ORDER BY id DESC")
        exploits = cur.fetchall()

    return render_template(
        "index.html",
        total_hosts=total_hosts,
        total_ports=total_ports,
        total_exploits=total_exploits,
        hosts=hosts,
        scans=scans,
        exploits=exploits
    )

if __name__ == "__main__":
    init_db()  # Ensure tables exist before starting the server
    app.run(host="0.0.0.0", port=5000, debug=True)
