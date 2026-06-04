from flask import Flask, render_template
import sqlite3
import logging

app = Flask(__name__)

DB_FILE = "scans.db"
ALLOWED_TABLES = {"scans", "vulnerability_reports", "exploits"}

# Set up basic logging
logging.basicConfig(level=logging.ERROR)

def get_table(cursor, table):
    """Fetches all rows and column names for a given table."""
    if table not in ALLOWED_TABLES:
        logging.error(f"Attempted to query unauthorized table: {table}")
        return [], []
        
    try:
        cursor.execute(f"SELECT * FROM {table}")
        rows = cursor.fetchall()
        cols = [description[0] for description in cursor.description] if cursor.description else []
        return rows, cols
    except sqlite3.Error as e:
        logging.error(f"Database error querying {table}: {e}")
        return [], []

def get_count(cursor, query):
    """Executes a count query and safely returns the integer result."""
    try:
        cursor.execute(query)
        result = cursor.fetchone()
        return result[0] if result else 0
    except sqlite3.Error as e:
        logging.error(f"Database error during count query: {e}")
        return 0

@app.route("/")
def dashboard():
    # Use context manager to ensure the connection is closed automatically
    with sqlite3.connect(DB_FILE) as conn:
        # row_factory allows accessing columns by name (e.g., row['severity'])
        conn.row_factory = sqlite3.Row 
        cur = conn.cursor()

        # Fetch Tables
        scans, scan_cols = get_table(cur, "scans")
        vulns, vuln_cols = get_table(cur, "vulnerability_reports")
        exploits, exploit_cols = get_table(cur, "exploits")

        # Fetch Statistics
        stats = {
            "hosts": get_count(cur, "SELECT COUNT(DISTINCT ip) FROM scans"),
            "ports": get_count(cur, "SELECT COUNT(*) FROM scans"),
            "vulns": get_count(cur, "SELECT COUNT(*) FROM vulnerability_reports"),
            "exploits": get_count(cur, "SELECT COUNT(*) FROM exploits")
        }

    return render_template(
        "dashboard.html",
        scans=scans, scan_cols=scan_cols,
        vulns=vulns, vuln_cols=vuln_cols,
        exploits=exploits, exploit_cols=exploit_cols,
        stats=stats
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
