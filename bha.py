from flask import Flask, render_template
import sqlite3
import logging

app = Flask(__name__)

DB_FILE = "scans.db"

ALLOWED_TABLES = {
    "scans",
    "vulnerability_reports",
    "exploits"
}

logging.basicConfig(level=logging.INFO)


def safe_query(conn, table):
    """Safe table fetch with validation + dict rows"""
    if table not in ALLOWED_TABLES:
        logging.error(f"Blocked illegal table access: {table}")
        return [], []

    try:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        # Add LIMIT for performance safety
        cur.execute(f"SELECT * FROM {table} ORDER BY 1 DESC LIMIT 200")
        rows = cur.fetchall()

        cols = rows[0].keys() if rows else []
        return rows, cols

    except sqlite3.Error as e:
        logging.error(f"DB error on {table}: {e}")
        return [], []


def get_stat(conn, query):
    try:
        cur = conn.cursor()
        cur.execute(query)
        result = cur.fetchone()
        return result[0] if result else 0
    except sqlite3.Error as e:
        logging.error(f"Stats query error: {e}")
        return 0


@app.route("/")
def dashboard():
    with sqlite3.connect(DB_FILE) as conn:

        scans, scan_cols = safe_query(conn, "scans")
        vulns, vuln_cols = safe_query(conn, "vulnerability_reports")
        exploits, exploit_cols = safe_query(conn, "exploits")

        stats = {
            "hosts": get_stat(conn, "SELECT COUNT(DISTINCT ip) FROM scans"),
            "ports": get_stat(conn, "SELECT COUNT(*) FROM scans WHERE port > 0"),
            "vulns": get_stat(conn, "SELECT COUNT(*) FROM vulnerability_reports"),
            "exploits": get_stat(conn, "SELECT COUNT(*) FROM exploits")
        }

    return render_template(
        "dashboard.html",
        scans=scans,
        scan_cols=scan_cols,
        vulns=vulns,
        vuln_cols=vuln_cols,
        exploits=exploits,
        exploit_cols=exploit_cols,
        stats=stats
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
