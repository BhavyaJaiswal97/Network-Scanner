from flask import Flask, render_template_string, request, jsonify
import sqlite3
import os

app = Flask(__name__)
DB_PATH = os.environ.get("DB_PATH", "scans.db")

# ── helpers ────────────────────────────────────────────────────────────────

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

def get_db():
    """Return a row-factory connection, or None on error."""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5.0)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error:
        return None


def query(sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    conn = get_db()
    if conn is None:
        return []
    try:
        with conn:
            return conn.execute(sql, params).fetchall()
    except sqlite3.Error:
        return []


def get_stats() -> dict:
    """Aggregate counts used by the summary cards."""
    conn = get_db()
    if conn is None:
        return {}
    try:
        with conn:
            total_scans  = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            total_hosts  = conn.execute("SELECT COUNT(DISTINCT ip) FROM scans").fetchone()[0]
            total_vulns  = conn.execute("SELECT COUNT(*) FROM vulnerability_reports").fetchone()[0]
            open_ports   = conn.execute("SELECT COUNT(*) FROM scans WHERE state='open'").fetchone()[0]

            sev_rows = conn.execute(
                "SELECT LOWER(severity) as sev, COUNT(*) as cnt "
                "FROM vulnerability_reports GROUP BY sev"
            ).fetchall()
            sev = {r["sev"]: r["cnt"] for r in sev_rows}

            return {
                "total_scans": total_scans,
                "total_hosts": total_hosts,
                "total_vulns": total_vulns,
                "open_ports":  open_ports,
                "critical": sev.get("critical", 0),
                "high":     sev.get("high", 0),
                "medium":   sev.get("medium", 0),
                "low":      sev.get("low", 0),
            }
    except sqlite3.Error:
        return {}


# ── template ───────────────────────────────────────────────────────────────

HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetWatch — Security Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
:root {
  --bg:       #07090f;
  --s1:       #0c1018;
  --s2:       #111520;
  --s3:       #181e2e;
  --border:   #1f2d45;
  --border2:  #263548;
  --text:     #c9d6e8;
  --dim:      #4a6080;
  --accent:   #3b82f6;
  --teal:     #06b6d4;
  --green:    #22c55e;
  --yellow:   #eab308;
  --orange:   #f97316;
  --red:      #ef4444;
  --crimson:  #dc2626;
  --mono: 'DM Mono', monospace;
  --sans: 'Syne', sans-serif;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--sans);
  min-height: 100vh;
  overflow-x: hidden;
}

/* scanline overlay */
body::after {
  content: '';
  position: fixed; inset: 0;
  background: repeating-linear-gradient(
    0deg, transparent, transparent 2px,
    rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px
  );
  pointer-events: none; z-index: 9999;
}

/* ── layout ── */
.shell { display: flex; min-height: 100vh; }

nav {
  width: 220px; flex-shrink: 0;
  background: var(--s1);
  border-right: 1px solid var(--border);
  display: flex; flex-direction: column;
  padding: 1.5rem 0;
  position: sticky; top: 0; height: 100vh;
}

.nav-brand {
  padding: 0 1.25rem 1.5rem;
  border-bottom: 1px solid var(--border);
  margin-bottom: 1rem;
}
.nav-brand .logo {
  font-family: var(--sans);
  font-size: 1.3rem; font-weight: 800;
  color: #fff; letter-spacing: -0.02em;
}
.nav-brand .logo span { color: var(--accent); }
.nav-brand .sub {
  font-family: var(--mono);
  font-size: 0.62rem; color: var(--dim);
  letter-spacing: 0.15em; text-transform: uppercase;
  margin-top: 2px;
}

.nav-item {
  display: flex; align-items: center; gap: 0.6rem;
  padding: 0.55rem 1.25rem;
  font-size: 0.82rem; color: var(--dim);
  cursor: pointer; border-left: 2px solid transparent;
  transition: all .15s; text-decoration: none;
  font-weight: 600; letter-spacing: 0.02em;
}
.nav-item:hover  { color: var(--text); background: var(--s2); }
.nav-item.active { color: var(--accent); border-left-color: var(--accent); background: rgba(59,130,246,0.07); }
.nav-icon { font-size: 0.9rem; width: 18px; text-align: center; }

.nav-section {
  padding: 1.25rem 1.25rem 0.35rem;
  font-family: var(--mono);
  font-size: 0.6rem; color: var(--dim);
  letter-spacing: 0.18em; text-transform: uppercase;
}

.nav-bottom {
  margin-top: auto;
  padding: 1rem 1.25rem 0;
  border-top: 1px solid var(--border);
}
.live-indicator {
  display: flex; align-items: center; gap: 0.5rem;
  font-family: var(--mono); font-size: 0.65rem; color: var(--green);
}
.live-dot {
  width: 6px; height: 6px; border-radius: 50%;
  background: var(--green);
  animation: pulse-green 2s infinite;
}
@keyframes pulse-green {
  0%,100% { box-shadow: 0 0 0 0 rgba(34,197,94,.5); }
  50%      { box-shadow: 0 0 0 5px rgba(34,197,94,0); }
}

main {
  flex: 1; padding: 2rem 2.5rem;
  overflow-y: auto;
}

/* ── page header ── */
.page-header {
  display: flex; align-items: center; justify-content: space-between;
  margin-bottom: 2rem;
}
.page-title { font-size: 1.5rem; font-weight: 800; color: #fff; letter-spacing: -0.02em; }
.page-meta  { font-family: var(--mono); font-size: 0.7rem; color: var(--dim); }
.page-meta span { color: var(--teal); }

/* ── stat cards ── */
.cards { display: grid; grid-template-columns: repeat(4,1fr); gap: 1rem; margin-bottom: 2rem; }

.card {
  background: var(--s1);
  border: 1px solid var(--border);
  border-radius: 8px; padding: 1.25rem;
  position: relative; overflow: hidden;
  transition: border-color .2s;
}
.card:hover { border-color: var(--border2); }
.card::before {
  content: '';
  position: absolute; top: 0; left: 0; right: 0; height: 2px;
}
.card.blue::before   { background: var(--accent); }
.card.teal::before   { background: var(--teal); }
.card.green::before  { background: var(--green); }
.card.red::before    { background: var(--red); }

.card-label { font-family: var(--mono); font-size: 0.62rem; color: var(--dim); letter-spacing: 0.15em; text-transform: uppercase; margin-bottom: 0.6rem; }
.card-value { font-size: 2rem; font-weight: 800; color: #fff; letter-spacing: -0.03em; line-height: 1; }
.card-value.blue   { color: var(--accent); }
.card-value.teal   { color: var(--teal); }
.card-value.green  { color: var(--green); }
.card-value.red    { color: var(--red); }
.card-sub { font-family: var(--mono); font-size: 0.68rem; color: var(--dim); margin-top: 0.4rem; }

/* severity mini-bar in cards */
.sev-bar { display: flex; gap: 4px; margin-top: 0.75rem; }
.sev-seg {
  height: 4px; border-radius: 2px; flex: 1;
  transition: opacity .2s;
}
.sev-seg.critical { background: var(--crimson); }
.sev-seg.high     { background: var(--red); }
.sev-seg.medium   { background: var(--yellow); }
.sev-seg.low      { background: var(--green); }

/* ── section panels ── */
.section { margin-bottom: 2.5rem; }

.section-head {
  display: flex; align-items: center; justify-content: space-between;
  margin-bottom: 1rem;
}
.section-title {
  font-size: 0.85rem; font-weight: 700;
  color: #fff; letter-spacing: 0.04em; text-transform: uppercase;
  display: flex; align-items: center; gap: 0.6rem;
}
.section-title::before {
  content: '//';
  font-family: var(--mono); color: var(--accent); font-size: 0.8rem;
}
.section-count {
  font-family: var(--mono); font-size: 0.7rem; color: var(--dim);
  background: var(--s2); border: 1px solid var(--border);
  padding: 0.2rem 0.6rem; border-radius: 20px;
}

/* search + filter row */
.toolbar {
  display: flex; gap: 0.6rem; flex-wrap: wrap;
  margin-bottom: 0.85rem;
}
.search-box {
  background: var(--s2);
  border: 1px solid var(--border);
  border-radius: 6px; color: var(--text);
  font-family: var(--mono); font-size: 0.8rem;
  padding: 0.45rem 0.85rem;
  outline: none; transition: border-color .2s;
  flex: 1; min-width: 160px;
}
.search-box::placeholder { color: var(--dim); }
.search-box:focus { border-color: var(--accent); }

.filter-btn {
  background: var(--s2);
  border: 1px solid var(--border);
  border-radius: 6px; color: var(--dim);
  font-family: var(--mono); font-size: 0.72rem;
  padding: 0.45rem 0.85rem; cursor: pointer;
  transition: all .15s; letter-spacing: 0.05em;
  white-space: nowrap;
}
.filter-btn:hover      { color: var(--text); border-color: var(--border2); }
.filter-btn.active     { color: var(--accent); border-color: var(--accent); background: rgba(59,130,246,0.08); }
.filter-btn.critical   { color: var(--crimson); border-color: rgba(220,38,38,.4); }
.filter-btn.critical.active { background: rgba(220,38,38,.1); }
.filter-btn.high       { color: var(--red); }
.filter-btn.medium     { color: var(--yellow); }
.filter-btn.low        { color: var(--green); }

/* ── table ── */
.table-wrap {
  background: var(--s1);
  border: 1px solid var(--border);
  border-radius: 8px; overflow: hidden;
}

table { width: 100%; border-collapse: collapse; }
thead tr { background: var(--s2); }
th {
  font-family: var(--mono); font-size: 0.63rem; color: var(--dim);
  letter-spacing: 0.12em; text-transform: uppercase;
  padding: 0.7rem 1rem; text-align: left;
  border-bottom: 1px solid var(--border); font-weight: 400;
  white-space: nowrap;
}
td {
  padding: 0.75rem 1rem; font-size: 0.83rem;
  border-bottom: 1px solid rgba(31,45,69,0.6);
  vertical-align: middle;
}
tr:last-child td { border-bottom: none; }
tbody tr { transition: background .12s; }
tbody tr:hover td { background: rgba(59,130,246,0.04); }

.cell-mono { font-family: var(--mono); font-size: 0.78rem; }
.cell-ip   { font-family: var(--mono); color: var(--teal); font-size: 0.82rem; }
.cell-dim  { color: var(--dim); font-size: 0.8rem; }
.cell-port {
  font-family: var(--mono); font-size: 0.75rem;
  background: var(--s3); border: 1px solid var(--border);
  border-radius: 4px; padding: 0.15rem 0.45rem;
  color: var(--text); display: inline-block;
}

/* severity badges */
.badge {
  display: inline-flex; align-items: center; gap: 4px;
  font-family: var(--mono); font-size: 0.68rem; font-weight: 500;
  padding: 0.2rem 0.55rem; border-radius: 4px;
  text-transform: uppercase; letter-spacing: 0.06em;
  white-space: nowrap;
}
.badge::before { content: '●'; font-size: 0.5rem; }
.badge-critical { background:rgba(220,38,38,.15); color:var(--crimson); border:1px solid rgba(220,38,38,.3); }
.badge-high     { background:rgba(239,68,68,.12); color:var(--red);    border:1px solid rgba(239,68,68,.25);}
.badge-medium   { background:rgba(234,179,8,.1);  color:var(--yellow); border:1px solid rgba(234,179,8,.25);}
.badge-low      { background:rgba(34,197,94,.1);  color:var(--green);  border:1px solid rgba(34,197,94,.2); }
.badge-info     { background:rgba(59,130,246,.1); color:var(--accent); border:1px solid rgba(59,130,246,.2);}
.badge-open     { background:rgba(34,197,94,.1);  color:var(--green);  border:1px solid rgba(34,197,94,.2); }
.badge-closed   { background:rgba(239,68,68,.08); color:var(--dim);    border:1px solid rgba(239,68,68,.15);}
.badge-filtered { background:rgba(234,179,8,.08); color:var(--yellow); border:1px solid rgba(234,179,8,.2); }

/* CVSS score pill */
.cvss {
  font-family: var(--mono); font-size: 0.78rem; font-weight: 500;
  padding: 0.18rem 0.5rem; border-radius: 4px; display: inline-block;
}
.cvss-critical { background: rgba(220,38,38,.2);  color: var(--crimson); }
.cvss-high     { background: rgba(239,68,68,.15); color: var(--red); }
.cvss-medium   { background: rgba(234,179,8,.12); color: var(--yellow); }
.cvss-low      { background: rgba(34,197,94,.1);  color: var(--green); }

/* cve tag */
.cve-tag {
  font-family: var(--mono); font-size: 0.72rem;
  color: var(--orange); background: rgba(249,115,22,.08);
  border: 1px solid rgba(249,115,22,.25);
  padding: 0.15rem 0.45rem; border-radius: 4px;
  display: inline-block;
}

/* empty state */
.empty {
  text-align: center; padding: 3rem 1rem;
  font-family: var(--mono); font-size: 0.8rem; color: var(--dim);
}

/* pagination */
.pagination {
  display: flex; align-items: center; justify-content: flex-end;
  gap: 0.4rem; padding: 0.75rem 1rem;
  border-top: 1px solid var(--border);
  background: var(--s2);
}
.page-btn {
  background: var(--s1); border: 1px solid var(--border);
  border-radius: 5px; color: var(--dim);
  font-family: var(--mono); font-size: 0.72rem;
  padding: 0.3rem 0.7rem; cursor: pointer;
  transition: all .15s;
}
.page-btn:hover   { color: var(--text); border-color: var(--border2); }
.page-btn.current { color: var(--accent); border-color: var(--accent); background: rgba(59,130,246,.08); }
.page-info { font-family: var(--mono); font-size: 0.68rem; color: var(--dim); margin-right: auto; }

/* error banner */
.db-error {
  background: rgba(239,68,68,.08); border: 1px solid rgba(239,68,68,.3);
  border-radius: 8px; padding: 1rem 1.25rem;
  color: var(--red); font-family: var(--mono); font-size: 0.82rem;
  margin-bottom: 1.5rem;
}

/* responsive */
@media (max-width: 900px) {
  nav { display: none; }
  .cards { grid-template-columns: repeat(2,1fr); }
}
@media (max-width: 560px) {
  .cards { grid-template-columns: 1fr 1fr; }
  main { padding: 1.25rem; }
}
</style>
</head>
<body>
<div class="shell">

<!-- ── sidebar ── -->
<nav>
  <div class="nav-brand">
    <div class="logo">Net<span>Watch</span></div>
    <div class="sub">Security Dashboard</div>
  </div>
  <div class="nav-section">Overview</div>
  <a class="nav-item active" href="#scans">
    <span class="nav-icon">◈</span> Scan Results
  </a>
  <a class="nav-item" href="#vulns">
    <span class="nav-icon">⚠</span> Vulnerabilities
  </a>
  <div class="nav-bottom">
    <div class="live-indicator">
      <span class="live-dot"></span> DB connected
    </div>
  </div>
</nav>

<!-- ── main ── -->
<main>
  <div class="page-header">
    <div class="page-title">Security Dashboard</div>
    <div class="page-meta">Last updated: <span>{{ now }}</span></div>
  </div>

  {% if db_error %}
  <div class="db-error">⚠ Database error: {{ db_error }}</div>
  {% endif %}

  <!-- ── stat cards ── -->
  <div class="cards">
    <div class="card blue">
      <div class="card-label">Total Scans</div>
      <div class="card-value blue">{{ stats.get('total_scans', '—') }}</div>
      <div class="card-sub">records in scans table</div>
    </div>
    <div class="card teal">
      <div class="card-label">Unique Hosts</div>
      <div class="card-value teal">{{ stats.get('total_hosts', '—') }}</div>
      <div class="card-sub">distinct IP addresses</div>
    </div>
    <div class="card green">
      <div class="card-label">Open Ports</div>
      <div class="card-value green">{{ stats.get('open_ports', '—') }}</div>
      <div class="card-sub">state = open</div>
    </div>
    <div class="card red">
      <div class="card-label">Vulnerabilities</div>
      <div class="card-value red">{{ stats.get('total_vulns', '—') }}</div>
      <div class="card-sub">
        {{ stats.get('critical', 0) }}C · {{ stats.get('high', 0) }}H · {{ stats.get('medium', 0) }}M
      </div>
      <div class="sev-bar">
        <div class="sev-seg critical"></div>
        <div class="sev-seg high"></div>
        <div class="sev-seg medium"></div>
        <div class="sev-seg low"></div>
      </div>
    </div>
  </div>

  <!-- ── Scan Results ── -->
  <div class="section" id="scans">
    <div class="section-head">
      <div class="section-title">Scan Results</div>
      <div class="section-count" id="scan-count">{{ scans|length }} rows</div>
    </div>
    <div class="toolbar">
      <input class="search-box" id="scan-search" placeholder="Search IP, service, port…" oninput="filterTable('scan-tbody','scan-search','scan-count')">
      <button class="filter-btn active" onclick="filterState(this,'scan-tbody','scan-count','')">All</button>
      <button class="filter-btn" onclick="filterState(this,'scan-tbody','scan-count','open')">Open</button>
      <button class="filter-btn" onclick="filterState(this,'scan-tbody','scan-count','closed')">Closed</button>
      <button class="filter-btn" onclick="filterState(this,'scan-tbody','scan-count','filtered')">Filtered</button>
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>ID</th><th>IP</th><th>Protocol</th><th>Port</th>
            <th>State</th><th>Service</th><th>Product</th><th>Version</th><th>OS</th>
          </tr>
        </thead>
        <tbody id="scan-tbody">
          {% for row in scans %}
          <tr data-state="{{ (row[4] or '')|lower }}">
            <td class="cell-mono cell-dim">{{ row[0] }}</td>
            <td class="cell-ip">{{ row[1] or '—' }}</td>
            <td class="cell-mono cell-dim">{{ row[2] or '—' }}</td>
            <td>
              {% if row[3] %}
              <span class="cell-port">{{ row[3] }}</span>
              {% else %}—{% endif %}
            </td>
            <td>
              {% set st = (row[4] or '')|lower %}
              {% if st == 'open' %}
                <span class="badge badge-open">open</span>
              {% elif st == 'closed' %}
                <span class="badge badge-closed">closed</span>
              {% elif st == 'filtered' %}
                <span class="badge badge-filtered">filtered</span>
              {% else %}
                <span class="cell-dim">{{ row[4] or '—' }}</span>
              {% endif %}
            </td>
            <td>{{ row[5] or '—' }}</td>
            <td class="cell-dim">{{ row[6] or '—' }}</td>
            <td class="cell-mono cell-dim" style="font-size:.73rem;">{{ row[7] or '—' }}</td>
            <td class="cell-dim">{{ row[8] or '—' }}</td>
          </tr>
          {% else %}
          <tr><td colspan="9" class="empty">// no scan records found</td></tr>
          {% endfor %}
        </tbody>
      </table>
      {% if scans|length > PAGE_SIZE %}
      <div class="pagination" id="scan-pagination"></div>
      {% endif %}
    </div>
  </div>

  <!-- ── Vulnerability Reports ── -->
  <div class="section" id="vulns">
    <div class="section-head">
      <div class="section-title">Vulnerability Reports</div>
      <div class="section-count" id="vuln-count">{{ vulns|length }} rows</div>
    </div>
    <div class="toolbar">
      <input class="search-box" id="vuln-search" placeholder="Search host, CVE, service…" oninput="filterTable('vuln-tbody','vuln-search','vuln-count')">
      <button class="filter-btn active" onclick="filterSeverity(this,'vuln-tbody','vuln-count','')">All</button>
      <button class="filter-btn critical" onclick="filterSeverity(this,'vuln-tbody','vuln-count','critical')">Critical</button>
      <button class="filter-btn high"     onclick="filterSeverity(this,'vuln-tbody','vuln-count','high')">High</button>
      <button class="filter-btn medium"   onclick="filterSeverity(this,'vuln-tbody','vuln-count','medium')">Medium</button>
      <button class="filter-btn low"      onclick="filterSeverity(this,'vuln-tbody','vuln-count','low')">Low</button>
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>ID</th><th>Host</th><th>Port</th><th>Service</th>
            <th>Product</th><th>Version</th><th>CVE</th><th>CVSS</th><th>Severity</th>
          </tr>
        </thead>
        <tbody id="vuln-tbody">
          {% for row in vulns %}
          {% set sev = (row[8] or 'info')|lower %}
          <tr data-severity="{{ sev }}">
            <td class="cell-mono cell-dim">{{ row[0] }}</td>
            <td class="cell-ip">{{ row[1] or '—' }}</td>
            <td>
              {% if row[2] %}
              <span class="cell-port">{{ row[2] }}</span>
              {% else %}—{% endif %}
            </td>
            <td>{{ row[3] or '—' }}</td>
            <td class="cell-dim">{{ row[4] or '—' }}</td>
            <td class="cell-mono cell-dim" style="font-size:.73rem;">{{ row[5] or '—' }}</td>
            <td>
              {% if row[6] %}
              <span class="cve-tag">{{ row[6] }}</span>
              {% else %}<span class="cell-dim">—</span>{% endif %}
            </td>
            <td>
              {% if row[7] %}
                {% set score = row[7]|float %}
                {% if score >= 9.0 %}
                  <span class="cvss cvss-critical">{{ row[7] }}</span>
                {% elif score >= 7.0 %}
                  <span class="cvss cvss-high">{{ row[7] }}</span>
                {% elif score >= 4.0 %}
                  <span class="cvss cvss-medium">{{ row[7] }}</span>
                {% else %}
                  <span class="cvss cvss-low">{{ row[7] }}</span>
                {% endif %}
              {% else %}<span class="cell-dim">—</span>{% endif %}
            </td>
            <td>
              <span class="badge badge-{{ sev }}">{{ sev }}</span>
            </td>
          </tr>
          {% else %}
          <tr><td colspan="9" class="empty">// no vulnerability records found</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>

</main>
</div>

<script>
// ── search filter ──────────────────────────────────────────────────
function filterTable(tbodyId, searchId, countId) {
  const q = document.getElementById(searchId).value.toLowerCase();
  const rows = document.querySelectorAll('#' + tbodyId + ' tr[data-state], #' + tbodyId + ' tr[data-severity]');
  let visible = 0;
  rows.forEach(function(tr) {
    const match = tr.textContent.toLowerCase().includes(q);
    tr.style.display = match ? '' : 'none';
    if (match) visible++;
  });
  document.getElementById(countId).textContent = visible + ' rows';
}

// ── state filter (scan table) ──────────────────────────────────────
function filterState(btn, tbodyId, countId, state) {
  document.querySelectorAll('.toolbar .filter-btn').forEach(function(b) { b.classList.remove('active'); });
  btn.classList.add('active');
  const rows = document.querySelectorAll('#' + tbodyId + ' tr[data-state]');
  let visible = 0;
  rows.forEach(function(tr) {
    const match = !state || tr.dataset.state === state;
    tr.style.display = match ? '' : 'none';
    if (match) visible++;
  });
  document.getElementById(countId).textContent = visible + ' rows';
}

// ── severity filter (vuln table) ──────────────────────────────────
function filterSeverity(btn, tbodyId, countId, sev) {
  // only deactivate sibling buttons in the same toolbar
  btn.closest('.toolbar').querySelectorAll('.filter-btn').forEach(function(b) { b.classList.remove('active'); });
  btn.classList.add('active');
  const rows = document.querySelectorAll('#' + tbodyId + ' tr[data-severity]');
  let visible = 0;
  rows.forEach(function(tr) {
    const match = !sev || tr.dataset.severity === sev;
    tr.style.display = match ? '' : 'none';
    if (match) visible++;
  });
  document.getElementById(countId).textContent = visible + ' rows';
}

// ── sidebar active link on scroll ────────────────────────────────
document.querySelectorAll('nav .nav-item[href^="#"]').forEach(function(link) {
  link.addEventListener('click', function() {
    document.querySelectorAll('nav .nav-item').forEach(function(l) { l.classList.remove('active'); });
    link.classList.add('active');
  });
});
</script>
</body>
</html>
"""

PAGE_SIZE = 500   # safety cap — render at most this many rows

# ── route ──────────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    from datetime import datetime

    db_error = None
    stats = {}
    scans = []
    vulns = []

    conn = get_db()
    if conn is None:
        db_error = f"Cannot open database at '{DB_PATH}'"
    else:
        try:
            with conn:
                # scans — newest first, capped
                scans = conn.execute(
                    "SELECT id, ip, protocol, port, state, service, product, version, os "
                    "FROM scans ORDER BY id DESC LIMIT ?",
                    (PAGE_SIZE,)
                ).fetchall()

                # vulns — critical/high first, then by id
                vulns = conn.execute(
                    """
                    SELECT id, host, port, service, product, version, cve, cvss, severity
                    FROM vulnerability_reports
                    ORDER BY
                        CASE LOWER(severity)
                            WHEN 'critical' THEN 0
                            WHEN 'high'     THEN 1
                            WHEN 'medium'   THEN 2
                            WHEN 'low'      THEN 3
                            ELSE 4
                        END,
                        id DESC
                    LIMIT ?
                    """,
                    (PAGE_SIZE,)
                ).fetchall()

                stats = get_stats()
        except sqlite3.Error as e:
            db_error = str(e)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return render_template_string(
        HTML,
        scans=scans,
        vulns=vulns,
        stats=stats,
        db_error=db_error,
        now=now,
        PAGE_SIZE=PAGE_SIZE,
    )


# ── JSON API (optional, handy for external tools) ──────────────────────────

@app.route("/api/scans")
def api_scans():
    rows = query("SELECT id, ip, protocol, port, state, service, product, version, os FROM scans ORDER BY id DESC LIMIT 1000")
    return jsonify([dict(r) for r in rows])


@app.route("/api/vulns")
def api_vulns():
    rows = query("SELECT id, host, port, service, product, version, cve, cvss, severity FROM vulnerability_reports ORDER BY id DESC LIMIT 1000")
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
