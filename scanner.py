"""
scanner.py — production-grade nmap port/service/OS scanner with SQLite persistence.

Usage:
  sudo python scanner.py 192.168.1.0/24
  sudo python scanner.py 10.0.0.1 --ports 22,80,443 --timing 4 --verbose
  sudo python scanner.py 10.0.0.1 --top-ports 100 --output report.txt
"""

import argparse
import logging
import sqlite3
import sys
import textwrap
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Optional

try:
    import nmap
except ImportError:
    sys.exit("[!] python-nmap not installed. Run: pip install python-nmap")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("scanner")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_DB       = "scans.db"
DEFAULT_TIMING   = 3          # nmap -T3 (normal)
OS_MIN_ACCURACY  = 85         # % threshold to accept an OS match

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class PortResult:
    ip:        str
    protocol:  str
    port:      int
    state:     str
    service:   str
    product:   str
    version:   str
    extra:     str
    os_name:   str
    scan_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class HostSummary:
    ip:        str
    os_name:   str
    hostname:  str
    state:     str
    ports:     list[PortResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Database
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
                product   TEXT,
                version   TEXT,
                extra     TEXT,
                os_name   TEXT,
                scan_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(ip, protocol, port, scan_time)
            );

            CREATE INDEX IF NOT EXISTS idx_scans_ip        ON scans(ip);
            CREATE INDEX IF NOT EXISTS idx_scans_port      ON scans(port);
            CREATE INDEX IF NOT EXISTS idx_scans_state     ON scans(state);
            CREATE INDEX IF NOT EXISTS idx_scans_scan_time ON scans(scan_time);

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


def save_host(db_path: str, summary: HostSummary) -> int:
    rows = [
        (
            p.ip, p.protocol, p.port, p.state,
            p.service, p.product, p.version, p.extra, p.os_name, p.scan_time,
        )
        for p in summary.ports
    ]
    with get_conn(db_path) as conn:
        cur = conn.executemany(
            """INSERT OR IGNORE INTO scans
               (ip, protocol, port, state, service, product, version, extra, os_name, scan_time)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            rows,
        )
    return cur.rowcount


def save_os_detection(db_path: str, ip: str, match: dict, scan_time: str) -> None:
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
            ),
        )


# ---------------------------------------------------------------------------
# OS detection helpers
# ---------------------------------------------------------------------------

def resolve_os(nm: nmap.PortScanner, host: str) -> tuple[str, Optional[dict]]:
    try:
        matches = nm[host].get("osmatch", [])
        if not matches:
            return "Unknown", None
        best = matches[0]
        accuracy = int(best.get("accuracy", 0))
        if accuracy >= OS_MIN_ACCURACY:
            label = best["name"]
        else:
            label = f"Possible: {best['name']} ({accuracy}%)"
        return label, best
    except Exception:
        return "Unknown", None


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def build_nmap_args(args: argparse.Namespace) -> str:
    parts = [f"-sV", f"-T{args.timing}"]
    if args.os_detect:
        parts.append("-O --osscan-guess")
    if args.ports:
        parts.append(f"-p {args.ports}")
    elif args.top_ports:
        parts.append(f"--top-ports {args.top_ports}")
    if args.udp:
        parts.append("-sU")
    return " ".join(parts)


def scan_target(target: str, args: argparse.Namespace) -> list[HostSummary]:
    nm        = nmap.PortScanner()
    nmap_args = build_nmap_args(args)
    scan_time = datetime.now(timezone.utc).isoformat()

    log.info("Scanning %s with args: %s", target, nmap_args)
    try:
        nm.scan(hosts=target, arguments=nmap_args)
    except nmap.PortScannerError as exc:
        log.error("nmap error: %s", exc)
        sys.exit(1)

    summaries: list[HostSummary] = []

    for host in nm.all_hosts():
        host_data  = nm[host]
        state      = host_data.state()
        hostname   = next(iter(host_data.hostname() or []), "")
        os_name, os_match = resolve_os(nm, host) if args.os_detect else ("N/A", None)

        summary = HostSummary(ip=host, os_name=os_name, hostname=hostname, state=state)

        for proto in host_data.all_protocols():
            for port in sorted(host_data[proto].keys()):
                d = host_data[proto][port]
                summary.ports.append(PortResult(
                    ip       = host,
                    protocol = proto,
                    port     = port,
                    state    = d.get("state",   ""),
                    service  = d.get("name",    ""),
                    product  = d.get("product", ""),
                    version  = d.get("version", ""),
                    extra    = d.get("extrainfo", ""),
                    os_name  = os_name,
                    scan_time= scan_time,
                ))

        saved = save_host(args.db, summary)
        log.info("Saved %d new port record(s) for %s", saved, host)

        if args.os_detect and os_match:
            save_os_detection(args.db, host, os_match, scan_time)

        summaries.append(summary)

    return summaries


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def print_report(summaries: list[HostSummary], output_path: Optional[str]) -> None:
    lines: list[str] = []
    sep   = "=" * 80
    dash  = "-" * 80

    lines.append(sep)
    lines.append(f"{'VULNSCAN — NETWORK SCAN REPORT':^80}")
    lines.append(f"{'Generated: ' + datetime.now().strftime('%Y-%m-%d %H:%M:%S'):^80}")
    lines.append(sep)

    for s in summaries:
        lines.append(f"\n  Host     : {s.ip}  ({s.hostname or '—'})")
        lines.append(f"  State    : {s.state}")
        lines.append(f"  OS       : {s.os_name}")
        lines.append(f"  Ports    : {len(s.ports)}")
        lines.append(f"\n  {'PROTO':<6}{'PORT':<8}{'STATE':<11}{'SERVICE':<16}{'PRODUCT / VERSION'}")
        lines.append(f"  {dash}")

        for p in s.ports:
            product_ver = f"{p.product} {p.version} {p.extra}".strip()
            lines.append(
                f"  {p.protocol.upper():<6}{p.port:<8}{p.state:<11}"
                f"{p.service:<16}{product_ver}"
            )
        lines.append(dash)

    total_ports = sum(len(s.ports) for s in summaries)
    open_ports  = sum(p.state == "open" for s in summaries for p in s.ports)
    lines.append(
        f"\n  SUMMARY  |  Hosts: {len(summaries)}  |  "
        f"Total ports: {total_ports}  |  Open: {open_ports}"
    )
    lines.append(f"{sep}\n")

    output = "\n".join(lines)
    print(output)

    if output_path:
        Path(output_path).write_text(output, encoding="utf-8")
        log.info("Report saved to %s", output_path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Production nmap scanner with SQLite persistence.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
            Examples:
              sudo python scanner.py 192.168.1.0/24
              sudo python scanner.py 10.0.0.1 --ports 22,80,443 --timing 4
              sudo python scanner.py 10.0.0.1 --top-ports 100 --output report.txt
              sudo python scanner.py 10.0.0.1 --no-os --udp
        """),
    )
    p.add_argument("target",              help="IP address, hostname, or CIDR subnet")
    p.add_argument("--db",                default=DEFAULT_DB,  help="SQLite database path")
    p.add_argument("--ports",             default=None,        help="Port list, e.g. 22,80,443 or 1-1024")
    p.add_argument("--top-ports",         type=int, default=None, help="Scan top N ports")
    p.add_argument("--timing",            type=int, default=DEFAULT_TIMING, choices=range(6),
                                          metavar="{0-5}", help="nmap timing template (default: 3)")
    p.add_argument("--no-os",             dest="os_detect", action="store_false",
                                          help="Skip OS detection (faster, no root needed)")
    p.add_argument("--udp",               action="store_true",  help="Include UDP scan (-sU)")
    p.add_argument("--output",            default=None,         help="Save report to text file")
    p.add_argument("--verbose",           action="store_true",  help="Enable DEBUG logging")
    p.set_defaults(os_detect=True)
    return p.parse_args()


def main() -> None:
    args = parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)

    ensure_schema(args.db)
    log.info("Database ready: %s", args.db)

    try:
        summaries = scan_target(args.target, args)
    except KeyboardInterrupt:
        log.warning("Scan interrupted by user.")
        sys.exit(130)

    if not summaries:
        log.warning("No hosts responded. Check target and network connectivity.")
        sys.exit(0)

    print_report(summaries, args.output)
    log.info("Done. %d host(s) scanned.", len(summaries))


if __name__ == "__main__":
    main()
