#!/usr/bin/env python3
"""
log_analysis.py
- Parse a PCAP with pyshark
- Compute simple SYN-flood indicators
- Insert summary into a SQL table (optional, if DB env is set)
- Send an alert over TCP to ALERT_HOST:ALERT_PORT when threshold is met

Usage:
  python scripts/log_analysis.py --pcap pcap_samples/showcase-sanitized.pcapng
  # optional tuning:
  python scripts/log_analysis.py --pcap mycap.pcapng --syn-threshold 100 --unique-src-threshold 25
"""

import os
import argparse
import socket
import datetime
from collections import Counter
from typing import Dict, Any

from dotenv import load_dotenv

# Load environment variables from .env (not committed) or from your shell
load_dotenv()

# --- Config from environment (safe: no secrets in code) ---
DB_DRIVER = os.getenv("DB_DRIVER")  # e.g., "ODBC Driver 17 for SQL Server"
DB_SERVER = os.getenv("DB_SERVER")  # host or host\instance
DB_PORT = os.getenv("DB_PORT", "1433")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")

ALERT_HOST = os.getenv("ALERT_HOST", "127.0.0.1")
ALERT_PORT = int(os.getenv("ALERT_PORT", "65111"))

# Optional deps: handle gracefully if not installed
try:
    import pyodbc
except Exception:
    pyodbc = None

try:
    import pyshark
except Exception as e:
    raise SystemExit(
        "pyshark is required and TShark (from Wireshark) must be installed.\n"
        f"Import error: {e}"
    )

def analyze_pcap(pcap_path: str) -> Dict[str, Any]:
    """
    Parse the PCAP and return:
      - total_packets (int)
      - syn_count (int)
      - syn_by_src (Counter)
      - first_ts, last_ts (datetime or None)
    """
    total_packets = 0
    syn_count = 0
    syn_by_src: Counter[str] = Counter()
    first_ts = None
    last_ts = None

    # keep_packets=False prevents memory blowups on large captures
    cap = pyshark.FileCapture(pcap_path, keep_packets=False)
    try:
        for pkt in cap:
            total_packets += 1

            # timestamps (best effort)
            try:
                ts = float(pkt.frame_info.time_epoch)
                tstamp = datetime.datetime.utcfromtimestamp(ts)
                if not first_ts:
                    first_ts = tstamp
                last_ts = tstamp
            except Exception:
                pass

            # TCP SYN-only detection
            try:
                if hasattr(pkt, "tcp"):
                    flags_raw = pkt.tcp.flags
                    flags = int(flags_raw, 16) if isinstance(flags_raw, str) else int(flags_raw)
                    syn = (flags & 0x02) != 0  # SYN bit
                    ack = (flags & 0x10) != 0  # ACK bit
                    if syn and not ack:
                        syn_count += 1
                        src = pkt.ip.src if hasattr(pkt, "ip") else "unknown"
                        syn_by_src[src] += 1
            except Exception:
                # skip malformed packets gracefully
                continue
    finally:
        cap.close()

    return {
        "total_packets": total_packets,
        "syn_count": syn_count,
        "syn_by_src": syn_by_src,
        "first_ts": first_ts,
        "last_ts": last_ts,
    }

def estimate_rate(count: int, start: datetime.datetime, end: datetime.datetime) -> float:
    """Return events per minute between start and end (safe for None/zero)."""
    if not start or not end:
        return 0.0
    seconds = max(1.0, (end - start).total_seconds())
    return (count / seconds) * 60.0

def write_to_db(summary: Dict[str, Any]) -> None:
    """
    Insert a row into a 'traffic_analysis' table.
    If DB env not present or pyodbc missing, we just print (safe fallback).
    Expected columns (you can adjust to your schema):
      captured_at (datetime), src_ip (varchar), dest_ip (varchar),
      syn_count (int), total_packets (int), sus_act (bit/int), traffic_type (varchar)
    """
    if not (pyodbc and DB_DRIVER and DB_SERVER and DB_NAME and DB_USER is not None):
        print("[DB] Skipping DB write (driver or connection settings missing).")
        return

    # Basic SQL Server connection string (adjust for your driver/OS)
    conn_str = (
        f"DRIVER={{{DB_DRIVER}}};"
        f"SERVER={DB_SERVER},{DB_PORT};"
        f"DATABASE={DB_NAME};"
        f"UID={DB_USER};"
        f"PWD={DB_PASS};"
        "TrustServerCertificate=Yes;"
    )

    try:
        with pyodbc.connect(conn_str, timeout=5) as conn:
            cursor = conn.cursor()

            # Insert the top source as representative; you can also batch insert per source if you want
            top_src, top_syns = ("none", 0)
            if summary["syn_by_src"]:
                top_src, top_syns = summary["syn_by_src"].most_common(1)[0]

            insert_sql = """
                INSERT INTO traffic_analysis
                    (captured_at, src_ip, dest_ip, syn_count, total_packets, sus_act, traffic_type)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """
            cursor.execute(
                insert_sql,
                datetime.datetime.utcnow(),
                top_src,
                None,  # dest_ip not tracked in this simple rollup
                int(top_syns),
                int(summary["total_packets"]),
                int(summary["sus_act"]),
                summary["traffic_type"],
            )
            conn.commit()
            print("[DB] Inserted row into traffic_analysis.")
    except Exception as e:
        print("[DB] Error writing to DB:", e)

def send_alert_tcp(summary: Dict[str, Any]) -> None:
    """Send a simple TCP alert to the PowerShell listener on the VM."""
    message = (
        "ALERT"
        f"|time={datetime.datetime.utcnow().isoformat()}"
        f"|syn_total={summary['syn_count']}"
        f"|unique_srcs={len(summary['syn_by_src'])}"
        f"|top_src={summary.get('top_src','none')}"
    )
    try:
        with socket.create_connection((ALERT_HOST, ALERT_PORT), timeout=5) as s:
            s.sendall(message.encode("utf-8"))
        print(f"[ALERT] Sent alert to {ALERT_HOST}:{ALERT_PORT}")
    except Exception as e:
        print("[ALERT] Could not send alert:", e)

def main():
    parser = argparse.ArgumentParser(description="Analyze PCAP for SYN-flood indicators")
    parser.add_argument("--pcap", required=True, help="Path to .pcap or .pcapng file")
    parser.add_argument("--syn-threshold", type=int, default=100,
                        help="Total SYN packets threshold to flag suspicious (default: 100)")
    parser.add_argument("--unique-src-threshold", type=int, default=25,
                        help="Unique SYN source threshold to flag suspicious (default: 25)")
    args = parser.parse_args()

    stats = analyze_pcap(args.pcap)

    # Derived metrics
    syn_rate_per_min = estimate_rate(stats["syn_count"], stats["first_ts"], stats["last_ts"])
    top_src, top_syns = ("none", 0)
    if stats["syn_by_src"]:
        top_src, top_syns = stats["syn_by_src"].most_common(1)[0]

    # Heuristic decision
    sus = 0
    ttype = "normal"
    if (
        stats["syn_count"] >= args.syn_threshold
        or len(stats["syn_by_src"]) >= args.unique_src_threshold
        or top_syns >= max(1, args.syn_threshold // 2)
        or syn_rate_per_min >= args.syn_threshold  # treat threshold as rough per-minute target if timing known
    ):
        sus = 1
        ttype = "syn_flood"

    summary = {
        "total_packets": stats["total_packets"],
        "syn_count": stats["syn_count"],
        "syn_by_src": stats["syn_by_src"],
        "top_src": top_src,
        "sus_act": sus,
        "traffic_type": ttype,
        "syn_rate_per_min": round(syn_rate_per_min, 2),
    }

    print("=== Analysis Summary ===")
    print(f"PCAP: {args.pcap}")
    print(f"Total packets: {summary['total_packets']}")
    print(f"SYN packets:  {summary['syn_count']}")
    print(f"Unique SYN srcs: {len(summary['syn_by_src'])}")
    print(f"Top src: {summary['top_src']} (SYNs: {stats['syn_by_src'].get(top_src,0)})")
    print(f"SYN rate (approx, per min): {summary['syn_rate_per_min']}")
    print(f"Suspicious: {bool(summary['sus_act'])}  type: {summary['traffic_type']}")

    # Optional: write to DB if configured
    write_to_db(summary)

    # Optional: send alert if suspicious
    if summary["sus_act"]:
        send_alert_tcp(summary)

if __name__ == "__main__":
    main()
