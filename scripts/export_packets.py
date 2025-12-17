#!/usr/bin/env python3
"""Export packets from per-run packet DB to CSV.

Usage:
  python scripts/export_packets.py             # export most recent 1000 rows from latest per-run DB
  python scripts/export_packets.py --db <path> --limit 500 --out out.csv
"""

import argparse
import glob
import csv
import os
import sys
import pathlib
from datetime import datetime

# Ensure project root is on sys.path so 'ids' package can be imported when running from scripts/
ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ids.database.db_manager import DatabaseManager


def find_latest_packet_db(path_pattern="data/packets/*.db"):
    dbs = sorted(glob.glob(path_pattern))
    return dbs[-1] if dbs else None


def export(db_path, out_path, limit=1000):
    db = DatabaseManager(db_path)
    rows = db.get_recent_packets(limit)
    if not rows:
        print("No packets found in", db_path)
        return 0

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    fields = [
        "id",
        "timestamp",
        "source_ip",
        "source_port",
        "dest_ip",
        "dest_port",
        "protocol",
        "length",
        "payload",
        "payload_hex",
        "raw_packet",
        "created_at",
    ]

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k) for k in fields})

    print(f"Exported {len(rows)} packets from {db_path} to {out_path}")
    return len(rows)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--db", help="Path to packet DB (default: latest per-run DB)", default=None)
    p.add_argument("--limit", type=int, default=1000, help="Max number of packets to export")
    p.add_argument("--out", default=None, help="Output CSV path")
    args = p.parse_args()

    db_path = args.db or find_latest_packet_db()
    if not db_path:
        print("No per-run packet DB found under data/packets/")
        raise SystemExit(1)

    out_path = args.out or f"data/packets_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    export(db_path, out_path, args.limit)
