"""Inject a malicious-looking packet into the engine to verify signature detection.

This script is safe: it only crafts a synthetic packet payload (plain text HTTP request)
and feeds it to the local DetectorEngine instance for testing. It stores any generated
alerts in a temporary on-disk DB and prints results.

Usage:
    python scripts/inject_malicious.py
"""

import tempfile
from pathlib import Path
from datetime import datetime
import time

from ids.core.detector_engine import DetectorEngine
from ids.database.db_manager import DatabaseManager


def load_sample(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def main():
    sample_fn = Path(__file__).parent / "malicious_sample.txt"
    if not sample_fn.exists():
        print("malicious_sample.txt not found in scripts/; create it first")
        return

    payload = load_sample(str(sample_fn))

    # Prepare a temp DB file so schema is created and shared properly across connections
    tf = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    tf.close()
    db_path = tf.name
    print("Using temporary DB:", db_path)

    db = DatabaseManager(db_path)

    # Disable per-run DB and packet logging for a quiet, deterministic run
    config = {"storage": {"per_run_packet_db": False}, "logging": {"log_packets": False}}

    engine = DetectorEngine(config=config, use_signature=True, use_anomaly=False)
    engine.db_manager = db
    engine.packet_db_manager = db

    features = {
        "timestamp": datetime.utcnow(),
        "source_ip": "10.0.0.5",
        "dest_ip": "192.168.0.50",
        "source_port": 54321,
        "dest_port": 80,
        "protocol": "tcp",
        "payload": payload,
        "payload_hex": payload.encode("utf-8").hex(),
        "length": len(payload),
    }

    print("Injecting synthetic packet into engine processing pipeline...")
    engine._process_packet(features)

    # Try to retrieve an alert from the queue
    try:
        alert = engine.alert_queue.get(timeout=2.0)
    except Exception:
        alert = None

    if not alert:
        print("No alert detected for sample payload.")
        # Show current signatures loaded to help debugging
        try:
            print("Loaded signature rules:", engine.signature_detector.stats.get("rules_loaded"))
        except Exception:
            pass
        return

    print("Alert detected:")
    try:
        print(alert.to_dict())
    except Exception:
        print(str(alert))

    # Store alert and confirm it was persisted
    try:
        engine._handle_alert(alert)
        recent = engine.db_manager.get_recent_alerts(limit=5)
        print("Recent stored alerts:")
        for a in recent:
            print(a.to_dict() if hasattr(a, "to_dict") else a.__dict__)
    except Exception as e:
        print("Error storing/fetching alert:", e)

    # Clean up
    try:
        engine.db_manager.close()
    except Exception:
        pass

    print("Temporary DB left at:", db_path)


if __name__ == "__main__":
    main()
