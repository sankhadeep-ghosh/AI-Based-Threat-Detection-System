"""
Database manager module - handles SQLite database operations
for alert storage and retrieval with connection pooling.
"""

import sqlite3
import base64
from pathlib import Path
from typing import List, Optional, Dict, Any
from contextlib import contextmanager
from threading import Lock

from ids.utils.logger import setup_logger
from ids.models.alert import Alert
from ids.config.config_loader import get_config

logger = setup_logger(__name__)


class DatabaseManager:
    """
    Thread-safe SQLite database manager for alert storage.

    Features:
    - Automatic connection management
    - Alert persistence and retrieval
    - Statistics aggregation
    - Connection pooling for concurrent access
    """

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize database manager.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path or get_config("database.path", "data/ids.db")
        self._connection_lock = Lock()

        # Create a persistent write connection to reduce per-insert overhead
        try:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            self._write_lock = Lock()
            self._write_conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=10.0)
            # Use WAL for better concurrency
            self._write_conn.execute("PRAGMA journal_mode=WAL")
            self._write_conn.execute("PRAGMA busy_timeout=5000")
        except Exception:
            # If opening a persistent connection fails, fall back to the connection context
            self._write_conn = None
            self._write_lock = Lock()

        # Initialize DB schema
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema."""
        try:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

            with self.get_connection() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        rule_id TEXT NOT NULL,
                        name TEXT NOT NULL,
                        alert_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        source_ip TEXT NOT NULL,
                        dest_ip TEXT NOT NULL,
                        source_port INTEGER,
                        dest_port INTEGER,
                        protocol TEXT NOT NULL,
                        message TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        confidence REAL NOT NULL,
                        raw_packet TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """
                )

                # Create indexes for performance
                conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_source_ip ON alerts(source_ip)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_severity ON alerts(severity)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_type ON alerts(alert_type)")

                # Packets table for raw packet persistence and forensics
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS packets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        source_ip TEXT,
                        dest_ip TEXT,
                        source_port INTEGER,
                        dest_port INTEGER,
                        protocol TEXT,
                        length INTEGER,
                        payload TEXT,
                        payload_hex TEXT,
                        raw_packet BLOB,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(source_ip)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_dst ON packets(dest_ip)")

                # Ensure alerts table has packet_id column to link to packets (backwards compatible)
                cursor = conn.cursor()
                cursor.execute("PRAGMA table_info(alerts)")
                cols = [r[1] for r in cursor.fetchall()]
                if "packet_id" not in cols:
                    try:
                        conn.execute("ALTER TABLE alerts ADD COLUMN packet_id INTEGER")
                        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_packet_id ON alerts(packet_id)")
                    except Exception:
                        # ALTER TABLE may fail on some environments; ignore safely
                        pass

                conn.commit()

            logger.info(f"Database initialized at {self.db_path}")

        except Exception as e:
            logger.error(f"Database initialization error: {e}")
            raise

    @contextmanager
    def get_connection(self):
        """
        Context manager for database connections.
        Ensures proper connection handling and thread safety.
        """
        conn = None
        try:
            with self._connection_lock:
                conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=10.0)
                conn.execute("PRAGMA journal_mode=WAL")  # Better concurrency
                conn.execute("PRAGMA busy_timeout=5000")

            yield conn

        except Exception as e:
            logger.error(f"Database connection error: {e}")
            raise
        finally:
            if conn:
                conn.close()

    def store_alert(self, alert: Alert) -> int:
        """
        Store alert in database.

        Args:
            alert: Alert object to store

        Returns:
            Database row ID
        """
        try:
            params = (
                alert.rule_id,
                alert.name,
                alert.alert_type.value if hasattr(alert.alert_type, "value") else str(alert.alert_type),
                alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity),
                alert.source_ip,
                alert.dest_ip,
                alert.source_port,
                alert.dest_port,
                alert.protocol,
                alert.message,
                (alert.timestamp.isoformat() if hasattr(alert.timestamp, "isoformat") else str(alert.timestamp)),
                alert.confidence,
                (alert.raw_packet if isinstance(alert.raw_packet, (bytes, bytearray)) else (alert.raw_packet or None)),
                getattr(alert, "packet_id", None),
            )

            if self._write_conn:
                with self._write_lock:
                    cursor = self._write_conn.cursor()
                    cursor.execute(
                        """
                        INSERT INTO alerts (
                            rule_id, name, alert_type, severity,
                            source_ip, dest_ip, source_port, dest_port,
                            protocol, message, timestamp, confidence, raw_packet, packet_id
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                        params,
                    )
                    self._write_conn.commit()
                    alert_id = cursor.lastrowid
                    logger.info(f"Alert stored with ID: {alert_id}")
                    return alert_id

            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO alerts (
                        rule_id, name, alert_type, severity,
                        source_ip, dest_ip, source_port, dest_port,
                        protocol, message, timestamp, confidence, raw_packet, packet_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    params,
                )
                conn.commit()
                alert_id = cursor.lastrowid
                logger.info(f"Alert stored with ID: {alert_id}")
                return alert_id
        except Exception as e:
            logger.error(f"Error storing alert: {e}")
            raise

    def store_packet(self, features: Dict[str, Any]) -> int:
        """Store a captured packet in the packets table and return its ID."""
        try:
            timestamp = features.get("timestamp")
            if hasattr(timestamp, "isoformat"):
                timestamp = timestamp.isoformat()
            source_ip = features.get("source_ip")
            dest_ip = features.get("dest_ip")
            source_port = features.get("source_port")
            dest_port = features.get("dest_port")
            protocol = features.get("protocol")
            length = features.get("length") or features.get("payload_length") or 0
            payload = features.get("payload")
            payload_hex = features.get("payload_hex")
            raw_packet = features.get("raw_packet")
            # Ensure raw_packet is bytes
            if isinstance(raw_packet, memoryview):
                raw_packet = bytes(raw_packet)

            # Prefer using persistent write connection for lower latency
            if self._write_conn:
                with self._write_lock:
                    cursor = self._write_conn.cursor()
                    cursor.execute(
                        """
                        INSERT INTO packets (
                            timestamp, source_ip, dest_ip, source_port,
                            dest_port, protocol, length, payload, payload_hex, raw_packet
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            timestamp,
                            source_ip,
                            dest_ip,
                            source_port,
                            dest_port,
                            protocol,
                            length,
                            payload,
                            payload_hex,
                            raw_packet,
                        ),
                    )
                    self._write_conn.commit()
                    packet_id = cursor.lastrowid
                    logger.info(f"Packet stored with ID: {packet_id}")
                    return packet_id

            # Fallback to per-call connection
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO packets (
                        timestamp, source_ip, dest_ip, source_port,
                        dest_port, protocol, length, payload, payload_hex, raw_packet
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        timestamp,
                        source_ip,
                        dest_ip,
                        source_port,
                        dest_port,
                        protocol,
                        length,
                        payload,
                        payload_hex,
                        raw_packet,
                    ),
                )
                conn.commit()
                packet_id = cursor.lastrowid
                logger.info(f"Packet stored with ID: {packet_id}")
                return packet_id
        except Exception as e:
            logger.error(f"Error storing packet: {e}")
            raise

    def get_recent_packets(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Return recent packets as list of dicts (raw_packet base64-encoded)."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT id, timestamp, source_ip, dest_ip, source_port, dest_port, protocol, length, payload, payload_hex, raw_packet, created_at FROM packets ORDER BY timestamp DESC LIMIT ?",
                    (limit,),
                )
                rows = cursor.fetchall()
                cols = [d[0] for d in cursor.description]
                packets = []
                for row in rows:
                    r = dict(zip(cols, row))
                    raw = r.get("raw_packet")
                    r["raw_packet"] = None if raw is None else base64.b64encode(raw).decode("ascii")
                    packets.append(r)
                return packets
        except Exception as e:
            logger.error(f"Error fetching packets: {e}")
            return []

    def get_packet_by_id(self, packet_id: int) -> Optional[Dict[str, Any]]:
        """Return a single packet record by id (raw_packet base64)."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT id, timestamp, source_ip, dest_ip, source_port, dest_port, protocol, length, payload, payload_hex, raw_packet, created_at FROM packets WHERE id = ?",
                    (packet_id,),
                )
                row = cursor.fetchone()
                if not row:
                    return None
                cols = [d[0] for d in cursor.description]
                r = dict(zip(cols, row))
                raw = r.get("raw_packet")
                r["raw_packet"] = None if raw is None else base64.b64encode(raw).decode("ascii")
                return r
        except Exception as e:
            logger.error(f"Error fetching packet by id {packet_id}: {e}")
            return None

    def get_recent_alerts(self, limit: int = 100) -> List[Alert]:
        """
        Get recent alerts from database.

        Args:
            limit: Maximum number of alerts to return

        Returns:
            List of Alert objects
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT * FROM alerts 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                """,
                    (limit,),
                )

                rows = cursor.fetchall()
                columns = [description[0] for description in cursor.description]

                alerts = []
                for row in rows:
                    row_dict = dict(zip(columns, row))
                    alert = Alert(
                        rule_id=row_dict["rule_id"],
                        name=row_dict["name"],
                        alert_type=row_dict["alert_type"],
                        severity=row_dict["severity"],
                        source_ip=row_dict["source_ip"],
                        dest_ip=row_dict["dest_ip"],
                        source_port=row_dict["source_port"],
                        dest_port=row_dict["dest_port"],
                        protocol=row_dict["protocol"],
                        message=row_dict["message"],
                        timestamp=row_dict["timestamp"],
                        raw_packet=(
                            None
                            if row_dict.get("raw_packet") is None
                            else (
                                row_dict.get("raw_packet")
                                if isinstance(row_dict.get("raw_packet"), str)
                                else base64.b64encode(row_dict.get("raw_packet")).decode("ascii")
                            )
                        ),
                        confidence=row_dict["confidence"],
                    )
                    # Map packet_id if present
                    if "packet_id" in row_dict:
                        setattr(alert, "packet_id", row_dict.get("packet_id"))
                    alerts.append(alert)

                return alerts

        except Exception as e:
            logger.error(f"Error fetching alerts: {e}")
            return []

    def get_alert_stats(self) -> Dict[str, Any]:
        """
        Get alert statistics for dashboard.

        Returns:
            Dictionary with statistics
        """
        try:
            with self.get_connection() as conn:
                stats = {}

                # Total alerts
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM alerts")
                stats["total_alerts"] = cursor.fetchone()[0]

                # Alerts by severity
                cursor.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
                stats["by_severity"] = dict(cursor.fetchall())

                # Alerts by type
                cursor.execute("SELECT alert_type, COUNT(*) FROM alerts GROUP BY alert_type")
                stats["by_type"] = dict(cursor.fetchall())

                # Top source IPs
                cursor.execute(
                    """
                    SELECT source_ip, COUNT(*) as count 
                    FROM alerts 
                    GROUP BY source_ip 
                    ORDER BY count DESC 
                    LIMIT 10
                """
                )
                stats["top_sources"] = cursor.fetchall()

                # Activity per hour (last 24 hours)
                cursor.execute(
                    """
                    SELECT strftime('%H:00', timestamp) as hour, COUNT(*) 
                    FROM alerts 
                    WHERE timestamp > datetime('now', '-24 hours')
                    GROUP BY hour 
                    ORDER BY hour
                """
                )
                stats["hourly_activity"] = cursor.fetchall()

                return stats

        except Exception as e:
            logger.error(f"Error getting alert stats: {e}")
            return {"error": str(e)}

    def close(self) -> None:
        """Close database connections and persistent writer if present."""
        try:
            if getattr(self, "_write_conn", None):
                try:
                    self._write_conn.close()
                except Exception:
                    pass
            logger.info("Database connections closed")
        except Exception as e:
            logger.error(f"Error closing database connections: {e}")

    def clear_old_alerts(self, days: int = 30) -> int:
        """
        Clear alerts older than specified days.

        Args:
            days: Number of days to keep

        Returns:
            Number of deleted rows
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    DELETE FROM alerts 
                    WHERE timestamp < datetime('now', '-{} days')
                """.format(
                        days
                    )
                )

                deleted = cursor.rowcount
                conn.commit()
                logger.info(f"Cleared {deleted} old alerts")
                return deleted
        except Exception as e:
            logger.error(f"Error clearing old alerts: {e}")
            return 0
