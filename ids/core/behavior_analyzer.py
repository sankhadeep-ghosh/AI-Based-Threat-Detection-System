"""
Behavior-based analysis module - detects anomalies through
statistical tracking and threshold-based detection.
"""

from collections import defaultdict, deque
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime, timedelta
from threading import Lock
import time

from ids.utils.logger import setup_logger
from ids.config.config_loader import ConfigLoader, get_config
from ids.models.alert import Alert, AlertSeverity, AlertType

logger = setup_logger(__name__)

# Type alias for tracking structure
ConnectionKey = Tuple[str, str, int]  # (src_ip, dst_ip, dst_port)


class SlidingWindowCounter:
    """
    Thread-safe sliding window counter for tracking events over time.

    Automatically removes old entries outside the time window to prevent
    memory leaks and maintain accuracy.
    """

    def __init__(self, window_seconds: int):
        """
        Initialize counter with time window.

        Args:
            window_seconds: Size of sliding window in seconds
        """
        self.window = window_seconds
        self.events: deque = deque()  # (timestamp, key, count)
        self.counts: Dict[Any, int] = defaultdict(int)
        self.lock = Lock()

    def increment(self, key: Any) -> None:
        """
        Increment counter for given key.

        Args:
            key: Identifier (e.g., IP address, port)
        """
        now = datetime.now()

        with self.lock:
            # Remove old events outside window
            cutoff = now - timedelta(seconds=self.window)
            while self.events and self.events[0][0] < cutoff:
                _, old_key, count = self.events.popleft()
                self.counts[old_key] -= count
                if self.counts[old_key] <= 0:
                    del self.counts[old_key]

            # Add new event
            self.events.append((now, key, 1))
            self.counts[key] += 1

    def get_count(self, key: Any) -> int:
        """Get current count for key within window."""
        with self.lock:
            self._cleanup()  # Remove old events
            return self.counts.get(key, 0)

    def get_top_n(self, n: int = 10) -> List[Tuple[Any, int]]:
        """
        Get top N keys with highest counts.

        Returns:
            List of (key, count) tuples sorted by count descending
        """
        with self.lock:
            self._cleanup()
            sorted_items = sorted(self.counts.items(), key=lambda x: x[1], reverse=True)
            return sorted_items[:n]

    def _cleanup(self) -> None:
        """Remove expired events (internal use)."""
        cutoff = datetime.now() - timedelta(seconds=self.window)
        while self.events and self.events[0][0] < cutoff:
            _, key, count = self.events.popleft()
            self.counts[key] -= count
            if self.counts[key] <= 0:
                del self.counts[key]

    def reset(self) -> None:
        """Reset all counters."""
        with self.lock:
            self.events.clear()
            self.counts.clear()


class PortScanTracker:
    """Track port scanning attempts per source IP."""

    def __init__(self, max_ports: int, window_seconds: int):
        """
        Initialize tracker.

        Args:
            max_ports: Maximum unique ports allowed
            window_seconds: Time window for tracking
        """
        self.max_ports = max_ports
        self.window = window_seconds
        # Structure: {src_ip: {dst_ip: set(ports)}}
        self.tracker: Dict[str, Dict[str, Set[int]]] = defaultdict(lambda: defaultdict(set))
        self.timestamps: Dict[str, datetime] = {}
        self.lock = Lock()

    def add_connection(self, src_ip: str, dst_ip: str, dst_port: int) -> Optional[Alert]:
        """
        Add connection attempt and check for port scan.

        Returns:
            Alert if port scan detected, None otherwise
        """
        now = datetime.now()

        with self.lock:
            # Cleanup old entries
            self._cleanup_old_entries(now)

            # Track port
            self.tracker[src_ip][dst_ip].add(dst_port)
            self.timestamps[src_ip] = now

            # Check threshold for each target IP
            for target_ip, ports in self.tracker[src_ip].items():
                if len(ports) >= self.max_ports:
                    return Alert(
                        rule_id="BEHAV-001",
                        name="Port Scan Detected",
                        alert_type=AlertType.PORT_SCAN,
                        severity=AlertSeverity.MEDIUM,
                        source_ip=src_ip,
                        dest_ip=target_ip,
                        source_port=None,
                        dest_port=None,
                        protocol="tcp",
                        message=f"Port scan detected: {len(ports)} unique ports scanned",
                        timestamp=now,
                        confidence=0.85,
                    )

            return None

    def _cleanup_old_entries(self, now: datetime) -> None:
        """Remove entries older than time window."""
        cutoff = now - timedelta(seconds=self.window)
        expired_ips = [ip for ip, timestamp in self.timestamps.items() if timestamp < cutoff]

        for ip in expired_ips:
            del self.tracker[ip]
            del self.timestamps[ip]


class BruteForceTracker:
    """Track brute force login attempts."""

    def __init__(self, max_attempts: int, window_seconds: int, target_ports: Set[int]):
        """
        Initialize tracker.

        Args:
            max_attempts: Maximum failed attempts allowed
            window_seconds: Time window for tracking
            target_ports: Ports to monitor (e.g., SSH, RDP)
        """
        self.max_attempts = max_attempts
        self.window = window_seconds
        self.target_ports = target_ports
        # Structure: {target_ip: {src_ip: count}}
        self.attempts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.timestamps: Dict[str, datetime] = {}
        self.lock = Lock()

    def add_attempt(self, src_ip: str, dst_ip: str, dst_port: int) -> Optional[Alert]:
        """
        Add connection attempt and check for brute force.

        Returns:
            Alert if brute force detected, None otherwise
        """
        if dst_port not in self.target_ports:
            return None

        now = datetime.now()

        with self.lock:
            self._cleanup_old_entries(now)

            # Track attempt
            self.attempts[dst_ip][src_ip] += 1
            self.timestamps[dst_ip] = now

            # Check threshold
            if self.attempts[dst_ip][src_ip] >= self.max_attempts:
                return Alert(
                    rule_id="BEHAV-002",
                    name="Brute Force Attack",
                    alert_type=AlertType.BRUTE_FORCE,
                    severity=AlertSeverity.HIGH,
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    source_port=None,
                    dest_port=dst_port,
                    protocol="tcp",
                    message=f"Brute force detected: {self.max_attempts}+ attempts to port {dst_port}",
                    timestamp=now,
                    confidence=0.90,
                )

            return None

    def _cleanup_old_entries(self, now: datetime) -> None:
        """Remove old entries."""
        cutoff = now - timedelta(seconds=self.window)
        expired_targets = [target for target, timestamp in self.timestamps.items() if timestamp < cutoff]

        for target in expired_targets:
            del self.attempts[target]
            del self.timestamps[target]


class DoSTracker:
    """Track DoS/DDoS attacks by packet rate."""

    def __init__(self, max_packets: int, window_seconds: int):
        """
        Initialize tracker.

        Args:
            max_packets: Maximum packets per IP
            window_seconds: Time window
        """
        self.max_packets = max_packets
        self.window = window_seconds
        self.packet_counter = SlidingWindowCounter(window_seconds)

    def add_packet(self, src_ip: str, dst_ip: str) -> Optional[Alert]:
        """
        Add packet and check for DoS.

        Returns:
            Alert if DoS detected, None otherwise
        """
        self.packet_counter.increment(src_ip)
        count = self.packet_counter.get_count(src_ip)

        if count >= self.max_packets:
            return Alert(
                rule_id="BEHAV-003",
                name="DoS Attack",
                alert_type=AlertType.DOS,
                severity=AlertSeverity.CRITICAL,
                source_ip=src_ip,
                dest_ip=dst_ip,
                source_port=None,
                dest_port=None,
                protocol="tcp",
                message=f"DoS detected: {count} packets from {src_ip}",
                timestamp=datetime.now(),
                confidence=0.95,
            )

        return None


class BehaviorAnalyzer:
    """
    Behavior-based threat detection engine.

    Tracks network behavior patterns and detects anomalies based on
    configurable thresholds for various attack types.
    """

    def __init__(self, thresholds_file: str = "thresholds.yaml"):
        """
        Initialize behavior analyzer.

        Args:
            thresholds_file: Name of thresholds YAML file
        """
        self.config_loader = ConfigLoader()
        self.thresholds = self._load_thresholds(thresholds_file)

        # Initialize trackers
        self.port_scan_tracker = PortScanTracker(
            max_ports=self.thresholds["port_scan"]["max_ports_per_ip"],
            window_seconds=self.thresholds["port_scan"]["time_window"],
        )

        self.brute_force_tracker = BruteForceTracker(
            max_attempts=self.thresholds["brute_force"]["max_failed_attempts"],
            window_seconds=self.thresholds["brute_force"]["time_window"],
            target_ports=set(self.thresholds["brute_force"]["target_ports"]),
        )

        self.dos_tracker = DoSTracker(
            max_packets=self.thresholds["dos"]["max_packets_per_ip"],
            window_seconds=self.thresholds["dos"]["time_window"],
        )

        self.dns_tracker = SlidingWindowCounter(window_seconds=self.thresholds["dns_amplification"]["time_window"])

        # Statistics
        self.stats = {
            "port_scans_detected": 0,
            "brute_force_detected": 0,
            "dos_detected": 0,
            "dns_amplification_detected": 0,
            "total_anomalies_checked": 0,
        }

        logger.info("BehaviorAnalyzer initialized with all trackers")

    def _load_thresholds(self, filename: str) -> Dict[str, Any]:
        """Load threshold configuration."""
        try:
            config = self.config_loader.load_yaml(filename)
            thresholds = config
            logger.info("Successfully loaded behavior thresholds")
            return thresholds
        except Exception as e:
            logger.error(f"Failed to load thresholds: {e}")
            # Return default thresholds
            return {
                "port_scan": {"max_ports_per_ip": 10, "time_window": 60, "severity": "medium"},
                "brute_force": {
                    "max_failed_attempts": 5,
                    "time_window": 60,
                    "target_ports": [22, 23, 3389, 21],
                    "severity": "high",
                },
                "dos": {"max_packets_per_ip": 1000, "time_window": 10, "severity": "critical"},
                "dns_amplification": {"max_dns_responses": 50, "time_window": 60, "severity": "medium"},
            }

    def analyze_packet(self, features: Dict[str, Any]) -> List[Alert]:
        """
        Analyze packet for behavioral anomalies.

        Args:
            features: Extracted packet features

        Returns:
            List of alerts (empty if no anomalies)
        """
        self.stats["total_anomalies_checked"] += 1
        alerts: List[Alert] = []

        src_ip = features.get("source_ip")
        dst_ip = features.get("dest_ip")
        dst_port = features.get("dest_port")
        protocol = features.get("protocol")

        if not src_ip or src_ip == "unknown":
            return alerts

        # Check port scanning
        if dst_port and protocol == "tcp":
            alert = self.port_scan_tracker.add_connection(src_ip, dst_ip, dst_port)
            if alert:
                alerts.append(alert)
                self.stats["port_scans_detected"] += 1

        # Check brute force
        if dst_port and protocol == "tcp":
            tcp_flags = features.get("tcp_flags", "")
            if "S" in tcp_flags and "A" not in tcp_flags:  # SYN only (failed attempt)
                alert = self.brute_force_tracker.add_attempt(src_ip, dst_ip, dst_port)
                if alert:
                    alerts.append(alert)
                    self.stats["brute_force_detected"] += 1

        # Check DoS
        alert = self.dos_tracker.add_packet(src_ip, dst_ip)
        if alert:
            alerts.append(alert)
            self.stats["dos_detected"] += 1

        # Check DNS amplification
        if protocol == "udp" and dst_port == 53:
            self.dns_tracker.increment(dst_ip)  # Track target IP receiving DNS responses
            count = self.dns_tracker.get_count(dst_ip)

            max_responses = self.thresholds["dns_amplification"]["max_dns_responses"]
            if count >= max_responses:
                alert = Alert(
                    rule_id="BEHAV-004",
                    name="DNS Amplification Attack",
                    alert_type=AlertType.DNS_EXFILTRATION,
                    severity=AlertSeverity(self.thresholds["dns_amplification"]["severity"]),
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    source_port=features.get("source_port"),
                    dest_port=dst_port,
                    protocol="udp",
                    message=f"DNS amplification: {count} responses to {dst_ip}",
                    timestamp=features.get("timestamp", datetime.now()),
                    confidence=0.80,
                )
                alerts.append(alert)
                self.stats["dns_amplification_detected"] += 1

        return alerts

    def get_stats(self) -> Dict[str, Any]:
        """Get analyzer statistics."""
        return self.stats.copy()

    def reset_trackers(self) -> None:
        """Reset all tracking data (useful for testing)."""
        self.port_scan_tracker = PortScanTracker(
            max_ports=self.thresholds["port_scan"]["max_ports_per_ip"],
            window_seconds=self.thresholds["port_scan"]["time_window"],
        )
        self.brute_force_tracker = BruteForceTracker(
            max_attempts=self.thresholds["brute_force"]["max_failed_attempts"],
            window_seconds=self.thresholds["brute_force"]["time_window"],
            target_ports=set(self.thresholds["brute_force"]["target_ports"]),
        )
        self.dos_tracker = DoSTracker(
            max_packets=self.thresholds["dos"]["max_packets_per_ip"],
            window_seconds=self.thresholds["dos"]["time_window"],
        )
        self.dns_tracker = SlidingWindowCounter(window_seconds=self.thresholds["dns_amplification"]["time_window"])
        logger.info("All behavior trackers reset")
