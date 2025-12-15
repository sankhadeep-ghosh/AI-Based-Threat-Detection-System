"""
Packet capture module - handles live network packet capture using Scapy
with performance optimizations and feature extraction capabilities.
"""

from typing import Callable, Optional, Dict, Any, List
from threading import Lock, Thread
import time
from datetime import datetime
import platform

from scapy.all import IP, TCP, UDP, ICMP, get_if_list
# try to import AsyncSniffer; some scapy installs have it, some older versions may not
try:
    from scapy.all import AsyncSniffer
    HAS_ASYNC_SNIFFER = True
except Exception:
    # fallback: use sniff with stop_filter
    from scapy.all import sniff
    HAS_ASYNC_SNIFFER = False

from scapy.packet import Packet

from ids.utils.logger import setup_logger
from ids.config.config_loader import get_config

logger = setup_logger(__name__)


def get_available_interfaces() -> List[str]:
    """Get list of available network interfaces that work with Scapy."""
    try:
        all_interfaces = get_if_list()
        logger.info(f"All interfaces from Scapy: {all_interfaces}")
        
        # Filter out loopback and invalid interfaces
        valid_interfaces = [
            iface for iface in all_interfaces 
            if iface and 'loopback' not in iface.lower()
        ]
        
        logger.info(f"Valid interfaces: {valid_interfaces}")
        return valid_interfaces
    except Exception as e:
        logger.warning(f"Could not get interface list: {e}")
        return []


class PacketCapture:
    """
    Thread-safe packet capture engine using Scapy.

    Features:
    - Live packet capture with BPF filtering
    - Feature extraction for IDS analysis
    - Rate limiting and performance tuning
    - Graceful shutdown handling
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        filter_exp: Optional[str] = None,
        promiscuous: bool = True
    ):
        """
        Initialize packet capture engine.

        Args:
            interface: Network interface (e.g., 'eth0')
            bpf_filter: Berkeley Packet Filter expression
            filter_exp: Alternate name for bpf_filter (backward compat)
            promiscuous: Enable promiscuous mode
        """

        # Backward compatibility: accept either name
        if filter_exp and not bpf_filter:
            bpf_filter = filter_exp

        # Get interface from param or config
        if not interface:
            interface = get_config("network.interface", None) or get_config("packet_capture.interface", None)
        
        # Get filter from param or config
        if not bpf_filter:
            bpf_filter = get_config("network.bpf_filter", None) or get_config("packet_capture.bpf_filter", None)
        
        # Get promiscuous from param or config
        config_promisc = get_config("network.promiscuous", None)
        if config_promisc is not None:
            promiscuous = config_promisc
        
        # Convert GUID format to \Device\NPF_GUID if needed
        if interface and not interface.startswith("\\Device\\NPF_") and "{" in interface:
            # It's a GUID, convert it
            interface = f"\\Device\\NPF_{interface}"
        
        # If interface not specified, try to auto-detect
        if not interface:
            available = get_available_interfaces()
            if available:
                # Get the first valid interface and convert if needed
                iface = available[0]
                if "{" in iface:
                    interface = f"\\Device\\NPF_{iface}"
                else:
                    interface = iface
                logger.info(f"Auto-detected interface: {interface}")
            else:
                interface = None  # Let Scapy handle it
                logger.warning("Could not auto-detect interface, will use Scapy default")

        self.interface = interface
        self.bpf_filter = bpf_filter or "ip"
        self.promiscuous = promiscuous

        # If using AsyncSniffer, we'll store the sniffer object here
        self._sniffer = None
        # If using fallback sniff in a thread, we'll keep that thread here
        self._capture_thread: Optional[Thread] = None

        self._is_running = False
        self._packet_callback: Optional[Callable] = None
        self._stats_lock = Lock()
        self._packet_count = 0
        self._start_time = None

        # Performance metrics
        self.stats = {
            "packets_captured": 0,
            "packets_dropped": 0,
            "capture_rate": 0.0,  # packets/sec
            "last_reset": datetime.now()
        }

        logger.info(
            f"PacketCapture initialized for interface {self.interface} "
            f"with filter '{self.bpf_filter}' (async_sniffer={HAS_ASYNC_SNIFFER})"
        )

        # If using AsyncSniffer, we'll store the sniffer object here
        self._sniffer = None
        # If using fallback sniff in a thread, we'll keep that thread here
        self._capture_thread: Optional[Thread] = None

        self._is_running = False
        self._packet_callback: Optional[Callable] = None
        self._stats_lock = Lock()
        self._packet_count = 0
        self._start_time = None

        # Performance metrics
        self.stats = {
            "packets_captured": 0,
            "packets_dropped": 0,
            "capture_rate": 0.0,  # packets/sec
            "last_reset": datetime.now()
        }

        logger.info(
            f"PacketCapture initialized for interface {self.interface} "
            f"with filter '{self.bpf_filter}' (async_sniffer={HAS_ASYNC_SNIFFER})"
        )

    def set_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """
        Set callback function to process captured packets.

        Args:
            callback: Function accepting packet dictionary
        """
        self._packet_callback = callback
        logger.debug("Packet callback registered")

    def extract_features(self, packet: Packet) -> Dict[str, Any]:
        """
        Extract relevant features from raw packet for analysis.

        Args:
            packet: Scapy packet object

        Returns:
            Dictionary of extracted features
        """
        features = {
            "timestamp": datetime.now(),
            "raw_packet": bytes(packet),
            "protocol": "unknown",
            "length": len(packet)
        }

        try:
            # Extract IP layer info
            if IP in packet:
                features.update({
                    "source_ip": packet[IP].src,
                    "dest_ip": packet[IP].dst,
                    "ip_version": packet[IP].version,
                    "ttl": packet[IP].ttl,
                    "protocol_num": packet[IP].proto
                })

                # Determine transport protocol
                if TCP in packet:
                    features.update({
                        "protocol": "tcp",
                        "source_port": packet[TCP].sport,
                        "dest_port": packet[TCP].dport,
                        "tcp_flags": str(packet[TCP].flags),
                        "sequence": packet[TCP].seq,
                        "acknowledgement": packet[TCP].ack,
                        "payload_length": len(packet[TCP].payload)
                    })

                    try:
                        payload = bytes(packet[TCP].payload)
                        features["payload"] = payload.decode('utf-8', errors='ignore')
                        features["payload_hex"] = payload.hex()
                    except Exception:
                        features["payload"] = ""
                        features["payload_hex"] = ""

                elif UDP in packet:
                    features.update({
                        "protocol": "udp",
                        "source_port": packet[UDP].sport,
                        "dest_port": packet[UDP].dport,
                        "payload_length": len(packet[UDP].payload)
                    })

                    try:
                        payload = bytes(packet[UDP].payload)
                        features["payload"] = payload.decode('utf-8', errors='ignore')
                        features["payload_hex"] = payload.hex()
                    except Exception:
                        features["payload"] = ""
                        features["payload_hex"] = ""

                elif ICMP in packet:
                    features.update({
                        "protocol": "icmp",
                        "icmp_type": packet[ICMP].type,
                        "icmp_code": packet[ICMP].code
                    })

            else:
                features["source_ip"] = "unknown"
                features["dest_ip"] = "unknown"

        except Exception as e:
            logger.warning(f"Error extracting packet features: {e}")
            features["error"] = str(e)

        return features

    def _packet_handler(self, packet: Packet) -> None:
        """Internal packet handler for Scapy."""
        try:
            features = self.extract_features(packet)

            with self._stats_lock:
                self._packet_count += 1
                self.stats["packets_captured"] += 1
                
                # Log every packet initially, then reduce frequency
                if self._packet_count <= 10:
                    logger.info(f"[Packet {self._packet_count}] {features.get('source_ip', 'unknown')} → {features.get('dest_ip', 'unknown')} ({features.get('protocol', 'unknown').upper()})")
                elif self._packet_count % 20 == 0:
                    logger.info(f"[Captured {self._packet_count} packets] Latest: {features.get('source_ip', 'unknown')} → {features.get('dest_ip', 'unknown')}")

            if self._packet_callback:
                try:
                    self._packet_callback(features)
                except Exception as e:
                    logger.error(f"Packet callback error: {e}", exc_info=True)

        except Exception as e:
            logger.error(f"Error in packet handler: {e}", exc_info=True)
            with self._stats_lock:
                self.stats["packets_dropped"] += 1

    def start(self) -> None:
        """Start packet capture."""
        if self._is_running:
            logger.warning("Packet capture already running")
            return

        self._is_running = True
        self._start_time = time.time()
        self._packet_count = 0

        logger.info(f"Starting packet capture on interface: {self.interface if self.interface else 'auto-detect'}")
        logger.info(f"Using filter: {self.bpf_filter}")
        logger.info(f"Promiscuous mode: {self.promiscuous}")
        logger.info(f"Using AsyncSniffer: {HAS_ASYNC_SNIFFER}")
        try:
            # Log available interfaces for easier debugging
            interfaces = get_available_interfaces()
            logger.info(f"Available interfaces for capture: {interfaces}")
        except Exception as e:
            logger.debug(f"Could not list interfaces: {e}")

        if HAS_ASYNC_SNIFFER:
            try:
                iface_str = self.interface if self.interface else "auto-detect"
                logger.info(f"Starting AsyncSniffer on {iface_str} with filter '{self.bpf_filter}'")
                
                kwargs = {
                    "filter": self.bpf_filter,
                    "prn": self._packet_handler,
                    "store": False,
                    "promisc": self.promiscuous
                }
                
                if self.interface:
                    kwargs["iface"] = self.interface
                
                self._sniffer = AsyncSniffer(**kwargs)
                self._sniffer.start()
                logger.info(f"[+] AsyncSniffer started successfully on {iface_str}")
                logger.info("[+] Waiting for packets... Listening now")
                return
            except Exception as e:
                logger.error(f"AsyncSniffer failed: {e}", exc_info=True)
                logger.info("Falling back to threaded sniff...")

        self._start_threaded_sniff()

    def _start_threaded_sniff(self) -> None:
        """Fallback sniff if AsyncSniffer fails."""
        def target():
            try:
                iface_str = self.interface if self.interface else "auto-detect"
                logger.info(f"Threaded sniff starting on {iface_str}")
                
                kwargs = {
                    "filter": self.bpf_filter,
                    "prn": self._packet_handler,
                    "store": get_config("packet_capture.store_packets", False),
                    "promisc": self.promiscuous,
                    "stop_filter": lambda _: not self._is_running
                }
                
                if self.interface:
                    kwargs["iface"] = self.interface
                
                sniff(**kwargs)
                logger.info("Threaded sniff completed normally")
            except Exception as e:
                logger.error(f"Fatal sniff error: {e}", exc_info=True)
            finally:
                self._is_running = False
                logger.info("Threaded sniff thread exiting")

        self._capture_thread = Thread(
            target=target,
            name="PacketCaptureThread",
            daemon=False
        )
        self._capture_thread.start()
        iface_str = self.interface if self.interface else "auto-detect"
        logger.info(f"[+] Threaded sniff started on {iface_str}")

    def stop(self) -> None:
        """Stop packet capture."""
        if not self._is_running:
            return

        logger.info("Stopping packet capture...")
        self._is_running = False

        if self._sniffer:
            try:
                # AsyncSniffer.stop() should check our _is_running flag
                self._sniffer.stop()
                logger.info("AsyncSniffer stopped")
            except Exception as e:
                logger.error(f"Failed to stop AsyncSniffer: {e}")
            finally:
                self._sniffer = None

        # Wait for capture thread if using threaded sniff
        if self._capture_thread and self._capture_thread.is_alive():
            logger.info("Waiting for capture thread to finish...")
            self._capture_thread.join(timeout=3)
            if self._capture_thread.is_alive():
                logger.warning("Capture thread did not terminate")

        self._update_stats()
        logger.info("Capture stopped")

    def _update_stats(self) -> None:
        with self._stats_lock:
            if self._start_time:
                elapsed = time.time() - self._start_time
                if elapsed > 0:
                    self.stats["capture_rate"] = self._packet_count / elapsed
            self.stats["last_reset"] = datetime.now()

    def get_stats(self) -> Dict[str, Any]:
        with self._stats_lock:
            self._update_stats()
            return self.stats.copy()

    def is_running(self) -> bool:
        return self._is_running

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
