"""
Main detection engine - orchestrates packet capture, signature-based
detection, and behavior-based analysis in a multithreaded architecture.
"""

from queue import Queue, Full, Empty
from threading import Thread, Lock, Event
from typing import List, Optional, Callable
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable 
import time

from ids.utils.logger import setup_logger
from ids.core.packet_capture import PacketCapture
from ids.core.signature_detector import SignatureDetector
from ids.core.behavior_analyzer import BehaviorAnalyzer
from ids.models.alert import Alert
from ids.database.db_manager import DatabaseManager
from ids.config.config_loader import get_config

logger = setup_logger(__name__)

class DetectorEngine:
    """
    Main IDS detection engine.
    
    Coordinates:
    - Packet capture
    - Signature-based detection
    - Behavior-based analysis
    - Alert generation and storage
    - Performance monitoring
    """
    
    def __init__(
        self,
        config=None,
        use_signature=True,
        use_anomaly=True,
        alert_callback: Optional[Callable[[Alert], None]] = None,
        stats_callback: Optional[Callable[[Dict], None]] = None
    ):
        """
        Initialize detection engine.
        
        Args:
            config: IDS configuration from YAML
            use_signature: enable signature-based detection
            use_anomaly: enable behavior-based detection
            alert_callback: Optional callback for new alerts
            stats_callback: Optional callback for periodic stats updates
        """
        # Store config
        self.config = config
        self.use_signature = use_signature
        self.use_anomaly = use_anomaly
        self.stats_callback = stats_callback
        
        # Components
        # Ensure we have a config dict (load defaults if not provided)
        if config is None:
            try:
                # Try to load main.yaml config
                from ids.config.config_loader import config_loader
                config = config_loader.load("main.yaml")
            except Exception:
                config = {}

        # normalize and protect access to network config
        net_cfg = config.get("network", {}) if isinstance(config, dict) else {}
        interface = net_cfg.get("interface", "eth0")
        promiscuous = net_cfg.get("promiscuous", True)
        filter_exp = net_cfg.get("bpf_filter", None)

        # Logging preference for per-packet terminal output (default true for your request)
        self.log_packets = config.get("logging", {}).get("log_packets", True)

        self.packet_capture = PacketCapture(
            interface=interface,
            promiscuous=promiscuous,
            filter_exp=filter_exp
        )

        # Gather local IPs to determine incoming vs outgoing
        try:
            self._local_ips = self._gather_local_ips()
        except Exception:
            self._local_ips = set()

        # optional detectors
        self.signature_detector = SignatureDetector() if use_signature else None
        self.behavior_analyzer = BehaviorAnalyzer() if use_anomaly else None

        self.db_manager = DatabaseManager()

        # Optionally create a separate per-run packet DB (config: storage.per_run_packet_db)
        storage_cfg = config.get("storage", {}) if isinstance(config, dict) else {}
        packet_db_dir = storage_cfg.get("packet_db_dir", "data/packets")
        per_run_packet_db = storage_cfg.get("per_run_packet_db", True)
        keep_central_copy = storage_cfg.get("keep_central_copy", False)
        self.keep_central_copy = keep_central_copy

        if per_run_packet_db:
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            packet_db_path = Path(packet_db_dir) / f"packets_{ts}.db"
            packet_db_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                self.packet_db_manager = DatabaseManager(str(packet_db_path))
                self.packet_db_path = str(packet_db_path)
                logger.info(f"Per-run packet DB enabled: {self.packet_db_path}")
            except Exception as e:
                logger.error(f"Failed to create per-run packet DB at {packet_db_path}: {e}")
                # Fallback to using main DB
                self.packet_db_manager = self.db_manager
                self.packet_db_path = None
        else:
            self.packet_db_manager = self.db_manager
            self.packet_db_path = None

        # Alert callback
        self.alert_callback = alert_callback
        
        # Stats callback for real-time broadcasts
        self.stats_callback = stats_callback
        
        # Queues for inter-thread communication
        self.packet_queue = Queue(maxsize=10000)  # Bounded queue
        self.alert_queue = Queue()
        
        # Threading
        self._is_running = False
        self._threads: List[Thread] = []
        self._stop_event = Event()
        
        # Locks
        self._stats_lock = Lock()
        self._alert_lock = Lock()
        
        # Statistics
        self.stats = {
            "packets_processed": 0,
            "signature_alerts": 0,
            "behavior_alerts": 0,
            "total_alerts": 0,
            "queue_drops": 0,
            "processing_rate": 0.0,
            "start_time": None
        }

        logger.info(
            f"DetectorEngine initialized | Signature={use_signature} | Anomaly={use_anomaly}"
        )
    
    def set_alert_callback(self, callback: Optional[Callable[[Alert], None]]) -> None:
        """Set or update the alert callback function."""
        self.alert_callback = callback
        logger.info("Alert callback updated")
    
    def set_stats_callback(self, callback: Optional[Callable[[Dict], None]]) -> None:
        """Set or update the stats callback function for real-time broadcasts."""
        self.stats_callback = callback
        logger.info("Stats callback updated")
    
    def start(self) -> None:
        """Start all detection components."""
        if self._is_running:
            logger.warning("Detector engine is already running")
            return
        
        self._is_running = True
        self._stop_event.clear()
        self.stats["start_time"] = time.time()
        
        # Start database
        logger.info("Starting database initialization...")
        try:
            self.db_manager._init_db()
            logger.info("Database initialized")
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise
        
        # Set packet callback
        logger.info("Setting packet capture callback...")
        self.packet_capture.set_callback(self._handle_packet)
        
        # Start packet capture in a separate thread (non-blocking)
        logger.info("Starting packet capture in background...")
        capture_thread = Thread(
            target=self.packet_capture.start,
            name="PacketCaptureInit",
            daemon=True
        )
        capture_thread.start()
        # Don't wait for it - let it run in background
        logger.info("Packet capture initialization started")

        # Ensure worker threads are running (idempotent)
        try:
            self._start_worker_threads()
        except Exception as e:
            logger.warning(f"Could not start worker threads automatically: {e}")

        logger.info("Detector engine initialization complete - worker threads started")
    
    def _start_worker_threads(self) -> None:
        """Start worker threads - can be called separately from initialization.

        This method is idempotent (will not spawn duplicate threads if already running).
        """
        if self._threads:
            logger.info("Worker threads already running, skipping start")
            return

        logger.info("Starting worker threads...")
        threads_config = [
            (self._packet_processor, "PacketProcessor"),
            (self._alert_processor, "AlertProcessor"),
            (self._stats_reporter, "StatsReporter")
        ]
        
        for target, name in threads_config:
            try:
                logger.info(f"Creating thread: {name}")
                thread = Thread(
                    target=target,
                    name=name,
                    daemon=True
                )
                logger.info(f"Starting thread: {name}")
                thread.start()
                logger.info(f"Thread {name} started")
                self._threads.append(thread)
            except Exception as e:
                logger.error(f"Failed to start thread {name}: {e}")
        
        logger.info("All worker threads started")
    
    def stop(self) -> None:
        """Stop all components gracefully."""
        if not self._is_running:
            logger.info("Detector engine already stopped")
            return
        
        logger.info("Stopping detector engine...")
        self._is_running = False
        self._stop_event.set()
        
        # Stop packet capture first
        try:
            logger.info("Stopping packet capture...")
            self.packet_capture.stop()
            logger.info("Packet capture stopped")
        except Exception as e:
            logger.error(f"Error stopping packet capture: {e}")
        
        # Signal threads to stop by putting sentinel values in queues
        logger.info("Signaling worker threads to stop...")
        try:
            # Put multiple None values in case we have multiple threads
            for _ in range(len(self._threads) + 1):
                try:
                    self.packet_queue.put_nowait(None)
                except:
                    pass
            for _ in range(len(self._threads) + 1):
                try:
                    self.alert_queue.put_nowait(None)
                except:
                    pass
        except Exception as e:
            logger.warning(f"Error signaling threads: {e}")
        
        # Wait for threads to finish with extended timeout
        logger.info(f"Waiting for {len(self._threads)} worker threads to finish...")
        for thread in self._threads:
            if thread.is_alive():
                logger.info(f"Joining thread {thread.name}...")
                thread.join(timeout=5)
                if thread.is_alive():
                    logger.warning(f"Thread {thread.name} did not terminate within timeout")
        
        logger.info(f"All {len(self._threads)} worker threads stopped")
        
        # Close databases
        try:
            logger.info("Closing main database...")
            self.db_manager.close()
            logger.info("Main database closed")
        except Exception as e:
            logger.error(f"Error closing main database: {e}")

        # Close per-run packet DB if separate
        try:
            if getattr(self, 'packet_db_manager', None) and self.packet_db_manager is not self.db_manager:
                logger.info("Closing per-run packet database...")
                try:
                    self.packet_db_manager.close()
                    logger.info("Per-run packet database closed")
                except Exception as e:
                    logger.error(f"Error closing per-run packet DB: {e}")
        except Exception as e:
            logger.error(f"Error during packet DB shutdown: {e}")
        
        logger.info("Detector engine stopped")
    
    def _handle_packet(self, features: dict) -> None:
        """
        Callback for captured packets.
        Packets are queued for processing.
        """
        try:
            self.packet_queue.put_nowait(features)
        except Full:
            with self._stats_lock:
                self.stats["queue_drops"] += 1
            if self.stats["queue_drops"] % 100 == 0:
                logger.warning(f"Packet queue full, dropped {self.stats['queue_drops']} packets")
    
    def _packet_processor(self) -> None:
        """Worker thread: processes packets from queue."""
        # Delay logging until thread is fully scheduled
        import time as time_module
        time_module.sleep(0.1)
        try:
            logger.info("Packet processor thread started")
        except:
            pass  # Skip logging if there's an issue
        
        packet_count = 0
        while not self._stop_event.is_set():
            try:
                features = self.packet_queue.get(timeout=0.5)
                
                if features is None:
                    break
                
                packet_count += 1
                
                # Log packets based on configuration
                if self.log_packets:
                    src = features.get('source_ip', 'unknown')
                    dst = features.get('dest_ip', 'unknown')
                    proto = features.get('protocol', 'unknown')
                    src_port = features.get('source_port')
                    dst_port = features.get('dest_port')
                    length = features.get('length', features.get('payload_length', 'unknown'))
                    direction = 'unknown'
                    try:
                        if self._is_local_ip(src):
                            direction = 'outgoing'
                        elif self._is_local_ip(dst):
                            direction = 'incoming'
                    except Exception:
                        direction = 'unknown'
                    logger.info(f"[Packet] {direction.upper():8} {src}{(':'+str(src_port)) if src_port else ''} → {dst}{(':'+str(dst_port)) if dst_port else ''} | {proto.upper()} | len={length}")
                else:
                    if packet_count <= 5:
                        src = features.get('source_ip', 'unknown')
                        dst = features.get('dest_ip', 'unknown')
                        proto = features.get('protocol', 'unknown')
                        logger.info(f"[Processor] Packet {packet_count}: {src} → {dst} ({proto})")
                    elif packet_count % 20 == 0:
                        logger.info(f"Processor: Handled {packet_count} packets")
                
                self._process_packet(features)
                
            except Empty:
                continue
            except Exception as e:
                try:
                    logger.error(f"Error in packet processor: {e}")
                except:
                    pass
                time_module.sleep(0.1)
        
        try:
            logger.info(f"Packet processor thread stopped (processed {packet_count} packets)")
        except:
            pass
    
    def _process_packet(self, features: dict) -> None:
        """Process single packet through all detectors."""
        try:
            with self._stats_lock:
                self.stats["packets_processed"] += 1
            
            # Store packet in the packet DB (may be a per-run DB) for forensics and linking
            packet_id = None
            try:
                packet_id = self.packet_db_manager.store_packet(features)
            except Exception as e:
                logger.debug(f"Failed to store packet in packet DB: {e}")

            # Optionally also keep a central copy in the main DB
            if getattr(self, 'keep_central_copy', False) and self.packet_db_manager is not self.db_manager:
                try:
                    self.db_manager.store_packet(features)
                except Exception as e:
                    logger.debug(f"Failed to store central copy of packet: {e}")

            # Use a reference string for packet linkage if using per-run DB
            packet_ref = None
            try:
                if packet_id and getattr(self, 'packet_db_path', None):
                    packet_ref = f"{Path(self.packet_db_path).name}:{packet_id}"
                else:
                    packet_ref = packet_id
            except Exception:
                packet_ref = packet_id

            alerts: List[Alert] = []
            
            # Signature-based detection
            if self.signature_detector:
                sig_alert = self.signature_detector.check_packet(features)
                if sig_alert:
                    if packet_ref:
                        sig_alert.packet_id = packet_ref
                    alerts.append(sig_alert)
                    with self._stats_lock:
                        self.stats["signature_alerts"] += 1
            
            # Behavior-based analysis
            if self.behavior_analyzer:
                beh_alerts = self.behavior_analyzer.analyze_packet(features)
                if beh_alerts:
                    for a in beh_alerts:
                        if packet_ref:
                            a.packet_id = packet_ref
                    alerts.extend(beh_alerts)
                    with self._stats_lock:
                        self.stats["behavior_alerts"] += len(beh_alerts)
            
            # Queue alerts
            for alert in alerts:
                try:
                    self.alert_queue.put_nowait(alert)
                except Full:
                    logger.warning("Alert queue full, dropping alert")
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _alert_processor(self) -> None:
        """Worker thread: processes and stores alerts."""
        import time as time_module
        time_module.sleep(0.1)  # Delay to ensure thread is fully scheduled before logging
        try:
            logger.info("Alert processor thread started")
        except:
            pass
        
        while not self._stop_event.is_set():
            try:
                alert = self.alert_queue.get(timeout=0.5)
                
                if alert is None:
                    break
                
                self._handle_alert(alert)
                
            except Empty:
                continue
            except Exception as e:
                try:
                    logger.error(f"Error in alert processor: {e}")
                except:
                    pass
                time_module.sleep(0.1)
        
        try:
            logger.info("Alert processor thread stopped")
        except:
            pass
    
    def _handle_alert(self, alert: Alert) -> None:
        """Handle generated alert."""
        try:
            alert_id = self.db_manager.store_alert(alert)
            alert.rule_id = f"{alert.rule_id}-{alert_id}"
            
            with self._stats_lock:
                self.stats["total_alerts"] += 1
            
            if self.alert_callback:
                try:
                    self.alert_callback(alert)
                except Exception as e:
                    logger.error(f"Error in alert callback: {e}")
            
            logger.info(f"ALERT: {alert}")
            
        except Exception as e:
            logger.error(f"Error handling alert: {e}")
    
    def _stats_reporter(self) -> None:
        import time as time_module
        time_module.sleep(0.1)  # Delay to ensure thread is fully scheduled before logging
        try:
            logger.info("Stats reporter thread started")
        except:
            pass
        
        log_interval = 60.0
        broadcast_interval = 2.0  # Broadcast every 2 seconds for real-time updates
        last_log = time_module.time()
        last_broadcast = time_module.time() - broadcast_interval  # Initialize to allow first broadcast immediately
        
        while not self._stop_event.wait(timeout=0.5):  # Reduced timeout for faster polling
            now = time_module.time()
            
            # Broadcast stats every 2 seconds for real-time dashboard updates
            if now - last_broadcast >= broadcast_interval:
                try:
                    stats = self.get_stats()
                    captured = stats.get('capture', {}).get('packets_captured', 0)
                    alerts = stats.get('total_alerts', 0)
                    
                    if self.stats_callback:
                        logger.info(f"Broadcasting stats: packets_captured={captured}, total_alerts={alerts}")
                        self.stats_callback(stats)
                    else:
                        logger.warning("Stats callback is None!")
                except Exception as e:
                    logger.error(f"Error broadcasting stats: {e}", exc_info=True)
                last_broadcast = now
            
            # Log stats every 60 seconds
            if now - last_log >= log_interval:
                self._log_stats()
                last_log = now
        
        try:
            logger.info("Stats reporter thread stopped")
        except:
            pass
    
    def _log_stats(self) -> None:
        try:
            cap_stats = self.packet_capture.get_stats()
            
            with self._stats_lock:
                elapsed = time.time() - self.stats["start_time"]
                rate = self.stats["packets_processed"] / elapsed if elapsed > 0 else 0
                
                logger.info("=== IDS Statistics ===")
                logger.info(f"Packets Processed: {self.stats['packets_processed']}")
                logger.info(f"Processing Rate: {rate:.2f} packets/sec")
                logger.info(f"Signature Alerts: {self.stats['signature_alerts']}")
                logger.info(f"Behavior Alerts: {self.stats['behavior_alerts']}")
                logger.info(f"Total Alerts: {self.stats['total_alerts']}")
                logger.info(f"Queue Drops: {self.stats['queue_drops']}")
                logger.info(f"Capture Stats: {cap_stats}")
                
        except Exception as e:
            logger.error(f"Error logging stats: {e}")

    def _gather_local_ips(self) -> set:
        """Try to discover local IP addresses for direction determination."""
        ips = set(["127.0.0.1", "::1"])
        try:
            import socket
            hostname = socket.gethostname()
            try:
                # Add the primary hostname resolution
                primary = socket.gethostbyname(hostname)
                ips.add(primary)
            except Exception:
                pass
            # Add any address families returned by getaddrinfo
            for res in socket.getaddrinfo(hostname, None):
                try:
                    addr = res[4][0]
                    if addr:
                        ips.add(addr)
                except Exception:
                    continue
        except Exception:
            pass
        return ips

    def _is_local_ip(self, ip: str) -> bool:
        if not ip:
            return False
        try:
            if ip in self._local_ips:
                return True
            # Heuristic private ranges
            if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
                return True
        except Exception:
            pass
        return False    
    def register_alert_callback(self, callback: Callable[[Alert], None]) -> None:
        self.alert_callback = callback
    
    def get_recent_alerts(self, limit: int = 100):
        try:
            return self.db_manager.get_recent_alerts(limit)
        except Exception as e:
            logger.error(f"Error fetching recent alerts: {e}")
            return []
    
    def get_stats(self) -> Dict[str, Any]:
        with self._stats_lock:
            stats_copy = self.stats.copy()
            stats_copy["capture"] = self.packet_capture.get_stats()
            
            if self.signature_detector:
                stats_copy["signature"] = self.signature_detector.get_stats()
            if self.behavior_analyzer:
                stats_copy["behavior"] = self.behavior_analyzer.get_stats()
            
            return stats_copy
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
