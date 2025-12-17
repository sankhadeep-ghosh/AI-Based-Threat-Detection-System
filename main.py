#!/usr/bin/env python3
"""
IDS Main Entry Point – orchestrates packet capture, detection, and dashboard.
"""

import signal
import sys
import yaml
from pathlib import Path
import threading
import time

from ids.utils.logger import setup_logger
from ids.core.detector_engine import DetectorEngine
from ids.dashboard.app import DashboardApp

logger = setup_logger(__name__)

# Global references for signal handler
_detector_engine = None
_dashboard = None
_shutdown_event = threading.Event()
_shutdown_lock = threading.Lock()


def signal_handler(sig, frame):
    """Handle SIGINT (CTRL+C) for graceful shutdown."""
    logger.info("\n" + "=" * 60)
    logger.info("CTRL+C detected - initiating graceful shutdown...")
    logger.info("=" * 60)
    with _shutdown_lock:
        # Immediately stop the dashboard to unblock the server
        if _dashboard:
            try:
                logger.info("Stopping SocketIO server...")
                _dashboard.socketio.stop()
            except Exception as e:
                logger.debug(f"Error stopping SocketIO: {e}")
    _shutdown_event.set()


def load_config(path: str = "config/main.yaml"):
    """Load YAML configuration from file."""
    p = Path(path)
    if not p.exists():
        logger.error("Configuration file not found: %s", p)
        return {}
    try:
        with open(p, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
            logger.info("Loaded configuration from %s", p)
            return cfg
    except Exception as e:
        logger.error("Failed to load config %s: %s", p, e)
        return {}


def main():
    """Main entry point - orchestrate engine and dashboard."""
    global _detector_engine, _dashboard

    logger.info("=" * 60)
    logger.info("Advanced Intrusion Detection System")
    logger.info("=" * 60)

    # Load configuration
    config = load_config("config/main.yaml")
    if not config:
        logger.error("Failed to load configuration, exiting")
        return

    detector_engine = None
    dashboard = None
    dashboard_thread = None

    try:
        # Initialize and start detection engine
        logger.info("Initializing detection engine...")
        detector_engine = DetectorEngine(
            config=config,
            use_signature=True,
            use_anomaly=True,
            alert_callback=None,  # We'll set this after dashboard is created
        )
        _detector_engine = detector_engine
        detector_engine.start()
        logger.info("Detection engine started successfully")

        # Start worker threads (packet processing, alert handling, stats reporting)
        detector_engine._start_worker_threads()
        logger.info("Worker threads started")

        # Initialize dashboard (registers alert callback with engine)
        logger.info("Initializing dashboard...")
        dashboard = DashboardApp(detector_engine)
        _dashboard = dashboard

        # Set alert callback so dashboard can broadcast alerts
        detector_engine.set_alert_callback(dashboard.broadcast_alert)

        # Set stats callback so dashboard can broadcast stats in real-time
        detector_engine.set_stats_callback(dashboard.broadcast_stats)

        logger.info("Dashboard initialized, starting web server...")
        logger.info("Press CTRL+C to shutdown gracefully\n")

        # Run dashboard in a thread so CTRL+C can interrupt it
        def run_dashboard():
            try:
                dashboard.run(
                    host=config.get("dashboard", {}).get("host", "0.0.0.0"),
                    port=config.get("dashboard", {}).get("port", 5000),
                    debug=config.get("dashboard", {}).get("debug", False),
                )
            except KeyboardInterrupt:
                logger.info("Dashboard interrupted")
            except SystemExit:
                logger.info("Dashboard system exit")
            except Exception as e:
                logger.error(f"Dashboard error: {e}")
            finally:
                logger.info("Dashboard thread exiting")

        dashboard_thread = threading.Thread(target=run_dashboard, daemon=False, name="DashboardThread")
        dashboard_thread.start()

        # Wait for shutdown signal
        logger.info("Main thread waiting for shutdown signal...")
        while not _shutdown_event.is_set():
            time.sleep(0.5)

    except KeyboardInterrupt:
        logger.info("Keyboard interrupt detected, shutting down...")

    except Exception as e:
        logger.error("Fatal error: %s", e, exc_info=True)

    finally:
        # Graceful shutdown
        logger.info("\nShutting down components...")

        # Stop dashboard first to unblock the server thread
        if dashboard:
            try:
                logger.info("Stopping dashboard...")
                dashboard.socketio.stop()
                logger.info("[+] Dashboard stopped")
            except Exception as e:
                logger.debug("Dashboard stop error: %s", str(e))

        if detector_engine:
            try:
                logger.info("Stopping detection engine...")
                detector_engine.stop()
                logger.info("[+] Detection engine stopped")
            except Exception as e:
                logger.error("Error stopping detection engine: %s", e)

        # Wait for dashboard thread to finish (max 5 seconds)
        if dashboard_thread and dashboard_thread.is_alive():
            logger.info("Waiting for dashboard thread to finish...")
            dashboard_thread.join(timeout=5)
            if dashboard_thread.is_alive():
                logger.warning("Dashboard thread did not terminate gracefully")

        logger.info("=" * 60)
        logger.info("Shutdown complete - goodbye!")
        logger.info("=" * 60)


if __name__ == "__main__":
    # Register signal handlers for graceful shutdown
    # Note: On Windows, only SIGINT and SIGTERM are available
    try:
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    except (ValueError, RuntimeError) as e:
        logger.warning(f"Could not register signal handlers: {e}")

    try:
        main()
    except KeyboardInterrupt:
        logger.info("Interrupted, exiting")
    except Exception as e:
        logger.error("Unexpected error: %s", e, exc_info=True)
    finally:
        # Force exit to ensure no hanging threads
        sys.exit(0)
