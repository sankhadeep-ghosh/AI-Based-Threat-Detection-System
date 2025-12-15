"""
Flask-SocketIO dashboard application - provides web interface for
real-time threat monitoring and visualization.
"""

from flask import Flask, render_template, jsonify, request, Response
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import json
from datetime import datetime
from threading import Lock, Thread
import time
from pathlib import Path

from ids.utils.logger import setup_logger
from ids.config.config_loader import get_config
from ids.database.db_manager import DatabaseManager
from ids.models.alert import Alert
import platform

logger = setup_logger(__name__)


class SafeJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder to safely serialize all types."""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if hasattr(obj, 'value'):  # Handle enums
            return obj.value
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        return str(obj)


def safe_json_response(data, status_code=200):
    """Create a safe JSON response that won't fail during serialization."""
    try:
        json_str = json.dumps(data, cls=SafeJSONEncoder, default=str)
        return Response(json_str, mimetype='application/json', status=status_code)
    except Exception as e:
        logger.error(f"Error creating JSON response: {e}", exc_info=True)
        error_response = json.dumps({
            "error": "Failed to serialize response",
            "details": str(e)
        })
        return Response(error_response, mimetype='application/json', status=500)


class DashboardApp:
    """
    Flask-SocketIO dashboard for real-time IDS monitoring.
    Features:
    - Real-time alert updates via WebSocket
    - Chart.js integration for metrics
    - REST API for data access
    - Alert management interface
    """

    def __init__(self, detector_engine=None):
        # Get absolute paths for templates and static
        dashboard_dir = Path(__file__).parent
        
        self.app = Flask(
            __name__,
            static_folder=str(dashboard_dir / 'static'),
            template_folder=str(dashboard_dir / 'templates')
        )
        self.app.config['SECRET_KEY'] = 'ids-dashboard-secret-key-change-in-production'
        self.app.json_encoder = SafeJSONEncoder
        CORS(self.app)

        self.socketio = SocketIO(
            self.app,
            cors_allowed_origins="*",
            async_mode='threading',
            logger=False,
            engineio_logger=False,
            ping_timeout=60,
            ping_interval=15,
            max_http_buffer_size=1e6,
            transports=['websocket', 'polling']  # WebSocket first for real-time
        )

        self.detector_engine = detector_engine
        self.db_manager = DatabaseManager()

        self._connected_clients = 0
        self._clients_lock = Lock()
        
        # Broadcast thread for periodic updates
        self._broadcast_thread = None
        self._broadcast_running = False

        self._register_routes()

        logger.info("DashboardApp initialized")

    # ------------------------------------------------------------------
    # ROUTES + SOCKET HANDLERS
    # ------------------------------------------------------------------
    def _register_routes(self):

        @self.app.before_request
        def before_request_handler():
            """Log all requests and ensure they complete safely."""
            logger.debug(f"Request: {request.method} {request.path}")

        @self.app.route('/')
        def index():
            try:
                return render_template('index.html')
            except Exception as e:
                logger.error(f"Error rendering index: {e}", exc_info=True)
                return jsonify({"error": str(e)}), 500

        @self.app.errorhandler(500)
        def handle_500(error):
            logger.error(f"500 Error: {error}", exc_info=True)
            return jsonify({"error": "Internal server error"}), 500

        @self.app.errorhandler(404)
        def handle_404(error):
            return jsonify({"error": "Not found"}), 404

        @self.app.route('/api/alerts')
        def get_alerts():
            try:
                limit = request.args.get('limit', 100, type=int)
                if limit > 1000:
                    limit = 1000
                if limit < 1:
                    limit = 10
                    
                alerts = self.db_manager.get_recent_alerts(limit)
                if alerts is None:
                    alerts = []
                
                result = [self._fix_alert_dict(a) for a in alerts]
                return jsonify({"alerts": result, "count": len(result)})
            except Exception as e:
                logger.error(f"Error in /api/alerts: {e}", exc_info=True)
                return jsonify({"error": str(e), "alerts": []}), 500

        @self.app.route('/api/stats')
        def get_stats():
            try:
                stats = self.db_manager.get_alert_stats()
                if stats is None or not isinstance(stats, dict):
                    stats = {}
                
                engine_stats = {}
                if self.detector_engine:
                    try:
                        engine_stats = self.detector_engine.get_stats()
                        if engine_stats is None:
                            engine_stats = {}
                    except Exception as e:
                        logger.error(f"Error getting engine stats: {e}")
                        engine_stats = {"error": str(e)}
                
                response = {
                    "database": stats,
                    "engine": engine_stats,
                    "timestamp": datetime.now().isoformat()
                }
                return jsonify(response)
            except Exception as e:
                logger.error(f"Error in /api/stats: {e}", exc_info=True)
                return jsonify({"error": str(e), "database": {}, "engine": {}}), 500

        @self.app.route('/api/config', methods=['GET'])
        def config():
            try:
                from ids.config.config_loader import config_loader
                cfg = config_loader.load_yaml("main.yaml")
                if cfg is None:
                    cfg = {}
                
                # Ensure all values are JSON serializable
                clean_cfg = {}
                for key, value in cfg.items():
                    if isinstance(value, dict):
                        clean_cfg[key] = value
                    else:
                        clean_cfg[key] = str(value) if value is not None else None
                
                return jsonify(clean_cfg)
            except Exception as e:
                logger.error(f"Error in /api/config: {e}", exc_info=True)
                return jsonify({"error": str(e)}), 500

        @self.app.route('/api/packets')
        def get_packets():
            try:
                limit = request.args.get('limit', 100, type=int)
                if limit > 1000:
                    limit = 1000
                if limit < 1:
                    limit = 10

                packets = self.db_manager.get_recent_packets(limit)
                return jsonify({"packets": packets, "count": len(packets)})
            except Exception as e:
                logger.error(f"Error in /api/packets: {e}", exc_info=True)
                return jsonify({"error": str(e), "packets": []}), 500

        @self.app.route('/api/packets/<int:packet_id>')
        def get_packet(packet_id):
            try:
                pkt = self.db_manager.get_packet_by_id(packet_id)
                if not pkt:
                    return jsonify({"error": "Not found"}), 404
                return jsonify(pkt)
            except Exception as e:
                logger.error(f"Error in /api/packets/<id>: {e}", exc_info=True)
                return jsonify({"error": str(e)}), 500

        @self.app.route('/api/interfaces')
        def get_interfaces():
            try:
                # Lazy-import to avoid circular imports
                from ids.core.packet_capture import get_available_interfaces
                interfaces = get_available_interfaces()
                configured = None
                try:
                    configured = self.detector_engine.packet_capture.interface if self.detector_engine and self.detector_engine.packet_capture else None
                except Exception:
                    configured = None

                return jsonify({
                    "available_interfaces": interfaces,
                    "configured_interface": configured,
                    "os": platform.system()
                })
            except Exception as e:
                logger.error(f"Error in /api/interfaces: {e}", exc_info=True)
                return jsonify({"error": str(e), "available_interfaces": []}), 500

        @self.app.route('/api/capture/status')
        def capture_status():
            try:
                running = False
                stats = {}
                iface = None
                bpf = None
                promisc = None
                if self.detector_engine and self.detector_engine.packet_capture:
                    pc = self.detector_engine.packet_capture
                    running = pc.is_running()
                    stats = pc.get_stats()
                    iface = pc.interface
                    bpf = pc.bpf_filter
                    promisc = pc.promiscuous

                return jsonify({
                    "running": running,
                    "interface": iface,
                    "bpf_filter": bpf,
                    "promiscuous": promisc,
                    "stats": stats
                })
            except Exception as e:
                logger.error(f"Error in /api/capture/status: {e}", exc_info=True)
                return jsonify({"error": str(e)}), 500

        @self.app.route('/api/capture/test', methods=['POST', 'GET'])
        def capture_test():
            """Inject a synthetic packet to test capture pipeline and DB storage."""
            try:
                test_packet = {
                    'timestamp': datetime.now(),
                    'source_ip': request.args.get('src', '10.0.0.1'),
                    'dest_ip': request.args.get('dst', '10.0.0.2'),
                    'source_port': request.args.get('sport', 1234, type=int),
                    'dest_port': request.args.get('dport', 80, type=int),
                    'protocol': request.args.get('proto', 'tcp'),
                    'length': 64,
                    'payload': request.args.get('payload', 'TEST-PAYLOAD'),
                    'payload_hex': request.args.get('payload_hex', None),
                    'raw_packet': (request.args.get('raw', None) or b'TEST_RAW')
                }

                # If we have an engine, put it through normal pipeline
                if self.detector_engine:
                    try:
                        self.detector_engine._handle_packet(test_packet)
                        return jsonify({'ok': True, 'message': 'Test packet injected into engine packet queue'})
                    except Exception as e:
                        logger.error(f"Error injecting packet into engine: {e}", exc_info=True)
                        # Fallback: store directly in DB

                packet_id = None
                try:
                    packet_id = self.db_manager.store_packet(test_packet)
                except Exception as e:
                    logger.error(f"Failed to store test packet directly: {e}")
                    return jsonify({'ok': False, 'error': str(e)}), 500

                return jsonify({'ok': True, 'packet_id': packet_id})
            except Exception as e:
                logger.error(f"Error in /api/capture/test: {e}", exc_info=True)
                return jsonify({"error": str(e)}), 500


        # WEBSOCKETS
        @self.socketio.on('connect')
        def handle_connect():
            with self._clients_lock:
                self._connected_clients += 1
                # Start broadcast thread on first client
                if self._connected_clients == 1 and not self._broadcast_running:
                    self._start_broadcast_thread()
            logger.info(f"Client connected ({self._connected_clients} online)")
            emit('connected', {'data': 'Connected to IDS Dashboard', 'timestamp': datetime.now().isoformat()})

        @self.socketio.on('disconnect')
        def handle_disconnect():
            with self._clients_lock:
                self._connected_clients -= 1
                # Stop broadcast thread when no clients
                if self._connected_clients == 0 and self._broadcast_running:
                    self._stop_broadcast_thread()
            logger.info(f"Client disconnected ({self._connected_clients} left)")

        @self.socketio.on('request_alerts')
        def handle_request_alerts(data):
            try:
                limit = data.get('limit', 50)
                alerts = self.db_manager.get_recent_alerts(limit)

                safe_alerts = [self._fix_alert_dict(a) for a in alerts]

                emit('alerts_update', {
                    'alerts': safe_alerts,
                    'timestamp': datetime.now().isoformat()
                })
            except Exception as e:
                logger.error(f"Error sending alerts: {e}")
                emit('error', {'message': str(e)})

    # ------------------------------------------------------------------
    # TIMESTAMP FIXER
    # ------------------------------------------------------------------
    def _fix_alert_dict(self, alert: Alert):
        """
        Ensures timestamps are always strings, never datetime objects.
        Safely converts Alert object to dictionary.
        """
        try:
            if alert is None:
                return {}
            
            # Convert alert to dict
            if hasattr(alert, 'to_dict'):
                data = alert.to_dict()
            elif hasattr(alert, '__dict__'):
                data = alert.__dict__.copy()
            else:
                data = {"error": "Cannot convert alert to dict"}
                return data
            
            # Ensure data is a dict
            if not isinstance(data, dict):
                data = {"error": f"Alert data is {type(data).__name__}, not dict"}
                return data
            
            # Fix timestamp
            ts = data.get("timestamp")
            if ts is None:
                data["timestamp"] = datetime.now().isoformat()
            elif isinstance(ts, datetime):
                data["timestamp"] = ts.isoformat()
            elif isinstance(ts, str):
                # Already a string, ensure it's ISO format
                if not ts:
                    data["timestamp"] = datetime.now().isoformat()
            else:
                # Convert any other type to string ISO format
                data["timestamp"] = str(ts)
            
            # Ensure all required fields are present and serializable
            required_fields = ["source_ip", "dest_ip", "alert_type", "severity", "confidence"]
            for field in required_fields:
                if field not in data:
                    data[field] = None
                # Ensure values are JSON-serializable
                if data[field] is not None and hasattr(data[field], '__dict__'):
                    # Convert enum-like objects to strings
                    if hasattr(data[field], 'value'):
                        data[field] = data[field].value
                    else:
                        data[field] = str(data[field])
            
            return data
            
        except Exception as e:
            logger.error(f"Error in _fix_alert_dict: {e}", exc_info=True)
            return {"error": str(e), "timestamp": datetime.now().isoformat()}

    # ------------------------------------------------------------------
    # BROADCAST HELPERS
    # ------------------------------------------------------------------
    def broadcast_alert(self, alert: Alert):
        try:
            with self._clients_lock:
                if self._connected_clients > 0:
                    self.socketio.emit('new_alert', {
                        'alert': self._fix_alert_dict(alert),
                        'timestamp': datetime.now().isoformat()
                    }, broadcast=True)
                    logger.info(f"Broadcast alert to {self._connected_clients} clients: {alert.name}")
        except Exception as e:
            logger.error(f"Error broadcasting alert: {e}")

    def broadcast_stats(self, stats: dict):
        try:
            with self._clients_lock:
                if self._connected_clients > 0:
                    self.socketio.emit('stats_update', {
                        'stats': stats,
                        'timestamp': datetime.now().isoformat()
                    }, broadcast=True, to=None)
        except Exception as e:
            logger.error(f"Error broadcasting stats: {e}")

    def _start_broadcast_thread(self):
        """Start periodic stats broadcast thread."""
        if not self._broadcast_running:
            self._broadcast_running = True
            self._broadcast_thread = Thread(target=self._periodic_broadcast, daemon=True)
            self._broadcast_thread.start()
            logger.info("Started stats broadcast thread")

    def _stop_broadcast_thread(self):
        """Stop periodic stats broadcast thread."""
        self._broadcast_running = False
        logger.info("Stopped stats broadcast thread")

    def _periodic_broadcast(self):
        """Periodically broadcast system stats to all connected clients."""
        while self._broadcast_running:
            try:
                time.sleep(2)  # Update every 2 seconds
                if not self._broadcast_running:
                    break
                    
                with self._clients_lock:
                    if self._connected_clients > 0 and self.detector_engine:
                        try:
                            stats = self.detector_engine.get_stats()
                            if stats:
                                self.socketio.emit('stats_update', {
                                    'stats': stats,
                                    'timestamp': datetime.now().isoformat()
                                }, broadcast=True)
                        except Exception as e:
                            logger.debug(f"Error in periodic broadcast: {e}")
            except Exception as e:
                logger.debug(f"Broadcast thread error: {e}")

    # ------------------------------------------------------------------
    # SERVER START
    # ------------------------------------------------------------------
    def run(self, host=None, port=None, debug=None):
        host = host or get_config("dashboard.host", "0.0.0.0")
        port = port or get_config("dashboard.port", 5000)
        debug = debug or get_config("dashboard.debug", False)

        logger.info(f"Starting dashboard server on {host}:{port}")

        try:
            # Use use_reloader=False and without_default_runner to avoid signal issues
            self.socketio.run(
                self.app,
                host=host,
                port=port,
                debug=False,  # Always False to avoid reloader issues
                use_reloader=False,
                log_output=False,
                allow_unsafe_werkzeug=True
            )
        except KeyboardInterrupt:
            logger.info("Dashboard interrupted via Ctrl+C")
        except Exception as e:
            logger.error(f"Dashboard error: {e}", exc_info=True)

    # For gunicorn / waitress
    def get_app(self):
        return self.app

    def shutdown_server(self):
        """Gracefully shutdown the Flask server."""
        try:
            self.socketio.stop()
            logger.info("SocketIO stopped")
        except Exception as e:
            logger.debug(f"Error stopping SocketIO: {e}")

    def stop(self):
        """Stop the dashboard server."""
        try:
            self.socketio.stop()
            logger.info("Dashboard server stopped")
        except Exception as e:
            logger.debug(f"Error stopping dashboard: {e}")
