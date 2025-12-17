import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from ids.database.db_manager import DatabaseManager
from ids.core.detector_engine import DetectorEngine
from datetime import datetime

# Create DB manager
mgr = DatabaseManager(db_path='data/test_ids.db')
print('DB initialized at', mgr.db_path)

# Simulate packet features
features = {
    'timestamp': datetime.now(),
    'source_ip': '192.0.2.1',
    'dest_ip': '198.51.100.2',
    'source_port': 12345,
    'dest_port': 80,
    'protocol': 'tcp',
    'length': 100,
    'payload': 'GET / HTTP/1.1',
    'payload_hex': '47455420',
    'raw_packet': b'RAWBYTES'
}

packet_id = mgr.store_packet(features)
print('Stored packet id:', packet_id)

pkt = mgr.get_packet_by_id(packet_id)
print('Fetched packet:', pkt)

# Now create an alert and ensure packet_id is linked
from ids.models.alert import Alert, AlertSeverity, AlertType
alert = Alert(
    rule_id='TST-1',
    name='Test Alert',
    alert_type=AlertType.SIGNATURE_MATCH,
    severity=AlertSeverity.LOW,
    source_ip=features['source_ip'],
    dest_ip=features['dest_ip'],
    source_port=features['source_port'],
    dest_port=features['dest_port'],
    protocol=features['protocol'],
    message='Test',
    timestamp=features['timestamp'],
    raw_packet=features['payload_hex'],
    confidence=0.5,
    packet_id=packet_id
)
alert_id = mgr.store_alert(alert)
print('Stored alert id:', alert_id)

alerts = mgr.get_recent_alerts(10)
print('Recent alerts count:', len(alerts))
print('First alert packet_id:', getattr(alerts[0], 'packet_id', None))
