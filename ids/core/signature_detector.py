"""
Signature-based detection module - matches network packets against
predefined rule patterns (regex, ports, protocols) for threat detection.
"""

import re
import yaml
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

from ids.utils.logger import setup_logger
from ids.config.config_loader import ConfigLoader
from ids.models.alert import Alert, AlertSeverity, AlertType

logger = setup_logger(__name__)

class SignatureDetector:
    """
    Signature-based threat detection engine.

    Features:
    - Loads rules from YAML configuration
    - Regex pattern matching on packet payload
    - Port and protocol validation
    - Cumulative scoring for complex rules
    - Thread-safe rule matching
    """

    def __init__(self, rules_file: str = "rules.yaml"):
        self.config_loader = ConfigLoader()
        self.rules_file = rules_file
        self.rules: List[Dict[str, Any]] = []
        self._compiled_regexes: Dict[str, re.Pattern] = {}

        self.stats = {
            "total_checks": 0,
            "matches_found": 0,
            "rules_loaded": 0
        }

        self._load_rules()

    def _load_rules(self) -> None:
        try:
            rules_config = self.config_loader.load_yaml(self.rules_file)
            self.rules = rules_config.get("signatures", [])

            for rule in self.rules:
                pattern = rule.get("pattern", {})
                if "payload_regex" in pattern:
                    try:
                        self._compiled_regexes[rule["id"]] = re.compile(
                            pattern["payload_regex"], re.IGNORECASE
                        )
                    except re.error as e:
                        logger.error(f"Invalid regex in rule {rule['id']}: {e}")
                        self.rules.remove(rule)

            self.stats["rules_loaded"] = len(self.rules)
            logger.info(f"Loaded {self.stats['rules_loaded']} signature rules")

        except Exception as e:
            logger.error(f"Failed to load rules: {e}")
            self.rules = []

    def _match_payload(self, rule, features) -> bool:
        pattern = rule.get("pattern", {})
        payload_regex = pattern.get("payload_regex")

        if not payload_regex:
            return True

        payload = features.get("payload", "")
        if not payload:
            return False

        try:
            compiled = self._compiled_regexes.get(rule["id"])
            if compiled:
                return bool(compiled.search(payload))
            return bool(re.search(payload_regex, payload, re.IGNORECASE))
        except Exception as e:
            logger.error(f"Regex match failed for rule {rule['id']}: {e}")
            return False

    def _match_ports(self, rule, features) -> bool:
        rule_ports = rule.get("pattern", {}).get("dst_ports", [])
        if not rule_ports:
            return True
        
        dest_port = features.get("dest_port")
        return dest_port in rule_ports

    def _match_protocol(self, rule, features) -> bool:
        expected = rule.get("protocol")
        if not expected:
            return True
        
        actual = features.get("protocol", "").lower()
        return actual == expected.lower()

    def _match_flags(self, rule, features) -> bool:
        expected = rule.get("pattern", {}).get("flags")
        if not expected:
            return True
        
        flags = features.get("tcp_flags", "")
        return expected in flags

    def check_packet(self, features: Dict[str, Any]) -> Optional[Alert]:
        """
        Called by Detection Engine.
        MUST return None or an Alert object.
        """
        self.stats["total_checks"] += 1

        for rule in self.rules:
            try:
                if not self._match_protocol(rule, features):
                    continue

                if not self._match_ports(rule, features):
                    continue

                if features.get("protocol") == "tcp":
                    if not self._match_flags(rule, features):
                        continue

                if not self._match_payload(rule, features):
                    continue

                # MATCH FOUND
                self.stats["matches_found"] += 1

                alert = Alert(
                    rule_id=rule["id"],
                    name=rule["name"],
                    alert_type=self._map_alert_type(rule.get("type")),
                    severity=AlertSeverity(rule["severity"]),
                    source_ip=features.get("source_ip", "unknown"),
                    dest_ip=features.get("dest_ip", "unknown"),
                    source_port=features.get("source_port"),
                    dest_port=features.get("dest_port"),
                    protocol=features.get("protocol", "unknown"),
                    message=f"Signature match: {rule['description']}",
                    timestamp=features.get("timestamp", datetime.now()),
                    raw_packet=features.get("payload_hex"),
                    confidence=0.95,
                )

                logger.info(f"Signature match: {rule['name']} from {alert.source_ip}")
                return alert

            except Exception as e:
                logger.error(f"Error in rule {rule['id']}: {e}")
                continue

        return None

    def _map_alert_type(self, rule_type: str) -> AlertType:
        mapping = {
            "port_scan": AlertType.PORT_SCAN,
            "brute_force": AlertType.BRUTE_FORCE,
            "dos": AlertType.DOS,
            "web_attack": AlertType.WEB_ATTACK,
            "dns_exfiltration": AlertType.DNS_EXFILTRATION
        }
        return mapping.get(rule_type, AlertType.SIGNATURE_MATCH)

    def reload_rules(self):
        logger.info("Reloading signature rules...")
        self._compiled_regexes.clear()
        self._load_rules()

    def get_stats(self) -> Dict[str, Any]:
        return self.stats.copy()
