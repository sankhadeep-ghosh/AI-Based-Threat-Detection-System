"""
Additional dashboard routes for configuration management,
rule editing, and system control.
"""

from flask import Blueprint, request, jsonify, render_template
from pathlib import Path
import yaml
import json

from ids.utils.logger import setup_logger
from ids.config.config_loader import ConfigLoader
from ids.core.signature_detector import SignatureDetector

logger = setup_logger(__name__)

# Create blueprint for additional routes
dashboard_bp = Blueprint('dashboard', __name__)

config_loader = ConfigLoader()
signature_detector = SignatureDetector()

@dashboard_bp.route('/config-editor')
def config_editor():
    """Configuration editor interface."""
    return render_template('config_editor.html')

@dashboard_bp.route('/api/rules', methods=['GET', 'POST'])
def manage_rules():
    """API endpoint for managing detection rules."""
    try:
        rules_file = Path("config/rules.yaml")
        
        if request.method == 'GET':
            # Load current rules
            with open(rules_file, 'r') as f:
                rules = yaml.safe_load(f)
            return jsonify(rules)
        
        elif request.method == 'POST':
            # Update rules (validate first)
            new_rules = request.json
            
            # Basic validation
            if 'signatures' not in new_rules:
                return jsonify({"error": "Invalid rules format"}), 400
            
            # Save new rules
            with open(rules_file, 'w') as f:
                yaml.dump(new_rules, f, default_flow_style=False)
            
            # Reload rules in detector
            signature_detector.reload_rules()
            
            logger.info("Rules updated via dashboard")
            return jsonify({"status": "success"})
            
    except Exception as e:
        logger.error(f"Error managing rules: {e}")
        return jsonify({"error": str(e)}), 500

@dashboard_bp.route('/api/thresholds', methods=['GET', 'POST'])
def manage_thresholds():
    """API endpoint for managing behavior thresholds."""
    try:
        thresholds_file = Path("config/thresholds.yaml")
        
        if request.method == 'GET':
            with open(thresholds_file, 'r') as f:
                thresholds = yaml.safe_load(f)
            return jsonify(thresholds)
        
        elif request.method == 'POST':
            new_thresholds = request.json
            
            # Validate numeric values
            for category, settings in new_thresholds.items():
                for key, value in settings.items():
                    if 'time' in key and not isinstance(value, int):
                        return jsonify({"error": f"Invalid value for {category}.{key}"}), 400
                    elif 'max_' in key and not isinstance(value, int):
                        return jsonify({"error": f"Invalid value for {category}.{key}"}), 400
            
            # Save thresholds
            with open(thresholds_file, 'w') as f:
                yaml.dump(new_thresholds, f, default_flow_style=False)
            
            logger.info("Thresholds updated via dashboard")
            return jsonify({"status": "success", "message": "Thresholds updated. Restart required for changes to take effect."})
            
    except Exception as e:
        logger.error(f"Error managing thresholds: {e}")
        return jsonify({"error": str(e)}), 500

@dashboard_bp.route('/api/system/control', methods=['POST'])
def system_control():
    """System control endpoint (start/stop/restart)."""
    try:
        action = request.json.get('action')
        
        if action not in ['start', 'stop', 'restart']:
            return jsonify({"error": "Invalid action"}), 400
        
        # In a real implementation, you would control the detector engine here
        # This is a placeholder that logs the action
        logger.info(f"System control action requested: {action}")
        
        # TODO: Implement actual system control
        # This would require integration with the main detector engine
        
        return jsonify({
            "status": "success",
            "message": f"Action '{action}' initiated",
            "note": "System control not fully implemented"
        })
        
    except Exception as e:
        logger.error(f"Error in system control: {e}")
        return jsonify({"error": str(e)}), 500

@dashboard_bp.route('/api/logs')
def get_logs():
    """Get recent log entries."""
    try:
        logs_file = Path("logs/ids.log")
        lines = request.args.get('lines', 100, type=int)
        
        if not logs_file.exists():
            return jsonify({"logs": ["No log file found"]})
        
        # Read last N lines
        with open(logs_file, 'r') as f:
            all_lines = f.readlines()
            recent_logs = all_lines[-lines:] if len(all_lines) > lines else all_lines
        
        return jsonify({
            "logs": recent_logs,
            "total_lines": len(all_lines)
        })
        
    except Exception as e:
        logger.error(f"Error reading logs: {e}")
        return jsonify({"error": str(e)}), 500
