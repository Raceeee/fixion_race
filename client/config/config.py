"""
config.py - Configuration Management for Fixion Client
Handles all configuration settings for the client-side components
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Any


class FixionConfig:
    """Configuration manager for Fixion client"""

    def __init__(self, config_file: str = "fixion_client_config.json"):
        self.config_file = config_file
        self.config = self._load_config()
        self._setup_logging()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create default"""
        default_config = {
            "server": {
                "ip": "192.168.1.100",
                "port": 8080,
                "timeout": 30,
                "retry_attempts": 3
            },
            "sandbox": {
                "enabled": True,
                "timeout": 45,
                "temp_dir": self._get_default_temp_dir(),
                "cleanup_after_analysis": True,
                "max_file_size_mb": 100
            },
            "analysis": {
                "quick_prescreen": True,
                "escalate_on_medium_confidence": True,
                "escalate_on_threat_detected": True,
                "escalate_high_risk_files": True,
                "local_timeout": 30,
                "server_timeout": 300,
                "skip_safe_locations": True
            },
            "file_types": {
                "safe_extensions": [".txt", ".pdf", ".jpg", ".png", ".gif", ".mp3", ".mp4", ".avi", ".doc", ".docx"],
                "high_risk_extensions": [".exe", ".dll", ".scr", ".bat", ".cmd", ".com", ".pif", ".msi"],
                "safe_locations": self._get_safe_locations(),
                "suspicious_locations": [
                    "Downloads",
                    "Temp",
                    "AppData\\Local\\Temp"
                ]
            },
            "logging": {
                "level": "INFO",
                "log_file": "fixion_client.log",
                "max_log_size_mb": 10,
                "backup_count": 5
            },
            "performance": {
                "max_concurrent_scans": 2,
                "cache_results": True,
                "cache_duration_hours": 24
            },
            "machine": {
                "id": self._generate_machine_id()
            },
            "user": {
                "id": "default_user"
            },
            "environment": {
                "type": "educational"
            },
            "auto_scanner": {
                "startup_scan": True,
                "scheduled_scans": True,
                "quick_scan_hours": 6,
                "full_scan_days": 7,
                "max_duration_minutes": 30
            },
            "monitor": {
                "paths": self._get_default_monitor_paths(),
                "excluded_extensions": ['.tmp', '.log', '.txt', '.pdf', '.jpg', '.png', '.gif', '.mp4', '.avi'],
                "analysis_delay_seconds": 5,
                "max_file_size_mb": 100
            },
            "network": {
                "block_mode": "educational",
                "log_all_connections": False,
                "notifications_enabled": True,
                "monitoring_interval": 5
            },
            "quarantine": {
                "directory": self._get_default_quarantine_dir()
            },
            "yara": {
                "max_file_size_mb": 100
            }
        }

        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                    # Merge loaded config with defaults
                    self._merge_config(default_config, loaded_config)
                    return default_config
            else:
                # Create default config file
                self._save_config(default_config)
                return default_config
        except Exception as e:
            print(f"Error loading config: {e}. Using defaults.")
            return default_config

    def _get_default_temp_dir(self) -> str:
        """Get platform-appropriate temp directory"""
        if os.name == 'nt':
            return "C:\\Temp\\Fixion"
        else:
            return "/tmp/fixion"

    def _get_safe_locations(self) -> List[str]:
        """Get platform-appropriate safe locations"""
        if os.name == 'nt':
            return [
                "C:\\Windows\\System32",
                "C:\\Windows\\SysWOW64",
                "C:\\Program Files",
                "C:\\Program Files (x86)"
            ]
        else:
            return [
                "/usr/bin",
                "/usr/sbin",
                "/bin",
                "/sbin",
                "/usr/lib",
                "/lib"
            ]

    def _get_default_monitor_paths(self) -> List[str]:
        """Get default monitoring paths"""
        paths = [
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Documents")
        ]

        # Add temp directory
        temp_dir = os.environ.get("TEMP") or os.environ.get("TMP") or "/tmp"
        paths.append(temp_dir)

        return paths

    def _get_default_quarantine_dir(self) -> str:
        """Get default quarantine directory"""
        temp_dir = self._get_default_temp_dir()
        return os.path.join(temp_dir, "Quarantine")

    def _generate_machine_id(self) -> str:
        """Generate a unique machine ID"""
        import uuid
        import socket

        try:
            # Try to get hostname
            hostname = socket.gethostname()
            # Generate UUID based on hostname and MAC address
            machine_id = f"{hostname}_{uuid.getnode()}"
            return machine_id
        except:
            # Fallback to random UUID
            return str(uuid.uuid4())

    def _merge_config(self, default: Dict, loaded: Dict):
        """Recursively merge loaded config with defaults"""
        for key, value in loaded.items():
            if key in default:
                if isinstance(value, dict) and isinstance(default[key], dict):
                    self._merge_config(default[key], value)
                else:
                    default[key] = value

    def _save_config(self, config: Dict):
        """Save configuration to file"""
        try:
            # Ensure directory exists
            config_dir = os.path.dirname(self.config_file)
            if config_dir and not os.path.exists(config_dir):
                os.makedirs(config_dir)

            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            print(f"Error saving config: {e}")

    def _setup_logging(self):
        """Setup logging based on configuration"""
        log_config = self.config["logging"]

        # Create logs directory if it doesn't exist
        log_file = log_config["log_file"]
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)

        # Configure logging
        logging.basicConfig(
            level=getattr(logging, log_config["level"]),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )

    def get(self, key_path: str, default=None):
        """Get configuration value using dot notation (e.g., 'server.ip')"""
        keys = key_path.split('.')
        value = self.config

        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default

        return value

    def set(self, key_path: str, value):
        """Set configuration value using dot notation"""
        keys = key_path.split('.')
        config = self.config

        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]

        config[keys[-1]] = value
        self._save_config(self.config)

    def get_server_url(self) -> str:
        """Get complete server URL"""
        return f"http://{self.get('server.ip')}:{self.get('server.port')}"

    def get_temp_dir(self) -> str:
        """Get temporary directory and ensure it exists"""
        temp_dir = self.get('sandbox.temp_dir')
        os.makedirs(temp_dir, exist_ok=True)
        return temp_dir

    def is_safe_location(self, file_path: str) -> bool:
        """Check if file is in a safe location"""
        file_path_lower = file_path.lower()
        safe_locations = self.get('file_types.safe_locations', [])

        return any(file_path_lower.startswith(loc.lower()) for loc in safe_locations)

    def is_suspicious_location(self, file_path: str) -> bool:
        """Check if file is in a suspicious location"""
        file_path_lower = file_path.lower()
        suspicious_locations = self.get('file_types.suspicious_locations', [])

        return any(loc.lower() in file_path_lower for loc in suspicious_locations)

    def is_safe_extension(self, file_path: str) -> bool:
        """Check if file has a safe extension"""
        ext = os.path.splitext(file_path)[1].lower()
        safe_extensions = self.get('file_types.safe_extensions', [])

        return ext in safe_extensions

    def is_high_risk_extension(self, file_path: str) -> bool:
        """Check if file has a high-risk extension"""
        ext = os.path.splitext(file_path)[1].lower()
        high_risk_extensions = self.get('file_types.high_risk_extensions', [])

        return ext in high_risk_extensions

    def should_skip_analysis(self, file_path: str) -> bool:
        """Determine if file analysis should be skipped"""
        # Skip if in safe location and has safe extension
        return (self.is_safe_location(file_path) and
                self.is_safe_extension(file_path))

    def reload_config(self):
        """Reload configuration from file"""
        self.config = self._load_config()
        self._setup_logging()


# Global config instance
config = FixionConfig()


# Convenience functions
def get_config(key_path: str, default=None):
    """Get configuration value"""
    return config.get(key_path, default)


def set_config(key_path: str, value):
    """Set configuration value"""
    config.set(key_path, value)


def get_logger(name: str):
    """Get logger instance"""
    return logging.getLogger(name)


# Export commonly used values
SERVER_URL = config.get_server_url()
TEMP_DIR = config.get_temp_dir()
SANDBOX_TIMEOUT = config.get('sandbox.timeout', 45)
ANALYSIS_TIMEOUT = config.get('analysis.local_timeout', 30)