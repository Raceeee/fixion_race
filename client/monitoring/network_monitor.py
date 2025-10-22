"""
network_monitor.py - Fixed Network Security Monitor for Fixion
Enhanced dependency handling to avoid cryptography/scapy issues
"""

import os
import time
import threading
import queue
import json
import subprocess
from typing import Dict, List, Any, Optional, Set
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

# Import with error handling
try:
    from client.config.config import get_config, get_logger
except ImportError:
    def get_config(key, default=None):
        return default
    def get_logger(name):
        import logging
        return logging.getLogger(name)

logger = get_logger(__name__)

# Try to import network monitoring libraries with better error handling
try:
    import psutil
    PSUTIL_AVAILABLE = True
    logger.info("psutil available for network monitoring")
except ImportError:
    PSUTIL_AVAILABLE = False
    logger.warning("psutil not installed. Run: pip install psutil")

# Disable Scapy for now due to cryptography conflicts
SCAPY_AVAILABLE = False
logger.info("Scapy disabled to avoid cryptography conflicts")

# Alternative: Try to import socket for basic network monitoring
try:
    import socket
    SOCKET_AVAILABLE = True
except ImportError:
    SOCKET_AVAILABLE = False


class AlertLevel(Enum):
    """Network alert severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class NetworkAlert:
    """Network security alert"""
    alert_id: str
    timestamp: datetime
    alert_type: str
    level: AlertLevel
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    description: str
    process_name: str = ""
    process_pid: int = 0
    details: Dict[str, Any] = None

    def __post_init__(self):
        if self.details is None:
            self.details = {}


class SimpleNetworkAnalyzer:
    """Simple network analyzer without Scapy dependencies"""

    def __init__(self):
        self.suspicious_ports = {
            1234: "Possible backdoor",
            4444: "Common reverse shell",
            5555: "Android Debug Bridge (suspicious if unexpected)",
            6666: "Possible malware communication",
            8080: "HTTP proxy (monitor for abuse)",
            9999: "Common backdoor port",
            3389: "RDP (monitor for brute force)",
            22: "SSH (monitor for brute force)",
            23: "Telnet (insecure protocol)",
            135: "Windows RPC (often targeted)"
        }

        self.trusted_processes = {
            'chrome.exe', 'firefox.exe', 'msedge.exe',
            'outlook.exe', 'teams.exe', 'zoom.exe',
            'python.exe', 'pythonw.exe'
        }

    def analyze_connection(self, connection: Dict[str, Any]) -> List[NetworkAlert]:
        """Analyze a connection and return alerts"""
        alerts = []

        try:
            remote_ip = connection['remote_ip']
            remote_port = connection['remote_port']
            process_name = connection['process_name'].lower()

            # Check suspicious ports
            if remote_port in self.suspicious_ports:
                alert = NetworkAlert(
                    alert_id=f"suspicious_port_{int(time.time())}",
                    timestamp=datetime.now(),
                    alert_type="suspicious_port",
                    level=AlertLevel.MEDIUM,
                    source_ip=connection['local_ip'],
                    destination_ip=remote_ip,
                    source_port=connection['local_port'],
                    destination_port=remote_port,
                    protocol=connection['protocol'],
                    description=f"Connection to suspicious port {remote_port}: {self.suspicious_ports[remote_port]}",
                    process_name=connection['process_name'],
                    process_pid=connection['process_pid']
                )
                alerts.append(alert)

            # Check for unknown processes making network connections
            if process_name and process_name not in self.trusted_processes:
                if any(keyword in process_name for keyword in ['nc', 'netcat', 'ncat', 'powershell', 'cmd']):
                    alert = NetworkAlert(
                        alert_id=f"suspicious_process_{int(time.time())}",
                        timestamp=datetime.now(),
                        alert_type="suspicious_process",
                        level=AlertLevel.HIGH,
                        source_ip=connection['local_ip'],
                        destination_ip=remote_ip,
                        source_port=connection['local_port'],
                        destination_port=remote_port,
                        protocol=connection['protocol'],
                        description=f"Suspicious process network activity: {process_name}",
                        process_name=connection['process_name'],
                        process_pid=connection['process_pid']
                    )
                    alerts.append(alert)

            # Check for private IP ranges that might be suspicious
            if self._is_potentially_suspicious_ip(remote_ip):
                alert = NetworkAlert(
                    alert_id=f"suspicious_ip_{int(time.time())}",
                    timestamp=datetime.now(),
                    alert_type="unusual_ip",
                    level=AlertLevel.LOW,
                    source_ip=connection['local_ip'],
                    destination_ip=remote_ip,
                    source_port=connection['local_port'],
                    destination_port=remote_port,
                    protocol=connection['protocol'],
                    description=f"Connection to potentially unusual IP range: {remote_ip}",
                    process_name=connection['process_name'],
                    process_pid=connection['process_pid']
                )
                alerts.append(alert)

        except Exception as e:
            logger.debug(f"Error analyzing connection: {e}")

        return alerts

    def _is_potentially_suspicious_ip(self, ip: str) -> bool:
        """Check if IP might be suspicious (basic heuristics)"""
        try:
            # Skip localhost and common private ranges
            if ip.startswith(('127.', '192.168.', '10.0.0.')):
                return False

            # Flag unusual private ranges
            if ip.startswith(('172.16.', '169.254.', '224.')):
                return True

            return False
        except:
            return False


class NetworkMonitor:
    """Network security monitor - FIXED for dependency issues"""

    def __init__(self):
        self.monitoring = False
        self.monitor_thread = None
        self.analysis_thread = None
        self.stop_event = threading.Event()

        # Initialize network analyzer
        self.analyzer = SimpleNetworkAnalyzer()

        # Monitoring data
        self.alerts_queue = queue.Queue()
        self.active_connections = {}
        self.suspicious_ips = set()
        self.blocked_ips = set()
        self.connection_history = []

        # Statistics
        self.stats = {
            'monitoring_started': None,
            'total_connections': 0,
            'alerts_generated': 0,
            'threats_blocked': 0,
            'packets_analyzed': 0,
            'unique_ips_seen': 0
        }

        # Configuration
        self.monitor_interfaces = get_config('network.interfaces', ['all'])
        self.alert_threshold = get_config('network.alert_threshold', 10)
        self.analysis_interval = get_config('network.analysis_interval', 5.0)
        self.max_history = get_config('network.max_history', 1000)

    def start_monitoring(self) -> bool:
        """Start network monitoring"""
        if self.monitoring:
            logger.warning("Network monitoring already active")
            return True

        if not PSUTIL_AVAILABLE:
            logger.error("psutil not available - network monitoring disabled")
            return False

        try:
            self.monitoring = True
            self.stop_event.clear()
            self.stats['monitoring_started'] = datetime.now()

            # Start monitoring thread
            self.monitor_thread = threading.Thread(target=self._monitor_worker, daemon=True)
            self.monitor_thread.start()

            # Start analysis thread
            self.analysis_thread = threading.Thread(target=self._analysis_worker, daemon=True)
            self.analysis_thread.start()

            logger.info("Network monitoring started successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to start network monitoring: {e}")
            self.monitoring = False
            return False

    def stop_monitoring(self):
        """Stop network monitoring"""
        if not self.monitoring:
            return

        try:
            self.monitoring = False
            self.stop_event.set()

            # Wait for threads to stop
            if self.monitor_thread and self.monitor_thread.is_alive():
                self.monitor_thread.join(timeout=5)

            if self.analysis_thread and self.analysis_thread.is_alive():
                self.analysis_thread.join(timeout=5)

            logger.info("Network monitoring stopped")

        except Exception as e:
            logger.error(f"Error stopping network monitoring: {e}")

    def _monitor_worker(self):
        """Main monitoring worker thread"""
        logger.info("Network monitor worker started")

        while not self.stop_event.is_set():
            try:
                # Monitor active network connections
                self._monitor_connections()

                # Monitor network statistics
                self._monitor_network_stats()

                # Clean up old data
                self._cleanup_old_data()

                # Sleep before next iteration
                time.sleep(self.analysis_interval)

            except Exception as e:
                logger.error(f"Error in network monitor worker: {e}")
                time.sleep(5)

        logger.info("Network monitor worker stopped")

    def _monitor_connections(self):
        """Monitor active network connections using psutil"""
        try:
            connections = psutil.net_connections(kind='inet')
            current_time = datetime.now()
            current_ips = set()

            for conn in connections:
                try:
                    # Skip if no remote address
                    if not conn.raddr:
                        continue

                    # Extract connection info
                    local_ip, local_port = conn.laddr
                    remote_ip, remote_port = conn.raddr
                    protocol = 'TCP' if conn.type == 1 else 'UDP'
                    current_ips.add(remote_ip)

                    # Get process info safely
                    process_name = ""
                    process_pid = conn.pid or 0

                    if conn.pid:
                        try:
                            process = psutil.Process(conn.pid)
                            process_name = process.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                            process_name = "Unknown"

                    # Create connection record
                    connection_record = {
                        'timestamp': current_time,
                        'local_ip': local_ip,
                        'local_port': local_port,
                        'remote_ip': remote_ip,
                        'remote_port': remote_port,
                        'protocol': protocol,
                        'process_name': process_name,
                        'process_pid': process_pid,
                        'status': conn.status
                    }

                    # Create connection ID
                    conn_id = f"{local_ip}:{local_port}->{remote_ip}:{remote_port}"

                    # Check if this is a new connection
                    if conn_id not in self.active_connections:
                        self.active_connections[conn_id] = connection_record
                        self.stats['total_connections'] += 1

                        # Store in history
                        self.connection_history.append(connection_record.copy())

                        # Analyze new connection for threats
                        alerts = self.analyzer.analyze_connection(connection_record)
                        for alert in alerts:
                            self.alerts_queue.put(alert)
                            self.stats['alerts_generated'] += 1
                    else:
                        # Update existing connection
                        self.active_connections[conn_id]['timestamp'] = current_time

                except Exception as e:
                    logger.debug(f"Error processing connection: {e}")

            # Update unique IPs count
            self.stats['unique_ips_seen'] = len(current_ips)

            # Clean up old connections (older than 5 minutes)
            cutoff_time = current_time - timedelta(minutes=5)
            self.active_connections = {
                k: v for k, v in self.active_connections.items()
                if v['timestamp'] > cutoff_time
            }

        except Exception as e:
            logger.error(f"Error monitoring connections: {e}")

    def _monitor_network_stats(self):
        """Monitor network statistics for anomalies"""
        try:
            # Get network I/O stats
            net_io = psutil.net_io_counters()

            # Update stats
            self.stats['packets_analyzed'] = net_io.packets_sent + net_io.packets_recv

            # Simple bandwidth monitoring
            bytes_total = net_io.bytes_sent + net_io.bytes_recv
            if hasattr(self, '_last_bytes_total'):
                bytes_diff = bytes_total - self._last_bytes_total
                # Could add bandwidth spike detection here
                if bytes_diff > 100 * 1024 * 1024:  # More than 100MB in interval
                    logger.info(f"High bandwidth usage detected: {bytes_diff / 1024 / 1024:.1f} MB")

            self._last_bytes_total = bytes_total

        except Exception as e:
            logger.debug(f"Error monitoring network stats: {e}")

    def _cleanup_old_data(self):
        """Clean up old data to prevent memory leaks"""
        try:
            # Limit connection history
            if len(self.connection_history) > self.max_history:
                self.connection_history = self.connection_history[-self.max_history:]

            # Clean up old suspicious IPs (older than 1 hour)
            # This would require timestamp tracking for suspicious IPs
            # For now, just limit the size
            if len(self.suspicious_ips) > 100:
                # Keep only the most recent 50
                self.suspicious_ips = set(list(self.suspicious_ips)[-50:])

        except Exception as e:
            logger.debug(f"Error cleaning up old data: {e}")

    def _analysis_worker(self):
        """Process network alerts"""
        logger.info("Network analysis worker started")

        while not self.stop_event.is_set():
            try:
                # Process alerts from queue
                try:
                    alert = self.alerts_queue.get(timeout=1.0)
                    self._process_alert(alert)
                    self.alerts_queue.task_done()
                except queue.Empty:
                    continue

            except Exception as e:
                logger.error(f"Error in network analysis worker: {e}")

        logger.info("Network analysis worker stopped")

    def _process_alert(self, alert: NetworkAlert):
        """Process a network security alert"""
        try:
            logger.warning(f"Network Alert [{alert.level.value.upper()}]: {alert.description}")
            logger.info(f"Details: {alert.source_ip}:{alert.source_port} -> "
                       f"{alert.destination_ip}:{alert.destination_port} ({alert.protocol})")

            # Take action based on alert level
            if alert.level in [AlertLevel.HIGH, AlertLevel.CRITICAL]:
                self._handle_high_severity_alert(alert)
            elif alert.level == AlertLevel.MEDIUM:
                self._handle_medium_severity_alert(alert)

            # Log alert to file or database
            self._log_alert(alert)

        except Exception as e:
            logger.error(f"Error processing alert: {e}")

    def _handle_high_severity_alert(self, alert: NetworkAlert):
        """Handle high severity network alerts"""
        try:
            # Add IP to suspicious list
            self.suspicious_ips.add(alert.destination_ip)

            # Log the action
            logger.warning(f"HIGH SEVERITY: Marked {alert.destination_ip} as suspicious")

            # In a real implementation, you might:
            # - Block the IP using Windows Firewall
            # - Kill the suspicious process
            # - Send notifications to administrators

            self.stats['threats_blocked'] += 1

        except Exception as e:
            logger.error(f"Error handling high severity alert: {e}")

    def _handle_medium_severity_alert(self, alert: NetworkAlert):
        """Handle medium severity network alerts"""
        try:
            # Add to monitoring list
            self.suspicious_ips.add(alert.destination_ip)
            logger.info(f"MEDIUM SEVERITY: Monitoring IP {alert.destination_ip}")

        except Exception as e:
            logger.error(f"Error handling medium severity alert: {e}")

    def _log_alert(self, alert: NetworkAlert):
        """Log alert to storage"""
        try:
            # Convert alert to dictionary for JSON serialization
            alert_dict = {
                'alert_id': alert.alert_id,
                'timestamp': alert.timestamp.isoformat(),
                'alert_type': alert.alert_type,
                'level': alert.level.value,
                'source_ip': alert.source_ip,
                'destination_ip': alert.destination_ip,
                'source_port': alert.source_port,
                'destination_port': alert.destination_port,
                'protocol': alert.protocol,
                'description': alert.description,
                'process_name': alert.process_name,
                'process_pid': alert.process_pid,
                'details': alert.details
            }

            # Log to debug for now
            logger.debug(f"Alert logged: {json.dumps(alert_dict, indent=2)}")

        except Exception as e:
            logger.error(f"Error logging alert: {e}")

    def block_ip(self, ip: str, reason: str = "Manual block") -> bool:
        """Block an IP address"""
        try:
            self.blocked_ips.add(ip)
            self.suspicious_ips.add(ip)

            # Log the action
            logger.info(f"IP blocked: {ip} - {reason}")

            # In a real implementation, you would add Windows Firewall rule:
            # netsh advfirewall firewall add rule name="Block {ip}" dir=out action=block remoteip={ip}

            return True

        except Exception as e:
            logger.error(f"Error blocking IP {ip}: {e}")
            return False

    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address"""
        try:
            self.blocked_ips.discard(ip)
            self.suspicious_ips.discard(ip)

            logger.info(f"IP unblocked: {ip}")
            return True

        except Exception as e:
            logger.error(f"Error unblocking IP {ip}: {e}")
            return False

    def get_status(self) -> Dict[str, Any]:
        """Get network monitor status"""
        return {
            'monitoring': self.monitoring,
            'psutil_available': PSUTIL_AVAILABLE,
            'scapy_available': SCAPY_AVAILABLE,
            'socket_available': SOCKET_AVAILABLE,
            'active_connections': len(self.active_connections),
            'suspicious_ips': len(self.suspicious_ips),
            'blocked_ips': len(self.blocked_ips),
            'alerts_queued': self.alerts_queue.qsize(),
            'connection_history_size': len(self.connection_history),
            'statistics': self.stats.copy()
        }

    def get_recent_alerts(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get recent network alerts"""
        # Return alerts from connection history that would have triggered alerts
        recent_alerts = []
        cutoff_time = datetime.now() - timedelta(hours=hours)

        for conn in self.connection_history:
            if conn['timestamp'] > cutoff_time:
                alerts = self.analyzer.analyze_connection(conn)
                for alert in alerts:
                    recent_alerts.append({
                        'timestamp': alert.timestamp.isoformat(),
                        'level': alert.level.value,
                        'description': alert.description,
                        'source_ip': alert.source_ip,
                        'destination_ip': alert.destination_ip,
                        'process_name': alert.process_name
                    })

        return recent_alerts[-50:]  # Return last 50 alerts

    def get_active_connections(self) -> List[Dict[str, Any]]:
        """Get list of active network connections"""
        return [
            {
                'local_ip': conn['local_ip'],
                'local_port': conn['local_port'],
                'remote_ip': conn['remote_ip'],
                'remote_port': conn['remote_port'],
                'protocol': conn['protocol'],
                'process_name': conn['process_name'],
                'process_pid': conn['process_pid'],
                'status': conn['status'],
                'timestamp': conn['timestamp'].isoformat()
            }
            for conn in self.active_connections.values()
        ]

    def get_suspicious_ips(self) -> List[str]:
        """Get list of suspicious IP addresses"""
        return list(self.suspicious_ips)

    def get_blocked_ips(self) -> List[str]:
        """Get list of blocked IP addresses"""
        return list(self.blocked_ips)

    def get_network_summary(self) -> Dict[str, Any]:
        """Get network activity summary"""
        return {
            'total_connections_monitored': self.stats['total_connections'],
            'active_connections': len(self.active_connections),
            'unique_ips_seen': self.stats['unique_ips_seen'],
            'alerts_generated': self.stats['alerts_generated'],
            'threats_blocked': self.stats['threats_blocked'],
            'monitoring_duration': (
                (datetime.now() - self.stats['monitoring_started']).total_seconds()
                if self.stats['monitoring_started'] else 0
            ),
            'top_processes': self._get_top_processes(),
            'top_remote_ips': self._get_top_remote_ips()
        }

    def _get_top_processes(self) -> List[Dict[str, Any]]:
        """Get top processes by connection count"""
        process_counts = {}
        for conn in self.connection_history[-100:]:  # Last 100 connections
            process = conn['process_name']
            if process:
                process_counts[process] = process_counts.get(process, 0) + 1

        return [
            {'process': proc, 'connections': count}
            for proc, count in sorted(process_counts.items(),
                                    key=lambda x: x[1], reverse=True)[:10]
        ]

    def _get_top_remote_ips(self) -> List[Dict[str, Any]]:
        """Get top remote IPs by connection count"""
        ip_counts = {}
        for conn in self.connection_history[-100:]:  # Last 100 connections
            ip = conn['remote_ip']
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

        return [
            {'ip': ip, 'connections': count}
            for ip, count in sorted(ip_counts.items(),
                                  key=lambda x: x[1], reverse=True)[:10]
        ]

    def clear_alerts(self):
        """Clear the alerts queue"""
        try:
            while not self.alerts_queue.empty():
                self.alerts_queue.get_nowait()
                self.alerts_queue.task_done()
            logger.info("Alerts queue cleared")
        except:
            pass

    def clear_history(self):
        """Clear connection history"""
        self.connection_history = []
        self.suspicious_ips = set()
        logger.info("Network monitoring history cleared")


# Convenience functions
def create_network_monitor():
    """Create and initialize network monitor"""
    monitor = NetworkMonitor()
    return monitor


def start_network_monitoring():
    """Start network monitoring"""
    monitor = create_network_monitor()
    if monitor.start_monitoring():
        return monitor
    else:
        return None


# Main function for testing
if __name__ == "__main__":
    import sys

    monitor = NetworkMonitor()

    if len(sys.argv) > 1:
        if sys.argv[1] == "start":
            if monitor.start_monitoring():
                print("Network monitoring started successfully")
                print("Dependencies:")
                print(f"  - psutil: {'Available' if PSUTIL_AVAILABLE else 'Not Available'}")
                print(f"  - scapy: {'Available' if SCAPY_AVAILABLE else 'Disabled (cryptography conflicts)'}")
                print("\nPress Ctrl+C to stop...")

                try:
                    while True:
                        status = monitor.get_status()
                        print(f"\nStatus Update:")
                        print(f"  Active connections: {status['active_connections']}")
                        print(f"  Suspicious IPs: {status['suspicious_ips']}")
                        print(f"  Alerts queued: {status['alerts_queued']}")
                        print(f"  Total connections seen: {status['statistics']['total_connections']}")
                        time.sleep(10)
                except KeyboardInterrupt:
                    print("\nStopping network monitoring...")
                    monitor.stop_monitoring()
                    print("Network monitoring stopped")
            else:
                print("Failed to start network monitoring")
                print("Make sure psutil is installed: pip install psutil")

        elif sys.argv[1] == "status":
            status = monitor.get_status()
            print("Network Monitor Status:")
            for key, value in status.items():
                print(f"  {key}: {value}")

        elif sys.argv[1] == "test":
            print("Testing network monitor dependencies...")
            print(f"psutil: {'OK' if PSUTIL_AVAILABLE else 'MISSING'}")
            print(f"socket: {'OK' if SOCKET_AVAILABLE else 'MISSING'}")
            print(f"scapy: {'DISABLED' if not SCAPY_AVAILABLE else 'OK'}")

            if PSUTIL_AVAILABLE:
                print("\nTesting psutil network connections...")
                try:
                    connections = psutil.net_connections(kind='inet')
                    print(f"Found {len(connections)} network connections")

                    if connections:
                        conn = connections[0]
                        print(f"Sample connection: {conn}")
                except Exception as e:
                    print(f"Error testing psutil: {e}")

    else:
        print("Usage: python network_monitor.py [start|status|test]")
        print("Commands:")
        print("  start - Start network monitoring")
        print("  status - Show monitor status")
        print("  test - Test dependencies")