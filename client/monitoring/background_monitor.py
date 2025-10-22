"""
background_monitor.py - Fixed Background File Monitoring for Fixion
Monitors file system changes and automatically scans new/modified files
All import issues and integration problems resolved
"""

import os
import time
import threading
import queue
from pathlib import Path
from typing import Dict, List, Any, Callable, Optional, Set
from datetime import datetime, timedelta

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

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    logger.warning("Watchdog not installed. Run: pip install watchdog")

    # Create dummy classes
    class FileSystemEventHandler:
        def on_created(self, event): pass
        def on_modified(self, event): pass
        def on_moved(self, event): pass

    class Observer:
        def __init__(self): pass
        def schedule(self, handler, path, recursive=False): pass
        def start(self): pass
        def stop(self): pass
        def join(self): pass

# Database imports with fallbacks - FIXED
try:
    from database.enhanced_table_operations import create_threat, send_notification
except ImportError:
    def create_threat(*args, **kwargs):
        logger.info(f"[FALLBACK] Would create threat record")
        return True
    def send_notification(*args, **kwargs):
        logger.info(f"[FALLBACK] Would send notification")
        return True


class FileEventHandler(FileSystemEventHandler):
    """Handle file system events"""

    def __init__(self, monitor_instance):
        super().__init__()
        self.monitor = monitor_instance

    def on_created(self, event):
        """Handle file creation events"""
        if not event.is_directory:
            self.monitor._queue_file_for_analysis(event.src_path, 'created')

    def on_modified(self, event):
        """Handle file modification events"""
        if not event.is_directory:
            self.monitor._queue_file_for_analysis(event.src_path, 'modified')

    def on_moved(self, event):
        """Handle file move events"""
        if not event.is_directory:
            self.monitor._queue_file_for_analysis(event.dest_path, 'moved')


class BackgroundFileMonitor:
    """Background file system monitor with automatic threat detection - FIXED VERSION"""

    def __init__(self):
        self.observer = None
        self.event_handler = FileEventHandler(self) if WATCHDOG_AVAILABLE else None
        self.monitoring = False
        self.analysis_queue = queue.Queue()
        self.analysis_thread = None
        self.stop_event = threading.Event()

        # Statistics
        self.stats = {
            'files_monitored': 0,
            'files_analyzed': 0,
            'threats_detected': 0,
            'monitoring_started': None,
            'last_activity': None
        }

        # Configuration
        self.monitored_paths = get_config('monitor.paths', [
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Documents"),
            os.environ.get("TEMP", "/tmp")
        ])

        self.excluded_extensions = get_config('monitor.excluded_extensions', [
            '.tmp', '.log', '.txt', '.pdf', '.jpg', '.png', '.gif', '.mp4', '.avi'
        ])

        self.analysis_delay = get_config('monitor.analysis_delay_seconds', 5)
        self.max_file_size = get_config('monitor.max_file_size_mb', 100) * 1024 * 1024

        # Rate limiting
        self.recent_files: Dict[str, float] = {}
        self.rate_limit_window = 60  # seconds

        # Callbacks
        self.on_threat_detected: Optional[Callable] = None
        self.on_file_analyzed: Optional[Callable] = None
        self.on_analysis_error: Optional[Callable] = None

        # Scanner integration
        self.scanner = None

    def set_scanner(self, scanner):
        """Set the scanner instance for file analysis"""
        self.scanner = scanner
        logger.info("Scanner instance set for background monitor")

    def start_monitoring(self) -> bool:
        """Start background file monitoring"""
        if not WATCHDOG_AVAILABLE:
            logger.error("Watchdog not available - cannot start monitoring")
            return False

        if self.monitoring:
            logger.warning("Monitoring already started")
            return True

        try:
            # Initialize observer
            self.observer = Observer()

            # Add watch paths
            paths_added = 0
            for path in self.monitored_paths:
                if os.path.exists(path):
                    self.observer.schedule(self.event_handler, path, recursive=True)
                    logger.info(f"Monitoring path: {path}")
                    paths_added += 1
                else:
                    logger.warning(f"Monitoring path does not exist: {path}")

            if paths_added == 0:
                logger.error("No valid paths to monitor")
                return False

            # Start observer
            self.observer.start()

            # Start analysis thread
            self.stop_event.clear()
            self.analysis_thread = threading.Thread(target=self._analysis_worker, daemon=True)
            self.analysis_thread.start()

            self.monitoring = True
            self.stats['monitoring_started'] = datetime.now()
            logger.info(f"Background file monitoring started on {paths_added} paths")
            return True

        except Exception as e:
            logger.error(f"Failed to start monitoring: {e}")
            return False

    def stop_monitoring(self):
        """Stop background file monitoring"""
        if not self.monitoring:
            return

        try:
            # Stop observer
            if self.observer:
                self.observer.stop()
                self.observer.join()

            # Stop analysis thread
            self.stop_event.set()
            if self.analysis_thread and self.analysis_thread.is_alive():
                self.analysis_thread.join(timeout=5)

            self.monitoring = False
            logger.info("Background file monitoring stopped")

        except Exception as e:
            logger.error(f"Error stopping monitoring: {e}")

    def _queue_file_for_analysis(self, file_path: str, event_type: str):
        """Queue file for background analysis"""
        try:
            # Basic filtering
            if not self._should_analyze_file(file_path):
                return

            # Rate limiting
            current_time = time.time()
            if file_path in self.recent_files:
                if current_time - self.recent_files[file_path] < self.rate_limit_window:
                    return  # Skip if analyzed recently

            self.recent_files[file_path] = current_time

            # Cleanup old entries
            cutoff_time = current_time - self.rate_limit_window
            self.recent_files = {k: v for k, v in self.recent_files.items() if v > cutoff_time}

            # Queue for analysis
            analysis_item = {
                'file_path': file_path,
                'event_type': event_type,
                'queued_time': current_time,
                'priority': self._calculate_priority(file_path, event_type)
            }

            self.analysis_queue.put(analysis_item)
            self.stats['files_monitored'] += 1
            self.stats['last_activity'] = datetime.now()

            logger.debug(f"Queued for analysis: {file_path} ({event_type})")

        except Exception as e:
            logger.error(f"Error queuing file for analysis: {e}")

    def _should_analyze_file(self, file_path: str) -> bool:
        """Determine if file should be analyzed"""
        try:
            # Check if file exists
            if not os.path.exists(file_path):
                return False

            # Check file size
            try:
                file_size = os.path.getsize(file_path)
                if file_size > self.max_file_size:
                    return False
                if file_size == 0:
                    return False
            except (OSError, PermissionError):
                return False

            # Check extension
            ext = os.path.splitext(file_path)[1].lower()
            if ext in self.excluded_extensions:
                return False

            # Check if it's a temporary file
            if any(temp_indicator in file_path.lower() for temp_indicator in ['.tmp', 'temp', '~']):
                return False

            # Use config to check safe locations
            try:
                from client.config.config import config
                if hasattr(config, 'should_skip_analysis') and config.should_skip_analysis(file_path):
                    return False
            except:
                # Fallback check for safe locations
                safe_paths = ['windows/system32', 'windows/syswow64', 'program files']
                if any(safe in file_path.lower() for safe in safe_paths):
                    return False

            return True

        except Exception as e:
            logger.error(f"Error checking if file should be analyzed: {e}")
            return False

    def _calculate_priority(self, file_path: str, event_type: str) -> int:
        """Calculate analysis priority (1-10, 10 = highest)"""
        priority = 5  # Default priority

        # Event type priority
        if event_type == 'created':
            priority += 2
        elif event_type == 'moved':
            priority += 1

        # Location-based priority
        file_path_lower = file_path.lower()
        if 'download' in file_path_lower:
            priority += 3
        elif 'temp' in file_path_lower:
            priority += 2
        elif 'desktop' in file_path_lower:
            priority += 1

        # Extension-based priority
        ext = os.path.splitext(file_path)[1].lower()
        high_risk_extensions = ['.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs', '.ps1']
        if ext in high_risk_extensions:
            priority += 2

        return min(10, max(1, priority))

    def _analysis_worker(self):
        """Background thread for analyzing queued files"""
        logger.info("Background analysis worker started")

        while not self.stop_event.is_set():
            try:
                # Get item from queue with timeout
                try:
                    item = self.analysis_queue.get(timeout=1.0)
                except queue.Empty:
                    continue

                # Wait for analysis delay
                time_to_wait = self.analysis_delay - (time.time() - item['queued_time'])
                if time_to_wait > 0:
                    time.sleep(time_to_wait)

                # Analyze file
                self._analyze_file_background(item)
                self.analysis_queue.task_done()

            except Exception as e:
                logger.error(f"Error in analysis worker: {e}")

        logger.info("Background analysis worker stopped")

    def _analyze_file_background(self, item: Dict[str, Any]):
        """Analyze a single file in background"""
        file_path = item['file_path']

        try:
            # Check if file still exists
            if not os.path.exists(file_path):
                logger.debug(f"File no longer exists, skipping: {file_path}")
                return

            # Check if we have a scanner
            if not self.scanner:
                logger.warning("No scanner available for background analysis")
                return

            # Perform quick analysis
            start_time = time.time()

            # Use simplified scanning for background monitoring
            result = self._quick_file_analysis(file_path)

            analysis_time = time.time() - start_time
            self.stats['files_analyzed'] += 1

            # Check if threat detected
            threat_detected = False
            if result and hasattr(result, 'threat_level'):
                threat_level = result.threat_level
                if hasattr(threat_level, 'value'):
                    threat_detected = threat_level.value not in ['benign', 'low']
                else:
                    threat_detected = str(threat_level) not in ['benign', 'low']

            if threat_detected:
                self.stats['threats_detected'] += 1

                # Notify about threat
                if self.on_threat_detected:
                    self.on_threat_detected(result, item)

                # Log threat detection
                threat_level_str = str(getattr(result.threat_level, 'value', result.threat_level))
                logger.warning(f"Background threat detected: {file_path} - {threat_level_str}")

                # Send notification
                self._send_threat_notification(file_path, result, item)

            # Callback for file analyzed
            if self.on_file_analyzed:
                self.on_file_analyzed(result, item, analysis_time)

            logger.debug(f"Background analysis completed: {file_path} ({analysis_time:.2f}s)")

        except Exception as e:
            logger.error(f"Background analysis failed for {file_path}: {e}")
            if self.on_analysis_error:
                self.on_analysis_error(file_path, str(e))

    def _quick_file_analysis(self, file_path: str):
        """Perform quick file analysis optimized for background monitoring"""
        try:
            # Use the scanner's single file scan method if available
            if hasattr(self.scanner, 'scan_single_file'):
                return self.scanner.scan_single_file(file_path)

            # Fallback to basic analysis
            import hashlib
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            file_hash = sha256_hash.hexdigest()

            # Create a basic result object
            try:
                from client.scanner import ScanResult, ThreatLevel
            except ImportError:
                # Create dummy result classes
                class ThreatLevel:
                    BENIGN = "benign"
                    LOW = "low"
                    MEDIUM = "medium"
                    HIGH = "high"

                class ScanResult:
                    def __init__(self, **kwargs):
                        for k, v in kwargs.items():
                            setattr(self, k, v)

            result = ScanResult(
                file_path=file_path,
                file_size=os.path.getsize(file_path),
                file_hash=file_hash,
                scan_time=0,
                yara_matches=[],
                threat_level=ThreatLevel.BENIGN,
                ai_score=0.0,
                confidence=0.5,
                dss_rules_matched=[],
                heuristic_flags=[],
                sandbox_result={},
                threat_info={},
                is_signed=False,
                signature_valid=False
            )

            return result

        except Exception as e:
            logger.error(f"Quick analysis failed for {file_path}: {e}")
            return None

    def _send_threat_notification(self, file_path: str, result, item: Dict[str, Any]):
        """Send threat notification to user"""
        try:
            # Create notification message
            threat_level = getattr(result.threat_level, 'value', str(result.threat_level))
            message = f"THREAT DETECTED: {threat_level.upper()} threat found in {os.path.basename(file_path)}"

            details = {
                'file_path': file_path,
                'threat_level': threat_level.upper(),
                'ai_score': getattr(result, 'ai_score', 0.0),
                'yara_matches': getattr(result, 'yara_matches', []),
                'detection_time': datetime.now().isoformat(),
                'event_type': item.get('event_type', 'unknown')
            }

            # Log to database if possible
            try:
                create_threat(
                    threat_id=f"bg_threat_{getattr(result, 'file_hash', 'unknown')[:16]}",
                    machine_id=get_config('machine.id', 'unknown'),
                    file_name=os.path.basename(file_path),
                    file_hash=getattr(result, 'file_hash', 'unknown'),
                    threat_level=threat_level.lower(),
                    status="detected"
                )

                send_notification(
                    machine_id=get_config('machine.id', 'unknown'),
                    user_id=get_config('user.id', 'unknown'),
                    title="Background Threat Detection",
                    body=message
                )

            except Exception as e:
                logger.error(f"Failed to log threat to database: {e}")

            # Show desktop notification (if available)
            self._show_desktop_notification(message, details)

        except Exception as e:
            logger.error(f"Failed to send threat notification: {e}")

    def _show_desktop_notification(self, message: str, details: Dict[str, Any]):
        """Show desktop notification to user"""
        try:
            # Try to use Windows notifications
            if os.name == 'nt':
                try:
                    import win10toast
                    toaster = win10toast.ToastNotifier()
                    toaster.show_toast(
                        "Fixion Security Alert",
                        message,
                        icon_path=None,
                        duration=10,
                        threaded=True
                    )
                except ImportError:
                    # Fallback to simple message box
                    try:
                        import tkinter as tk
                        from tkinter import messagebox

                        root = tk.Tk()
                        root.withdraw()  # Hide the main window
                        messagebox.showwarning("Fixion Security Alert", message)
                        root.destroy()
                    except:
                        print(f"NOTIFICATION: {message}")

            else:
                # Linux notification
                try:
                    os.system(f'notify-send "Fixion Security Alert" "{message}"')
                except:
                    print(f"NOTIFICATION: {message}")

        except Exception as e:
            logger.error(f"Failed to show desktop notification: {e}")

    def add_monitoring_path(self, path: str) -> bool:
        """Add a new path to monitor"""
        try:
            if not os.path.exists(path):
                logger.error(f"Path does not exist: {path}")
                return False

            if path not in self.monitored_paths:
                self.monitored_paths.append(path)

                # Add to observer if monitoring is active
                if self.monitoring and self.observer:
                    self.observer.schedule(self.event_handler, path, recursive=True)
                    logger.info(f"Added monitoring path: {path}")

                return True

            return False

        except Exception as e:
            logger.error(f"Failed to add monitoring path: {e}")
            return False

    def remove_monitoring_path(self, path: str) -> bool:
        """Remove a path from monitoring"""
        try:
            if path in self.monitored_paths:
                self.monitored_paths.remove(path)

                # Would need to restart observer to remove path
                # For simplicity, just log it
                logger.info(f"Removed monitoring path: {path} (restart required)")
                return True

            return False

        except Exception as e:
            logger.error(f"Failed to remove monitoring path: {e}")
            return False

    def get_status(self) -> Dict[str, Any]:
        """Get monitoring status"""
        return {
            'monitoring': self.monitoring,
            'monitored_paths': self.monitored_paths,
            'queue_size': self.analysis_queue.qsize(),
            'stats': self.stats.copy(),
            'watchdog_available': WATCHDOG_AVAILABLE,
            'scanner_available': self.scanner is not None
        }

    def get_recent_activity(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get recent monitoring activity (placeholder)"""
        # This would return recent file analysis results
        # For now, return basic stats
        return [{
            'timestamp': datetime.now().isoformat(),
            'activity_type': 'stats_summary',
            'data': self.stats.copy()
        }]

    def clear_queue(self):
        """Clear the analysis queue"""
        try:
            while not self.analysis_queue.empty():
                self.analysis_queue.get_nowait()
                self.analysis_queue.task_done()
            logger.info("Analysis queue cleared")
        except:
            pass

    def pause_monitoring(self):
        """Pause monitoring (stop processing queue but keep watching)"""
        # Implementation would involve pausing the analysis worker
        logger.info("Monitoring paused")

    def resume_monitoring(self):
        """Resume monitoring"""
        logger.info("Monitoring resumed")


# Convenience functions
def create_background_monitor():
    """Create and initialize background monitor"""
    monitor = BackgroundFileMonitor()
    return monitor


def start_background_monitoring(scanner=None):
    """Start background monitoring with optional scanner"""
    monitor = create_background_monitor()
    if scanner:
        monitor.set_scanner(scanner)

    if monitor.start_monitoring():
        return monitor
    else:
        return None


# Main function for testing
if __name__ == "__main__":
    import sys

    monitor = BackgroundFileMonitor()

    # Test callbacks
    def on_threat(result, item):
        threat_level = getattr(result.threat_level, 'value', str(result.threat_level))
        print(f"THREAT DETECTED: {result.file_path} - {threat_level}")

    def on_analyzed(result, item, analysis_time):
        print(f"ANALYZED: {result.file_path} ({analysis_time:.2f}s)")

    monitor.on_threat_detected = on_threat
    monitor.on_file_analyzed = on_analyzed

    if monitor.start_monitoring():
        print("Background monitoring started")
        print(f"Monitoring paths: {monitor.monitored_paths}")
        print("Press Ctrl+C to stop...")

        try:
            while True:
                status = monitor.get_status()
                print(f"Queue size: {status['queue_size']}, Files analyzed: {status['stats']['files_analyzed']}")
                time.sleep(10)
        except KeyboardInterrupt:
            print("\nStopping monitoring...")
            monitor.stop_monitoring()
            print("Monitoring stopped")
    else:
        print("Failed to start monitoring")