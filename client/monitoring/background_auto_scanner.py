"""
background_auto_scanner.py - Fixed version with proper imports and error handling
"""

import os
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

# Import with error handling
try:
    import schedule
except ImportError:
    print("Warning: schedule module not available. Install with: pip install schedule")
    # Create a dummy schedule module
    class DummySchedule:
        def every(self, interval):
            return self
        def hours(self):
            return self
        def days(self):
            return self
        def day(self):
            return self
        def at(self, time):
            return self
        def do(self, func):
            return self
        def run_pending(self):
            pass
        def clear(self):
            pass
    schedule = DummySchedule()

try:
    from client.config.config import get_config, get_logger
except ImportError:
    def get_config(key, default=None):
        return default
    def get_logger(name):
        import logging
        return logging.getLogger(name)

try:
    from client.scanner import OptimizedAntivirusScanner, ScanMode, ThreatLevel
except ImportError:
    # Create dummy classes
    class ScanMode:
        QUICK = "quick"
        FULL = "full"
        BACKGROUND = "background"

    class ThreatLevel:
        BENIGN = "benign"
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"

    class OptimizedAntivirusScanner:
        def __init__(self):
            self.callbacks = type('obj', (object,), {})()
        def scan(self, mode=None):
            return []
        def stop_scan(self):
            pass

logger = get_logger(__name__)


class BackgroundAutoScanner:
    """Automatic background scanner that runs on startup and scheduled intervals"""

    def __init__(self):
        self.scanner = None
        self.is_running = False
        self.scheduler_thread = None
        self.current_scan_thread = None
        self.stop_event = threading.Event()

        # Configuration
        self.startup_scan_enabled = get_config('auto_scanner.startup_scan', True)
        self.scheduled_scans_enabled = get_config('auto_scanner.scheduled_scans', True)
        self.quick_scan_interval = get_config('auto_scanner.quick_scan_hours', 6)  # Every 6 hours
        self.full_scan_interval = get_config('auto_scanner.full_scan_days', 7)  # Every 7 days
        self.max_scan_duration = get_config('auto_scanner.max_duration_minutes', 30)  # 30 minutes max

        # Statistics
        self.stats = {
            'auto_scans_completed': 0,
            'threats_found': 0,
            'last_startup_scan': None,
            'last_quick_scan': None,
            'last_full_scan': None,
            'total_scan_time': 0,
            'scanner_started': None
        }

        # Scan results storage
        self.recent_scan_results = []
        self.max_stored_results = 10

        # Callbacks
        self.on_scan_complete = None
        self.on_threat_detected = None
        self.on_scan_start = None

    def initialize(self, scanner=None):
        """Initialize the background scanner"""
        try:
            if scanner:
                self.scanner = scanner
            else:
                self.scanner = OptimizedAntivirusScanner()

            # Setup scanner callbacks
            self._setup_scanner_callbacks()

            logger.info("Background auto scanner initialized")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize background scanner: {e}")
            return False

    def start(self):
        """Start the background auto scanner"""
        if self.is_running:
            logger.warning("Background scanner already running")
            return

        try:
            self.is_running = True
            self.stats['scanner_started'] = datetime.now()
            self.stop_event.clear()

            # Schedule scans
            self._setup_scheduled_scans()

            # Start scheduler thread
            self.scheduler_thread = threading.Thread(target=self._scheduler_worker, daemon=True)
            self.scheduler_thread.start()

            # Run startup scan if enabled
            if self.startup_scan_enabled:
                self._schedule_startup_scan()

            logger.info("Background auto scanner started")

        except Exception as e:
            logger.error(f"Failed to start background scanner: {e}")
            self.is_running = False

    def stop(self):
        """Stop the background auto scanner"""
        if not self.is_running:
            return

        try:
            self.is_running = False
            self.stop_event.set()

            # Stop current scan if running
            if self.current_scan_thread and self.current_scan_thread.is_alive():
                if self.scanner:
                    self.scanner.stop_scan()
                self.current_scan_thread.join(timeout=10)

            # Stop scheduler
            if self.scheduler_thread and self.scheduler_thread.is_alive():
                self.scheduler_thread.join(timeout=5)

            # Clear scheduled jobs
            schedule.clear()

            logger.info("Background auto scanner stopped")

        except Exception as e:
            logger.error(f"Error stopping background scanner: {e}")

    def _setup_scheduled_scans(self):
        """Setup scheduled scans"""
        if not self.scheduled_scans_enabled:
            return

        try:
            # Schedule quick scans every N hours
            schedule.every(self.quick_scan_interval).hours.do(self._run_quick_scan)

            # Schedule full scan weekly
            schedule.every(self.full_scan_interval).days.do(self._run_full_scan)

            # Schedule daily maintenance scan (very light)
            try:
                schedule.every().day.at("02:00").do(self._run_maintenance_scan)
            except:
                # Fallback if schedule doesn't support .at()
                schedule.every(24).hours.do(self._run_maintenance_scan)

            logger.info(
                f"Scheduled scans: Quick every {self.quick_scan_interval}h, Full every {self.full_scan_interval}d")

        except Exception as e:
            logger.error(f"Failed to setup scheduled scans: {e}")

    def _setup_scanner_callbacks(self):
        """Setup callbacks for the scanner"""
        if not self.scanner:
            return

        def on_progress_update(progress, scanned, total, remaining, current_file):
            # Log progress periodically
            if scanned % 100 == 0:  # Log every 100 files
                logger.debug(f"Auto scan progress: {progress:.1f}% ({scanned}/{total})")

        def on_threat_detected(result):
            self.stats['threats_found'] += 1
            threat_level = getattr(result, 'threat_level', 'unknown')
            if hasattr(threat_level, 'value'):
                threat_level = threat_level.value
            logger.warning(f"Auto scan threat detected: {result.file_path} - {threat_level}")

            # Callback to dashboard/UI
            if self.on_threat_detected:
                self.on_threat_detected(result, 'auto_scan')

        def on_scan_complete(results):
            self.stats['auto_scans_completed'] += 1
            self._store_scan_results(results)

            # Callback to dashboard/UI
            if self.on_scan_complete:
                self.on_scan_complete(results, 'auto_scan')

        def on_error(error_msg):
            logger.error(f"Auto scan error: {error_msg}")

        # Set callbacks safely
        if hasattr(self.scanner, 'callbacks'):
            self.scanner.callbacks.on_progress_update = on_progress_update
            self.scanner.callbacks.on_threat_detected = on_threat_detected
            self.scanner.callbacks.on_scan_complete = on_scan_complete
            self.scanner.callbacks.on_error = on_error

    def _scheduler_worker(self):
        """Background thread for running scheduled scans"""
        logger.info("Auto scanner scheduler started")

        while not self.stop_event.is_set():
            try:
                # Run pending scheduled jobs
                schedule.run_pending()

                # Sleep for a minute
                time.sleep(60)

            except Exception as e:
                logger.error(f"Error in scheduler worker: {e}")
                time.sleep(300)  # Wait 5 minutes on error

        logger.info("Auto scanner scheduler stopped")

    def _schedule_startup_scan(self):
        """Schedule startup scan to run after a delay"""

        def delayed_startup_scan():
            # Wait for system to settle after startup
            time.sleep(60)  # Wait 1 minute

            if not self.stop_event.is_set():
                logger.info("Running startup scan")
                self._run_quick_scan()

        startup_thread = threading.Thread(target=delayed_startup_scan, daemon=True)
        startup_thread.start()

    def _run_quick_scan(self):
        """Run a quick background scan"""
        if not self._can_start_scan():
            return

        try:
            logger.info("Starting automatic quick scan")
            self.stats['last_quick_scan'] = datetime.now()

            if self.on_scan_start:
                self.on_scan_start('quick', 'auto')

            self.current_scan_thread = threading.Thread(
                target=self._execute_scan,
                args=(ScanMode.QUICK, "Auto Quick Scan"),
                daemon=True
            )
            self.current_scan_thread.start()

        except Exception as e:
            logger.error(f"Failed to start quick scan: {e}")

    def _run_full_scan(self):
        """Run a full background scan"""
        if not self._can_start_scan():
            return

        try:
            logger.info("Starting automatic full scan")
            self.stats['last_full_scan'] = datetime.now()

            if self.on_scan_start:
                self.on_scan_start('full', 'auto')

            self.current_scan_thread = threading.Thread(
                target=self._execute_scan,
                args=(ScanMode.FULL, "Auto Full Scan"),
                daemon=True
            )
            self.current_scan_thread.start()

        except Exception as e:
            logger.error(f"Failed to start full scan: {e}")

    def _run_maintenance_scan(self):
        """Run a lightweight maintenance scan"""
        if not self._can_start_scan():
            return

        try:
            # Only run if no scan in last 4 hours
            if (self.stats['last_quick_scan'] and
                    datetime.now() - self.stats['last_quick_scan'] < timedelta(hours=4)):
                logger.info("Skipping maintenance scan - recent scan completed")
                return

            logger.info("Starting maintenance scan")

            # Run background scan mode (very selective)
            self.current_scan_thread = threading.Thread(
                target=self._execute_scan,
                args=(ScanMode.BACKGROUND, "Auto Maintenance Scan"),
                daemon=True
            )
            self.current_scan_thread.start()

        except Exception as e:
            logger.error(f"Failed to start maintenance scan: {e}")

    def _can_start_scan(self) -> bool:
        """Check if a new scan can be started"""
        if not self.scanner:
            logger.warning("No scanner available for auto scan")
            return False

        if self.current_scan_thread and self.current_scan_thread.is_alive():
            logger.info("Auto scan skipped - another scan is running")
            return False

        if self.stop_event.is_set():
            return False

        return True

    def _execute_scan(self, scan_mode, scan_name: str):
        """Execute a scan with timeout protection"""
        start_time = time.time()

        try:
            logger.info(f"Executing {scan_name}")

            # Set timeout for scan
            max_duration = self.max_scan_duration * 60  # Convert to seconds

            # Start scan
            results = self.scanner.scan(mode=scan_mode)

            # Check if scan took too long
            scan_time = time.time() - start_time
            if scan_time > max_duration:
                logger.warning(f"{scan_name} exceeded time limit ({scan_time:.1f}s > {max_duration}s)")
                self.scanner.stop_scan()

            self.stats['total_scan_time'] += scan_time
            logger.info(f"{scan_name} completed in {scan_time:.1f} seconds")

        except Exception as e:
            logger.error(f"Error executing {scan_name}: {e}")

    def _store_scan_results(self, results: List):
        """Store scan results for history"""
        try:
            scan_summary = {
                'timestamp': datetime.now(),
                'total_files': len(results),
                'threats_found': len([r for r in results if self._is_threat(r)]),
                'scan_time': sum(getattr(r, 'scan_time', 0) for r in results),
                'threat_breakdown': {}
            }

            # Count threats by level
            for result in results:
                if hasattr(result, 'threat_level'):
                    level = result.threat_level
                    if hasattr(level, 'value'):
                        level = level.value
                    scan_summary['threat_breakdown'][level] = scan_summary['threat_breakdown'].get(level, 0) + 1

            # Store in recent results
            self.recent_scan_results.insert(0, scan_summary)

            # Keep only recent results
            if len(self.recent_scan_results) > self.max_stored_results:
                self.recent_scan_results = self.recent_scan_results[:self.max_stored_results]

        except Exception as e:
            logger.error(f"Error storing scan results: {e}")

    def _is_threat(self, result) -> bool:
        """Check if result represents a threat"""
        try:
            if hasattr(result, 'threat_level'):
                threat_level = result.threat_level
                if hasattr(threat_level, 'value'):
                    return threat_level.value != 'benign'
                else:
                    return str(threat_level) != 'benign'
            return False
        except:
            return False

    def force_quick_scan(self) -> bool:
        """Force an immediate quick scan"""
        if not self._can_start_scan():
            return False

        try:
            logger.info("Force starting quick scan")
            self._run_quick_scan()
            return True
        except Exception as e:
            logger.error(f"Failed to force quick scan: {e}")
            return False

    def force_full_scan(self) -> bool:
        """Force an immediate full scan"""
        if not self._can_start_scan():
            return False

        try:
            logger.info("Force starting full scan")
            self._run_full_scan()
            return True
        except Exception as e:
            logger.error(f"Failed to force full scan: {e}")
            return False

    def get_status(self) -> Dict[str, Any]:
        """Get auto scanner status"""
        return {
            'is_running': self.is_running,
            'startup_scan_enabled': self.startup_scan_enabled,
            'scheduled_scans_enabled': self.scheduled_scans_enabled,
            'current_scan_active': (self.current_scan_thread and self.current_scan_thread.is_alive()),
            'next_quick_scan': self._get_next_scheduled_time('quick'),
            'next_full_scan': self._get_next_scheduled_time('full'),
            'stats': self.stats.copy(),
            'configuration': {
                'quick_scan_interval_hours': self.quick_scan_interval,
                'full_scan_interval_days': self.full_scan_interval,
                'max_scan_duration_minutes': self.max_scan_duration
            }
        }

    def _get_next_scheduled_time(self, scan_type: str) -> Optional[str]:
        """Get next scheduled scan time"""
        try:
            if scan_type == 'quick' and self.stats['last_quick_scan']:
                next_time = self.stats['last_quick_scan'] + timedelta(hours=self.quick_scan_interval)
                return next_time.isoformat()
            elif scan_type == 'full' and self.stats['last_full_scan']:
                next_time = self.stats['last_full_scan'] + timedelta(days=self.full_scan_interval)
                return next_time.isoformat()
            return None
        except:
            return None

    def get_recent_scan_history(self) -> List[Dict[str, Any]]:
        """Get recent scan history"""
        return self.recent_scan_results.copy()

    def update_configuration(self, config: Dict[str, Any]) -> bool:
        """Update scanner configuration"""
        try:
            if 'startup_scan_enabled' in config:
                self.startup_scan_enabled = config['startup_scan_enabled']

            if 'scheduled_scans_enabled' in config:
                self.scheduled_scans_enabled = config['scheduled_scans_enabled']
                if not self.scheduled_scans_enabled:
                    schedule.clear()
                elif self.is_running:
                    self._setup_scheduled_scans()

            if 'quick_scan_interval' in config:
                self.quick_scan_interval = config['quick_scan_interval']
                if self.is_running:
                    self._setup_scheduled_scans()

            if 'full_scan_interval' in config:
                self.full_scan_interval = config['full_scan_interval']
                if self.is_running:
                    self._setup_scheduled_scans()

            if 'max_scan_duration' in config:
                self.max_scan_duration = config['max_scan_duration']

            logger.info("Auto scanner configuration updated")
            return True

        except Exception as e:
            logger.error(f"Failed to update configuration: {e}")
            return False

    def is_scan_due(self) -> Dict[str, bool]:
        """Check if scans are due"""
        now = datetime.now()

        quick_due = False
        full_due = False

        if self.stats['last_quick_scan']:
            time_since_quick = now - self.stats['last_quick_scan']
            quick_due = time_since_quick.total_seconds() >= (self.quick_scan_interval * 3600)
        else:
            quick_due = True  # Never scanned

        if self.stats['last_full_scan']:
            time_since_full = now - self.stats['last_full_scan']
            full_due = time_since_full.total_seconds() >= (self.full_scan_interval * 24 * 3600)
        else:
            full_due = True  # Never scanned

        return {
            'quick_scan_due': quick_due,
            'full_scan_due': full_due
        }


# Convenience functions
def create_auto_scanner(scanner=None):
    """Create and initialize auto scanner"""
    auto_scanner = BackgroundAutoScanner()
    auto_scanner.initialize(scanner)
    return auto_scanner


def start_auto_scanning(scanner=None):
    """Start automatic background scanning"""
    auto_scanner = create_auto_scanner(scanner)
    auto_scanner.start()
    return auto_scanner


# Main function for testing
if __name__ == "__main__":
    import sys

    auto_scanner = BackgroundAutoScanner()

    if len(sys.argv) > 1:
        if sys.argv[1] == "start":
            # Test auto scanner
            if auto_scanner.initialize():
                auto_scanner.start()

                print("Auto scanner started. Press Ctrl+C to stop...")
                try:
                    while True:
                        status = auto_scanner.get_status()
                        print(f"Status: Running={status['is_running']}, Current scan={status['current_scan_active']}")
                        print(f"Stats: {status['stats']}")
                        time.sleep(30)
                except KeyboardInterrupt:
                    print("\nStopping auto scanner...")
                    auto_scanner.stop()
                    print("Auto scanner stopped")
            else:
                print("Failed to initialize auto scanner")

        elif sys.argv[1] == "force-quick":
            # Force quick scan
            if auto_scanner.initialize():
                if auto_scanner.force_quick_scan():
                    print("Quick scan started")
                else:
                    print("Failed to start quick scan")

        elif sys.argv[1] == "status":
            # Show status
            if auto_scanner.initialize():
                status = auto_scanner.get_status()
                print("Auto Scanner Status:")
                for key, value in status.items():
                    print(f"  {key}: {value}")

                due_checks = auto_scanner.is_scan_due()
                print("Scan Due Status:")
                for key, value in due_checks.items():
                    print(f"  {key}: {value}")
    else:
        print("Usage: python background_auto_scanner.py [start|force-quick|status]")
        print("Commands:")
        print("  start - Start the auto scanner")
        print("  force-quick - Force a quick scan")
        print("  status - Show scanner status")