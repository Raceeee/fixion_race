"""
main.py - Fixion 2.0 Main Entry Point
"""

import sys
import os
import logging
import argparse
from pathlib import Path

project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('fixion_client.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description='Fixion 2.0 Security Suite')
    parser.add_argument('--no-tray', action='store_true', help='Start without system tray')
    parser.add_argument('--no-monitor', action='store_true', help='Disable background monitoring')
    parser.add_argument('--dashboard-only', action='store_true', help='Only launch dashboard UI')
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("Starting Fixion 2.0 Security Suite")
    logger.info("=" * 60)

    try:
        from client.config.config import FixionConfig
        from client.database.local_database import LocalDatabase
        from client.protection.whitelist_manager import WhitelistManager

        config = FixionConfig()
        db = LocalDatabase()
        whitelist_manager = WhitelistManager()

        logger.info("Core components initialized")

        monitor = None
        if not args.no_monitor and not args.dashboard_only:
            from client.monitoring.background_monitor import BackgroundFileMonitor
            monitor = BackgroundFileMonitor(
                config=config,
                database=db,
                whitelist_manager=whitelist_manager
            )
            monitor.start()
            logger.info("Background monitoring started")

        tray = None
        if not args.no_tray and not args.dashboard_only:
            try:
                from client.gui.tray_indicator import TrayIndicator

                def open_dashboard():
                    launch_dashboard(config, db, whitelist_manager, monitor)

                def quick_scan():
                    if monitor:
                        monitor.trigger_quick_scan()

                tray = TrayIndicator(
                    on_open_dashboard=open_dashboard,
                    on_quick_scan=quick_scan,
                    icon_path=str(project_root / 'assets' / 'images' / 'CRESTAL_logo.png')
                )
                tray.start()
                logger.info("System tray started")
            except Exception as e:
                logger.warning(f"Tray indicator error: {e}")

        launch_dashboard(config, db, whitelist_manager, monitor)

    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


def launch_dashboard(config, db, whitelist_manager, monitor=None):
    try:
        import customtkinter as ctk
        from client.gui.client_dashboard import FixionClientDashboard

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        root = ctk.CTk()
        root.title("Fixion 2.0 - Security Suite")

        window_width = 1400
        window_height = 900
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        root.geometry(f"{window_width}x{window_height}+{x}+{y}")
        root.minsize(1200, 800)

        app = FixionClientDashboard(
            root,
            config=config,
            database=db,
            whitelist_manager=whitelist_manager,
            background_monitor=monitor
        )

        logger.info("Dashboard initialized")
        root.mainloop()

    except ImportError as e:
        logger.error(f"Missing UI libraries: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Dashboard error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()