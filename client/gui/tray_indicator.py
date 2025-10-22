import os
import sys
import threading
import logging
import time
import ctypes
from typing import Callable


from PIL import Image, ImageOps
import pystray
from win10toast import ToastNotifier
import subprocess
import winreg


logger = logging.getLogger("client.tray_indicator")
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logger.addHandler(ch)

class TrayIndicator:
    def __init__(self, on_open_dashboard: Callable, on_quick_scan: Callable, icon_path: str = 'fixion_icon.png'):
        self.icon_path = icon_path
        self.on_open_dashboard = on_open_dashboard
        self.on_quick_scan = on_quick_scan
        self.icon = None
        self.thread = None
        self.notifier = ToastNotifier()
        self.state = 'idle' # idle, scanning, threat
        self._ensure_autostart()

    def _ensure_autostart(self):
        try:
            exe = sys.executable
            # If running from script, use a small launcher path or python path. For packaging, replace with exe path.
            entry = 'Fixion'
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ)
            try:
                val, _ = winreg.QueryValueEx(key, entry)
                winreg.CloseKey(key)
            except FileNotFoundError:
                winreg.CloseKey(key)
                try:
                    keyw = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
                                          winreg.KEY_SET_VALUE)
                    # Use sys.executable + script path; when packaged replace with exe installation path
                    cmd = f'"{exe}" "{os.path.abspath(sys.argv[0])}"'
                    winreg.SetValueEx(keyw, entry, 0, winreg.REG_SZ, cmd)
                    winreg.CloseKey(keyw)
                    logger.info('Autostart entry created')
                except Exception as e:
                    logger.error(f'Failed to create autostart entry: {e}')
        except Exception as e:
                    logger.error(f'Autostart check error: {e}')
