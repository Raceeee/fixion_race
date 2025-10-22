import threading
import time
import os
import tkinter as tk
from tkinter import messagebox, filedialog
from datetime import datetime
from typing import List, Dict, Any
import customtkinter as ctk
import math
from PIL import Image

from client.ai.ember_threat_scanner import EMBERThreatScanner, ThreatLevel
from client.ai.ember_sandbox_analyzer import EMBERSandboxAnalyzer
from client.database.local_database import LocalDatabase
from client.protection.rollback_system import RollbackSystem
from client.protection.snapshot_rollback_manager import WindowsSnapshotManager
from settings_tab import SettingsTab
from client.gui.widgets.scan_animation import ScanAnimation
from client.gui.dialogs.batch_threat_dialog import BatchThreatDialog

try:
    from client.core.dss_engine import DSSEngine

    DSS_AVAILABLE = True
except Exception:
    DSSEngine = None
    DSS_AVAILABLE = False

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class FixionDashboard:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("Fixion")

        self.root.geometry("1400x800")
        self.root.minsize(1200, 700)
        self.root.configure(fg_color="#14151b")

        self.db = LocalDatabase()
        self.rollback_system = RollbackSystem(self.db)
        self.snapshot_manager = WindowsSnapshotManager()

        self.initialize_scanner_components()

        self.setup_callbacks()

        self.scanning = False
        self.sandboxing = False
        self.scan_progress = 0
        self.current_file = ""
        self.files_scanned = 0
        self.total_files = 0
        self.scan_results = []
        self.threat_reports = []
        self.selected_scan_mode = "quick"

        self.current_view = "dashboard"
        self.scan_animation = None

        # Load SVG icons
        self.load_svg_icons()

        self.setup_main_ui()

        self.load_settings()

        self.check_auto_scan()

        self.update_dashboard_stats()

    def load_svg_icons(self):
        """Load SVG icons for navigation"""
        self.icons = {}
        icon_dir = "assets/icon"
        icon_files = {
            "dashboard": "home.svg",
            "threats": "threats.svg",
            "rollback": "rollback.svg",
            "quarantine": "quarantine.svg",
            "settings": "settings.svg"
        }

        for key, filename in icon_files.items():
            path = os.path.join(icon_dir, filename)
            if os.path.exists(path):
                try:
                    from cairosvg import svg2png
                    from io import BytesIO

                    png_data = svg2png(url=path, output_width=20, output_height=20)
                    img = Image.open(BytesIO(png_data))

                    self.icons[key] = ctk.CTkImage(light_image=img, dark_image=img, size=(20, 20))
                except Exception as e:
                    print(f"Error loading icon {filename}: {e}")
                    self.icons[key] = None
            else:
                self.icons[key] = None

    def initialize_scanner_components(self):
        try:
            self.scanner = EMBERThreatScanner(
                ember_model_dir=r"C:\Users\Gel\PycharmProjects\Fixion2.0\ai_models\ember_models",
                db=self.db
            )
            self.sandbox_analyzer = EMBERSandboxAnalyzer()
            if DSS_AVAILABLE:
                self.dss_engine = DSSEngine()
                try:
                    self.dss_engine.load_rules()
                except Exception:
                    pass
            print("✓ EMBER scanner and sandbox initialized")
            self.SCANNER_AVAILABLE = True
        except Exception as e:
            print(f"Error initializing EMBER scanner/sandbox: {e}")
            self.scanner = None
            self.sandbox_analyzer = None
            self.dss_engine = None
            self.SCANNER_AVAILABLE = False

    def setup_callbacks(self):
        if not getattr(self, 'SCANNER_AVAILABLE', False) or not self.scanner:
            return

        def on_progress(progress, scanned=None, total=None, remaining=None, current_file=None):
            try:
                if scanned is not None:
                    self.files_scanned = scanned
                if total is not None:
                    self.total_files = total
                if current_file:
                    self.current_file = current_file
                if isinstance(progress, float) and 0.0 <= progress <= 1.0:
                    self.scan_progress = float(progress)
                else:
                    try:
                        self.scan_progress = float(progress) / 100.0
                    except Exception:
                        self.scan_progress = 0.0
            except Exception:
                self.scan_progress = 0.0
            self.root.after(0, self.update_scan_ui)

        def on_complete(results=None):
            try:
                self.scan_results = results or []
                if hasattr(self.scanner, 'get_threat_report'):
                    self.threat_reports = self.scanner.get_threat_report() or []
                else:
                    self.threat_reports = []
            except Exception:
                self.scan_results = results or []
                self.threat_reports = []
            self.root.after(0, self.scan_complete)

        def on_error(error_msg):
            print(f"Scanner error: {error_msg}")
            self.root.after(0, lambda: messagebox.showerror("Scan Error", str(error_msg)))

        cbs = getattr(self.scanner, 'callbacks', None)
        if cbs is None:
            try:
                self.scanner.callbacks = {}
                cbs = self.scanner.callbacks
            except Exception:
                cbs = None

        if isinstance(cbs, dict):
            cbs['on_scan_progress'] = on_progress
            cbs['on_scan_complete'] = on_complete
            cbs['on_error'] = on_error
        else:
            try:
                setattr(cbs, 'on_progress_update', on_progress)
                setattr(cbs, 'on_scan_complete', on_complete)
                setattr(cbs, 'on_error', on_error)
            except Exception:
                pass

    def setup_main_ui(self):
        self.main_container = ctk.CTkFrame(self.root, fg_color="transparent")
        self.main_container.pack(fill="both", expand=True)

        self.main_container.grid_columnconfigure(0, weight=0)
        self.main_container.grid_columnconfigure(1, weight=1)
        self.main_container.grid_rowconfigure(0, weight=1)

        self.create_sidebar()
        self.create_content_area()

    def create_sidebar(self):
        """Sidebar with CRESTAL logo and navigation with SVG icons"""
        sidebar = ctk.CTkFrame(self.main_container, width=220, corner_radius=0, fg_color="#1a1c24")
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)

        # Try to load CRESTAL logo
        try:
            logo_path = "assets/images/CRESTAL_logo.png"
            if os.path.exists(logo_path):
                logo_image = tk.PhotoImage(file=logo_path)
                logo_image = logo_image.subsample(4, 4)
                logo_label = ctk.CTkLabel(sidebar, image=logo_image, text="")
                logo_label.image = logo_image
                logo_label.pack(pady=(20, 5))
            else:
                ctk.CTkLabel(sidebar, text="FIXION", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=(30, 10))
        except:
            ctk.CTkLabel(sidebar, text="FIXION", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=(30, 10))

        ctk.CTkLabel(sidebar, text="Security", font=ctk.CTkFont(size=12), text_color="#94a3b8").pack(pady=(0, 30))

        self.nav_buttons = {}
        nav_items = [
            ("dashboard", "Dashboard"),
            ("threats", "Threats"),
            ("rollback", "Rollback"),
            ("quarantine", "Quarantine"),
            ("settings", "Settings")
        ]

        for key, text in nav_items:
            icon = self.icons.get(key)
            btn = ctk.CTkButton(
                sidebar,
                text=f"  {text}",
                image=icon if icon else None,
                compound="left",
                command=lambda k=key: self.switch_view(k),
                height=50,
                corner_radius=10,
                fg_color="transparent",
                text_color=("gray10", "gray90"),
                hover_color=("gray70", "gray30"),
                anchor="w",
                font=ctk.CTkFont(size=14)
            )
            btn.pack(padx=12, pady=6, fill="x")
            self.nav_buttons[key] = btn

        self.nav_buttons["dashboard"].configure(fg_color=("#047eaf", "#047eaf"))

    def create_content_area(self):
        self.content_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.content_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)

        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_rowconfigure(0, weight=1)

        self.views = {}
        self.create_dashboard_view()
        self.create_threats_view()
        self.create_rollback_view()
        self.create_quarantine_view()
        self.create_settings_view()

    def create_dashboard_view(self):
        """NEW LAYOUT: 3 columns with recent threats on right"""
        frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.views["dashboard"] = frame

        frame.grid_columnconfigure(0, weight=3, minsize=320)
        frame.grid_columnconfigure(1, weight=4, minsize=450)
        frame.grid_columnconfigure(2, weight=3, minsize=320)
        frame.grid_rowconfigure(0, weight=1)

        # LEFT COLUMN
        left_frame = ctk.CTkFrame(frame, fg_color="transparent")
        left_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        left_frame.grid_rowconfigure(0, weight=1)
        left_frame.grid_rowconfigure(1, weight=1)
        left_frame.grid_columnconfigure(0, weight=1)

        self.create_sandbox_analysis_section(left_frame)
        self.create_system_restore_section(left_frame)

        # MIDDLE COLUMN
        middle_frame = ctk.CTkFrame(frame, fg_color="transparent")
        middle_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        middle_frame.grid_rowconfigure(0, weight=1)
        middle_frame.grid_columnconfigure(0, weight=1)

        self.create_scan_control_section(middle_frame)

        # RIGHT COLUMN - Security Overview and Recent Threats
        right_frame = ctk.CTkFrame(frame, fg_color="transparent")
        right_frame.grid(row=0, column=2, sticky="nsew", padx=5, pady=5)
        right_frame.grid_rowconfigure(0, weight=1)
        right_frame.grid_rowconfigure(1, weight=1)
        right_frame.grid_columnconfigure(0, weight=1)

        self.create_system_security_section(right_frame)
        self.create_threat_activity_section(right_frame)

    # ==================== LEFT COLUMN ====================

    def create_sandbox_analysis_section(self, parent):
        """Sandbox Analysis section"""
        container = ctk.CTkFrame(parent, fg_color="#132a3f", corner_radius=15)
        container.grid(row=0, column=0, sticky="nsew", pady=(0, 5))

        ctk.CTkLabel(
            container,
            text="🧪 Sandbox Analysis",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=(15, 10))

        ctk.CTkLabel(
            container,
            text="Deep malware analysis in isolated environment",
            font=ctk.CTkFont(size=11),
            text_color="#94a3b8"
        ).pack(pady=(0, 15))

        # Analyze File button
        analyze_btn = ctk.CTkButton(
            container,
            text="📁 Analyze File",
            command=self.analyze_file_manually,
            height=45,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#047eaf",
            hover_color="#036a91"
        )
        analyze_btn.pack(fill="x", padx=20, pady=(0, 10))

        # Status info
        status_frame = ctk.CTkFrame(container, fg_color="#1a1c24", corner_radius=8)
        status_frame.pack(fill="x", padx=20, pady=(0, 15))

        ctk.CTkLabel(
            status_frame,
            text="Sandbox Status: Ready",
            font=ctk.CTkFont(size=11),
            text_color="#10b981"
        ).pack(pady=10)

    def create_system_restore_section(self, parent):
        """System Restore section"""
        container = ctk.CTkFrame(parent, fg_color="#132a3f", corner_radius=15)
        container.grid(row=1, column=0, sticky="nsew", pady=(5, 0))

        ctk.CTkLabel(
            container,
            text="⏮️ System Restore",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=(15, 10))

        ctk.CTkLabel(
            container,
            text="Rollback system to previous state",
            font=ctk.CTkFont(size=11),
            text_color="#94a3b8"
        ).pack(pady=(0, 15))

        # Emergency Rollback
        emergency_btn = ctk.CTkButton(
            container,
            text="🚨 Emergency Rollback",
            command=self.emergency_rollback,
            height=45,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#dc2626",
            hover_color="#b91c1c"
        )
        emergency_btn.pack(fill="x", padx=20, pady=(0, 8))

        # Manual Rollback
        manual_btn = ctk.CTkButton(
            container,
            text="📋 Manual Rollback",
            command=self.manual_rollback,
            height=40,
            font=ctk.CTkFont(size=13),
            fg_color="#f59e0b",
            hover_color="#d97706"
        )
        manual_btn.pack(fill="x", padx=20, pady=(0, 8))

        # Create Snapshot
        snapshot_btn = ctk.CTkButton(
            container,
            text="📸 Create Snapshot",
            command=self.create_snapshot_now,
            height=40,
            font=ctk.CTkFont(size=13),
            fg_color="#10b981",
            hover_color="#059669"
        )
        snapshot_btn.pack(fill="x", padx=20, pady=(0, 10))

        # Snapshot count
        snapshot_info = ctk.CTkFrame(container, fg_color="#1a1c24", corner_radius=8)
        snapshot_info.pack(fill="x", padx=20, pady=(0, 15))

        count_row = ctk.CTkFrame(snapshot_info, fg_color="transparent")
        count_row.pack(fill="x", padx=10, pady=8)

        ctk.CTkLabel(
            count_row,
            text="Available Snapshots:",
            font=ctk.CTkFont(size=11),
            text_color="#94a3b8"
        ).pack(side="left")

        self.snapshot_count_label = ctk.CTkLabel(
            count_row,
            text="0",
            font=ctk.CTkFont(size=11, weight="bold")
        )
        self.snapshot_count_label.pack(side="right")

    # ==================== MIDDLE COLUMN ====================

    def create_scan_control_section(self, parent):
        """Main Scan Control section with scan modes at top"""
        container = ctk.CTkFrame(parent, fg_color="#132a3f", corner_radius=15)
        container.grid(row=0, column=0, sticky="nsew")

        # Title - CENTERED
        title_frame = ctk.CTkFrame(container, fg_color="transparent")
        title_frame.pack(fill="x", padx=20, pady=(15, 10))

        ctk.CTkLabel(
            title_frame,
            text="🛡️ System Protection",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(anchor="center")

        # Main stats row
        stats_row = ctk.CTkFrame(container, fg_color="transparent")
        stats_row.pack(fill="x", padx=15, pady=(0, 10))
        stats_row.grid_columnconfigure((0, 1, 2), weight=1)

        # Files Scanned
        files_card = ctk.CTkFrame(stats_row, fg_color="#1a1c24", corner_radius=10)
        files_card.grid(row=0, column=0, sticky="ew", padx=5)

        ctk.CTkLabel(
            files_card,
            text="FILES",
            font=ctk.CTkFont(size=10),
            text_color="#94a3b8"
        ).pack(pady=(10, 2))

        self.files_scanned_label = ctk.CTkLabel(
            files_card,
            text="0",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        self.files_scanned_label.pack(pady=(0, 10))

        # Threats Found
        threats_card = ctk.CTkFrame(stats_row, fg_color="#1a1c24", corner_radius=10)
        threats_card.grid(row=0, column=1, sticky="ew", padx=5)

        ctk.CTkLabel(
            threats_card,
            text="THREATS",
            font=ctk.CTkFont(size=10),
            text_color="#94a3b8"
        ).pack(pady=(10, 2))

        self.threats_found_label = ctk.CTkLabel(
            threats_card,
            text="0",
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color="#dc2626"
        )
        self.threats_found_label.pack(pady=(0, 10))

        # Threat Level
        level_card = ctk.CTkFrame(stats_row, fg_color="#1a1c24", corner_radius=10)
        level_card.grid(row=0, column=2, sticky="ew", padx=5)

        ctk.CTkLabel(
            level_card,
            text="LEVEL",
            font=ctk.CTkFont(size=10),
            text_color="#94a3b8"
        ).pack(pady=(10, 2))

        self.threat_indicator = ctk.CTkLabel(
            level_card,
            text="LOW",
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color="#10b981"
        )
        self.threat_indicator.pack(pady=(0, 10))

        # Scan Mode Buttons - PROMINENT AT TOP
        ctk.CTkLabel(
            container,
            text="Select Scan Mode:",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#94a3b8"
        ).pack(pady=(10, 5))

        scan_modes_frame = ctk.CTkFrame(container, fg_color="transparent")
        scan_modes_frame.pack(fill="x", padx=20, pady=(0, 10))
        scan_modes_frame.grid_columnconfigure((0, 1, 2), weight=1)

        # Quick Scan
        self.quick_scan_btn = ctk.CTkButton(
            scan_modes_frame,
            text="⚡ Quick Scan",
            command=lambda: self.select_scan_mode("quick"),
            height=45,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#1a1c24",
            hover_color="#047eaf",
            border_width=2,
            border_color="#047eaf"
        )
        self.quick_scan_btn.grid(row=0, column=0, sticky="ew", padx=5)

        # Full Scan
        self.full_scan_btn = ctk.CTkButton(
            scan_modes_frame,
            text="🔍 Full Scan",
            command=lambda: self.select_scan_mode("full"),
            height=45,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#1a1c24",
            hover_color="#0891b2",
            border_width=2,
            border_color="#0891b2"
        )
        self.full_scan_btn.grid(row=0, column=1, sticky="ew", padx=5)

        # Custom Scan
        self.custom_scan_btn = ctk.CTkButton(
            scan_modes_frame,
            text="📁 Custom Scan",
            command=lambda: self.select_scan_mode("custom"),
            height=45,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#1a1c24",
            hover_color="#8b5cf6",
            border_width=2,
            border_color="#8b5cf6"
        )
        self.custom_scan_btn.grid(row=0, column=2, sticky="ew", padx=5)

        # Highlight default selected mode (quick)
        self.quick_scan_btn.configure(fg_color="#047eaf")

        # Circular scan button with animation
        scan_container = ctk.CTkFrame(container, fg_color="transparent")
        scan_container.pack(pady=10)

        self.scan_canvas = tk.Canvas(
            scan_container,
            width=160,
            height=160,
            bg="#132a3f",
            highlightthickness=0
        )
        self.scan_canvas.pack()

        self.scan_circle = self.scan_canvas.create_oval(
            10, 10, 150, 150,
            fill="#047eaf",
            outline=""
        )

        self.scan_text = self.scan_canvas.create_text(
            80, 80,
            text="SCAN",
            fill="white",
            font=("Arial", 20, "bold")
        )

        self.scan_canvas.bind("<Button-1>", lambda e: self.start_scan())
        self.scan_canvas.bind("<Enter>", self.on_scan_hover)
        self.scan_canvas.bind("<Leave>", self.on_scan_leave)

        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(container, width=380, height=8)
        self.progress_bar.pack(pady=(10, 8))
        self.progress_bar.set(0)

        self.progress_label = ctk.CTkLabel(
            container,
            text="Ready to scan - Quick Scan selected",
            font=ctk.CTkFont(size=12),
            text_color="#94a3b8"
        )
        self.progress_label.pack(pady=(0, 15))

        # Control buttons - AT BOTTOM
        ctk.CTkLabel(
            container,
            text="Scan Controls:",
            font=ctk.CTkFont(size=11),
            text_color="#64748b"
        ).pack(pady=(5, 5))

        buttons_frame = ctk.CTkFrame(container, fg_color="transparent")
        buttons_frame.pack(fill="x", padx=20, pady=(0, 15))

        self.stop_button = ctk.CTkButton(
            buttons_frame,
            text="⏹ Stop",
            command=self.stop_scan,
            state="disabled",
            height=40,
            fg_color="#dc2626",
            hover_color="#b91c1c"
        )
        self.stop_button.pack(side="left", expand=True, padx=(0, 5))

        self.pause_button = ctk.CTkButton(
            buttons_frame,
            text="⏸ Pause",
            command=self.pause_scan,
            state="disabled",
            height=40,
            fg_color="#f59e0b",
            hover_color="#d97706"
        )
        self.pause_button.pack(side="right", expand=True, padx=(5, 0))

    # ==================== RIGHT COLUMN ====================

    def create_system_security_section(self, parent):
        """System Security Overview - SMALLER CIRCLE"""
        container = ctk.CTkFrame(parent, fg_color="#132a3f", corner_radius=15)
        container.grid(row=0, column=0, sticky="nsew", pady=(0, 5))

        ctk.CTkLabel(
            container,
            text="🔒 Security Overview",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=(15, 20))

        # Smaller pie chart
        chart_frame = ctk.CTkFrame(container, fg_color="transparent")
        chart_frame.pack(pady=(0, 20))

        self.chart_canvas = tk.Canvas(
            chart_frame,
            width=140,
            height=140,
            bg="#132a3f",
            highlightthickness=0
        )
        self.chart_canvas.pack()

        self.draw_security_pie_chart()

        # Security metrics
        metrics_frame = ctk.CTkFrame(container, fg_color="#1a1c24", corner_radius=10)
        metrics_frame.pack(fill="x", padx=20, pady=(0, 15))

        metrics = [
            ("Protection", "Active", "#10b981"),
            ("Real-time Scan", "Enabled", "#10b981"),
            ("Last Update", "Today", "#94a3b8"),
            ("Quarantine", "0 items", "#94a3b8")
        ]

        for label, value, color in metrics:
            row = ctk.CTkFrame(metrics_frame, fg_color="transparent")
            row.pack(fill="x", padx=12, pady=6)

            ctk.CTkLabel(
                row,
                text=label,
                font=ctk.CTkFont(size=11),
                text_color="#94a3b8"
            ).pack(side="left")

            ctk.CTkLabel(
                row,
                text=value,
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color=color
            ).pack(side="right")

    def create_threat_activity_section(self, parent):
        """Recent Threat Activity section"""
        container = ctk.CTkFrame(parent, fg_color="#132a3f", corner_radius=15)
        container.grid(row=1, column=0, sticky="nsew", pady=(5, 0))

        # Header
        header = ctk.CTkFrame(container, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(15, 10))

        ctk.CTkLabel(
            header,
            text="⚠️ Recent Threats",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(side="left")

        # SCROLLABLE threat list
        self.threat_activity_frame = ctk.CTkScrollableFrame(
            container,
            fg_color="transparent",
            height=150
        )
        self.threat_activity_frame.pack(fill="both", expand=True, padx=20, pady=(0, 15))

        # Initial message
        ctk.CTkLabel(
            self.threat_activity_frame,
            text="No recent threats detected",
            font=ctk.CTkFont(size=12),
            text_color="#94a3b8"
        ).pack(pady=20)

    def draw_security_pie_chart(self):
        """Draw security status pie chart - SMALLER"""
        self.chart_canvas.delete("all")

        try:
            stats = self.db.get_statistics()
            total_threats = stats.get('total_threats', 0)
            resolved_threats = stats.get('resolved_threats', 0)
            unresolved_threats = stats.get('unresolved_threats', 0)

            if total_threats == 0:
                self.chart_canvas.create_oval(10, 10, 130, 130, fill="#10b981", outline="")
                self.chart_canvas.create_text(
                    70, 70,
                    text="SECURE",
                    fill="white",
                    font=("Arial", 16, "bold")
                )
            else:
                total = resolved_threats + unresolved_threats
                resolved_angle = (resolved_threats / total) * 360 if total > 0 else 0

                self.chart_canvas.create_arc(
                    10, 10, 130, 130,
                    start=0,
                    extent=resolved_angle,
                    fill="#10b981",
                    outline=""
                )

                self.chart_canvas.create_arc(
                    10, 10, 130, 130,
                    start=resolved_angle,
                    extent=360 - resolved_angle,
                    fill="#dc2626",
                    outline=""
                )

                self.chart_canvas.create_text(
                    70, 70,
                    text=f"{total_threats}\nThreats",
                    fill="white",
                    font=("Arial", 12, "bold")
                )
        except Exception as e:
            print(f"Error drawing chart: {e}")

    # ==================== SCAN FUNCTIONS ====================

    def select_scan_mode(self, mode):
        """Select scan mode and update button highlights"""
        self.selected_scan_mode = mode

        # Reset all buttons
        self.quick_scan_btn.configure(fg_color="#1a1c24")
        self.full_scan_btn.configure(fg_color="#1a1c24")
        self.custom_scan_btn.configure(fg_color="#1a1c24")

        # Highlight selected button
        if mode == "quick":
            self.quick_scan_btn.configure(fg_color="#047eaf")
            self.progress_label.configure(text="Ready to scan - Quick Scan selected")
        elif mode == "full":
            self.full_scan_btn.configure(fg_color="#0891b2")
            self.progress_label.configure(text="Ready to scan - Full Scan selected")
        elif mode == "custom":
            self.custom_scan_btn.configure(fg_color="#8b5cf6")
            self.progress_label.configure(text="Ready to scan - Custom Scan selected")

    def on_scan_hover(self, event):
        """Scan button hover effect"""
        if not self.scanning:
            self.scan_canvas.itemconfig(self.scan_circle, fill="#058ac5")

    def on_scan_leave(self, event):
        """Scan button leave effect"""
        if not self.scanning:
            self.scan_canvas.itemconfig(self.scan_circle, fill="#047eaf")

    def start_scan_mode(self, mode):
        """Start scan with specified mode (legacy support)"""
        self.select_scan_mode(mode)
        self.start_scan()

    def start_scan(self):
        """Start system scan using selected mode"""
        if self.scanning:
            return

        if not getattr(self, 'SCANNER_AVAILABLE', False) or not self.scanner:
            messagebox.showwarning(
                "Scanner Unavailable",
                "EMBER scanner is not available. Please check installation."
            )
            return

        # For custom mode, show path selection dialog
        if self.selected_scan_mode == "custom":
            paths = self.get_custom_paths()
            if not paths:
                return
            self.perform_scan(self.selected_scan_mode, paths)
        else:
            self.perform_scan(self.selected_scan_mode, None)

    def get_custom_paths(self):
        """Get custom paths for scanning"""
        dialog = CustomPathDialog(self.root)
        self.root.wait_window(dialog.dialog)
        return dialog.get_paths()

    def perform_scan(self, mode, paths=None):
        """Perform the actual scan"""
        self.scanning = True

        # Update scan button animation
        self.scan_canvas.itemconfig(self.scan_text, text="SCANNING", font=("Arial", 14, "bold"))
        self.scan_canvas.itemconfig(self.scan_circle, fill="#f59e0b")

        self.stop_button.configure(state="normal")
        self.pause_button.configure(state="normal")

        if not self.scan_animation:
            self.scan_animation = ScanAnimation(self.scan_canvas, self.scan_circle)
        self.scan_animation.start()

        def scan_thread():
            try:
                if mode == "quick":
                    scan_paths = [
                        os.path.expanduser("~/Downloads"),
                        os.path.expanduser("~/Documents")
                    ]
                elif mode == "full":
                    scan_paths = [os.path.expanduser("~")]
                elif mode == "custom" and paths:
                    scan_paths = paths
                else:
                    return

                self.scanner.scan_paths(scan_paths)
            except Exception as e:
                print(f"Scan error: {e}")
                self.root.after(0, lambda: messagebox.showerror("Scan Error", str(e)))

        thread = threading.Thread(target=scan_thread)
        thread.daemon = True
        thread.start()

    def auto_sandbox_analysis(self, threat_reports):
        """Automatically analyze high-risk threats in sandbox"""
        if not threat_reports:
            return

        high_risk_threats = [
            t for t in threat_reports
            if t.get('threat_level') in ['Critical', 'High']
        ]

        if high_risk_threats and self.sandbox_analyzer:
            messagebox.showinfo(
                "Sandbox Analysis",
                f"Found {len(high_risk_threats)} high-risk threats.\n"
                "Starting automatic sandbox analysis..."
            )

            for threat in high_risk_threats[:3]:
                try:
                    file_path = threat.get('file_path')
                    if file_path and os.path.exists(file_path):
                        self.sandbox_analyzer.analyze_file(file_path)
                except Exception as e:
                    print(f"Auto sandbox analysis error: {e}")

    def update_scan_ui(self):
        """Update scan UI with progress"""
        self.progress_bar.set(self.scan_progress)
        self.progress_label.configure(
            text=f"Scanning... {self.files_scanned}/{self.total_files} files"
        )

    def scan_complete(self):
        """Handle scan completion"""
        self.reset_scan_ui()

        # Show batch threat dialog if threats found
        if self.threat_reports and len(self.threat_reports) > 0:
            dialog = BatchThreatDialog(
                self.root,
                self.threat_reports,
                self.db,
                self.sandbox_analyzer
            )
        else:
            messagebox.showinfo(
                "Scan Complete",
                f"Scan completed!\nFiles scanned: {self.files_scanned}\nNo threats found."
            )

        self.update_dashboard_stats()

    def reset_scan_ui(self):
        """Reset scan UI to default state"""
        self.scanning = False

        # Stop and reset scan animation
        if self.scan_animation:
            self.scan_animation.stop()
        self.scan_canvas.itemconfig(self.scan_text, text="SCAN", font=("Arial", 20, "bold"))
        self.scan_canvas.itemconfig(self.scan_circle, fill="#047eaf")

        self.stop_button.configure(state="disabled")
        self.pause_button.configure(state="disabled")
        self.progress_bar.set(0)

        # Update progress label based on selected mode
        mode_labels = {
            "quick": "Ready to scan - Quick Scan selected",
            "full": "Ready to scan - Full Scan selected",
            "custom": "Ready to scan - Custom Scan selected"
        }
        self.progress_label.configure(text=mode_labels.get(self.selected_scan_mode, "Ready to scan"))

    def stop_scan(self):
        """Stop current scan"""
        if self.scanner and hasattr(self.scanner, 'stop_scan'):
            self.scanner.stop_scan()
        self.reset_scan_ui()

    def pause_scan(self):
        """Pause current scan"""
        if self.scanner and hasattr(self.scanner, 'pause_scan'):
            self.scanner.pause_scan()

    # ==================== SANDBOX FUNCTIONS ====================

    def analyze_file_manually(self):
        """Manually analyze a file in sandbox"""
        filepath = filedialog.askopenfilename(title="Select file to analyze")
        if not filepath:
            return

        if not self.sandbox_analyzer:
            messagebox.showwarning(
                "Sandbox Not Available",
                "Sandbox analyzer is not available."
            )
            return

        # Use the new analyze_single_file function with report viewer
        self.sandbox_analyzer.analyze_single_file(filepath, self.root)

    def manual_sandbox_analysis(self):
        """Alias for analyze_file_manually"""
        self.analyze_file_manually()

    def _run_sandbox_analysis(self, file_path):
        """Run sandbox analysis (legacy support)"""
        if self.sandbox_analyzer:
            return self.sandbox_analyzer.analyze_file(file_path)
        return None

    def display_sandbox_result(self, result, file_path):
        """Display sandbox result (legacy support)"""
        messagebox.showinfo(
            "Sandbox Analysis Complete",
            f"Analysis complete for {os.path.basename(file_path)}\n"
            f"Result: {result.get('verdict', 'Unknown')}"
        )

    def show_sandbox_results(self, result):
        """Show sandbox analysis results"""
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Sandbox Results")
        dialog.geometry("600x400")

        ctk.CTkLabel(
            dialog,
            text="Sandbox Analysis Results",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(pady=20)

        results_text = ctk.CTkTextbox(dialog, width=550, height=300)
        results_text.pack(padx=20, pady=(0, 20))
        results_text.insert("1.0", str(result))
        results_text.configure(state="disabled")

        ctk.CTkButton(dialog, text="Close", command=dialog.destroy).pack(pady=10)

    # ==================== SYSTEM RESTORE FUNCTIONS ====================

    def emergency_rollback(self):
        """Perform emergency rollback"""
        response = messagebox.askyesno(
            "Emergency Rollback",
            "Perform emergency system rollback?\n\n"
            "This will restore the system to the most recent snapshot."
        )

        if response:
            self._do_emergency_rollback()

    def _do_emergency_rollback(self):
        """Execute emergency rollback"""
        try:
            snapshots = self.rollback_system.get_snapshots()
            if snapshots:
                latest = snapshots[0]
                self.rollback_system.restore_snapshot(latest['snapshot_id'])
                messagebox.showinfo("Success", "Emergency rollback completed!")
            else:
                messagebox.showwarning("No Snapshots", "No snapshots available for rollback.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def manual_rollback(self):
        """Open manual rollback dialog"""
        self.switch_view("rollback")

    def create_snapshot_now(self):
        """Create a new system snapshot"""
        response = messagebox.askyesno(
            "Create Snapshot",
            "Create a system snapshot for rollback?"
        )

        if response:
            self._create_snapshot()

    def _create_snapshot(self):
        """Execute snapshot creation"""
        try:
            snapshot = self.rollback_system.create_snapshot()
            self.update_dashboard_stats()
            self.load_snapshots_list()
            messagebox.showinfo("Success", f"Snapshot created: {snapshot['snapshot_id']}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def update_snapshot_count(self):
        """Update snapshot count display"""
        try:
            snapshots = self.rollback_system.get_snapshots()
            count = len(snapshots) if snapshots else 0
            self.snapshot_count_label.configure(text=str(count))
        except Exception:
            self.snapshot_count_label.configure(text="0")

    # ==================== STATS UPDATE ====================

    def update_dashboard_stats(self):
        """Update dashboard statistics"""
        try:
            stats = self.db.get_statistics()

            self.files_scanned_label.configure(
                text=str(self.db.get_files_scanned_count())
            )

            self.threats_found_label.configure(
                text=str(stats.get('total_threats', 0))
            )

            threat_count = stats.get('unresolved_threats', 0)
            if threat_count > 10:
                self.threat_indicator.configure(text="HIGH", text_color="#dc2626")
            elif threat_count > 5:
                self.threat_indicator.configure(text="MEDIUM", text_color="#f59e0b")
            else:
                self.threat_indicator.configure(text="LOW", text_color="#10b981")

            self.draw_security_pie_chart()
            self.update_snapshot_count()

        except Exception as e:
            print(f"Error updating stats: {e}")

    # ==================== VIEW SWITCHING ====================

    def switch_view(self, view_name):
        """Switch between different views"""
        for view in self.views.values():
            view.grid_forget()

        for key, btn in self.nav_buttons.items():
            if key == view_name:
                btn.configure(fg_color=("#047eaf", "#047eaf"))
            else:
                btn.configure(fg_color="transparent")

        if view_name in self.views:
            self.views[view_name].grid(row=0, column=0, sticky="nsew")
            self.current_view = view_name

            if view_name == "threats":
                self.load_threat_history()
            elif view_name == "rollback":
                self.load_snapshots_list()
            elif view_name == "quarantine":
                self.load_quarantine_list()

    # ==================== THREATS VIEW ====================

    def create_threats_view(self):
        """Threats history view"""
        frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.views["threats"] = frame

        ctk.CTkLabel(
            frame,
            text="Threat Detection History",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(pady=20)

        self.threat_list_frame = ctk.CTkScrollableFrame(frame)
        self.threat_list_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))

    def load_threat_history(self):
        """Load threat detection history"""
        try:
            for widget in self.threat_list_frame.winfo_children():
                widget.destroy()
        except Exception:
            pass

        try:
            threats = self.db.get_all_threats()
        except:
            threats = []

        if not threats:
            ctk.CTkLabel(
                self.threat_list_frame,
                text="No threats detected",
                text_color="gray"
            ).pack(pady=20)
            return

        for threat in threats:
            card = ctk.CTkFrame(self.threat_list_frame, fg_color="#1a1c24")
            card.pack(fill="x", padx=10, pady=5)

            info_frame = ctk.CTkFrame(card, fg_color="transparent")
            info_frame.pack(side="left", fill="both", expand=True, padx=15, pady=15)

            ctk.CTkLabel(
                info_frame,
                text=threat.get('file_path', 'Unknown'),
                font=ctk.CTkFont(size=13, weight="bold"),
                anchor="w"
            ).pack(anchor="w")

            details = f"Level: {threat.get('threat_level', 'Unknown')} | " \
                      f"Type: {threat.get('threat_type', 'Unknown')} | " \
                      f"Detected: {threat.get('timestamp', 'Unknown')}"

            ctk.CTkLabel(
                info_frame,
                text=details,
                font=ctk.CTkFont(size=10),
                text_color="gray",
                anchor="w"
            ).pack(anchor="w")

    # ==================== ROLLBACK VIEW ====================

    def create_rollback_view(self):
        """Rollback/Snapshot management view"""
        frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.views["rollback"] = frame

        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.pack(fill="x", pady=20, padx=20)

        ctk.CTkLabel(
            header,
            text="System Snapshots",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(side="left")

        ctk.CTkButton(
            header,
            text="+ Create Snapshot",
            command=self._create_snapshot,
            fg_color="#10b981",
            hover_color="#059669"
        ).pack(side="right")

        self.snapshots_list_frame = ctk.CTkScrollableFrame(frame)
        self.snapshots_list_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))

    def load_snapshots_list(self):
        """Load snapshots list"""
        try:
            for widget in self.snapshots_list_frame.winfo_children():
                widget.destroy()
        except Exception:
            pass

        try:
            snapshots = self.rollback_system.get_snapshots()
        except:
            snapshots = []

        if not snapshots:
            ctk.CTkLabel(
                self.snapshots_list_frame,
                text="No snapshots available",
                text_color="gray"
            ).pack(pady=20)
            return

        for snapshot in snapshots:
            card = ctk.CTkFrame(self.snapshots_list_frame, fg_color="#1a1c24")
            card.pack(fill="x", padx=10, pady=5)

            ctk.CTkLabel(
                card,
                text=f"Snapshot {snapshot['snapshot_id'][:8]}...",
                font=ctk.CTkFont(size=12)
            ).pack(side="left", padx=10, pady=10)

            ctk.CTkButton(
                card,
                text="Restore",
                width=100,
                command=lambda s=snapshot: self.restore_snapshot(s)
            ).pack(side="right", padx=10)

    def restore_snapshot(self, snapshot):
        """Restore from snapshot"""
        try:
            response = messagebox.askyesno(
                "Restore Snapshot",
                f"Restore from snapshot {snapshot['snapshot_id'][:8]}?\n\n"
                "This will revert system files to their previous state."
            )
            if response:
                self.rollback_system.restore_snapshot(snapshot['snapshot_id'])
                messagebox.showinfo("Success", "System restored successfully!")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ==================== QUARANTINE VIEW ====================

    def create_quarantine_view(self):
        """Quarantine management view"""
        frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.views["quarantine"] = frame

        ctk.CTkLabel(
            frame,
            text="Quarantined Files",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(pady=20)

        self.quarantine_list_frame = ctk.CTkScrollableFrame(frame)
        self.quarantine_list_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))

    def load_quarantine_list(self):
        """Load quarantine list"""
        try:
            for widget in self.quarantine_list_frame.winfo_children():
                widget.destroy()
        except Exception:
            pass

        try:
            quarantined = self.db.get_quarantine_items()
        except:
            quarantined = []

        if not quarantined:
            ctk.CTkLabel(
                self.quarantine_list_frame,
                text="No files in quarantine",
                text_color="gray"
            ).pack(pady=20)
            return

        for item in quarantined:
            card = ctk.CTkFrame(self.quarantine_list_frame)
            card.pack(fill="x", padx=10, pady=5)

            info_frame = ctk.CTkFrame(card, fg_color="transparent")
            info_frame.pack(side="left", fill="both", expand=True, padx=10, pady=10)

            ctk.CTkLabel(
                info_frame,
                text=item.get('file_name', 'Unknown'),
                font=ctk.CTkFont(size=13, weight="bold"),
                anchor="w"
            ).pack(anchor="w")

            ctk.CTkLabel(
                info_frame,
                text=f"Quarantined: {item.get('timestamp', 'Unknown')}",
                font=ctk.CTkFont(size=10),
                text_color="gray",
                anchor="w"
            ).pack(anchor="w")

            ctk.CTkButton(
                card,
                text="Delete",
                width=80,
                command=lambda i=item: self.delete_quarantine_item(i),
                fg_color="#dc2626"
            ).pack(side="right", padx=10)

    def delete_quarantine_item(self, item):
        """Delete quarantine item"""
        response = messagebox.askyesno(
            "Delete File",
            f"Permanently delete {item.get('file_name')}?"
        )
        if response:
            try:
                self.db.delete_quarantine_item(item['id'])
                self.load_quarantine_list()
                messagebox.showinfo("Success", "File deleted successfully")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    # ==================== SETTINGS VIEW ====================

    def create_settings_view(self):
        """Settings view"""
        frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.views["settings"] = frame

        settings_tab = SettingsTab(frame, self.db, self)
        settings_tab.pack(fill="both", expand=True)

    def update_definitions(self):
        """Update threat definitions"""
        messagebox.showinfo("Update", "Definitions update feature coming soon!")

    # ==================== UTILITY METHODS ====================

    def load_settings(self):
        """Load application settings"""
        try:
            settings = self.db.get_settings()
        except Exception as e:
            print(f"Error loading settings: {e}")

    def check_auto_scan(self):
        """Check if auto scan is enabled"""
        try:
            settings = self.db.get_settings()
            if settings.get('auto_scan') == 'true':
                pass
        except Exception:
            pass

    def run(self):
        """Run the application"""
        self.root.mainloop()


# ==================== DIALOG CLASSES ====================

class CustomPathDialog:
    def __init__(self, parent):
        self.dialog = ctk.CTkToplevel(parent)
        self.dialog.title("Custom Scan")
        self.dialog.geometry("500x400")
        self.dialog.transient(parent)
        self.dialog.grab_set()

        self.paths = []

        ctk.CTkLabel(
            self.dialog,
            text="Select Paths to Scan",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=20)

        self.path_frame = ctk.CTkScrollableFrame(self.dialog, height=200)
        self.path_frame.pack(fill="both", expand=True, padx=20, pady=10)

        btn_frame = ctk.CTkFrame(self.dialog, fg_color="transparent")
        btn_frame.pack(fill="x", padx=20, pady=10)

        ctk.CTkButton(
            btn_frame,
            text="Add Folder",
            command=self.add_folder
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            btn_frame,
            text="Add File",
            command=self.add_file
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            btn_frame,
            text="Start Scan",
            command=self.start_scan,
            fg_color="#047eaf"
        ).pack(side="right", padx=5)

    def add_folder(self):
        folder = filedialog.askdirectory(title="Select folder")
        if folder:
            self.paths.append(folder)
            ctk.CTkLabel(
                self.path_frame,
                text=folder,
                anchor="w"
            ).pack(fill="x", pady=2)

    def add_file(self):
        file = filedialog.askopenfilename(title="Select file")
        if file:
            self.paths.append(file)
            ctk.CTkLabel(
                self.path_frame,
                text=file,
                anchor="w"
            ).pack(fill="x", pady=2)

    def start_scan(self):
        self.dialog.destroy()

    def get_paths(self):
        return self.paths


if __name__ == "__main__":
    dashboard = FixionDashboard()
    dashboard.run()
