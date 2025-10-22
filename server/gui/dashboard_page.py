import customtkinter as ctk
import tkinter as tk
import os
import json
import threading
import random
from datetime import datetime
from PIL import Image
from tkinter import filedialog

# Import pages
from clientmachine_page import open_clientmachine_page
from threatlogs_page import open_threatlogs_page
from snapshot_page import open_snapshot_page
from userm_page import open_userm_page
from systems_page import open_systems_page

# Analytics page will be handled differently to pass server_manager
import analytics_page


# ==================== SERVER-SIDE COMPONENTS ====================

class ServerDatabase:
    """Centralized database handler for server operations"""

    def __init__(self, db_path="server_database.json"):
        self.db_path = db_path
        self.data = self.load_database()

    def load_database(self):
        try:
            with open(self.db_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {
                "threats": [],
                "scans": [],
                "quarantine": [],
                "snapshots": [],
                "statistics": {
                    "total_threats": 0,
                    "resolved_threats": 0,
                    "unresolved_threats": 0,
                    "files_scanned": 0
                },
                "threat_types": {}
            }

    def save_database(self):
        with open(self.db_path, 'w') as f:
            json.dump(self.data, f, indent=4)

    def add_threat(self, threat_data):
        threat_data['id'] = len(self.data['threats']) + 1
        threat_data['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.data['threats'].append(threat_data)
        self.data['statistics']['total_threats'] += 1
        self.data['statistics']['unresolved_threats'] += 1

        # Update threat types count
        threat_type = threat_data.get('threat_type', 'Unknown')
        if 'threat_types' not in self.data:
            self.data['threat_types'] = {}

        if threat_type not in self.data['threat_types']:
            self.data['threat_types'][threat_type] = {"count": 0}
        self.data['threat_types'][threat_type]["count"] += 1

        self.save_database()
        return threat_data

    def get_all_threats(self):
        return self.data.get('threats', [])

    def get_statistics(self):
        return self.data.get('statistics', {})

    def get_threat_types(self):
        """Get threat type distribution"""
        return self.data.get('threat_types', {})

    def add_to_quarantine(self, file_data):
        file_data['id'] = len(self.data['quarantine']) + 1
        file_data['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.data['quarantine'].append(file_data)
        self.save_database()

    def get_quarantine_items(self):
        return self.data.get('quarantine', [])

    def delete_quarantine_item(self, item_id):
        self.data['quarantine'] = [q for q in self.data['quarantine'] if q['id'] != item_id]
        self.save_database()

    def add_snapshot(self, snapshot_data):
        snapshot_data['id'] = len(self.data['snapshots']) + 1
        snapshot_data['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.data['snapshots'].append(snapshot_data)
        self.save_database()
        return snapshot_data

    def get_snapshots(self):
        return self.data.get('snapshots', [])

    def update_files_scanned(self, count):
        self.data['statistics']['files_scanned'] += count
        self.save_database()


class ServerScanEngine:
    """Server-side scanning engine with pause/stop controls"""

    def __init__(self, database):
        self.db = database
        self.scanning = False
        self.paused = False
        self.scan_progress = 0
        self.callbacks = {}

    def scan_paths(self, paths, client_id=None):
        self.scanning = True
        self.paused = False
        self.scan_progress = 0

        total_files = 0
        scanned_files = 0
        threats_found = []

        # Count total files
        for path in paths:
            if os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    total_files += len(files)
            elif os.path.isfile(path):
                total_files += 1

        # Scan files
        for path in paths:
            if not self.scanning:
                break

            if os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    for file in files:
                        # Check if scan should stop
                        if not self.scanning:
                            break

                        # Check if scan is paused
                        while self.paused and self.scanning:
                            threading.Event().wait(0.1)

                        file_path = os.path.join(root, file)
                        scanned_files += 1
                        self.scan_progress = scanned_files / total_files if total_files > 0 else 0

                        if 'on_scan_progress' in self.callbacks:
                            self.callbacks['on_scan_progress'](
                                self.scan_progress,
                                scanned=scanned_files,
                                total=total_files,
                                current_file=file_path
                            )

                        threat = self._analyze_file(file_path, client_id)
                        if threat:
                            threats_found.append(threat)

            elif os.path.isfile(path):
                # Check if scan should stop
                if not self.scanning:
                    break

                # Check if scan is paused
                while self.paused and self.scanning:
                    threading.Event().wait(0.1)

                scanned_files += 1
                self.scan_progress = scanned_files / total_files if total_files > 0 else 0

                if 'on_scan_progress' in self.callbacks:
                    self.callbacks['on_scan_progress'](
                        self.scan_progress,
                        scanned=scanned_files,
                        total=total_files,
                        current_file=path
                    )

                threat = self._analyze_file(path, client_id)
                if threat:
                    threats_found.append(threat)

        self.db.update_files_scanned(scanned_files)

        if 'on_scan_complete' in self.callbacks:
            was_stopped = not self.scanning
            self.callbacks['on_scan_complete'](threats_found, was_stopped)

        self.scanning = False
        self.paused = False
        return threats_found

    def _analyze_file(self, file_path, client_id=None):
        dangerous_extensions = ['.exe', '.dll', '.bat', '.vbs', '.ps1', '.scr']
        file_ext = os.path.splitext(file_path)[1].lower()

        if file_ext in dangerous_extensions and random.random() < 0.1:
            threat_types = ['Malware', 'Trojan', 'Ransomware', 'Spyware']
            threat_levels = ['Low', 'Medium', 'High', 'Critical']

            threat_data = {
                'file_path': file_path,
                'file_name': os.path.basename(file_path),
                'threat_type': random.choice(threat_types),
                'threat_level': random.choice(threat_levels),
                'client_id': client_id,
                'status': 'detected'
            }

            self.db.add_threat(threat_data)
            return threat_data

        return None

    def pause_scan(self):
        """Pause the current scan"""
        if self.scanning:
            self.paused = True
            print("[SERVER] Scan paused")

    def resume_scan(self):
        """Resume a paused scan"""
        if self.scanning and self.paused:
            self.paused = False
            print("[SERVER] Scan resumed")

    def stop_scan(self):
        """Stop the current scan"""
        self.scanning = False
        self.paused = False
        print("[SERVER] Scan stopped")


class ServerSandboxAnalyzer:
    """Server-side sandbox analysis"""

    def __init__(self, database):
        self.db = database

    def analyze_file(self, file_path, client_id=None):
        print(f"[SERVER] Analyzing file in sandbox: {file_path}")

        analysis_result = {
            'file_path': file_path,
            'verdict': 'Safe',
            'behaviors': [],
            'risk_score': 0.2,
            'client_id': client_id,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        threat_data = {
            'file_path': file_path,
            'threat_type': 'Sandbox Analysis',
            'threat_level': 'Info',
            'details': analysis_result,
            'client_id': client_id
        }
        self.db.add_threat(threat_data)

        return analysis_result


class ServerSnapshotManager:
    """Server-side snapshot/rollback management"""

    def __init__(self, database):
        self.db = database

    def create_snapshot(self, client_id=None, description=""):
        snapshot_data = {
            'snapshot_id': f"SNAP-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            'client_id': client_id,
            'description': description,
            'status': 'created'
        }

        return self.db.add_snapshot(snapshot_data)

    def get_snapshots(self, client_id=None):
        snapshots = self.db.get_snapshots()
        if client_id:
            return [s for s in snapshots if s.get('client_id') == client_id]
        return snapshots

    def restore_snapshot(self, snapshot_id):
        print(f"[SERVER] Restoring snapshot: {snapshot_id}")
        return True


class ServerQuarantineManager:
    """Server-side quarantine management"""

    def __init__(self, database):
        self.db = database

    def quarantine_file(self, file_path, threat_info, client_id=None):
        quarantine_data = {
            'file_name': os.path.basename(file_path),
            'original_path': file_path,
            'threat_info': threat_info,
            'client_id': client_id,
            'status': 'quarantined'
        }

        self.db.add_to_quarantine(quarantine_data)
        print(f"[SERVER] File quarantined: {file_path}")
        return True

    def restore_file(self, quarantine_id):
        print(f"[SERVER] Restoring file from quarantine: {quarantine_id}")
        return True

    def delete_file(self, quarantine_id):
        self.db.delete_quarantine_item(quarantine_id)
        print(f"[SERVER] Deleted quarantined file: {quarantine_id}")
        return True


class ServerManager:
    """Main server manager"""

    def __init__(self):
        self.database = ServerDatabase()
        self.scan_engine = ServerScanEngine(self.database)
        self.sandbox_analyzer = ServerSandboxAnalyzer(self.database)
        self.snapshot_manager = ServerSnapshotManager(self.database)
        self.quarantine_manager = ServerQuarantineManager(self.database)

        print("[SERVER] Server components initialized successfully")

    def start_scan(self, paths, client_id=None, callback=None):
        def scan_thread():
            results = self.scan_engine.scan_paths(paths, client_id)
            if callback:
                callback(results)

        thread = threading.Thread(target=scan_thread)
        thread.daemon = True
        thread.start()

    def analyze_in_sandbox(self, file_path, client_id=None):
        return self.sandbox_analyzer.analyze_file(file_path, client_id)

    def create_snapshot(self, client_id=None, description=""):
        return self.snapshot_manager.create_snapshot(client_id, description)

    def get_threat_statistics(self):
        return self.database.get_statistics()

    def get_all_threats(self):
        return self.database.get_all_threats()

    def get_threat_types_distribution(self):
        """Get threat types for pie chart"""
        threat_types = self.database.get_threat_types()
        if not threat_types:
            # Return sample data if no real data exists
            return {
                "Malware": {"count": random.randint(45, 65)},
                "Phishing": {"count": random.randint(25, 35)},
                "Ransomware": {"count": random.randint(8, 15)},
                "Trojan": {"count": random.randint(15, 25)},
                "Spyware": {"count": random.randint(10, 18)}
            }
        return threat_types


# ==================== UI FUNCTIONS ====================

current_dir = os.path.dirname(os.path.abspath(__file__))


def get_assets_path():
    direct_path = os.path.join(current_dir, "assets")
    if os.path.exists(direct_path):
        return direct_path
    parent_path = os.path.join(current_dir, "..", "assets")
    if os.path.exists(parent_path):
        return parent_path
    return "assets"


assets_path = get_assets_path()


def center_window(window, width, height):
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width - width) // 2
    y = (screen_height - height) // 2
    window.geometry(f"{width}x{height}+{x}+{y}")


def clear_frame(frame):
    for widget in frame.winfo_children():
        widget.destroy()


def load_users():
    try:
        with open('users.json', 'r') as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def get_client_machines():
    users = load_users()
    return [user for user in users if user.get("role") == "client machine"]


def create_stats_card(parent, title, value, icon_name, row, column):
    card = ctk.CTkFrame(parent, corner_radius=10, fg_color="#22232e")
    card.grid(row=row, column=column, padx=10, pady=10, sticky="nsew")

    try:
        icon_path = os.path.join(assets_path, "icon", icon_name)
        icon_image = ctk.CTkImage(
            light_image=Image.open(icon_path),
            dark_image=Image.open(icon_path),
            size=(32, 32)
        )
        icon_label = ctk.CTkLabel(card, image=icon_image, text="")
        icon_label.pack(anchor="w", padx=15, pady=(15, 5))
    except:
        pass

    ctk.CTkLabel(card, text=title, font=("Roboto", 14), text_color="#e9e8e8").pack(anchor="w", padx=15, pady=5)
    ctk.CTkLabel(card, text=value, font=("Roboto", 24, "bold"), text_color="#e9e8e8").pack(anchor="w", padx=15,
                                                                                           pady=(5, 15))


def create_dashboard_legend(parent, threat_types, total_threats):
    """Create a professional legend for dashboard (matching the image style)"""
    for widget in parent.winfo_children():
        widget.destroy()

    professional_colors = [
        "#3B82F6", "#10B981", "#F59E0B", "#EF4444",
        "#8B5CF6", "#6B7280", "#EC4899", "#14B8A6"
    ]

    # Header with title and total
    header_frame = ctk.CTkFrame(parent, fg_color="transparent")
    header_frame.pack(fill="x", padx=20, pady=(20, 15))

    ctk.CTkLabel(
        header_frame,
        text="Threat Distribution",
        font=("Roboto", 16, "bold"),
        text_color="#FFFFFF"
    ).pack(side="left")

    if total_threats > 0:
        ctk.CTkLabel(
            header_frame,
            text=f"{total_threats} Total",
            font=("Roboto", 13),
            text_color="#94A3B8"
        ).pack(side="right")

    if total_threats == 0:
        ctk.CTkLabel(
            parent,
            text="No threat data",
            font=("Roboto", 12),
            text_color="#6B7280"
        ).pack(pady=30)
        return

    sorted_threats = sorted(
        threat_types.items(),
        key=lambda x: x[1]["count"],
        reverse=True
    )

    # Legend entries
    for i, (threat_type, data) in enumerate(sorted_threats):
        percentage = (data["count"] / total_threats) * 100

        # Main row container
        row_container = ctk.CTkFrame(parent, fg_color="transparent")
        row_container.pack(fill="x", padx=20, pady=8)

        # Inner row with dark background
        row_frame = ctk.CTkFrame(
            row_container,
            fg_color="#2D3748",
            corner_radius=8,
            height=50
        )
        row_frame.pack(fill="x")
        row_frame.pack_propagate(False)

        # Content frame
        content_frame = ctk.CTkFrame(row_frame, fg_color="transparent")
        content_frame.pack(fill="both", expand=True, padx=15, pady=12)

        # Left side: color square + name
        left_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        left_frame.pack(side="left", fill="y")

        # Color square
        color_square = ctk.CTkFrame(
            left_frame,
            width=18,
            height=18,
            corner_radius=4,
            fg_color=professional_colors[i % len(professional_colors)]
        )
        color_square.pack(side="left", padx=(0, 12))

        # Threat name
        ctk.CTkLabel(
            left_frame,
            text=threat_type,
            font=("Roboto", 13, "bold"),
            text_color="#FFFFFF"
        ).pack(side="left")

        # Right side: percentage + count
        right_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        right_frame.pack(side="right", fill="y")

        # Percentage
        ctk.CTkLabel(
            right_frame,
            text=f"{percentage:.1f}%",
            font=("Roboto", 12),
            text_color="#94A3B8"
        ).pack(side="left", padx=(0, 15))

        # Count
        ctk.CTkLabel(
            right_frame,
            text=str(data['count']),
            font=("Roboto", 13, "bold"),
            text_color="#FFFFFF"
        ).pack(side="left")

        # Progress bar at bottom - FIXED VERSION
        progress_outer = ctk.CTkFrame(row_frame, fg_color="transparent")
        progress_outer.pack(side="bottom", fill="x", padx=15, pady=(0, 8))

        # Background bar (gray)
        progress_bg = ctk.CTkFrame(
            progress_outer,
            height=3,
            corner_radius=2,
            fg_color="#1A202C"
        )
        progress_bg.pack(fill="x")

        # Foreground bar (colored, proportional width)
        progress_width_percent = percentage / 100
        progress_bar = ctk.CTkFrame(
            progress_bg,
            height=3,
            corner_radius=2,
            fg_color=professional_colors[i % len(professional_colors)]
        )
        progress_bar.place(x=0, y=0, relwidth=progress_width_percent)


def create_professional_pie_chart(canvas, threat_types, total_threats):
    canvas.delete("all")

    # Force canvas to update and get actual size
    canvas.update_idletasks()
    width = canvas.winfo_width()
    height = canvas.winfo_height()

    # Fallback if size is still not ready
    if width <= 1 or height <= 1:
        width = 220
        height = 220

    center_x = width // 2
    center_y = height // 2
    base_radius = min(width, height) // 3
    radius = max(base_radius, 70)

    professional_colors = [
        "#3B82F6", "#10B981", "#F59E0B", "#EF4444",
        "#8B5CF6", "#6B7280", "#EC4899", "#14B8A6"
    ]

    if total_threats == 0:
        canvas.create_oval(
            center_x - radius, center_y - radius,
            center_x + radius, center_y + radius,
            fill="#F8FAFC", outline="#E2E8F0", width=2
        )
        canvas.create_text(
            center_x, center_y,
            text="No Data",
            fill="#64748B",
            font=("Roboto", 11),
            anchor="center"
        )
        return

    sorted_threats = sorted(threat_types.items(), key=lambda x: x[1]["count"], reverse=True)
    start_angle = -90

    for i, (threat_type, data) in enumerate(sorted_threats):
        angle_extent = (data["count"] / total_threats) * 360
        color = professional_colors[i % len(professional_colors)]

        canvas.create_arc(
            center_x - radius, center_y - radius,
            center_x + radius, center_y + radius,
            start=start_angle, extent=angle_extent,
            fill=color,
            outline="#FFFFFF",
            width=2,
            style="pieslice"
        )
        start_angle += angle_extent

    inner_radius = radius * 0.45
    canvas.create_oval(
        center_x - inner_radius, center_y - inner_radius,
        center_x + inner_radius, center_y + inner_radius,
        fill="#1c253a", outline="#E5E7EB", width=1
    )

    canvas.create_text(
        center_x, center_y - 6,
        text="Total",
        fill="#94a3b8",
        font=("Roboto", 8),
        anchor="center"
    )

    canvas.create_text(
        center_x, center_y + 8,
        text=f"{total_threats}",
        fill="#e9e8e8",
        font=("Roboto", 14, "bold"),
        anchor="center"
    )


def create_compact_legend(parent, threat_types, total_threats):
    for widget in parent.winfo_children():
        widget.destroy()

    professional_colors = [
        "#3B82F6", "#10B981", "#F59E0B", "#EF4444",
        "#8B5CF6", "#6B7280", "#EC4899", "#14B8A6"
    ]

    if total_threats == 0:
        ctk.CTkLabel(
            parent,
            text="No data",
            font=("Roboto", 10),
            text_color="#6B7280"
        ).pack(pady=10)
        return

    sorted_threats = sorted(
        threat_types.items(),
        key=lambda x: x[1]["count"],
        reverse=True
    )

    for i, (threat_type, data) in enumerate(sorted_threats):
        percentage = (data["count"] / total_threats) * 100

        row_frame = ctk.CTkFrame(parent, fg_color="transparent")
        row_frame.pack(fill="x", pady=6, padx=8)

        color_frame = ctk.CTkFrame(
            row_frame,
            width=8,
            height=8,
            corner_radius=2,
            fg_color=professional_colors[i % len(professional_colors)]
        )
        color_frame.pack(side="left", padx=(0, 6), pady=6)

        ctk.CTkLabel(
            row_frame,
            text=threat_type,
            font=("Roboto", 9),
            text_color="#ffffff"
        ).pack(side="left")

        ctk.CTkLabel(
            row_frame,
            text=f"{data['count']} ({percentage:.0f}%)",
            font=("Roboto", 9),
            text_color="#94a3b8"
        ).pack(side="right")


def open_dashboard_content(parent_frame, server_manager=None):
    """Dashboard with pie chart and scan options"""
    clear_frame(parent_frame)

    if server_manager:
        stats = server_manager.get_threat_statistics()
        total_threats = stats.get('total_threats', 0)
        files_scanned = stats.get('files_scanned', 0)
    else:
        total_threats = 0
        files_scanned = 0

    # Page title
    title = ctk.CTkLabel(
        master=parent_frame,
        text="Dashboard Overview",
        font=("Roboto", 24, "bold"),
        text_color="#e9e8e8"
    )
    title.pack(anchor="w", padx=12, pady=12)

    main_content = ctk.CTkScrollableFrame(parent_frame, width=950, height=700, fg_color="#22222f")
    main_content.pack(fill="both", expand=True, padx=20, pady=10)

    # Stats cards
    stats_section = ctk.CTkFrame(main_content, fg_color="#22232e")
    stats_section.pack(fill="x", padx=10, pady=10)

    for i in range(4):
        stats_section.grid_columnconfigure(i, weight=1)

    stats_data = [
        ("Total Threats", str(total_threats), "threat_logs_icon.png"),
        ("Active Clients", str(len(get_client_machines())), "client_machine_icon.png"),
        ("Files Scanned", str(files_scanned), "analytics_icon.png"),
        ("Server Status", "Online", "systems_icon.png")
    ]

    for i, (title, value, icon) in enumerate(stats_data):
        create_stats_card(stats_section, title, value, icon, 0, i)

    # Main content
    content_area = ctk.CTkFrame(main_content, fg_color="transparent")
    content_area.pack(fill="both", expand=True, padx=10, pady=10)

    # LEFT - Pie Chart
    left_frame = ctk.CTkFrame(content_area, fg_color="#22232e", corner_radius=10)
    left_frame.pack(side="left", fill="both", expand=True, padx=(0, 5))

    ctk.CTkLabel(
        left_frame,
        text="Client Threat Analysis",
        font=("Roboto", 16, "bold"),
        text_color="#e9e8e8"
    ).pack(pady=(15, 10), padx=20, anchor="w")

    chart_container = ctk.CTkFrame(left_frame, fg_color="#1c253a", corner_radius=10)
    chart_container.pack(fill="both", expand=True, padx=15, pady=10)

    # Bigger pie chart at the top
    pie_canvas = tk.Canvas(chart_container, bg="#1c253a", highlightthickness=0, width=280, height=280)
    pie_canvas.pack(padx=15, pady=(15, 10))

    # Legend directly below pie chart in same frame
    legend_section = ctk.CTkFrame(chart_container, fg_color="transparent")
    legend_section.pack(fill="both", expand=True, padx=5, pady=(0, 10))

    # Generate data
    threat_types = server_manager.get_threat_types_distribution() if server_manager else {
        "Malware": {"count": random.randint(45, 65)},
        "Phishing": {"count": random.randint(25, 35)},
        "Ransomware": {"count": random.randint(8, 15)},
        "Trojan": {"count": random.randint(15, 25)},
        "Spyware": {"count": random.randint(10, 18)}
    }

    total = sum(t["count"] for t in threat_types.values())

    # Bind configure event to redraw on resize
    def on_canvas_resize(event):
        pie_canvas.after(10, lambda: create_professional_pie_chart(pie_canvas, threat_types, total))

    pie_canvas.bind("<Configure>", on_canvas_resize)

    # Initial draw with longer delay to ensure canvas is ready
    pie_canvas.after(200, lambda: create_professional_pie_chart(pie_canvas, threat_types, total))
    create_dashboard_legend(legend_section, threat_types, total)

    # RIGHT - Scan Controls with Pause/Stop functionality
    right_frame = ctk.CTkFrame(content_area, fg_color="#22232e", corner_radius=10)
    right_frame.pack(side="right", fill="both", expand=True, padx=(5, 0))

    ctk.CTkLabel(
        right_frame,
        text="Scan Controls",
        font=("Roboto", 16, "bold"),
        text_color="#e9e8e8"
    ).pack(pady=(15, 10), padx=20, anchor="w")

    scan_mode_var = tk.StringVar(value="quick")

    ctk.CTkLabel(
        right_frame,
        text="Select Scan Type:",
        font=("Roboto", 11),
        text_color="#94a3b8"
    ).pack(pady=(8, 5), padx=20, anchor="w")

    modes_frame = ctk.CTkFrame(right_frame, fg_color="transparent")
    modes_frame.pack(fill="x", padx=20, pady=(0, 8))

    scan_desc = ctk.CTkLabel(
        right_frame,
        text="Quick scan of common locations",
        font=("Roboto", 9),
        text_color="#64748b",
        wraplength=250
    )

    def select_mode(mode, btn_q, btn_f, btn_c):
        scan_mode_var.set(mode)
        btn_q.configure(fg_color="#1a1c24")
        btn_f.configure(fg_color="#1a1c24")
        btn_c.configure(fg_color="#1a1c24")

        if mode == "quick":
            btn_q.configure(fg_color="#047eaf")
            scan_desc.configure(text="Quick scan of common threat locations")
        elif mode == "full":
            btn_f.configure(fg_color="#0891b2")
            scan_desc.configure(text="Complete system scan (takes longer)")
        elif mode == "custom":
            btn_c.configure(fg_color="#8b5cf6")
            scan_desc.configure(text="Choose specific files/folders")

    quick_btn = ctk.CTkButton(
        modes_frame,
        text="⚡ Quick Scan",
        height=38,
        font=("Roboto", 11, "bold"),
        fg_color="#047eaf",
        hover_color="#036a91"
    )
    quick_btn.pack(fill="x", pady=2)

    full_btn = ctk.CTkButton(
        modes_frame,
        text="🔍 Full Scan",
        height=38,
        font=("Roboto", 11, "bold"),
        fg_color="#1a1c24",
        hover_color="#0891b2",
        border_width=2,
        border_color="#0891b2"
    )
    full_btn.pack(fill="x", pady=2)

    custom_btn = ctk.CTkButton(
        modes_frame,
        text="📁 Custom Scan",
        height=38,
        font=("Roboto", 11, "bold"),
        fg_color="#1a1c24",
        hover_color="#8b5cf6",
        border_width=2,
        border_color="#8b5cf6"
    )
    custom_btn.pack(fill="x", pady=2)

    quick_btn.configure(command=lambda: select_mode("quick", quick_btn, full_btn, custom_btn))
    full_btn.configure(command=lambda: select_mode("full", quick_btn, full_btn, custom_btn))
    custom_btn.configure(command=lambda: select_mode("custom", quick_btn, full_btn, custom_btn))

    scan_desc.pack(pady=(5, 12), padx=20)

    if server_manager:
        # Control buttons frame
        control_frame = ctk.CTkFrame(right_frame, fg_color="transparent")
        control_frame.pack(fill="x", padx=20, pady=(0, 8))

        # Start button (initially visible)
        start_btn = ctk.CTkButton(
            control_frame,
            text="🛡️ Start Scan",
            height=48,
            font=("Roboto", 14, "bold"),
            fg_color="#10B981",
            hover_color="#059669"
        )
        start_btn.pack(fill="x")

        # Control buttons (initially hidden)
        active_controls = ctk.CTkFrame(control_frame, fg_color="transparent")

        pause_btn = ctk.CTkButton(
            active_controls,
            text="⏸️ Pause",
            height=48,
            font=("Roboto", 13, "bold"),
            fg_color="#F59E0B",
            hover_color="#D97706"
        )
        pause_btn.pack(side="left", fill="x", expand=True, padx=(0, 5))

        stop_btn = ctk.CTkButton(
            active_controls,
            text="⏹️ Stop",
            height=48,
            font=("Roboto", 13, "bold"),
            fg_color="#EF4444",
            hover_color="#DC2626"
        )
        stop_btn.pack(side="right", fill="x", expand=True, padx=(5, 0))

        # Progress info
        progress_frame = ctk.CTkFrame(right_frame, fg_color="#1a1c24", corner_radius=8)
        progress_frame.pack(fill="x", padx=20, pady=(0, 8))

        status_lbl = ctk.CTkLabel(
            progress_frame,
            text="Ready",
            font=("Roboto", 11, "bold"),
            text_color="#94a3b8"
        )
        status_lbl.pack(pady=(8, 4))

        progress_detail = ctk.CTkLabel(
            progress_frame,
            text="",
            font=("Roboto", 9),
            text_color="#64748b"
        )
        progress_detail.pack(pady=(0, 8))

        scan_active = [False]  # Use list to modify in nested functions

        def start_scan():
            mode = scan_mode_var.get()

            if mode == "quick":
                paths = [os.path.expanduser("~/Downloads"), os.path.expanduser("~/Documents")]
            elif mode == "full":
                paths = [os.path.expanduser("~")]
            else:
                path = filedialog.askdirectory(title="Select folder")
                if not path:
                    return
                paths = [path]

            # Show active controls
            start_btn.pack_forget()
            active_controls.pack(fill="x")
            scan_active[0] = True

            status_lbl.configure(text="🔄 Scanning...", text_color="#10B981")
            progress_detail.configure(text="Starting scan...")

            # Setup progress callback
            def on_progress(progress, scanned, total, current_file):
                percentage = int(progress * 100)
                file_name = os.path.basename(current_file)
                status_lbl.configure(text=f"🔄 Scanning... {percentage}%")
                progress_detail.configure(text=f"{scanned}/{total} files • {file_name[:30]}...")

            server_manager.scan_engine.callbacks['on_scan_progress'] = on_progress

            def done(results, was_stopped=False):
                # Show start button again
                active_controls.pack_forget()
                start_btn.pack(fill="x")
                scan_active[0] = False
                pause_btn.configure(text="⏸️ Pause")

                if was_stopped:
                    status_lbl.configure(
                        text=f"⚠️ Scan stopped",
                        text_color="#F59E0B"
                    )
                    progress_detail.configure(text=f"Found {len(results)} threats before stopping")
                else:
                    status_lbl.configure(
                        text=f"✅ Scan complete!",
                        text_color="#10B981"
                    )
                    progress_detail.configure(text=f"Found {len(results)} threats")

            server_manager.start_scan(paths, callback=done)

        def pause_scan():
            if server_manager.scan_engine.paused:
                # Resume
                server_manager.scan_engine.resume_scan()
                pause_btn.configure(text="⏸️ Pause")
                status_lbl.configure(text="🔄 Scanning...", text_color="#10B981")
            else:
                # Pause
                server_manager.scan_engine.pause_scan()
                pause_btn.configure(text="▶️ Resume")
                status_lbl.configure(text="⏸️ Paused", text_color="#F59E0B")

        def stop_scan():
            server_manager.scan_engine.stop_scan()
            status_lbl.configure(text="⏹️ Stopping...", text_color="#EF4444")

        start_btn.configure(command=start_scan)
        pause_btn.configure(command=pause_scan)
        stop_btn.configure(command=stop_scan)

    # System status
    info = ctk.CTkFrame(right_frame, fg_color="#1a1c24", corner_radius=8)
    info.pack(fill="x", padx=20, pady=(8, 15))

    ctk.CTkLabel(info, text="System Status", font=("Roboto", 12, "bold"), text_color="#e9e8e8").pack(pady=(8, 4))

    for lbl, val, clr in [("Protection", "Active", "#10B981"), ("Database", "OK", "#10B981"),
                          ("Engine", "Ready", "#10B981")]:
        r = ctk.CTkFrame(info, fg_color="transparent")
        r.pack(fill="x", padx=8, pady=3)
        ctk.CTkLabel(r, text=lbl, font=("Roboto", 9), text_color="#94a3b8").pack(side="left")
        ctk.CTkLabel(r, text=val, font=("Roboto", 9, "bold"), text_color=clr).pack(side="right")


def open_dashboard_page(user_info=None):
    server_manager = ServerManager()

    mainframe = ctk.CTk(fg_color="#15141b")
    mainframe.title('Server UI Dashboard - Enhanced')

    width, height = 1100, 750
    center_window(mainframe, width, height)

    sidebar_frame = ctk.CTkFrame(master=mainframe, width=118, corner_radius=24, fg_color="#122a3e")
    sidebar_frame.pack(side="left", fill="y")
    sidebar_frame.pack_propagate(False)

    main_content = ctk.CTkFrame(master=mainframe, fg_color="#15141b", border_width=0)
    main_content.pack(side="right", fill="both", expand=True)

    mainframe.server_manager = server_manager

    sidebar_items = [
        {"name": "Dashboard", "page": lambda f: open_dashboard_content(f, server_manager),
         "icon": "dashboard_icon.png"},
        {"name": "Client machine", "page": open_clientmachine_page, "icon": "client_machine_icon.png"},
        {"name": "Threat logs", "page": open_threatlogs_page, "icon": "threat_logs_icon.png"},
        {"name": "Analytics", "page": lambda f: analytics_page.open_analytics_page(f, server_manager),
         "icon": "analytics_icon.png"},
        {"name": "Snapshots", "page": open_snapshot_page, "icon": "snapshot_icon.png"},
        {"name": "User Management", "page": open_userm_page, "icon": "userm_icon.png"},
        {"name": "System Settings", "page": open_systems_page, "icon": "systems_icon.png"}
    ]

    try:
        logo_path = os.path.join(os.path.dirname(__file__), "logo", "fixion_logo.png")
        logo_image = ctk.CTkImage(
            light_image=Image.open(logo_path),
            size=(38, 48)
        )
        logo_label = ctk.CTkLabel(master=sidebar_frame, image=logo_image, text="")
        logo_label.pack(padx=8, pady=13)
    except:
        ctk.CTkLabel(
            sidebar_frame,
            text="FIXION",
            font=("Roboto", 16, "bold"),
            text_color="#e9e8e8"
        ).pack(pady=20)

    for item in sidebar_items:
        item_frame = ctk.CTkFrame(master=sidebar_frame, fg_color="transparent")
        item_frame.pack(fill="x", padx=2, pady=4)

        try:
            icon_path = os.path.join(assets_path, "icon", item["icon"])
            icon_image = ctk.CTkImage(
                light_image=Image.open(icon_path),
                dark_image=Image.open(icon_path),
                size=(25, 25)
            )
            icon_label = ctk.CTkLabel(master=item_frame, image=icon_image, text="")
            icon_label.pack(pady=(5, 10))
            icon_element = icon_label
        except:
            icon_frame = ctk.CTkFrame(master=item_frame, width=35, height=35, fg_color="transparent")
            icon_frame.pack(pady=(1, 1))
            icon_element = icon_frame

        item_label = ctk.CTkLabel(
            master=item_frame,
            text=item["name"],
            font=("Arial", 11),
            anchor="center"
        )
        item_label.pack(pady=(5, 10))

        def create_click_handler(page_func):
            return lambda e: page_func(main_content)

        item_frame.bind("<Button-1>", create_click_handler(item["page"]))
        icon_element.bind("<Button-1>", create_click_handler(item["page"]))
        item_label.bind("<Button-1>", create_click_handler(item["page"]))

    open_dashboard_content(main_content, server_manager)

    if user_info:
        mainframe.title(f'Server UI Dashboard - {user_info["username"]}')

    mainframe.mainloop()


if __name__ == "__main__":
    open_dashboard_page({"username": "admin", "role": "admin"})