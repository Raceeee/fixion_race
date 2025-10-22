import customtkinter as ctk
import tkinter as tk
import os
import json
import threading
from datetime import datetime
from PIL import Image

# Import pages
from clientmachine_page import open_clientmachine_page
from threatlogs_page import open_threatlogs_page
from analytics_page import open_analytics_page
from snapshot_page import open_snapshot_page
from userm_page import open_userm_page
from systems_page import open_systems_page


# ==================== SERVER-SIDE COMPONENTS ====================
# These components handle business logic, database, and scanning

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
                }
            }

    def save_database(self):
        with open(self.db_path, 'w') as f:
            json.dump(self.data, f, indent=4)

    def add_threat(self, threat_data):
        """Add threat to database"""
        threat_data['id'] = len(self.data['threats']) + 1
        threat_data['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.data['threats'].append(threat_data)
        self.data['statistics']['total_threats'] += 1
        self.data['statistics']['unresolved_threats'] += 1
        self.save_database()
        return threat_data

    def get_all_threats(self):
        return self.data.get('threats', [])

    def get_statistics(self):
        return self.data.get('statistics', {})

    def add_to_quarantine(self, file_data):
        """Add file to quarantine"""
        file_data['id'] = len(self.data['quarantine']) + 1
        file_data['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.data['quarantine'].append(file_data)
        self.save_database()

    def get_quarantine_items(self):
        return self.data.get('quarantine', [])

    def delete_quarantine_item(self, item_id):
        """Remove item from quarantine"""
        self.data['quarantine'] = [q for q in self.data['quarantine'] if q['id'] != item_id]
        self.save_database()

    def add_snapshot(self, snapshot_data):
        """Add snapshot record"""
        snapshot_data['id'] = len(self.data['snapshots']) + 1
        snapshot_data['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.data['snapshots'].append(snapshot_data)
        self.save_database()
        return snapshot_data

    def get_snapshots(self):
        return self.data.get('snapshots', [])

    def update_files_scanned(self, count):
        """Update files scanned count"""
        self.data['statistics']['files_scanned'] += count
        self.save_database()


class ServerScanEngine:
    """Server-side scanning engine"""

    def __init__(self, database):
        self.db = database
        self.scanning = False
        self.scan_progress = 0
        self.callbacks = {}

    def scan_paths(self, paths, client_id=None):
        """Scan specified paths for threats"""
        self.scanning = True
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
                        if not self.scanning:
                            break

                        file_path = os.path.join(root, file)
                        scanned_files += 1
                        self.scan_progress = scanned_files / total_files

                        # Progress callback
                        if 'on_scan_progress' in self.callbacks:
                            self.callbacks['on_scan_progress'](
                                self.scan_progress,
                                scanned=scanned_files,
                                total=total_files,
                                current_file=file_path
                            )

                        # Simulate threat detection
                        threat = self._analyze_file(file_path, client_id)
                        if threat:
                            threats_found.append(threat)

            elif os.path.isfile(path):
                scanned_files += 1
                self.scan_progress = scanned_files / total_files

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

        # Update database
        self.db.update_files_scanned(scanned_files)

        # Complete callback
        if 'on_scan_complete' in self.callbacks:
            self.callbacks['on_scan_complete'](threats_found)

        self.scanning = False
        return threats_found

    def _analyze_file(self, file_path, client_id=None):
        """Analyze individual file for threats"""
        # Simplified threat detection logic
        # In real implementation, use ML models or signature matching

        dangerous_extensions = ['.exe', '.dll', '.bat', '.vbs', '.ps1', '.scr']
        file_ext = os.path.splitext(file_path)[1].lower()

        # Simulate threat detection (10% chance)
        import random
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

            # Add to database
            self.db.add_threat(threat_data)
            return threat_data

        return None

    def stop_scan(self):
        """Stop ongoing scan"""
        self.scanning = False

    def pause_scan(self):
        """Pause scan (placeholder)"""
        pass


class ServerSandboxAnalyzer:
    """Server-side sandbox analysis"""

    def __init__(self, database):
        self.db = database

    def analyze_file(self, file_path, client_id=None):
        """Analyze file in isolated sandbox environment"""
        print(f"[SERVER] Analyzing file in sandbox: {file_path}")

        # Simulate sandbox analysis
        analysis_result = {
            'file_path': file_path,
            'verdict': 'Safe',  # or 'Malicious', 'Suspicious'
            'behaviors': [],
            'risk_score': 0.2,
            'client_id': client_id,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        # Store analysis results
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
        """Create system snapshot"""
        snapshot_data = {
            'snapshot_id': f"SNAP-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            'client_id': client_id,
            'description': description,
            'status': 'created'
        }

        return self.db.add_snapshot(snapshot_data)

    def get_snapshots(self, client_id=None):
        """Get all snapshots"""
        snapshots = self.db.get_snapshots()
        if client_id:
            return [s for s in snapshots if s.get('client_id') == client_id]
        return snapshots

    def restore_snapshot(self, snapshot_id):
        """Restore from snapshot"""
        print(f"[SERVER] Restoring snapshot: {snapshot_id}")
        # Implement actual restoration logic
        return True


class ServerQuarantineManager:
    """Server-side quarantine management"""

    def __init__(self, database):
        self.db = database

    def quarantine_file(self, file_path, threat_info, client_id=None):
        """Move file to quarantine"""
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
        """Restore file from quarantine"""
        print(f"[SERVER] Restoring file from quarantine: {quarantine_id}")
        return True

    def delete_file(self, quarantine_id):
        """Permanently delete quarantined file"""
        self.db.delete_quarantine_item(quarantine_id)
        print(f"[SERVER] Deleted quarantined file: {quarantine_id}")
        return True


# ==================== SERVER MAIN CLASS ====================

class ServerManager:
    """Main server manager coordinating all server-side operations"""

    def __init__(self):
        self.database = ServerDatabase()
        self.scan_engine = ServerScanEngine(self.database)
        self.sandbox_analyzer = ServerSandboxAnalyzer(self.database)
        self.snapshot_manager = ServerSnapshotManager(self.database)
        self.quarantine_manager = ServerQuarantineManager(self.database)

        print("[SERVER] Server components initialized successfully")

    def start_scan(self, paths, client_id=None, callback=None):
        """Initiate scan operation"""

        def scan_thread():
            results = self.scan_engine.scan_paths(paths, client_id)
            if callback:
                callback(results)

        thread = threading.Thread(target=scan_thread)
        thread.daemon = True
        thread.start()

    def analyze_in_sandbox(self, file_path, client_id=None):
        """Analyze file in sandbox"""
        return self.sandbox_analyzer.analyze_file(file_path, client_id)

    def create_snapshot(self, client_id=None, description=""):
        """Create system snapshot"""
        return self.snapshot_manager.create_snapshot(client_id, description)

    def get_threat_statistics(self):
        """Get threat statistics"""
        return self.database.get_statistics()

    def get_all_threats(self):
        """Get all detected threats"""
        return self.database.get_all_threats()


# ==================== EXISTING UI CODE ====================

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


# Keep all existing UI functions (create_stats_card, pie charts, etc.)
# ... [Previous UI code remains unchanged] ...

def open_dashboard_page(user_info=None):
    """Opens dashboard with integrated server manager"""
    # Initialize server manager
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

    # Store server_manager reference for use in pages
    mainframe.server_manager = server_manager

    sidebar_items = [
        {"name": "Dashboard", "page": lambda f: open_dashboard_content(f, server_manager),
         "icon": "dashboard_icon.png"},
        {"name": "Client machine", "page": open_clientmachine_page, "icon": "client_machine_icon.png"},
        {"name": "Threat logs", "page": lambda f: open_threatlogs_page(f, server_manager),
         "icon": "threat_logs_icon.png"},
        {"name": "Analytics", "page": open_analytics_page, "icon": "analytics_icon.png"},
        {"name": "Snapshots", "page": lambda f: open_snapshot_page(f, server_manager), "icon": "snapshot_icon.png"},
        {"name": "User Management", "page": open_userm_page, "icon": "userm_icon.png"},
        {"name": "System Settings", "page": open_systems_page, "icon": "systems_icon.png"}
    ]

    # Logo
    try:
        logo_path = os.path.join(os.path.dirname(__file__), "logo", "fixion_logo.png")
        logo_image = ctk.CTkImage(
            light_image=Image.open(logo_path),
            size=(38, 48)
        )
        logo_label = ctk.CTkLabel(master=sidebar_frame, image=logo_image, text="")
        logo_label.pack(padx=8, pady=13)
    except:
        pass

    # Sidebar navigation
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
            icon_frame = ctk.CTkFrame(master=item_frame, width=35, height=35)
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

    # Open dashboard by default
    open_dashboard_content(main_content, server_manager)

    if user_info:
        mainframe.title(f'Server UI Dashboard - {user_info["username"]}')

    mainframe.mainloop()


def create_stats_card(parent, title, value, icon_name, row, column):
    """Create a single statistics card"""
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


def open_dashboard_content(parent_frame, server_manager=None):
    """Dashboard with server integration"""
    clear_frame(parent_frame)

    # Get statistics from server
    if server_manager:
        stats = server_manager.get_threat_statistics()
        total_threats = stats.get('total_threats', 0)
        files_scanned = stats.get('files_scanned', 0)
    else:
        total_threats = 0
        files_scanned = 0

    # Main scrollable content
    main_content = ctk.CTkScrollableFrame(parent_frame, width=950, height=700, fg_color="#22222f")
    main_content.pack(fill="both", expand=True, padx=20, pady=10)

    # Stats section
    stats_section = ctk.CTkFrame(main_content, fg_color="#22232e")
    stats_section.pack(fill="x", padx=10, pady=10)

    for i in range(4):
        stats_section.grid_columnconfigure(i, weight=1)

    # Display real statistics from server
    stats_data = [
        ("Total Threats", str(total_threats), "threat_logs_icon.png"),
        ("Active Clients", str(len(get_client_machines())), "client_machine_icon.png"),
        ("Files Scanned", str(files_scanned), "analytics_icon.png"),
        ("Server Status", "Online", "systems_icon.png")
    ]

    for i, (title, value, icon) in enumerate(stats_data):
        create_stats_card(stats_section, title, value, icon, 0, i)

    # Main content area
    content_area = ctk.CTkFrame(main_content, fg_color="transparent")
    content_area.pack(fill="both", expand=True, padx=10, pady=10)

    # Left side - Server Controls
    left_frame = ctk.CTkFrame(content_area, fg_color="#22232e", corner_radius=10)
    left_frame.pack(side="left", fill="both", expand=True, padx=(0, 5))

    ctk.CTkLabel(
        left_frame,
        text="Server Controls",
        font=("Roboto", 18, "bold"),
        text_color="#e9e8e8"
    ).pack(pady=(20, 10))

    # Scan button
    if server_manager:
        def start_server_scan():
            scan_paths = [os.path.expanduser("~")]
            ctk.CTkLabel(
                left_frame,
                text="Scan started...",
                font=("Roboto", 12),
                text_color="#10B981"
            ).pack(pady=5)
            server_manager.start_scan(scan_paths, callback=lambda r: print(f"Scan complete: {len(r)} threats"))

        ctk.CTkButton(
            left_frame,
            text="Start Server Scan",
            command=start_server_scan,
            height=45,
            font=("Roboto", 14, "bold"),
            fg_color="#3B82F6",
            hover_color="#2563EB"
        ).pack(fill="x", padx=20, pady=10)

        ctk.CTkButton(
            left_frame,
            text="Create Snapshot",
            command=lambda: server_manager.create_snapshot(description="Manual snapshot"),
            height=45,
            font=("Roboto", 14, "bold"),
            fg_color="#10B981",
            hover_color="#059669"
        ).pack(fill="x", padx=20, pady=10)

    # System info
    info_frame = ctk.CTkFrame(left_frame, fg_color="#1a1c24", corner_radius=8)
    info_frame.pack(fill="x", padx=20, pady=20)

    ctk.CTkLabel(
        info_frame,
        text="System Information",
        font=("Roboto", 14, "bold"),
        text_color="#e9e8e8"
    ).pack(pady=(10, 5))

    info_items = [
        ("Protection Status", "Active", "#10B981"),
        ("Database Status", "Connected", "#10B981"),
        ("Scan Engine", "Ready", "#10B981"),
        ("Last Update", "Today", "#94A3B8")
    ]

    for label, value, color in info_items:
        row = ctk.CTkFrame(info_frame, fg_color="transparent")
        row.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(
            row,
            text=label,
            font=("Roboto", 11),
            text_color="#94a3b8"
        ).pack(side="left")

        ctk.CTkLabel(
            row,
            text=value,
            font=("Roboto", 11, "bold"),
            text_color=color
        ).pack(side="right")

    # Right side - Recent Activity
    right_frame = ctk.CTkFrame(content_area, fg_color="#22232e", corner_radius=10)
    right_frame.pack(side="right", fill="both", expand=True, padx=(5, 0))

    ctk.CTkLabel(
        right_frame,
        text="Recent Threats",
        font=("Roboto", 18, "bold"),
        text_color="#e9e8e8"
    ).pack(pady=(20, 10))

    # Display recent threats from server
    threats_list = ctk.CTkScrollableFrame(right_frame, fg_color="#1a1c24", height=300)
    threats_list.pack(fill="both", expand=True, padx=20, pady=(0, 20))

    if server_manager:
        recent_threats = server_manager.get_all_threats()[-5:]  # Last 5 threats

        if recent_threats:
            for threat in reversed(recent_threats):
                threat_card = ctk.CTkFrame(threats_list, fg_color="#22232e", corner_radius=8)
                threat_card.pack(fill="x", pady=5, padx=5)

                ctk.CTkLabel(
                    threat_card,
                    text=threat.get('file_name', 'Unknown'),
                    font=("Roboto", 12, "bold"),
                    text_color="#e9e8e8"
                ).pack(anchor="w", padx=10, pady=(10, 2))

                ctk.CTkLabel(
                    threat_card,
                    text=f"{threat.get('threat_type', 'Unknown')} - {threat.get('threat_level', 'Unknown')}",
                    font=("Roboto", 10),
                    text_color="#94a3b8"
                ).pack(anchor="w", padx=10, pady=(0, 10))
        else:
            ctk.CTkLabel(
                threats_list,
                text="No threats detected",
                font=("Roboto", 12),
                text_color="#6B7280"
            ).pack(pady=20)
    else:
        ctk.CTkLabel(
            threats_list,
            text="Server not initialized",
            font=("Roboto", 12),
            text_color="#EF4444"
        ).pack(pady=20)


if __name__ == "__main__":
    open_dashboard_page({"username": "admin", "role": "admin"})