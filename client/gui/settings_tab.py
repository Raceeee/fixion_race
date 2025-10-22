import customtkinter as ctk
from tkinter import messagebox, filedialog
import os


class SettingsTab(ctk.CTkScrollableFrame):
    def __init__(self, parent, database, dashboard):
        super().__init__(parent, fg_color="transparent")

        self.db = database
        self.dashboard = dashboard

        # Load settings
        self.settings = self.db.get_settings()

        # Configure grid
        self.grid_columnconfigure(0, weight=1)

        # Create UI
        self.create_ui()

    def create_ui(self):
        """Create settings UI"""
        # Header
        header = ctk.CTkLabel(
            self,
            text="Settings & Configuration",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        header.grid(row=0, column=0, padx=30, pady=(30, 20), sticky="w")

        # Create all sections
        row = 1
        row = self.create_security_components_section(row)
        row = self.create_whitelist_section(row)
        row = self.create_scan_settings(row)
        row = self.create_snapshot_settings(row)
        row = self.create_protection_settings(row)
        row = self.create_sync_settings(row)
        row = self.create_notification_settings(row)

        # Save button
        self.create_save_button(row)

    def create_section_header(self, row: int, title: str) -> int:
        """Create section header"""
        header_frame = ctk.CTkFrame(self)
        header_frame.grid(row=row, column=0, padx=30, pady=(30, 10), sticky="ew")

        label = ctk.CTkLabel(
            header_frame,
            text=title,
            font=ctk.CTkFont(size=18, weight="bold")
        )
        label.pack(anchor="w", padx=15, pady=15)

        return row + 1

    def create_security_components_section(self, row: int) -> int:
        """Security Components Configuration"""
        row = self.create_section_header(row, "🛡️ Security Components")

        components_frame = ctk.CTkFrame(self)
        components_frame.grid(row=row, column=0, padx=30, pady=(0, 10), sticky="ew")
        components_frame.grid_columnconfigure(0, weight=1)

        # Component controls
        components = [
            ("EMBER AI Engine", "AI-powered threat detection", "ember_enabled"),
            ("Sandbox Analyzer", "Isolated file analysis", "sandbox_enabled"),
            ("Background Monitor", "Real-time file monitoring", "bg_monitor_enabled"),
            ("Network Monitor", "Network traffic analysis", "net_monitor_enabled"),
            ("Auto Scanner", "Scheduled automatic scanning", "auto_scan_enabled"),
            ("DSS Engine", "Dynamic signature system", "dss_enabled"),
            ("Behavior Analysis", "Behavioral threat detection", "behavior_enabled")
        ]

        self.component_vars = {}

        for idx, (name, desc, key) in enumerate(components):
            comp_frame = ctk.CTkFrame(components_frame, fg_color="#0f3460", corner_radius=8)
            comp_frame.grid(row=idx, column=0, padx=15, pady=5, sticky="ew")
            comp_frame.grid_columnconfigure(1, weight=1)

            # Component name and description
            info_frame = ctk.CTkFrame(comp_frame, fg_color="transparent")
            info_frame.grid(row=0, column=0, sticky="w", padx=15, pady=10)

            ctk.CTkLabel(
                info_frame,
                text=name,
                font=ctk.CTkFont(size=13, weight="bold")
            ).pack(anchor="w")

            ctk.CTkLabel(
                info_frame,
                text=desc,
                font=ctk.CTkFont(size=10),
                text_color="gray"
            ).pack(anchor="w")

            # Toggle switch
            var = ctk.BooleanVar(value=self.settings.get(key, True))
            self.component_vars[key] = var

            toggle = ctk.CTkSwitch(
                comp_frame,
                text="",
                variable=var,
                width=50,
                height=25
            )
            toggle.grid(row=0, column=1, sticky="e", padx=15, pady=10)

        # Component status update interval
        status_frame = ctk.CTkFrame(components_frame, fg_color="transparent")
        status_frame.grid(row=len(components), column=0, padx=15, pady=(15, 10), sticky="ew")

        ctk.CTkLabel(
            status_frame,
            text="Status Update Interval:",
            font=ctk.CTkFont(size=12)
        ).pack(side="left", padx=10)

        self.component_update_interval_var = ctk.StringVar(
            value=self.settings.get('component_update_interval', '5')
        )

        ctk.CTkEntry(
            status_frame,
            textvariable=self.component_update_interval_var,
            width=80
        ).pack(side="left", padx=5)

        ctk.CTkLabel(
            status_frame,
            text="seconds",
            font=ctk.CTkFont(size=10),
            text_color="gray"
        ).pack(side="left")

        return row + 1

    def create_whitelist_section(self, row: int) -> int:
        """Whitelist Management"""
        row = self.create_section_header(row, "📝 Whitelist Management")

        whitelist_frame = ctk.CTkFrame(self)
        whitelist_frame.grid(row=row, column=0, padx=30, pady=(0, 10), sticky="ew")
        whitelist_frame.grid_columnconfigure(0, weight=1)

        # Whitelist options
        options_frame = ctk.CTkFrame(whitelist_frame, fg_color="transparent")
        options_frame.grid(row=0, column=0, padx=15, pady=15, sticky="ew")

        # Auto-whitelist settings
        auto_whitelist_frame = ctk.CTkFrame(options_frame, fg_color="#0f3460", corner_radius=8)
        auto_whitelist_frame.pack(fill="x", pady=5)

        ctk.CTkLabel(
            auto_whitelist_frame,
            text="Auto-Whitelist Settings",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=15, pady=(15, 10))

        # Auto-whitelist for signed files
        self.auto_whitelist_signed_var = ctk.BooleanVar(
            value=self.settings.get('auto_whitelist_signed', True)
        )

        ctk.CTkCheckBox(
            auto_whitelist_frame,
            text="Automatically whitelist digitally signed files from trusted publishers",
            variable=self.auto_whitelist_signed_var,
            font=ctk.CTkFont(size=12)
        ).pack(anchor="w", padx=15, pady=5)

        # Auto-whitelist threshold
        threshold_frame = ctk.CTkFrame(auto_whitelist_frame, fg_color="transparent")
        threshold_frame.pack(fill="x", padx=15, pady=(10, 15))

        ctk.CTkLabel(
            threshold_frame,
            text="False Positive Likelihood Threshold:",
            font=ctk.CTkFont(size=12)
        ).pack(side="left", padx=5)

        self.whitelist_threshold_var = ctk.StringVar(
            value=self.settings.get('whitelist_threshold', '0.7')
        )

        ctk.CTkEntry(
            threshold_frame,
            textvariable=self.whitelist_threshold_var,
            width=60
        ).pack(side="left", padx=5)

        ctk.CTkLabel(
            threshold_frame,
            text="(0.0 - 1.0)",
            font=ctk.CTkFont(size=10),
            text_color="gray"
        ).pack(side="left")

        # Whitelist management buttons
        buttons_frame = ctk.CTkFrame(whitelist_frame, fg_color="transparent")
        buttons_frame.grid(row=1, column=0, padx=15, pady=(0, 15), sticky="ew")
        buttons_frame.grid_columnconfigure((0, 1, 2), weight=1)

        ctk.CTkButton(
            buttons_frame,
            text="📁 Add File to Whitelist",
            command=self.add_file_to_whitelist,
            height=35
        ).grid(row=0, column=0, padx=5, sticky="ew")

        ctk.CTkButton(
            buttons_frame,
            text="📂 Add Folder to Whitelist",
            command=self.add_folder_to_whitelist,
            height=35
        ).grid(row=0, column=1, padx=5, sticky="ew")

        ctk.CTkButton(
            buttons_frame,
            text="📋 View Whitelist",
            command=self.view_whitelist,
            height=35
        ).grid(row=0, column=2, padx=5, sticky="ew")

        # Whitelist statistics
        stats_frame = ctk.CTkFrame(whitelist_frame, fg_color="#0f3460", corner_radius=8)
        stats_frame.grid(row=2, column=0, padx=15, pady=(0, 15), sticky="ew")

        ctk.CTkLabel(
            stats_frame,
            text="Whitelist Statistics",
            font=ctk.CTkFont(size=12, weight="bold")
        ).pack(anchor="w", padx=15, pady=(10, 5))

        self.whitelist_stats_label = ctk.CTkLabel(
            stats_frame,
            text="Loading...",
            font=ctk.CTkFont(size=10),
            text_color="gray"
        )
        self.whitelist_stats_label.pack(anchor="w", padx=15, pady=(0, 10))

        self.update_whitelist_stats()

        return row + 1

    def create_scan_settings(self, row: int) -> int:
        """Auto-Scan Settings"""
        row = self.create_section_header(row, "🔍 Auto-Scan Settings")

        settings_frame = ctk.CTkFrame(self)
        settings_frame.grid(row=row, column=0, padx=30, pady=(0, 10), sticky="ew")
        settings_frame.grid_columnconfigure(0, weight=1)

        # Auto-scan enabled
        self.auto_scan_var = ctk.BooleanVar(
            value=self.settings.get('auto_scan_enabled', False)
        )

        ctk.CTkCheckBox(
            settings_frame,
            text="Enable Automatic Scanning",
            variable=self.auto_scan_var,
            font=ctk.CTkFont(size=14)
        ).grid(row=0, column=0, padx=20, pady=(20, 10), sticky="w")

        # Scan interval
        interval_label = ctk.CTkLabel(
            settings_frame,
            text="Scan Frequency:",
            font=ctk.CTkFont(size=13)
        )
        interval_label.grid(row=1, column=0, padx=20, pady=(10, 5), sticky="w")

        self.scan_interval_var = ctk.StringVar(
            value=self.settings.get('auto_scan_interval', 'daily')
        )

        intervals = ["hourly", "daily", "weekly", "monthly"]
        interval_descriptions = {
            "hourly": "Every Hour",
            "daily": "Once Per Day",
            "weekly": "Once Per Week",
            "monthly": "Once Per Month"
        }

        for interval in intervals:
            radio = ctk.CTkRadioButton(
                settings_frame,
                text=interval_descriptions[interval],
                variable=self.scan_interval_var,
                value=interval,
                font=ctk.CTkFont(size=12)
            )
            radio.grid(row=intervals.index(interval) + 2, column=0, padx=40, pady=3, sticky="w")

        # Scan mode preference
        mode_label = ctk.CTkLabel(
            settings_frame,
            text="Default Scan Mode:",
            font=ctk.CTkFont(size=13)
        )
        mode_label.grid(row=len(intervals) + 2, column=0, padx=20, pady=(15, 5), sticky="w")

        self.default_scan_mode_var = ctk.StringVar(
            value=self.settings.get('default_scan_mode', 'quick')
        )

        modes = ["quick", "full"]
        mode_descriptions = {
            "quick": "Quick Scan (Faster, critical areas)",
            "full": "Full Scan (Thorough, entire system)"
        }

        for mode in modes:
            radio = ctk.CTkRadioButton(
                settings_frame,
                text=mode_descriptions[mode],
                variable=self.default_scan_mode_var,
                value=mode,
                font=ctk.CTkFont(size=12)
            )
            radio.grid(row=len(intervals) + modes.index(mode) + 3, column=0, padx=40, pady=3, sticky="w")

        # Last scan info
        last_scan = self.db.get_last_scan_time()
        info_text = f"Last scan: {last_scan}" if last_scan else "No scans performed yet"

        ctk.CTkLabel(
            settings_frame,
            text=info_text,
            font=ctk.CTkFont(size=11),
            text_color="gray"
        ).grid(row=len(intervals) + len(modes) + 3, column=0, padx=20, pady=(15, 20), sticky="w")

        return row + 1

    def create_snapshot_settings(self, row: int) -> int:
        """Snapshot Settings"""
        row = self.create_section_header(row, "💾 Snapshot Settings")

        settings_frame = ctk.CTkFrame(self)
        settings_frame.grid(row=row, column=0, padx=30, pady=(0, 10), sticky="ew")
        settings_frame.grid_columnconfigure(0, weight=1)

        # Snapshot interval
        interval_label = ctk.CTkLabel(
            settings_frame,
            text="Automatic Snapshot Creation:",
            font=ctk.CTkFont(size=13)
        )
        interval_label.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="w")

        self.snapshot_interval_var = ctk.StringVar(
            value=self.settings.get('snapshot_interval', 'monthly')
        )

        snapshot_intervals = ["twice_monthly", "monthly"]
        snapshot_descriptions = {
            "twice_monthly": "Twice Per Month (Every 15 days)",
            "monthly": "Once Per Month"
        }

        for interval in snapshot_intervals:
            radio = ctk.CTkRadioButton(
                settings_frame,
                text=snapshot_descriptions[interval],
                variable=self.snapshot_interval_var,
                value=interval,
                font=ctk.CTkFont(size=12)
            )
            radio.grid(
                row=snapshot_intervals.index(interval) + 1,
                column=0,
                padx=40,
                pady=3,
                sticky="w"
            )

        # Max snapshots
        max_label = ctk.CTkLabel(
            settings_frame,
            text="Maximum Snapshots to Keep:",
            font=ctk.CTkFont(size=13)
        )
        max_label.grid(row=len(snapshot_intervals) + 1, column=0, padx=20, pady=(15, 5), sticky="w")

        self.max_snapshots_var = ctk.StringVar(
            value=self.settings.get('max_snapshots', '10')
        )

        max_entry = ctk.CTkEntry(
            settings_frame,
            textvariable=self.max_snapshots_var,
            width=100
        )
        max_entry.grid(row=len(snapshot_intervals) + 2, column=0, padx=40, pady=(0, 5), sticky="w")

        ctk.CTkLabel(
            settings_frame,
            text="Older snapshots will be automatically deleted",
            font=ctk.CTkFont(size=10),
            text_color="gray"
        ).grid(row=len(snapshot_intervals) + 3, column=0, padx=40, pady=(0, 20), sticky="w")

        return row + 1

    def create_protection_settings(self, row: int) -> int:
        """Protection Settings"""
        row = self.create_section_header(row, "🛡️ Protection Settings")

        settings_frame = ctk.CTkFrame(self)
        settings_frame.grid(row=row, column=0, padx=30, pady=(0, 10), sticky="ew")
        settings_frame.grid_columnconfigure(0, weight=1)

        # Real-time protection
        self.realtime_protection_var = ctk.BooleanVar(
            value=self.settings.get('real_time_protection', True)
        )

        ctk.CTkCheckBox(
            settings_frame,
            text="Enable Real-Time Protection",
            variable=self.realtime_protection_var,
            font=ctk.CTkFont(size=14)
        ).grid(row=0, column=0, padx=20, pady=(20, 5), sticky="w")

        ctk.CTkLabel(
            settings_frame,
            text="Continuously monitors files and processes",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        ).grid(row=1, column=0, padx=40, pady=(0, 15), sticky="w")

        # Behavior monitoring
        self.behavior_monitoring_var = ctk.BooleanVar(
            value=self.settings.get('behavior_monitoring', True)
        )

        ctk.CTkCheckBox(
            settings_frame,
            text="Enable Behavior Monitoring",
            variable=self.behavior_monitoring_var,
            font=ctk.CTkFont(size=14)
        ).grid(row=2, column=0, padx=20, pady=(0, 5), sticky="w")

        ctk.CTkLabel(
            settings_frame,
            text="Detects suspicious activities and patterns",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        ).grid(row=3, column=0, padx=40, pady=(0, 20), sticky="w")

        return row + 1

    def create_sync_settings(self, row: int) -> int:
        """Cloud Sync Settings"""
        row = self.create_section_header(row, "☁️ Cloud Sync Settings")

        settings_frame = ctk.CTkFrame(self)
        settings_frame.grid(row=row, column=0, padx=30, pady=(0, 10), sticky="ew")
        settings_frame.grid_columnconfigure(0, weight=1)

        # Cloud sync enabled
        self.cloud_sync_var = ctk.BooleanVar(
            value=self.settings.get('cloud_sync_enabled', True)
        )

        ctk.CTkCheckBox(
            settings_frame,
            text="Enable Cloud Synchronization",
            variable=self.cloud_sync_var,
            font=ctk.CTkFont(size=14)
        ).grid(row=0, column=0, padx=20, pady=(20, 5), sticky="w")

        ctk.CTkLabel(
            settings_frame,
            text="Sync threat reports and analytics to cloud",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        ).grid(row=1, column=0, padx=40, pady=(0, 15), sticky="w")

        # Sync frequency
        sync_label = ctk.CTkLabel(
            settings_frame,
            text="Sync Frequency:",
            font=ctk.CTkFont(size=13)
        )
        sync_label.grid(row=2, column=0, padx=20, pady=(10, 5), sticky="w")

        self.sync_frequency_var = ctk.StringVar(
            value=self.settings.get('sync_frequency', 'hourly')
        )

        sync_options = ["realtime", "hourly", "daily"]
        sync_descriptions = {
            "realtime": "Real-time (Immediate)",
            "hourly": "Every Hour",
            "daily": "Once Per Day"
        }

        for option in sync_options:
            radio = ctk.CTkRadioButton(
                settings_frame,
                text=sync_descriptions[option],
                variable=self.sync_frequency_var,
                value=option,
                font=ctk.CTkFont(size=12)
            )
            radio.grid(row=sync_options.index(option) + 3, column=0, padx=40, pady=3, sticky="w")

        ctk.CTkLabel(settings_frame, text="").grid(row=len(sync_options) + 3, column=0, pady=10)

        return row + 1

    def create_notification_settings(self, row: int) -> int:
        """Notification Settings"""
        row = self.create_section_header(row, "🔔 Notification Settings")

        settings_frame = ctk.CTkFrame(self)
        settings_frame.grid(row=row, column=0, padx=30, pady=(0, 10), sticky="ew")
        settings_frame.grid_columnconfigure(0, weight=1)

        # Notifications enabled
        self.notifications_var = ctk.BooleanVar(
            value=self.settings.get('notifications_enabled', True)
        )

        ctk.CTkCheckBox(
            settings_frame,
            text="Enable Notifications",
            variable=self.notifications_var,
            font=ctk.CTkFont(size=14)
        ).grid(row=0, column=0, padx=20, pady=(20, 15), sticky="w")

        # Notification types
        notif_types_label = ctk.CTkLabel(
            settings_frame,
            text="Notify me about:",
            font=ctk.CTkFont(size=13)
        )
        notif_types_label.grid(row=1, column=0, padx=20, pady=(0, 10), sticky="w")

        # Individual notification toggles
        notification_types = [
            ("Threat Detections", "notify_threats", True),
            ("Scan Completions", "notify_scans", True),
            ("Snapshot Creations", "notify_snapshots", True),
            ("System Updates", "notify_updates", True)
        ]

        self.notif_vars = {}

        for idx, (text, key, default) in enumerate(notification_types):
            var = ctk.BooleanVar(value=self.settings.get(key, default))
            self.notif_vars[key] = var

            check = ctk.CTkCheckBox(
                settings_frame,
                text=text,
                variable=var,
                font=ctk.CTkFont(size=12)
            )
            check.grid(row=idx + 2, column=0, padx=40, pady=3, sticky="w")

        ctk.CTkLabel(settings_frame, text="").grid(row=len(notification_types) + 2, column=0, pady=10)

        return row + 1

    def create_save_button(self, row: int):
        """Create save/reset buttons"""
        button_frame = ctk.CTkFrame(self, fg_color="transparent")
        button_frame.grid(row=row, column=0, padx=30, pady=30, sticky="ew")
        button_frame.grid_columnconfigure((0, 1), weight=1)

        # Save button
        save_btn = ctk.CTkButton(
            button_frame,
            text="💾 Save All Settings",
            command=self.save_all_settings,
            height=50,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color="#2ECC71",
            hover_color="#27AE60"
        )
        save_btn.grid(row=0, column=0, padx=5, sticky="ew")

        # Reset button
        reset_btn = ctk.CTkButton(
            button_frame,
            text="🔄 Reset to Defaults",
            command=self.reset_all_settings,
            height=50,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color="#95A5A6",
            hover_color="#7F8C8D"
        )
        reset_btn.grid(row=0, column=1, padx=5, sticky="ew")

    def add_file_to_whitelist(self):
        """Add file to whitelist"""
        filepath = filedialog.askopenfilename(title="Select file to whitelist")
        if filepath:
            # Implementation depends on whitelist manager
            messagebox.showinfo("Added", f"Added to whitelist:\n{os.path.basename(filepath)}")
            self.update_whitelist_stats()

    def add_folder_to_whitelist(self):
        """Add folder to whitelist"""
        folder = filedialog.askdirectory(title="Select folder to whitelist")
        if folder:
            messagebox.showinfo("Added", f"Added to whitelist:\n{folder}")
            self.update_whitelist_stats()

    def view_whitelist(self):
        """View whitelist entries"""
        dialog = ctk.CTkToplevel(self)
        dialog.title("Whitelist Entries")
        dialog.geometry("700x500")
        dialog.transient(self.master)

        ctk.CTkLabel(
            dialog,
            text="Whitelist Entries",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(pady=20)

        # List frame
        list_frame = ctk.CTkScrollableFrame(dialog)
        list_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # Placeholder
        ctk.CTkLabel(
            list_frame,
            text="Whitelist entries will be displayed here",
            text_color="gray"
        ).pack(pady=50)

        ctk.CTkButton(
            dialog,
            text="Close",
            command=dialog.destroy
        ).pack(pady=20)

    def update_whitelist_stats(self):
        """Update whitelist statistics"""
        # This would query the actual whitelist manager
        stats_text = "Files: 0 | Folders: 0 | Publishers: 0"
        if hasattr(self, 'whitelist_stats_label'):
            self.whitelist_stats_label.configure(text=stats_text)

    def save_all_settings(self):
        """Save all settings"""
        try:
            # Validate max snapshots
            try:
                max_snapshots = int(self.max_snapshots_var.get())
                if max_snapshots < 1 or max_snapshots > 50:
                    raise ValueError()
            except:
                messagebox.showerror("Invalid Input", "Max snapshots must be between 1 and 50")
                return

            # Save all settings
            settings = {
                # Security components
                **{key: str(var.get()).lower() for key, var in self.component_vars.items()},
                'component_update_interval': self.component_update_interval_var.get(),

                # Whitelist
                'auto_whitelist_signed': str(self.auto_whitelist_signed_var.get()).lower(),
                'whitelist_threshold': self.whitelist_threshold_var.get(),

                # Scan settings
                'auto_scan_enabled': str(self.auto_scan_var.get()).lower(),
                'auto_scan_interval': self.scan_interval_var.get(),
                'default_scan_mode': self.default_scan_mode_var.get(),

                # Snapshot settings
                'snapshot_interval': self.snapshot_interval_var.get(),
                'max_snapshots': self.max_snapshots_var.get(),

                # Protection settings
                'real_time_protection': str(self.realtime_protection_var.get()).lower(),
                'behavior_monitoring': str(self.behavior_monitoring_var.get()).lower(),

                # Cloud sync
                'cloud_sync_enabled': str(self.cloud_sync_var.get()).lower(),
                'sync_frequency': self.sync_frequency_var.get(),

                # Notifications
                'notifications_enabled': str(self.notifications_var.get()).lower(),
                **{key: str(var.get()).lower() for key, var in self.notif_vars.items()}
            }

            for key, value in settings.items():
                self.db.set_setting(key, value)

            # Update dashboard settings
            self.dashboard.load_settings()

            messagebox.showinfo("Success", "All settings saved successfully!")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings:\n{str(e)}")

    def reset_all_settings(self):
        """Reset all settings to defaults"""
        response = messagebox.askyesno(
            "Reset Settings",
            "Are you sure you want to reset ALL settings to defaults?"
        )

        if response:
            # Reset all variables
            for var in self.component_vars.values():
                var.set(True)

            self.auto_whitelist_signed_var.set(True)
            self.whitelist_threshold_var.set("0.7")
            self.auto_scan_var.set(False)
            self.scan_interval_var.set("daily")
            self.default_scan_mode_var.set("quick")
            self.snapshot_interval_var.set("monthly")
            self.max_snapshots_var.set("10")
            self.realtime_protection_var.set(True)
            self.behavior_monitoring_var.set(True)
            self.cloud_sync_var.set(True)
            self.sync_frequency_var.set("hourly")
            self.notifications_var.set(True)

            for var in self.notif_vars.values():
                var.set(True)

            messagebox.showinfo("Reset Complete", "Settings reset to defaults. Click 'Save All Settings' to apply.")