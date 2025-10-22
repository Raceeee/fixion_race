import customtkinter
import tkinter as tk
from tkinter import ttk
import random
import json
import os
from datetime import datetime, timedelta
import math
from PIL import Image


# Mock data generation functions for demonstration
def generate_mock_threat_data(days=30):
    """Generate sample threat detection data for demonstration"""
    today = datetime.now()
    data = []
    threat_types = ["Malware", "Phishing", "Ransomware", "Trojan", "Spyware", "Zero-day"]
    severity_levels = ["Critical", "High", "Medium", "Low"]

    num_threats = random.randint(50, 150)

    for _ in range(num_threats):
        random_day = random.randint(0, days - 1)
        date = today - timedelta(days=random_day)

        data.append({
            "date": date.strftime("%Y-%m-%d"),
            "time": date.strftime("%H:%M:%S"),
            "threat_type": random.choice(threat_types),
            "severity": random.choice(severity_levels),
            "client_id": random.randint(1, 5),
            "resolved": random.random() > 0.2
        })

    return data


def load_users():
    """Load users from the JSON file"""
    try:
        with open('users.json', 'r') as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def get_client_machines():
    """Extract client machines from users data"""
    users = load_users()
    return [user for user in users if user.get("role") == "client machine"]


def create_stats_card(parent, title, value, icon_name, row, column):
    """Create a single statistics card"""
    card = customtkinter.CTkFrame(parent, corner_radius=10, fg_color="#22232e")
    card.grid(row=row, column=column, padx=10, pady=10, sticky="nsew")

    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        icon_path = os.path.join(current_dir, "assets", "icon", icon_name)

        icon_image = customtkinter.CTkImage(
            light_image=Image.open(icon_path),
            dark_image=Image.open(icon_path),
            size=(32, 32)
        )

        icon_label = customtkinter.CTkLabel(card, image=icon_image, text="")
        icon_label.pack(anchor="w", padx=15, pady=(15, 5))
    except Exception:
        pass

    customtkinter.CTkLabel(card, text=title, font=("Roboto", 14), text_color="#e9e8e8").pack(anchor="w", padx=15,
                                                                                             pady=5)
    customtkinter.CTkLabel(card, text=value, font=("Roboto", 24, "bold"), text_color="#e9e8e8").pack(anchor="w",
                                                                                                     padx=15,
                                                                                                     pady=(5, 15))


def create_threat_chart(parent, threat_data):
    """Create threat detection trend chart"""
    threat_counts = {}
    for threat in threat_data:
        date = threat.get("date", datetime.now().strftime("%Y-%m-%d"))
        threat_counts[date] = threat_counts.get(date, 0) + 1

    sorted_dates = sorted(threat_counts.keys())
    chart_dates = [date if i % 5 == 0 else "" for i, date in enumerate(sorted_dates)]
    chart_values = [threat_counts[date] for date in sorted_dates]
    max_value = max(chart_values) if chart_values else 10

    chart_canvas = tk.Canvas(parent, bg="#1c253a", highlightthickness=0, height=150)
    chart_canvas.pack(fill="x", padx=20, pady=10)

    def draw_chart():
        chart_canvas.delete("all")
        chart_width = chart_canvas.winfo_width() or 900
        chart_height = 150
        bar_spacing = chart_width / (len(chart_values) * 1.5) if chart_values else 1
        bottom_margin = 30

        chart_canvas.create_line(40, chart_height - bottom_margin, chart_width - 20,
                                 chart_height - bottom_margin, fill="#a9b8c4", width=2)
        chart_canvas.create_line(40, 20, 40, chart_height - bottom_margin, fill="#a9b8c4", width=2)

        for i, value in enumerate(chart_values):
            bar_height = (value / max_value) * (chart_height - bottom_margin - 30)
            x1 = 50 + (i * bar_spacing * 1.5)
            y1 = chart_height - bottom_margin - bar_height
            x2 = x1 + bar_spacing
            y2 = chart_height - bottom_margin

            color = f"#{int(min(255, 100 + (155 * value / max_value))):02x}4080"
            chart_canvas.create_rectangle(x1, y1, x2, y2, fill=color, outline="")

            if chart_dates[i]:
                chart_canvas.create_text(x1 + bar_spacing / 2, chart_height - bottom_margin + 15,
                                         text=chart_dates[i][5:], fill="#a9b8c4", font=("Roboto", 8))

        for i in range(5):
            value = int(max_value * i / 4)
            y_pos = chart_height - bottom_margin - (i * (chart_height - bottom_margin - 30) / 4)
            chart_canvas.create_text(30, y_pos, text=str(value), fill="#a9b8c4", font=("Roboto", 8))

    chart_canvas.bind("<Configure>", lambda e: draw_chart())
    chart_canvas.after(100, draw_chart)


def create_client_table(parent, clients):
    """Create client activity table with proper layout and spacing"""
    if not clients:
        customtkinter.CTkLabel(parent, text="No client machines found. Add clients in User Management.",
                               font=("Roboto", 12), text_color="#e9e8e8").pack(pady=20)
        return

    table_container = customtkinter.CTkFrame(parent, fg_color="transparent")
    table_container.pack(fill="both", expand=True)

    column_weights = [3, 1, 1, 1, 2]
    for i in range(5):
        table_container.grid_columnconfigure(i, weight=column_weights[i], minsize=100)

    header_frame = customtkinter.CTkFrame(table_container, fg_color="#323b50", height=50)
    header_frame.grid(row=0, column=0, columnspan=5, sticky="ew", padx=2, pady=(0, 2))
    header_frame.grid_propagate(False)

    for i in range(5):
        header_frame.grid_columnconfigure(i, weight=column_weights[i], minsize=100)

    headers = ["Client Name", "Status", "Last Active", "Threats Detected", "Protection Status"]

    for i, header in enumerate(headers):
        header_label = customtkinter.CTkLabel(
            header_frame,
            text=header,
            font=("Roboto", 12, "bold"),
            text_color="#e9e8e8"
        )
        header_label.grid(row=0, column=i, padx=10, pady=15, sticky="w")

    for row_index, client in enumerate(clients, start=1):
        row_frame = customtkinter.CTkFrame(table_container, fg_color="#22232e", height=60)
        row_frame.grid(row=row_index, column=0, columnspan=5, sticky="ew", padx=2, pady=1)
        row_frame.grid_propagate(False)

        for i in range(5):
            row_frame.grid_columnconfigure(i, weight=column_weights[i], minsize=100)

        client_name = client.get("username", "Unknown")
        if len(client_name) > 25:
            display_name = client_name[:22] + "..."
        else:
            display_name = client_name

        name_label = customtkinter.CTkLabel(
            row_frame,
            text=display_name,
            font=("Roboto", 12),
            text_color="#e9e8e8",
            anchor="w"
        )
        name_label.grid(row=0, column=0, padx=10, pady=15, sticky="w")

        status_text = "Online" if client.get("active", True) else "Offline"
        status_color = "#1b720f" if client.get("active", True) else "#63003d"

        status_container = customtkinter.CTkFrame(row_frame, fg_color="transparent")
        status_container.grid(row=0, column=1, padx=10, pady=15, sticky="w")

        status_dot = customtkinter.CTkFrame(
            status_container,
            width=12,
            height=12,
            corner_radius=6,
            fg_color=status_color
        )
        status_dot.pack(side="left", padx=(0, 8))

        status_label = customtkinter.CTkLabel(
            status_container,
            text=status_text,
            font=("Roboto", 12),
            text_color="#e9e8e8"
        )
        status_label.pack(side="left")

        if client.get("active", True):
            last_active_text = "Now"
        else:
            minutes_ago = random.randint(60, 10080)
            if minutes_ago > 1440:
                last_active_text = f"{minutes_ago // 1440} days ago"
            else:
                last_active_text = f"{minutes_ago // 60} hours ago"

        last_active_label = customtkinter.CTkLabel(
            row_frame,
            text=last_active_text,
            font=("Roboto", 12),
            text_color="#e9e8e8"
        )
        last_active_label.grid(row=0, column=2, padx=10, pady=15, sticky="w")

        threats_count = str(random.randint(0, 20))
        threats_label = customtkinter.CTkLabel(
            row_frame,
            text=threats_count,
            font=("Roboto", 12),
            text_color="#e9e8e8"
        )
        threats_label.grid(row=0, column=3, padx=10, pady=15, sticky="w")

        protection_status = random.choice(["Protected", "Update Required", "Protected"])
        protection_color = "#1b720f" if protection_status == "Protected" else "#714bae"

        protection_label = customtkinter.CTkLabel(
            row_frame,
            text=protection_status,
            text_color=protection_color,
            font=("Roboto", 12)
        )
        protection_label.grid(row=0, column=4, padx=10, pady=15, sticky="w")


def create_professional_pie_chart(canvas, threat_types, total_threats):
    """Create a highly professional, clean pie chart with modern styling"""
    canvas.delete("all")

    canvas.update_idletasks()
    width = canvas.winfo_width()
    height = canvas.winfo_height()

    if width <= 1 or height <= 1:
        width = 350
        height = 350

    center_x = width // 2
    center_y = height // 2
    base_radius = min(width, height) // 3
    radius = max(base_radius, 90)

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
            text="No Data Available",
            fill="#64748B",
            font=("Roboto", 14),
            anchor="center"
        )
        return

    sorted_threats = sorted(threat_types.items(), key=lambda x: x[1]["count"], reverse=True)
    start_angle = -90

    shadow_offset = 2
    shadow_radius = radius + 1
    for i, (threat_type, data) in enumerate(sorted_threats):
        angle_extent = (data["count"] / total_threats) * 360
        canvas.create_arc(
            center_x - shadow_radius + shadow_offset,
            center_y - shadow_radius + shadow_offset,
            center_x + shadow_radius + shadow_offset,
            center_y + shadow_radius + shadow_offset,
            start=start_angle, extent=angle_extent,
            fill="#1F2937", outline="", width=0, style="pieslice",
            stipple="gray25"
        )
        start_angle += angle_extent

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
        fill="#FFFFFF", outline="#E5E7EB", width=1
    )

    inner_shadow_radius = inner_radius - 3
    canvas.create_oval(
        center_x - inner_shadow_radius, center_y - inner_shadow_radius,
        center_x + inner_shadow_radius, center_y + inner_shadow_radius,
        fill="", outline="#F3F4F6", width=1
    )

    canvas.create_text(
        center_x, center_y - 12,
        text="Total Threats",
        fill="#6B7280",
        font=("Roboto", 10),
        anchor="center"
    )

    canvas.create_text(
        center_x, center_y + 8,
        text=f"{total_threats:,}",
        fill="#1F2937",
        font=("Roboto", 16, "bold"),
        anchor="center"
    )


def create_professional_legend(parent, threat_types, total_threats):
    """Create a professional legend with modern styling and better organization"""
    for widget in parent.winfo_children():
        widget.destroy()

    professional_colors = [
        "#3B82F6", "#10B981", "#F59E0B", "#EF4444",
        "#8B5CF6", "#6B7280", "#EC4899", "#14B8A6"
    ]

    header_frame = customtkinter.CTkFrame(parent, fg_color="transparent")
    header_frame.pack(fill="x", padx=25, pady=(25, 15))

    title_label = customtkinter.CTkLabel(
        header_frame,
        text="Threat Distribution",
        font=("Roboto", 16, "bold"),
        text_color="#FFFFFF"
    )
    title_label.pack(side="left")

    if total_threats > 0:
        summary_label = customtkinter.CTkLabel(
            header_frame,
            text=f"{total_threats:,} Total",
            font=("Roboto", 12),
            text_color="#94A3B8"
        )
        summary_label.pack(side="right")

    separator = customtkinter.CTkFrame(parent, height=1, fg_color="#374151")
    separator.pack(fill="x", padx=25, pady=(0, 20))

    if total_threats == 0:
        empty_label = customtkinter.CTkLabel(
            parent,
            text="No threat data to display",
            font=("Roboto", 13),
            text_color="#6B7280"
        )
        empty_label.pack(pady=30)
        return

    sorted_threats = sorted(threat_types.items(), key=lambda x: x[1]["count"], reverse=True)

    entries_container = customtkinter.CTkFrame(parent, fg_color="transparent")
    entries_container.pack(fill="both", expand=True, padx=25, pady=(0, 25))

    for i, (threat_type, data) in enumerate(sorted_threats):
        percentage = (data["count"] / total_threats) * 100

        row_frame = customtkinter.CTkFrame(
            entries_container,
            fg_color="#2D3748",
            corner_radius=8,
            height=55
        )
        row_frame.pack(fill="x", pady=6)
        row_frame.pack_propagate(False)

        left_section = customtkinter.CTkFrame(row_frame, fg_color="transparent")
        left_section.pack(side="left", fill="y", padx=15, pady=10)

        color_frame = customtkinter.CTkFrame(
            left_section,
            width=20,
            height=20,
            corner_radius=4,
            fg_color=professional_colors[i % len(professional_colors)]
        )
        color_frame.pack(side="left", padx=(0, 12))

        name_label = customtkinter.CTkLabel(
            left_section,
            text=threat_type,
            font=("Roboto", 13, "bold"),
            text_color="#FFFFFF"
        )
        name_label.pack(side="left")

        right_section = customtkinter.CTkFrame(row_frame, fg_color="transparent")
        right_section.pack(side="right", fill="y", padx=15, pady=10)

        count_label = customtkinter.CTkLabel(
            right_section,
            text=f"{data['count']:,}",
            font=("Roboto", 13, "bold"),
            text_color="#FFFFFF"
        )
        count_label.pack(side="right", padx=(10, 0))

        percentage_label = customtkinter.CTkLabel(
            right_section,
            text=f"{percentage:.1f}%",
            font=("Roboto", 12),
            text_color="#94A3B8"
        )
        percentage_label.pack(side="right")

        progress_width = int((percentage / 100) * 60)
        if progress_width > 0:
            progress_frame = customtkinter.CTkFrame(
                row_frame,
                width=progress_width,
                height=3,
                corner_radius=2,
                fg_color=professional_colors[i % len(professional_colors)]
            )
            progress_frame.place(x=15, y=52)


def open_analytics_page(parent_frame, server_manager=None):
    """Analytics dashboard page with charts and statistics - INTEGRATED WITH SERVER"""
    for widget in parent_frame.winfo_children():
        widget.destroy()

    # GET REAL DATA FROM SERVER
    if server_manager:
        stats = server_manager.get_threat_statistics()
        all_threats = server_manager.get_all_threats()
        threat_types = server_manager.get_threat_types_distribution()
        total_threats_value = stats.get('total_threats', 0)
        resolved_threats_value = stats.get('resolved_threats', 0)
        files_scanned = stats.get('files_scanned', 0)

        # Convert threats to chart format
        threat_data = []
        for threat in all_threats:
            threat_data.append({
                "date": threat.get("timestamp", datetime.now().strftime("%Y-%m-%d"))[:10],
                "time": threat.get("timestamp", "00:00:00")[11:],
                "threat_type": threat.get("threat_type", "Unknown"),
                "severity": threat.get("threat_level", "Low"),
                "client_id": threat.get("client_id", 0),
                "resolved": threat.get("status") == "resolved"
            })
    else:
        # Fallback to mock data
        threat_data = generate_mock_threat_data(30)
        total_threats_value = random.randint(120, 300)
        resolved_threats_value = random.randint(100, 250)
        files_scanned = random.randint(500, 2000)
        threat_types = {
            "Malware": {"count": random.randint(45, 65)},
            "Phishing": {"count": random.randint(25, 35)},
            "Ransomware": {"count": random.randint(8, 15)},
            "Trojan": {"count": random.randint(15, 25)},
            "Spyware": {"count": random.randint(10, 18)},
            "Zero-day": {"count": random.randint(3, 8)}
        }

    title = customtkinter.CTkLabel(
        master=parent_frame,
        text="Analytics",
        font=("Roboto", 24, "bold"),
        text_color="#e9e8e8"
    )
    title.pack(anchor="w", padx=12, pady=12)

    main_content = customtkinter.CTkScrollableFrame(parent_frame, width=950, height=800, fg_color="#22222f")
    main_content.pack(fill="both", expand=True, padx=20, pady=10)

    # TOP CONTROLS
    controls = customtkinter.CTkFrame(main_content, fg_color="#22232e")
    controls.pack(fill="x", padx=10, pady=(0, 10))

    customtkinter.CTkLabel(controls, text="Time Period:", font=("Roboto", 14), text_color="#e9e8e8").pack(
        side="left", padx=20, pady=10)

    time_periods = ["Last 24 Hours", "Last 7 Days", "Last 30 Days", "Last 90 Days"]
    time_var = tk.StringVar(value="Last 30 Days")
    time_dropdown = customtkinter.CTkOptionMenu(controls, values=time_periods, variable=time_var, width=200)
    time_dropdown.pack(side="left", padx=10, pady=10)

    customtkinter.CTkButton(controls, text="Export Report", width=120, fg_color="#586b78").pack(
        side="right", padx=10, pady=10)
    customtkinter.CTkButton(controls, text="Refresh Data", width=120).pack(
        side="right", padx=20, pady=10)

    # STATISTICS CARDS - USING REAL DATA
    stats_section = customtkinter.CTkFrame(main_content, fg_color="#22232e")
    stats_section.pack(fill="x", padx=10, pady=10)

    for i in range(4):
        stats_section.grid_columnconfigure(i, weight=1)

    stats_data = [
        ("Total Threats Detected", str(total_threats_value), "threat_logs_icon.png"),
        ("Active Clients", str(len(get_client_machines())), "client_machine_icon.png"),
        ("Resolved Threats", str(resolved_threats_value), "systems_icon.png"),
        ("Files Scanned", str(files_scanned), "analytics_icon.png")
    ]

    for i, (title, value, icon) in enumerate(stats_data):
        create_stats_card(stats_section, title, value, icon, 0, i)

    # THREAT DETECTION CHART
    chart_section = customtkinter.CTkFrame(main_content, fg_color="#22232e")
    chart_section.pack(fill="x", padx=10, pady=10)

    customtkinter.CTkLabel(chart_section, text="Threat Detection Trend (30 Days)",
                           font=("Roboto", 16, "bold"), text_color="#e9e8e8").pack(anchor="w", padx=20, pady=10)

    create_threat_chart(chart_section, threat_data)

    # CLIENT ACTIVITY TABLE
    clients_section = customtkinter.CTkFrame(main_content, fg_color="#22232e")
    clients_section.pack(fill="x", padx=10, pady=10)

    customtkinter.CTkLabel(clients_section, text="Client Machine Activity",
                           font=("Roboto", 16, "bold"), text_color="#e9e8e8").pack(anchor="w", padx=20, pady=10)

    table_container = customtkinter.CTkFrame(clients_section, fg_color="#22232e")
    table_container.pack(fill="x", padx=20, pady=10)

    create_client_table(table_container, get_client_machines())

    # THREAT BREAKDOWN - USING REAL DATA
    breakdown_section = customtkinter.CTkFrame(main_content, fg_color="#22232e")
    breakdown_section.pack(fill="x", padx=10, pady=10)

    customtkinter.CTkLabel(breakdown_section, text="Threat Type Analysis",
                           font=("Roboto", 16, "bold"), text_color="#e9e8e8").pack(anchor="w", padx=20, pady=(15, 5))

    pie_container = customtkinter.CTkFrame(breakdown_section, fg_color="transparent")
    pie_container.pack(fill="x", padx=20, pady=15)

    pie_chart_section = customtkinter.CTkFrame(pie_container, fg_color="#1c253a", corner_radius=12)
    pie_chart_section.pack(side="left", fill="both", expand=True, padx=(0, 15))

    pie_canvas = tk.Canvas(pie_chart_section, bg="#1c253a", highlightthickness=0, width=350, height=350)
    pie_canvas.pack(fill="both", expand=True, padx=25, pady=25)

    legend_section = customtkinter.CTkFrame(pie_container, fg_color="#1c253a", corner_radius=12)
    legend_section.pack(side="right", fill="both", expand=True, padx=(15, 0))

    # USE REAL THREAT TYPES FROM SERVER
    total_threats = sum(threat["count"] for threat in threat_types.values())

    # Bind resize and draw
    def on_resize(event):
        pie_canvas.after(10, lambda: create_professional_pie_chart(pie_canvas, threat_types, total_threats))

    pie_canvas.bind("<Configure>", on_resize)
    pie_canvas.after(200, lambda: create_professional_pie_chart(pie_canvas, threat_types, total_threats))
    create_professional_legend(legend_section, threat_types, total_threats)