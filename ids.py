import customtkinter as ctk
import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import time
import json
from datetime import datetime

import scapy.all as scapy
from scapy.all import IP, TCP
from scapy.arch.windows import get_windows_if_list

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class Intrudex(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("HUSSAIN IDS - Intrudex")
        try:
            self.iconbitmap("intrudex.ico")
        except:
            pass

        self.geometry("1400x900")
        self.minsize(1200, 700)

        self.monitoring = False
        self.alerts = []
        self.total_alerts = 0
        self.high_severity = 0
        self.log_file = "intrudex_logs.json"
        self.start_time = None

        self.iface_map = {}
        self.iface_list = self.get_friendly_interfaces()
        self.selected_iface = ctk.StringVar(value=self.iface_list[0] if self.iface_list else "any")

        self.setup_ui()
        self.after(1000, self.update_uptime)

    def get_friendly_interfaces(self):
        try:
            win_list = get_windows_if_list()
            intf_list = scapy.get_if_list()
            guid_to_name = {e.get("guid"): e.get("name") for e in win_list if e.get("guid") and e.get("name")}

            friendly = []
            for dev in intf_list:
                name = dev
                if "NPF_" in dev:
                    guid = dev.split("NPF_")[-1]
                    name = guid_to_name.get(guid, dev)
                friendly.append(name)
                self.iface_map[name] = dev

            seen = set()
            unique = []
            for n in friendly:
                if n not in seen:
                    unique.append(n)
                    seen.add(n)
            return unique if unique else ["any"]
        except Exception:
            self.iface_map = {}
            return ["any"]

    def setup_ui(self):
        title = ctk.CTkLabel(self, text="INTRUDEX DETECTION SYSTEM ", font=ctk.CTkFont(size=24, weight="bold"))
        title.pack(pady=20)

        main_frame = ctk.CTkFrame(self)
        main_frame.pack(fill="both", expand=True, padx=20, pady=10)

        left_panel = ctk.CTkFrame(main_frame, width=340)
        left_panel.pack(side="left", fill="y", padx=(0, 10))

        ctk.CTkLabel(left_panel, text="📊 DASHBOARD", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)

        stats_frame = ctk.CTkFrame(left_panel)
        stats_frame.pack(fill="x", padx=10, pady=10)

        self.total_alerts_var = ctk.StringVar(value="0")
        self.high_severity_var = ctk.StringVar(value="0")
        self.blocked_ips_var = ctk.StringVar(value="0")
        self.uptime_var = ctk.StringVar(value="00:00:00")

        stats = [
            ("Total Alerts", self.total_alerts_var, "#ff4444"),
            ("High Severity", self.high_severity_var, "#ff8800"),
            ("Blocked IPs", self.blocked_ips_var, "#44ff44"),
            ("Uptime", self.uptime_var, "#4444ff")
        ]

        for i, (label, var, color) in enumerate(stats):
            frame = ctk.CTkFrame(stats_frame, fg_color=color)
            frame.grid(row=i // 2, column=i % 2, padx=5, pady=5, sticky="nsew")
            ctk.CTkLabel(frame, text=label, font=ctk.CTkFont(size=12, weight="bold")).pack(pady=(10, 0))
            ctk.CTkLabel(frame, textvariable=var, font=ctk.CTkFont(size=28, weight="bold")).pack(pady=(0, 10))

        ctk.CTkLabel(left_panel, text="Select Interface", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=(10, 5))
        self.iface_combo = ctk.CTkComboBox(left_panel, values=self.iface_list, variable=self.selected_iface, width=280)
        self.iface_combo.pack(padx=10, pady=(0, 15))
        self.iface_combo.set(self.selected_iface.get())

        control_frame = ctk.CTkFrame(left_panel)
        control_frame.pack(fill="x", padx=10, pady=10)

        self.start_btn = ctk.CTkButton(control_frame, text="▶️ START MONITORING", command=self.start_monitoring, height=40, fg_color="#28a745")
        self.start_btn.pack(fill="x", pady=5)

        self.stop_btn = ctk.CTkButton(control_frame, text="⏹️ STOP MONITORING", command=self.stop_monitoring, height=40, fg_color="#dc3545", state="disabled")
        self.stop_btn.pack(fill="x", pady=5)

        self.save_btn = ctk.CTkButton(control_frame, text="💾 SAVE LOGS", command=self.save_logs, height=40, fg_color="#1f6aa5")
        self.save_btn.pack(fill="x", pady=5)

        right_panel = ctk.CTkFrame(main_frame)
        right_panel.pack(side="right", fill="both", expand=True)

        ctk.CTkLabel(right_panel, text="🚨 REAL-TIME SECURITY LOGS", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)

        self.log_text = scrolledtext.ScrolledText(right_panel, height=25, bg="#1a1a1a", fg="#00ff00", font=("Consolas", 11))
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)

        self.status_var = ctk.StringVar(value="🟢 READY - Select interface and press START")
        status_bar = ctk.CTkLabel(self, textvariable=self.status_var, font=ctk.CTkFont(size=12))
        status_bar.pack(side="bottom", fill="x", padx=20, pady=10)

        self.bind("<Escape>", lambda e: self.stop_monitoring())
        self.bind("<Control-s>", lambda e: self.save_logs())

    def update_uptime(self):
        if self.monitoring and self.start_time:
            elapsed = int(time.time() - self.start_time)
            h = elapsed // 3600
            m = (elapsed % 3600) // 60
            s = elapsed % 60
            self.uptime_var.set(f"{h:02d}:{m:02d}:{s:02d}")
        else:
            self.uptime_var.set("00:00:00")
        self.after(1000, self.update_uptime)

    def handle_packet(self, packet):
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        flags = str(packet[TCP].flags)

        alert_type = "NORMAL_TCP"
        severity = "LOW"

        if flags == "S":
            alert_type = "SYN_SCAN"
            severity = "HIGH"
        elif dport == 22:
            alert_type = "SSH_TRAFFIC"
            severity = "MEDIUM"
        elif dport in (80, 443):
            alert_type = "HTTP_TRAFFIC"
            severity = "LOW"

        alert = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "type": alert_type,
            "ip": src_ip,
            "port": dport,
            "flags": flags,
            "details": f"TCP {alert_type} from {src_ip}:{sport} to {dst_ip}:{dport}",
            "severity": severity
        }

        self.alerts.append(alert)
        self.total_alerts += 1
        if severity == "HIGH":
            self.high_severity += 1

        self.total_alerts_var.set(str(self.total_alerts))
        self.high_severity_var.set(str(self.high_severity))
        self.add_log(alert)

    def monitoring_loop(self):
        while self.monitoring:
            try:
                iface_name = self.iface_map.get(self.selected_iface.get(), self.selected_iface.get())
                scapy.sniff(iface=iface_name, prn=self.handle_packet, store=0, timeout=3)
            except Exception as e:
                self.add_log({
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "type": "ERROR",
                    "ip": self.selected_iface.get(),
                    "details": str(e),
                    "severity": "HIGH"
                })
                break

    def start_monitoring(self):
        if not self.monitoring:
            self.monitoring = True
            self.start_time = time.time()
            self.start_btn.configure(state="disabled")
            self.stop_btn.configure(state="normal")
            self.status_var.set(f"🔴 REAL MONITORING ACTIVE ({self.selected_iface.get()})")
            self.add_log({
                "time": datetime.now().strftime("%H:%M:%S"),
                "type": "SYSTEM",
                "ip": self.selected_iface.get(),
                "details": f"Real monitoring started on {self.selected_iface.get()}",
                "severity": "INFO"
            })
            self.monitor_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
            self.monitor_thread.start()

    def stop_monitoring(self):
        if self.monitoring:
            self.monitoring = False
            self.start_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
            self.status_var.set("🛑 REAL MONITORING STOPPED")
            self.add_log({
                "time": datetime.now().strftime("%H:%M:%S"),
                "type": "SYSTEM",
                "ip": self.selected_iface.get(),
                "details": "Real monitoring stopped by user",
                "severity": "INFO"
            })

    def add_log(self, alert):
        msg = f"[{alert['time']}] {alert['severity']} | {alert['type']}: {alert['ip']} - {alert['details']}"
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)

    def save_logs(self):
        with open(self.log_file, "w", encoding="utf-8") as f:
            json.dump(self.alerts, f, indent=2)
        messagebox.showinfo("Saved", f"✅ {len(self.alerts)} alerts saved to {self.log_file}")


if __name__ == "__main__":
    app = Intrudex()
    app.mainloop()