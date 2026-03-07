"""
dashboard.py - Security Dashboard Window
Shows real-time security events, stats, tamper alerts, and connection logs.
"""

import tkinter as tk
from tkinter import ttk
import time

DARK_BG = "#0a0e1a"
PANEL_BG = "#0f1629"
ACCENT = "#00d4ff"
ACCENT2 = "#7c3aed"
SUCCESS = "#00ff88"
ERROR = "#ff4444"
WARNING = "#ffaa00"
TEXT_PRIMARY = "#e2e8f0"
TEXT_DIM = "#64748b"
INPUT_BG = "#1e2a3a"
BORDER = "#1e3a5f"
FONT_MONO = ("Courier New", 9)
FONT_LABEL = ("Courier New", 10)
FONT_SMALL = ("Courier New", 8)
FONT_TITLE = ("Courier New", 13, "bold")

SEVERITY_COLORS = {
    "INFO": ACCENT,
    "WARNING": WARNING,
    "CRITICAL": ERROR
}


class DashboardWindow(tk.Toplevel):
    """
    Security dashboard showing stats, events, and alerts.
    Auto-refreshes every 3 seconds.
    """

    def __init__(self, parent, storage):
        """
        Initialize dashboard.
        Args:
            parent: Parent tkinter window
            storage: Storage instance
        """
        super().__init__(parent)
        self.storage = storage
        self.title("👻 GhostPixel — Security Dashboard")
        self.configure(bg=DARK_BG)
        self.geometry("900x620")
        self.resizable(True, True)
        self._build_ui()
        self._refresh()

    def _build_ui(self):
        """Build dashboard interface."""

        # ── Title bar ─────────────────────────────────────────────────────────
        title_bar = tk.Frame(self, bg="#070c18", pady=12, padx=16)
        title_bar.pack(fill=tk.X)

        tk.Label(
            title_bar, text="👻 GHOSTPIXEL SECURITY DASHBOARD",
            font=FONT_TITLE, bg="#070c18", fg=ACCENT
        ).pack(side=tk.LEFT)

        self.last_update_var = tk.StringVar(value="")
        tk.Label(
            title_bar, textvariable=self.last_update_var,
            font=FONT_SMALL, bg="#070c18", fg=TEXT_DIM
        ).pack(side=tk.RIGHT)

        # ── Stats row ────────────────────────────────────────────────────────
        stats_frame = tk.Frame(self, bg=DARK_BG, pady=12, padx=16)
        stats_frame.pack(fill=tk.X)

        self.stat_widgets = {}
        stats_config = [
            ("users", "👤 USERS", SUCCESS),
            ("messages", "💬 MESSAGES", ACCENT),
            ("tampered", "⚠ TAMPERED", ERROR),
            ("security_events", "🔔 EVENTS", WARNING),
        ]

        for key, label, color in stats_config:
            card = tk.Frame(stats_frame, bg=PANEL_BG, padx=20, pady=12, relief="flat")
            card.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)

            # Border
            border = tk.Frame(stats_frame, bg=color, width=2)

            val_var = tk.StringVar(value="0")
            tk.Label(
                card, textvariable=val_var,
                font=("Courier New", 22, "bold"), bg=PANEL_BG, fg=color
            ).pack()
            tk.Label(
                card, text=label,
                font=FONT_SMALL, bg=PANEL_BG, fg=TEXT_DIM
            ).pack()

            self.stat_widgets[key] = val_var

        # ── Tabs ──────────────────────────────────────────────────────────────
        tab_frame = tk.Frame(self, bg=DARK_BG)
        tab_frame.pack(fill=tk.X, padx=16, pady=(8, 0))

        self._active_tab = tk.StringVar(value="events")
        tabs = [("SECURITY EVENTS", "events"), ("TAMPER ALERTS", "tamper"), ("ALL MESSAGES", "messages")]

        self.tab_buttons = {}
        for label, key in tabs:
            btn = tk.Button(
                tab_frame, text=label, font=FONT_SMALL,
                bg=ACCENT if key == "events" else INPUT_BG,
                fg=DARK_BG if key == "events" else TEXT_DIM,
                relief="flat", cursor="hand2", padx=12, pady=6,
                command=lambda k=key: self._switch_tab(k)
            )
            btn.pack(side=tk.LEFT, padx=(0, 4))
            self.tab_buttons[key] = btn

        # ── Content area ─────────────────────────────────────────────────────
        content = tk.Frame(self, bg=DARK_BG, padx=16, pady=8)
        content.pack(fill=tk.BOTH, expand=True)

        # Events table
        self.events_frame = tk.Frame(content, bg=DARK_BG)
        self.events_frame.pack(fill=tk.BOTH, expand=True)
        self._build_events_table()

        # Tamper alerts frame
        self.tamper_frame = tk.Frame(content, bg=DARK_BG)
        self._build_tamper_table()

        # Messages frame
        self.messages_frame = tk.Frame(content, bg=DARK_BG)
        self._build_messages_table()

        # ── Refresh button ────────────────────────────────────────────────────
        btn_frame = tk.Frame(self, bg=DARK_BG, pady=8)
        btn_frame.pack()

        tk.Button(
            btn_frame, text="🔄 REFRESH NOW",
            font=FONT_SMALL, bg=ACCENT2, fg="white",
            relief="flat", cursor="hand2", padx=16, pady=6,
            command=self._refresh
        ).pack(side=tk.LEFT, padx=6)

        tk.Button(
            btn_frame, text="✕ CLOSE",
            font=FONT_SMALL, bg=INPUT_BG, fg=TEXT_DIM,
            relief="flat", cursor="hand2", padx=16, pady=6,
            command=self.destroy
        ).pack(side=tk.LEFT, padx=6)

    def _build_events_table(self):
        """Build the security events table."""
        cols = ("Time", "Severity", "Event Type", "User", "Description")
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Dark.Treeview",
            background=PANEL_BG, foreground=TEXT_PRIMARY,
            rowheight=24, fieldbackground=PANEL_BG,
            font=FONT_SMALL
        )
        style.configure("Dark.Treeview.Heading",
            background=INPUT_BG, foreground=ACCENT,
            font=("Courier New", 8, "bold")
        )
        style.map("Dark.Treeview",
            background=[("selected", INPUT_BG)],
            foreground=[("selected", ACCENT)]
        )

        self.events_tree = ttk.Treeview(
            self.events_frame, columns=cols, show="headings",
            style="Dark.Treeview"
        )

        for col in cols:
            widths = {"Time": 120, "Severity": 80, "Event Type": 160, "User": 100, "Description": 340}
            self.events_tree.heading(col, text=col)
            self.events_tree.column(col, width=widths.get(col, 120), minwidth=60)

        scrollbar = ttk.Scrollbar(self.events_frame, orient="vertical",
                                   command=self.events_tree.yview)
        self.events_tree.configure(yscrollcommand=scrollbar.set)

        self.events_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def _build_tamper_table(self):
        """Build tamper alerts table."""
        cols = ("Time", "User", "Description")
        self.tamper_tree = ttk.Treeview(
            self.tamper_frame, columns=cols, show="headings",
            style="Dark.Treeview"
        )
        for col in cols:
            widths = {"Time": 150, "User": 120, "Description": 500}
            self.tamper_tree.heading(col, text=col)
            self.tamper_tree.column(col, width=widths.get(col, 120))

        scrollbar = ttk.Scrollbar(self.tamper_frame, orient="vertical",
                                   command=self.tamper_tree.yview)
        self.tamper_tree.configure(yscrollcommand=scrollbar.set)
        self.tamper_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def _build_messages_table(self):
        """Build messages log table."""
        cols = ("Time", "From", "To", "Encrypted", "Tampered")
        self.messages_tree = ttk.Treeview(
            self.messages_frame, columns=cols, show="headings",
            style="Dark.Treeview"
        )
        for col in cols:
            widths = {"Time": 150, "From": 100, "To": 100, "Encrypted": 300, "Tampered": 80}
            self.messages_tree.heading(col, text=col)
            self.messages_tree.column(col, width=widths.get(col, 100))

        scrollbar = ttk.Scrollbar(self.messages_frame, orient="vertical",
                                   command=self.messages_tree.yview)
        self.messages_tree.configure(yscrollcommand=scrollbar.set)
        self.messages_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def _switch_tab(self, key: str):
        """Switch between dashboard tabs."""
        self._active_tab.set(key)
        for k, btn in self.tab_buttons.items():
            if k == key:
                btn.config(bg=ACCENT, fg=DARK_BG)
            else:
                btn.config(bg=INPUT_BG, fg=TEXT_DIM)

        self.events_frame.pack_forget()
        self.tamper_frame.pack_forget()
        self.messages_frame.pack_forget()

        if key == "events":
            self.events_frame.pack(fill=tk.BOTH, expand=True)
        elif key == "tamper":
            self.tamper_frame.pack(fill=tk.BOTH, expand=True)
        elif key == "messages":
            self.messages_frame.pack(fill=tk.BOTH, expand=True)

    def _refresh(self):
        """Refresh all dashboard data."""
        # Stats
        stats = self.storage.get_stats()
        for key, var in self.stat_widgets.items():
            var.set(str(stats.get(key, 0)))

        # Events
        for item in self.events_tree.get_children():
            self.events_tree.delete(item)

        events = self.storage.get_security_events(limit=100)
        for evt in events:
            time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(evt["timestamp"]))
            self.events_tree.insert("", "end", values=(
                time_str, evt["severity"], evt["event_type"],
                evt.get("username") or "—", evt["description"]
            ))

        # Tamper alerts
        for item in self.tamper_tree.get_children():
            self.tamper_tree.delete(item)

        tamper_events = [e for e in events if e["event_type"] in
                         ("TAMPER_DETECTED", "REPLAY_ATTACK_BLOCKED")]
        for evt in tamper_events:
            time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(evt["timestamp"]))
            self.tamper_tree.insert("", "end", values=(
                time_str, evt.get("username") or "—", evt["description"]
            ))

        # Messages
        from core.storage import Storage
        for item in self.messages_tree.get_children():
            self.messages_tree.delete(item)

        with self.storage._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM messages ORDER BY timestamp DESC LIMIT 50"
            ).fetchall()
            for row in rows:
                time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row["timestamp"]))
                enc_preview = row["encrypted_content"][:40] + "..." if row["encrypted_content"] else ""
                tampered_str = "⚠ YES" if row["tampered"] else "✓ No"
                self.messages_tree.insert("", "end", values=(
                    time_str, row["sender"], row["recipient"],
                    enc_preview, tampered_str
                ))

        self.last_update_var.set(
            f"Last updated: {time.strftime('%H:%M:%S')}"
        )

        # Auto-refresh
        if self.winfo_exists():
            self.after(5000, self._refresh)