"""
login_screen.py - Login and Registration Screen
Dark cybersecurity-themed GUI with animated elements.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
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
FONT_MONO = ("Courier New", 10)
FONT_TITLE = ("Courier New", 22, "bold")
FONT_LABEL = ("Courier New", 10)
FONT_SMALL = ("Courier New", 8)


class LoginScreen(tk.Frame):
    """
    Login and Registration screen with password strength meter.
    Supports tab-switching between login and register modes.
    """

    def __init__(self, parent, on_login_success, storage, auth_manager):
        """
        Initialize login screen.
        Args:
            parent: Parent tkinter widget
            on_login_success: Callback fn(username, token)
            storage: Storage instance
            auth_manager: AuthManager instance
        """
        super().__init__(parent, bg=DARK_BG)
        self.parent = parent
        self.on_login_success = on_login_success
        self.storage = storage
        self.auth = auth_manager
        self._mode = "login"   # "login" or "register"
        self._build_ui()
        self._start_animation()

    def _build_ui(self):
        """Build the complete login UI."""
        self.pack(fill=tk.BOTH, expand=True)

        # ── Background canvas for animated grid ──────────────────────────────
        self.canvas = tk.Canvas(self, bg=DARK_BG, highlightthickness=0)
        self.canvas.place(relwidth=1, relheight=1)
        self._draw_grid()

        # ── Center container ─────────────────────────────────────────────────
        center = tk.Frame(self, bg=PANEL_BG, relief="flat")
        center.place(relx=0.5, rely=0.5, anchor="center", width=420, height=580)

        # Border effect
        border = tk.Frame(self, bg=ACCENT, relief="flat")
        border.place(relx=0.5, rely=0.5, anchor="center", width=422, height=582)
        center.lift()

        # ── Header ───────────────────────────────────────────────────────────
        header = tk.Frame(center, bg="#070c18", pady=20)
        header.pack(fill=tk.X)

        tk.Label(
            header, text="👻 GhostPixel", font=FONT_TITLE,
            bg="#070c18", fg=ACCENT
        ).pack()

        tk.Label(
            header, text="HIDDEN IN PLAIN SIGHT  •  AES-256 + LSB STEGANOGRAPHY",
            font=FONT_SMALL, bg="#070c18", fg=TEXT_DIM
        ).pack(pady=(2, 0))

        # ── Tab switcher ─────────────────────────────────────────────────────
        tab_frame = tk.Frame(center, bg=PANEL_BG)
        tab_frame.pack(fill=tk.X, padx=20, pady=(15, 0))

        self.login_tab = tk.Button(
            tab_frame, text="LOGIN", font=FONT_LABEL,
            bg=ACCENT, fg=DARK_BG, relief="flat", cursor="hand2",
            activebackground=ACCENT, activeforeground=DARK_BG,
            command=lambda: self._switch_mode("login"), padx=20, pady=6
        )
        self.login_tab.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.register_tab = tk.Button(
            tab_frame, text="REGISTER", font=FONT_LABEL,
            bg=INPUT_BG, fg=TEXT_DIM, relief="flat", cursor="hand2",
            activebackground=ACCENT2, activeforeground="white",
            command=lambda: self._switch_mode("register"), padx=20, pady=6
        )
        self.register_tab.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # ── Form container ───────────────────────────────────────────────────
        self.form_frame = tk.Frame(center, bg=PANEL_BG)
        self.form_frame.pack(fill=tk.BOTH, expand=True, padx=24, pady=10)

        self._build_form()

        # ── Status label ─────────────────────────────────────────────────────
        self.status_var = tk.StringVar(value="")
        self.status_label = tk.Label(
            center, textvariable=self.status_var,
            font=FONT_SMALL, bg=PANEL_BG, fg=ERROR, wraplength=380
        )
        self.status_label.pack(pady=(0, 8))

        # ── Submit button ─────────────────────────────────────────────────────
        self.submit_btn = tk.Button(
            center, text="LOGIN  ▶", font=("Courier New", 11, "bold"),
            bg=ACCENT, fg=DARK_BG, relief="flat", cursor="hand2",
            activebackground="#00b8d9", activeforeground=DARK_BG,
            command=self._submit, pady=10
        )
        self.submit_btn.pack(fill=tk.X, padx=24, pady=(0, 20))

        # ── Footer ────────────────────────────────────────────────────────────
        tk.Label(
            center,
            text="Messages hidden in images • HMAC tamper detection • AES-256-GCM",
            font=("Courier New", 7), bg=PANEL_BG, fg=TEXT_DIM, wraplength=380
        ).pack(pady=(0, 10))

    def _build_form(self):
        """Build form fields inside form_frame."""
        for widget in self.form_frame.winfo_children():
            widget.destroy()

        # Username
        tk.Label(
            self.form_frame, text="USERNAME", font=FONT_SMALL,
            bg=PANEL_BG, fg=ACCENT, anchor="w"
        ).pack(fill=tk.X, pady=(10, 2))

        self.username_var = tk.StringVar()
        username_entry = tk.Entry(
            self.form_frame, textvariable=self.username_var,
            font=FONT_MONO, bg=INPUT_BG, fg=TEXT_PRIMARY,
            insertbackground=ACCENT, relief="flat",
            highlightthickness=1, highlightcolor=ACCENT,
            highlightbackground=BORDER
        )
        username_entry.pack(fill=tk.X, ipady=8)
        username_entry.bind("<Return>", lambda e: self._submit())

        # Password
        tk.Label(
            self.form_frame, text="PASSWORD", font=FONT_SMALL,
            bg=PANEL_BG, fg=ACCENT, anchor="w"
        ).pack(fill=tk.X, pady=(12, 2))

        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(
            self.form_frame, textvariable=self.password_var,
            font=FONT_MONO, bg=INPUT_BG, fg=TEXT_PRIMARY,
            insertbackground=ACCENT, relief="flat", show="●",
            highlightthickness=1, highlightcolor=ACCENT,
            highlightbackground=BORDER
        )
        self.password_entry.pack(fill=tk.X, ipady=8)
        self.password_entry.bind("<Return>", lambda e: self._submit())

        if self._mode == "register":
            # Confirm Password
            tk.Label(
                self.form_frame, text="CONFIRM PASSWORD", font=FONT_SMALL,
                bg=PANEL_BG, fg=ACCENT, anchor="w"
            ).pack(fill=tk.X, pady=(12, 2))

            self.confirm_var = tk.StringVar()
            self.confirm_entry = tk.Entry(
                self.form_frame, textvariable=self.confirm_var,
                font=FONT_MONO, bg=INPUT_BG, fg=TEXT_PRIMARY,
                insertbackground=ACCENT, relief="flat", show="●",
                highlightthickness=1, highlightcolor=ACCENT,
                highlightbackground=BORDER
            )
            self.confirm_entry.pack(fill=tk.X, ipady=8)
            self.confirm_entry.bind("<Return>", lambda e: self._submit())

            # Password strength meter
            tk.Label(
                self.form_frame, text="PASSWORD STRENGTH", font=FONT_SMALL,
                bg=PANEL_BG, fg=TEXT_DIM, anchor="w"
            ).pack(fill=tk.X, pady=(10, 2))

            self.strength_bar = ttk.Progressbar(
                self.form_frame, length=200, mode="determinate", maximum=5
            )
            self.strength_bar.pack(fill=tk.X)

            self.strength_label = tk.Label(
                self.form_frame, text="", font=FONT_SMALL,
                bg=PANEL_BG, fg=TEXT_DIM, anchor="w"
            )
            self.strength_label.pack(fill=tk.X)

            self.password_var.trace("w", self._update_strength)

        # Show/hide password toggle
        show_frame = tk.Frame(self.form_frame, bg=PANEL_BG)
        show_frame.pack(fill=tk.X, pady=(6, 0))
        self.show_pw_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            show_frame, text="Show password", variable=self.show_pw_var,
            font=FONT_SMALL, bg=PANEL_BG, fg=TEXT_DIM,
            activebackground=PANEL_BG, selectcolor=INPUT_BG,
            command=self._toggle_password
        ).pack(side=tk.LEFT)

        username_entry.focus_set()

    def _toggle_password(self):
        """Toggle password visibility."""
        show = "" if self.show_pw_var.get() else "●"
        self.password_entry.config(show=show)
        if self._mode == "register" and hasattr(self, "confirm_entry"):
            self.confirm_entry.config(show=show)

    def _update_strength(self, *args):
        """Update password strength meter on keystroke."""
        if not hasattr(self, "strength_bar"):
            return
        password = self.password_var.get()
        from core.auth import PasswordHasher
        _, msg, score = PasswordHasher.validate_password_strength(password)
        self.strength_bar["value"] = score
        colors = {0: ERROR, 1: ERROR, 2: WARNING, 3: WARNING, 4: SUCCESS, 5: SUCCESS}
        self.strength_label.config(
            text=f"{'█' * score}{'░' * (5 - score)}  {msg}",
            fg=colors.get(score, TEXT_DIM)
        )

    def _switch_mode(self, mode: str):
        """Switch between login and register tabs."""
        self._mode = mode
        if mode == "login":
            self.login_tab.config(bg=ACCENT, fg=DARK_BG)
            self.register_tab.config(bg=INPUT_BG, fg=TEXT_DIM)
            self.submit_btn.config(text="LOGIN  ▶")
        else:
            self.register_tab.config(bg=ACCENT2, fg="white")
            self.login_tab.config(bg=INPUT_BG, fg=TEXT_DIM)
            self.submit_btn.config(text="CREATE ACCOUNT  ▶")
        self._build_form()
        self.status_var.set("")

    def _submit(self):
        """Handle form submission."""
        username = self.username_var.get().strip()
        password = self.password_var.get()

        if not username or not password:
            self._show_status("Please fill in all fields.", ERROR)
            return

        self.submit_btn.config(state="disabled", text="Processing...")
        self.after(100, lambda: self._process_auth(username, password))

    def _process_auth(self, username: str, password: str):
        """Process authentication in background."""
        try:
            if self._mode == "login":
                success, result = self.auth.login(username, password)
                if success:
                    self._show_status("✓ Authentication successful!", SUCCESS)
                    self.after(600, lambda: self.on_login_success(username, result))
                else:
                    self._show_status(f"✗ {result}", ERROR)
                    self.storage.log_security_event(
                        "LOGIN_FAILED", f"Failed login attempt for '{username}'",
                        username=username, severity="WARNING"
                    )
            else:
                confirm = self.confirm_var.get() if hasattr(self, "confirm_var") else ""
                if password != confirm:
                    self._show_status("✗ Passwords do not match.", ERROR)
                    return
                success, result = self.auth.register(username, password)
                if success:
                    self._show_status("✓ Account created! Please login.", SUCCESS)
                    self.after(1200, lambda: self._switch_mode("login"))
                else:
                    self._show_status(f"✗ {result}", ERROR)
        finally:
            self.submit_btn.config(state="normal",
                text="LOGIN  ▶" if self._mode == "login" else "CREATE ACCOUNT  ▶")

    def _show_status(self, msg: str, color: str = ERROR):
        """Show a status message below the form."""
        self.status_var.set(msg)
        self.status_label.config(fg=color)

    def _draw_grid(self):
        """Draw cyberpunk grid background."""
        self.canvas.delete("grid")
        w = self.winfo_screenwidth()
        h = self.winfo_screenheight()
        step = 40
        for x in range(0, w, step):
            self.canvas.create_line(x, 0, x, h, fill="#0d1a2e", tags="grid", width=1)
        for y in range(0, h, step):
            self.canvas.create_line(0, y, w, y, fill="#0d1a2e", tags="grid", width=1)

    def _start_animation(self):
        """Start blinking cursor animation on title."""
        self._animate()

    def _animate(self):
        """Animate scan line effect."""
        if not self.winfo_exists():
            return
        self.after(2000, self._animate)