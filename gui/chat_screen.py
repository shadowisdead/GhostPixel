"""
chat_screen.py - Main Chat Window
Shows message bubbles, online users sidebar, stego image preview,
and tamper detection alerts.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import time
import os
import secrets
import json
import base64

DARK_BG = "#0a0e1a"
PANEL_BG = "#0f1629"
SIDEBAR_BG = "#080d18"
ACCENT = "#00d4ff"
ACCENT2 = "#7c3aed"
SUCCESS = "#00ff88"
ERROR = "#ff4444"
WARNING = "#ffaa00"
TEXT_PRIMARY = "#e2e8f0"
TEXT_DIM = "#64748b"
INPUT_BG = "#1e2a3a"
BORDER = "#1e3a5f"
MSG_SENT_BG = "#0d2137"
MSG_RECV_BG = "#12192b"
TAMPER_BG = "#3a0a0a"
FONT_MONO = ("Courier New", 10)
FONT_LABEL = ("Courier New", 10)
FONT_SMALL = ("Courier New", 8)
FONT_MSG = ("Courier New", 10)
FONT_TITLE = ("Courier New", 12, "bold")


class MessageBubble(tk.Frame):
    """A single chat message bubble widget."""

    def __init__(self, parent, sender: str, content: str, timestamp: float,
                 is_own: bool = False, tampered: bool = False, **kwargs):
        """
        Initialize a message bubble.
        Args:
            parent: Parent widget
            sender (str): Message sender username
            content (str): Decrypted message text
            timestamp (float): Unix timestamp
            is_own (bool): True if sent by current user
            tampered (bool): True if tamper was detected
        """
        bg = TAMPER_BG if tampered else (MSG_SENT_BG if is_own else MSG_RECV_BG)
        super().__init__(parent, bg=bg, pady=6, padx=10, relief="flat")

        anchor = "e" if is_own else "w"
        align = tk.RIGHT if is_own else tk.LEFT

        # Tamper warning banner
        if tampered:
            tk.Label(
                self, text="⚠ TAMPER DETECTED — MESSAGE INTEGRITY COMPROMISED",
                font=("Courier New", 7, "bold"), bg=TAMPER_BG, fg=WARNING
            ).pack(fill=tk.X)

        # Sender + time header
        time_str = time.strftime("%H:%M", time.localtime(timestamp))
        sender_color = ACCENT if is_own else "#a78bfa"
        header_frame = tk.Frame(self, bg=bg)
        header_frame.pack(fill=tk.X)

        tk.Label(
            header_frame,
            text=f"{'YOU' if is_own else sender.upper()}",
            font=("Courier New", 8, "bold"), bg=bg, fg=sender_color
        ).pack(side=align)

        tk.Label(
            header_frame, text=time_str,
            font=FONT_SMALL, bg=bg, fg=TEXT_DIM
        ).pack(side=tk.RIGHT if is_own else tk.LEFT, padx=(8, 0))

        # Message content
        content_label = tk.Label(
            self, text=content, font=FONT_MSG,
            bg=bg, fg=TEXT_PRIMARY if not tampered else ERROR,
            wraplength=400, justify=align, anchor=anchor
        )
        content_label.pack(fill=tk.X, pady=(2, 0))

        # Encryption indicator
        enc_text = "🔒 AES-256-GCM + LSB Stego" if not tampered else "🔓 COMPROMISED"
        tk.Label(
            self, text=enc_text, font=("Courier New", 7),
            bg=bg, fg=TEXT_DIM if not tampered else ERROR
        ).pack(anchor=anchor)


class ChatScreen(tk.Frame):
    """
    Main chat window with sidebar, message display, and input area.
    """

    def __init__(self, parent, username: str, session_token: str,
                 auth_manager, storage, on_logout):
        """
        Initialize chat screen.
        Args:
            parent: Parent tkinter widget
            username (str): Logged-in username
            session_token (str): Active session token
            auth_manager: AuthManager instance
            storage: Storage instance
            on_logout: Callback fn() for logout
        """
        super().__init__(parent, bg=DARK_BG)
        self.username = username
        self.session_token = session_token
        self.auth = auth_manager
        self.storage = storage
        self.on_logout = on_logout
        self.selected_user = None
        self.server = None
        self.client = None
        self._message_list = None  # MessageLinkedList for current conversation
        self._build_ui()
        self._init_crypto()
        self._start_server_or_connect()
        self._load_users()

    def _init_crypto(self):
        """Initialize cryptographic components."""
        from core.crypto import AESCipher, RSACipher, KeyDerivation
        from core.steganography import SteganographyEngine
        from core.tamper import TamperDetector, NonceManager
        from dsa.linked_list import MessageLinkedList

        # Derive a shared static AES key so that all peers use the same
        # encryption key and can successfully decrypt each other's messages.
        shared_secret = "GhostPixel-SharedSecret-2024"
        shared_salt = b"ghostpixel_salt_"
        shared_key, _ = KeyDerivation.derive_key(shared_secret, shared_salt)
        self.aes = AESCipher(key=shared_key)
        self.rsa = RSACipher()
        self.stego = SteganographyEngine()
        self.tamper_detector = TamperDetector()
        self.nonce_manager = NonceManager()
        self.message_history = MessageLinkedList()

        # Register public key in storage
        self.storage.update_public_key(self.username, self.rsa.get_public_key_pem())

    def _build_ui(self):
        """Build the main chat interface."""
        self.pack(fill=tk.BOTH, expand=True)

        # ── Top bar ──────────────────────────────────────────────────────────
        topbar = tk.Frame(self, bg="#070c18", pady=8, padx=16)
        topbar.pack(fill=tk.X, side=tk.TOP)

        tk.Label(
            topbar, text="👻 GhostPixel",
            font=FONT_TITLE, bg="#070c18", fg=ACCENT
        ).pack(side=tk.LEFT)

        # Connection status
        self.conn_var = tk.StringVar(value="⚫ Offline")
        self.conn_label = tk.Label(
            topbar, textvariable=self.conn_var,
            font=FONT_SMALL, bg="#070c18", fg=TEXT_DIM
        )
        self.conn_label.pack(side=tk.LEFT, padx=20)

        # Logged in user
        tk.Label(
            topbar, text=f"👤 {self.username.upper()}",
            font=FONT_LABEL, bg="#070c18", fg=SUCCESS
        ).pack(side=tk.RIGHT, padx=(0, 10))

        tk.Button(
            topbar, text="LOGOUT", font=FONT_SMALL,
            bg=ERROR, fg="white", relief="flat", cursor="hand2",
            activebackground="#cc0000", command=self._logout, padx=10
        ).pack(side=tk.RIGHT)

        tk.Button(
            topbar, text="DASHBOARD", font=FONT_SMALL,
            bg=ACCENT2, fg="white", relief="flat", cursor="hand2",
            activebackground="#6d28d9", command=self._open_dashboard, padx=10
        ).pack(side=tk.RIGHT, padx=(0, 8))

        # ── Main content ──────────────────────────────────────────────────────
        content = tk.Frame(self, bg=DARK_BG)
        content.pack(fill=tk.BOTH, expand=True)

        # ── Left sidebar — users ─────────────────────────────────────────────
        sidebar = tk.Frame(content, bg=SIDEBAR_BG, width=180)
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)

        tk.Label(
            sidebar, text="ONLINE USERS",
            font=("Courier New", 8, "bold"), bg=SIDEBAR_BG, fg=ACCENT, pady=10
        ).pack(fill=tk.X, padx=10)

        tk.Frame(sidebar, bg=BORDER, height=1).pack(fill=tk.X)

        self.users_frame = tk.Frame(sidebar, bg=SIDEBAR_BG)
        self.users_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # Stego image preview panel
        tk.Frame(sidebar, bg=BORDER, height=1).pack(fill=tk.X)
        tk.Label(
            sidebar, text="LAST CARRIER IMAGE",
            font=("Courier New", 7, "bold"), bg=SIDEBAR_BG, fg=TEXT_DIM, pady=6
        ).pack()

        self.img_preview_label = tk.Label(
            sidebar, text="No image yet",
            font=FONT_SMALL, bg=SIDEBAR_BG, fg=TEXT_DIM,
            width=20, height=8
        )
        self.img_preview_label.pack(padx=5, pady=5)

        # ── Chat area ─────────────────────────────────────────────────────────
        chat_area = tk.Frame(content, bg=DARK_BG)
        chat_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Chat header
        self.chat_header = tk.Frame(chat_area, bg=PANEL_BG, pady=8, padx=16)
        self.chat_header.pack(fill=tk.X)

        self.chat_title_var = tk.StringVar(value="Select a user to start chatting")
        tk.Label(
            self.chat_header, textvariable=self.chat_title_var,
            font=FONT_LABEL, bg=PANEL_BG, fg=TEXT_PRIMARY
        ).pack(side=tk.LEFT)

        self.encryption_badge = tk.Label(
            self.chat_header,
            text="",
            font=("Courier New", 7), bg=PANEL_BG, fg=SUCCESS
        )
        self.encryption_badge.pack(side=tk.RIGHT)

        # Messages scroll area
        msg_container = tk.Frame(chat_area, bg=DARK_BG)
        msg_container.pack(fill=tk.BOTH, expand=True)

        self.msg_canvas = tk.Canvas(msg_container, bg=DARK_BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(msg_container, orient="vertical",
                                   command=self.msg_canvas.yview)
        self.msg_canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.msg_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.messages_frame = tk.Frame(self.msg_canvas, bg=DARK_BG)
        self.msg_canvas_window = self.msg_canvas.create_window(
            (0, 0), window=self.messages_frame, anchor="nw"
        )

        self.messages_frame.bind("<Configure>", self._on_frame_configure)
        self.msg_canvas.bind("<Configure>", self._on_canvas_configure)

        # Welcome message
        self._show_welcome()

        # ── Input area ────────────────────────────────────────────────────────
        input_area = tk.Frame(chat_area, bg=PANEL_BG, pady=10, padx=12)
        input_area.pack(fill=tk.X, side=tk.BOTTOM)

        # Carrier image selector
        img_btn_frame = tk.Frame(input_area, bg=PANEL_BG)
        img_btn_frame.pack(fill=tk.X, pady=(0, 6))

        self.carrier_path_var = tk.StringVar(value="Using: generated noise carrier")
        tk.Label(
            img_btn_frame, textvariable=self.carrier_path_var,
            font=FONT_SMALL, bg=PANEL_BG, fg=TEXT_DIM
        ).pack(side=tk.LEFT)

        tk.Button(
            img_btn_frame, text="📎 Custom Carrier",
            font=FONT_SMALL, bg=INPUT_BG, fg=ACCENT,
            relief="flat", cursor="hand2",
            command=self._select_carrier
        ).pack(side=tk.RIGHT)

        # Message input row
        input_row = tk.Frame(input_area, bg=PANEL_BG)
        input_row.pack(fill=tk.X)

        self.msg_input = tk.Text(
            input_row, font=FONT_MONO, bg=INPUT_BG, fg=TEXT_PRIMARY,
            insertbackground=ACCENT, relief="flat",
            highlightthickness=1, highlightcolor=ACCENT,
            highlightbackground=BORDER, height=3, wrap=tk.WORD
        )
        self.msg_input.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, ipady=4)
        self.msg_input.bind("<Return>", self._on_enter_key)
        self.msg_input.bind("<Shift-Return>", lambda e: None)

        send_btn = tk.Button(
            input_row, text="SEND\n🔒",
            font=("Courier New", 9, "bold"),
            bg=ACCENT, fg=DARK_BG, relief="flat", cursor="hand2",
            activebackground="#00b8d9", activeforeground=DARK_BG,
            command=self._send_message, padx=14, pady=8
        )
        send_btn.pack(side=tk.RIGHT, padx=(8, 0), fill=tk.Y)

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        tk.Label(
            input_area, textvariable=self.status_var,
            font=FONT_SMALL, bg=PANEL_BG, fg=TEXT_DIM, anchor="w"
        ).pack(fill=tk.X, pady=(4, 0))

    def _show_welcome(self):
        """Show welcome info in message area."""
        info = tk.Frame(self.messages_frame, bg=DARK_BG, pady=30)
        info.pack(fill=tk.X, padx=20)
        tk.Label(
            info, text="👻", font=("Courier New", 36),
            bg=DARK_BG, fg=ACCENT
        ).pack()
        tk.Label(
            info, text="GhostPixel",
            font=("Courier New", 16, "bold"), bg=DARK_BG, fg=TEXT_PRIMARY
        ).pack()
        tk.Label(
            info,
            text="Messages are AES-256-GCM encrypted,\nthen hidden inside PNG images using LSB steganography.\nHMAC-SHA256 tamper detection active.",
            font=FONT_SMALL, bg=DARK_BG, fg=TEXT_DIM, justify=tk.CENTER
        ).pack(pady=8)

    def _start_server_or_connect(self):
        """Start server and connect as client."""
        from core.network import ChatServer, ChatClient
        self.server = ChatServer(host="127.0.0.1", port=9999)
        self.server.start(on_event=self._on_server_event)

        # Give the server time to bind and listen before connecting the client
        time.sleep(0.5)

        self.client = ChatClient(host="127.0.0.1", port=9999)
        self.client.on_message = self._on_message_received
        self.client.on_user_list = self._on_user_list_update
        self.client.on_disconnect = self._on_disconnected

        # Retry connect a few times in case the server is still starting up
        attempts = 3
        delay = 0.3
        success = False
        msg = ""
        for _ in range(attempts):
            success, msg = self.client.connect(
                self.username,
                self.rsa.get_public_key_pem()
            )
            if success:
                break
            time.sleep(delay)

        if success:
            self.after(0, lambda: self.conn_var.set("🟢 Connected — Port 9999"))
            self.after(0, lambda: self.conn_label.config(fg=SUCCESS))
            self.storage.log_security_event(
                "USER_CONNECTED", f"{self.username} connected to server",
                username=self.username, severity="INFO"
            )
        else:
            self.after(0, lambda: self.conn_var.set(f"🔴 {msg}"))
            self.after(0, lambda: self.conn_label.config(fg=ERROR))

    def _load_users(self):
        """Load registered users into sidebar."""
        self.after(500, self._refresh_user_list)

    def _refresh_user_list(self):
        """Refresh the user list in sidebar."""
        for w in self.users_frame.winfo_children():
            w.destroy()

        all_users = self.storage.get_all_users()
        online = self.client.online_users if self.client else []

        for user in all_users:
            if user == self.username:
                continue
            is_online = user in online
            status_dot = "🟢" if is_online else "⚫"
            btn = tk.Button(
                self.users_frame,
                text=f"{status_dot} {user}",
                font=FONT_SMALL, bg=SIDEBAR_BG,
                fg=ACCENT if is_online else TEXT_DIM,
                relief="flat", cursor="hand2", anchor="w",
                activebackground=INPUT_BG, padx=12, pady=6,
                command=lambda u=user: self._select_user(u)
            )
            if self.selected_user == user:
                btn.config(bg=INPUT_BG, fg=TEXT_PRIMARY)
            btn.pack(fill=tk.X)

        self.after(3000, self._refresh_user_list)

    def _select_user(self, username: str):
        """Select a user to chat with."""
        self.selected_user = username
        self.chat_title_var.set(f"💬 Chatting with {username.upper()}")
        self.encryption_badge.config(
            text="🔒 AES-256-GCM + LSB Steganography + HMAC Tamper Detection"
        )
        self._clear_messages()
        self._load_conversation(username)
        self._refresh_user_list()

    def _clear_messages(self):
        """Clear the message display area."""
        for w in self.messages_frame.winfo_children():
            w.destroy()

    def _load_conversation(self, other_user: str):
        """Load message history from storage."""
        from core.crypto import AESCipher
        messages = self.storage.get_messages(self.username, other_user)
        for msg in messages:
            try:
                plaintext = self.aes.decrypt(msg["nonce"], msg["encrypted_content"])
                is_own = msg["sender"] == self.username
                self._add_message_bubble(
                    sender=msg["sender"],
                    content=plaintext,
                    timestamp=msg["timestamp"],
                    is_own=is_own,
                    tampered=bool(msg.get("tampered", 0))
                )
            except Exception:
                self._add_message_bubble(
                    sender=msg["sender"],
                    content="[Unable to decrypt message]",
                    timestamp=msg["timestamp"],
                    is_own=msg["sender"] == self.username,
                    tampered=True
                )
        self._scroll_to_bottom()

    def _add_message_bubble(self, sender: str, content: str, timestamp: float,
                             is_own: bool = False, tampered: bool = False):
        """Add a message bubble to the chat display."""
        bubble = MessageBubble(
            self.messages_frame, sender, content, timestamp,
            is_own=is_own, tampered=tampered
        )
        bubble.pack(fill=tk.X, padx=10, pady=3,
                    anchor="e" if is_own else "w")

        # Separator line
        tk.Frame(self.messages_frame, bg=BORDER, height=1).pack(
            fill=tk.X, padx=20
        )
        self._scroll_to_bottom()

    def _on_enter_key(self, event):
        """Send on Enter, newline on Shift+Enter."""
        if not event.state & 0x1:  # No Shift held
            self._send_message()
            return "break"

    def _send_message(self):
        """Encrypt, embed in stego image, and send message."""
        if not self.selected_user:
            self._show_status("Select a user first.", WARNING)
            return

        content = self.msg_input.get("1.0", tk.END).strip()
        if not content:
            return

        if not self.client or not self.client.is_connected():
            self._show_status("Not connected to server.", ERROR)
            return

        self.msg_input.delete("1.0", tk.END)
        self._show_status("🔒 Encrypting and embedding in image...", ACCENT)

        def _do_send():
            try:
                # 1. AES-256-GCM encrypt
                enc_result = self.aes.encrypt(content)

                # 2. Create message packet with nonce
                from core.tamper import MessagePacket
                msg_id = secrets.token_hex(8)
                packet = MessagePacket(
                    sender=self.username,
                    encrypted_payload=enc_result,
                    signature="",
                    nonce=secrets.token_hex(16),
                    timestamp=time.time()
                )

                # 3. HMAC sign the packet on UNSIGNED bytes (signature field empty)
                packet.signature = ""
                unsigned_bytes = packet.to_bytes()
                signature = self.tamper_detector.sign(unsigned_bytes)
                packet.signature = signature
                final_bytes = packet.to_bytes()

                # 4. LSB embed in carrier image
                carrier = getattr(self, "_carrier_path", None)
                self.stego.carrier_path = carrier
                stego_bytes = self.stego.embed(final_bytes)

                # 5. Send over TCP as raw binary frame (no JSON, no base64)
                from core.network import NetworkFrame
                binary_frame = NetworkFrame.pack_chat_message(
                    self.username,
                    self.selected_user,
                    msg_id,
                    stego_bytes  # raw PNG bytes, no base64
                )
                if self.client and self.client._sock:
                    self.client._sock.sendall(
                        NetworkFrame.pack(NetworkFrame.TYPE_MESSAGE, binary_frame)
                    )

                # 6. Save to DB (encrypted at-rest)
                self.storage.save_message(
                    msg_id=msg_id,
                    sender=self.username,
                    recipient=self.selected_user,
                    encrypted_content=enc_result["ciphertext"],
                    nonce=enc_result["nonce"],
                    signature=signature,
                    timestamp=packet.timestamp,
                    stego_image_b64=base64.b64encode(stego_bytes).decode("utf-8")[:200]
                )

                # 7. Add to linked list
                from dsa.linked_list import MessageLinkedList
                self.message_history.append({
                    "id": msg_id, "sender": self.username,
                    "content": content, "timestamp": packet.timestamp
                })

                # 8. Update UI
                self.after(0, lambda: self._add_message_bubble(
                    self.username, content, packet.timestamp, is_own=True
                ))
                self.after(0, lambda: self._show_status(
                    f"✓ Sent — hidden in {len(stego_bytes)/1024:.1f}KB PNG image", SUCCESS
                ))
                self.after(0, lambda: self._update_image_preview(stego_bytes))

            except Exception as e:
                self.after(0, lambda: self._show_status(f"Send failed: {e}", ERROR))

        threading.Thread(target=_do_send, daemon=True).start()

    def _on_message_received(self, sender: str, payload: bytes):
        """Handle incoming message from network."""
        def _process():
            try:
                # payload is now raw binary, not JSON
                from core.network import NetworkFrame
                sender_name, recipient, msg_id, image_bytes = \
                    NetworkFrame.unpack_chat_message(payload)

                actual_sender = sender_name
                stego_bytes = image_bytes

                # Extract from stego image
                from core.tamper import MessagePacket
                extracted = self.stego.extract(stego_bytes)
                packet = MessagePacket.from_bytes(extracted)

                # Verify HMAC on UNSIGNED packet bytes
                tampered = False

                temp_sig = packet.signature
                packet.signature = ""
                unsigned_bytes = packet.to_bytes()
                packet.signature = temp_sig

                if not self.tamper_detector.verify(unsigned_bytes, packet.signature):
                    tampered = True
                    self.storage.log_security_event(
                        "TAMPER_DETECTED",
                        f"Message from {actual_sender} failed HMAC verification!",
                        username=actual_sender, severity="CRITICAL"
                    )
                    self.after(0, self._show_tamper_alert)

                # Validate nonce (replay protection)
                envelope = {
                    "nonce": packet.nonce,
                    "timestamp": packet.timestamp
                }
                valid, reason = self.nonce_manager.validate_envelope(envelope)
                if not valid:
                    self.storage.log_security_event(
                        "REPLAY_ATTACK_BLOCKED", reason,
                        username=actual_sender, severity="CRITICAL"
                    )
                    return

                # Decrypt
                enc = packet.encrypted_payload
                plaintext = self.aes.decrypt(enc["nonce"], enc["ciphertext"])

                # Save to DB
                self.storage.save_message(
                    msg_id=msg_id,
                    sender=actual_sender,
                    recipient=self.username,
                    encrypted_content=enc["ciphertext"],
                    nonce=enc["nonce"],
                    signature=packet.signature,
                    timestamp=packet.timestamp,
                    tampered=tampered
                )

                # Update UI
                if self.selected_user == actual_sender or actual_sender == self.username:
                    self.after(0, lambda: self._add_message_bubble(
                        actual_sender, plaintext, packet.timestamp,
                        is_own=False, tampered=tampered
                    ))
                    self.after(0, lambda: self._update_image_preview(stego_bytes))

            except Exception as e:
                pass

        threading.Thread(target=_process, daemon=True).start()

    def _show_tamper_alert(self):
        """Show a prominent tamper detection alert."""
        alert = tk.Toplevel(self)
        alert.title("⚠ TAMPER DETECTED")
        alert.configure(bg=TAMPER_BG)
        alert.geometry("420x220")
        alert.resizable(False, False)

        tk.Label(
            alert, text="⚠", font=("Courier New", 48),
            bg=TAMPER_BG, fg=WARNING
        ).pack(pady=(20, 5))

        tk.Label(
            alert, text="MESSAGE TAMPERED",
            font=("Courier New", 14, "bold"), bg=TAMPER_BG, fg=ERROR
        ).pack()

        tk.Label(
            alert,
            text="HMAC-SHA256 verification failed.\nThis message was modified in transit.\nThe message has been flagged in the security log.",
            font=FONT_SMALL, bg=TAMPER_BG, fg=TEXT_PRIMARY, justify=tk.CENTER
        ).pack(pady=10)

        tk.Button(
            alert, text="ACKNOWLEDGE", font=FONT_LABEL,
            bg=ERROR, fg="white", relief="flat", cursor="hand2",
            command=alert.destroy, padx=20, pady=6
        ).pack()

    def _update_image_preview(self, image_bytes: bytes):
        """Update the carrier image preview in sidebar."""
        try:
            from PIL import Image, ImageTk #type: ignore
            import io
            img = Image.open(io.BytesIO(image_bytes))
            img.thumbnail((160, 120))
            photo = ImageTk.PhotoImage(img)
            self.img_preview_label.config(image=photo, text="")
            self.img_preview_label.image = photo
        except Exception:
            pass

    def _select_carrier(self):
        """Open file dialog to select carrier image."""
        path = filedialog.askopenfilename(
            title="Select Carrier Image",
            filetypes=[("PNG Images", "*.png"), ("All files", "*.*")]
        )
        if path:
            self._carrier_path = path
            filename = os.path.basename(path)
            self.carrier_path_var.set(f"Using: {filename}")

    def _on_server_event(self, event_type: str, data: dict):
        """Handle server events for logging."""
        severity_map = {
            "RATE_LIMITED": "WARNING",
            "CLIENT_DISCONNECTED": "INFO",
            "CLIENT_CONNECTED": "INFO",
            "ROUTE_ERROR": "WARNING"
        }
        severity = severity_map.get(event_type, "INFO")
        self.storage.log_security_event(event_type, str(data), severity=severity)

    def _on_user_list_update(self, users: list):
        """Handle updated user list from server."""
        self.after(0, self._refresh_user_list)

    def _on_disconnected(self):
        """Handle disconnection."""
        self.after(0, lambda: self.conn_var.set("🔴 Disconnected"))
        self.after(0, lambda: self.conn_label.config(fg=ERROR))

    def _on_frame_configure(self, event):
        """Update scroll region when messages frame changes size."""
        self.msg_canvas.configure(scrollregion=self.msg_canvas.bbox("all"))

    def _on_canvas_configure(self, event):
        """Resize messages frame to canvas width."""
        self.msg_canvas.itemconfig(self.msg_canvas_window, width=event.width)

    def _scroll_to_bottom(self):
        """Scroll message area to bottom."""
        self.after(50, lambda: self.msg_canvas.yview_moveto(1.0))

    def _show_status(self, msg: str, color: str = TEXT_DIM):
        """Update status bar."""
        self.status_var.set(msg)

    def _open_dashboard(self):
        """Open security dashboard window."""
        from gui.dashboard import DashboardWindow
        DashboardWindow(self, self.storage)

    def _logout(self):
        """Logout and return to login screen."""
        if self.client:
            self.client.disconnect()
        if self.server:
            self.server.stop()
        self.auth.logout(self.session_token)
        self.storage.log_security_event(
            "USER_LOGOUT", f"{self.username} logged out",
            username=self.username
        )
        self.on_logout()