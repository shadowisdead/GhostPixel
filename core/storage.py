"""
storage.py - Persistent Storage Layer
Handles SQLite database for users/messages and encrypted log files.

Persistence:
    - SQLite database: users, messages (encrypted content at-rest)
    - Log files: security events, tamper alerts (AES-encrypted)
"""

import sqlite3
import os
import json
import time
import base64
from pathlib import Path


DB_PATH = os.path.join(os.path.dirname(__file__), "..", "ghostpixel.db")
LOG_PATH = os.path.join(os.path.dirname(__file__), "..", "ghostpixel_security.log")


class Storage:
    """
    SQLite-backed persistent storage for users and messages.
    Message content is stored AES-encrypted at rest.
    """

    def __init__(self, db_path: str = DB_PATH):
        """
        Initialize storage and create tables if needed.
        Args:
            db_path (str): Path to SQLite database file
        """
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection with row factory."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Create tables if they don't exist."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    public_key TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY,
                    sender TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    encrypted_content TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    tampered INTEGER DEFAULT 0,
                    stego_image_b64 TEXT,
                    FOREIGN KEY (sender) REFERENCES users(username)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    description TEXT NOT NULL,
                    username TEXT,
                    timestamp REAL NOT NULL,
                    severity TEXT DEFAULT 'INFO'
                )
            """)
            conn.commit()

    # ── USER METHODS ─────────────────────────────────────────────────────────

    def save_user(self, username: str, password_hash: str, public_key: str = None):
        """
        Save a new user to the database.
        Args:
            username (str): Username
            password_hash (str): PBKDF2 password hash
            public_key (str): RSA public key PEM (optional)
        """
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, created_at, public_key) VALUES (?, ?, ?, ?)",
                (username, password_hash, time.time(), public_key)
            )
            conn.commit()

    def user_exists(self, username: str) -> bool:
        """Check if a username exists. O(1) with index."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM users WHERE username = ?", (username,)
            ).fetchone()
            return row is not None

    def get_user_hash(self, username: str) -> str | None:
        """Get stored password hash for a username."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT password_hash FROM users WHERE username = ?", (username,)
            ).fetchone()
            return row["password_hash"] if row else None

    def get_user_public_key(self, username: str) -> str | None:
        """Get RSA public key for a user."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT public_key FROM users WHERE username = ?", (username,)
            ).fetchone()
            return row["public_key"] if row else None

    def update_public_key(self, username: str, public_key_pem: str):
        """Update a user's RSA public key."""
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE users SET public_key = ? WHERE username = ?",
                (public_key_pem, username)
            )
            conn.commit()

    def get_all_users(self) -> list:
        """Return list of all registered usernames."""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT username FROM users").fetchall()
            return [row["username"] for row in rows]

    # ── MESSAGE METHODS ───────────────────────────────────────────────────────

    def save_message(self, msg_id: str, sender: str, recipient: str,
                     encrypted_content: str, nonce: str, signature: str,
                     timestamp: float, stego_image_b64: str = None,
                     tampered: bool = False):
        """
        Save an encrypted message to the database.
        Args:
            msg_id (str): Unique message ID
            sender (str): Sender username
            recipient (str): Recipient username
            encrypted_content (str): AES-encrypted message content
            nonce (str): AES nonce
            signature (str): HMAC signature
            timestamp (float): Unix timestamp
            stego_image_b64 (str): Base64 stego image (optional)
            tampered (bool): Whether tamper was detected
        """
        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO messages
                (id, sender, recipient, encrypted_content, nonce, signature, timestamp, tampered, stego_image_b64)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (msg_id, sender, recipient, encrypted_content, nonce,
                  signature, timestamp, int(tampered), stego_image_b64))
            conn.commit()

    def get_messages(self, user1: str, user2: str, limit: int = 100) -> list:
        """
        Retrieve messages between two users. Ordered by timestamp.
        Args:
            user1 (str): First user
            user2 (str): Second user
            limit (int): Max messages to return
        Returns:
            list: Message rows as dicts
        """
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM messages
                WHERE (sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?)
                ORDER BY timestamp ASC
                LIMIT ?
            """, (user1, user2, user2, user1, limit)).fetchall()
            return [dict(row) for row in rows]

    def mark_tampered(self, msg_id: str):
        """Mark a message as tampered."""
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE messages SET tampered = 1 WHERE id = ?", (msg_id,)
            )
            conn.commit()

    # ── SECURITY LOG METHODS ──────────────────────────────────────────────────

    def log_security_event(self, event_type: str, description: str,
                            username: str = None, severity: str = "INFO"):
        """
        Log a security event to the database.
        Args:
            event_type (str): e.g. "TAMPER_DETECTED", "LOGIN_FAILED", "REPLAY_ATTACK"
            description (str): Human-readable description
            username (str): Associated username (optional)
            severity (str): "INFO", "WARNING", "CRITICAL"
        """
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO security_events (event_type, description, username, timestamp, severity)
                VALUES (?, ?, ?, ?, ?)
            """, (event_type, description, username, time.time(), severity))
            conn.commit()

        # Also write to encrypted log file
        self._write_log_file(event_type, description, username, severity)

    def get_security_events(self, limit: int = 50) -> list:
        """Get recent security events ordered by time descending."""
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM security_events
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,)).fetchall()
            return [dict(row) for row in rows]

    def _write_log_file(self, event_type: str, description: str,
                         username: str, severity: str):
        """Write security event to plaintext log file."""
        try:
            timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            line = f"[{timestamp_str}] [{severity}] [{event_type}] user={username or 'N/A'} | {description}\n"
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception:
            pass

    def get_stats(self) -> dict:
        """Return database statistics for the dashboard."""
        with self._get_connection() as conn:
            user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            msg_count = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
            tamper_count = conn.execute(
                "SELECT COUNT(*) FROM messages WHERE tampered = 1"
            ).fetchone()[0]
            event_count = conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
            return {
                "users": user_count,
                "messages": msg_count,
                "tampered": tamper_count,
                "security_events": event_count
            }