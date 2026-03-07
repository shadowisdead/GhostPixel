"""
auth.py - User Authentication System
Handles user registration, login, and session token management.

Security:
    - PBKDF2-HMAC-SHA256 password hashing (260,000 iterations)
    - Cryptographically random session tokens
    - Session expiry enforcement
"""

import os
import hashlib
import hmac
import secrets
import time
import base64
import json


class PasswordHasher:
    """
    Secure password hashing using PBKDF2-HMAC-SHA256.
    Stores: base64(salt) + ":" + base64(hash)
    """

    ITERATIONS = 260_000
    SALT_SIZE = 32
    HASH_SIZE = 32
    ALGORITHM = "sha256"

    def hash_password(self, password: str) -> str:
        """
        Hash a password with a random salt. O(iterations)
        Args:
            password (str): Raw password
        Returns:
            str: "salt_b64:hash_b64" stored string
        """
        salt = os.urandom(self.SALT_SIZE)
        pw_hash = hashlib.pbkdf2_hmac(
            self.ALGORITHM,
            password.encode("utf-8"),
            salt,
            self.ITERATIONS,
            dklen=self.HASH_SIZE
        )
        salt_b64 = base64.b64encode(salt).decode("utf-8")
        hash_b64 = base64.b64encode(pw_hash).decode("utf-8")
        return f"{salt_b64}:{hash_b64}"

    def verify_password(self, password: str, stored_hash: str) -> bool:
        """
        Verify password against stored hash using constant-time compare. O(iterations)
        Args:
            password (str): Password to check
            stored_hash (str): Stored "salt_b64:hash_b64"
        Returns:
            bool: True if password matches
        """
        try:
            salt_b64, hash_b64 = stored_hash.split(":")
            salt = base64.b64decode(salt_b64)
            expected = base64.b64decode(hash_b64)
            computed = hashlib.pbkdf2_hmac(
                self.ALGORITHM,
                password.encode("utf-8"),
                salt,
                self.ITERATIONS,
                dklen=self.HASH_SIZE
            )
            return hmac.compare_digest(computed, expected)
        except Exception:
            return False

    @staticmethod
    def validate_password_strength(password: str) -> tuple:
        """
        Check password meets minimum security requirements.
        Args:
            password (str): Password to validate
        Returns:
            tuple: (is_valid: bool, message: str, score: int 0-5)
        """
        score = 0
        issues = []

        if len(password) >= 8:
            score += 1
        else:
            issues.append("At least 8 characters required")

        if any(c.isupper() for c in password):
            score += 1
        else:
            issues.append("Add an uppercase letter")

        if any(c.islower() for c in password):
            score += 1
        else:
            issues.append("Add a lowercase letter")

        if any(c.isdigit() for c in password):
            score += 1
        else:
            issues.append("Add a number")

        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 1
        else:
            issues.append("Add a special character")

        is_valid = score >= 3
        message = "Strong password" if score == 5 else (
            "Acceptable" if is_valid else "; ".join(issues)
        )
        return is_valid, message, score


class SessionManager:
    """
    Manages user session tokens with expiry.
    Uses custom HashTable internally.
    """

    SESSION_EXPIRY = 3600  # 1 hour in seconds
    TOKEN_LENGTH = 32       # 32 bytes = 64 hex chars

    def __init__(self):
        """Initialize session store using custom HashTable."""
        from dsa.hash_table import HashTable
        self._sessions = HashTable(capacity=64)   # token -> session_data
        self._user_tokens = HashTable(capacity=64) # username -> token

    def create_session(self, username: str) -> str:
        """
        Create a new session token for a user. O(1)
        Args:
            username (str): Authenticated username
        Returns:
            str: Session token (hex string)
        """
        # Invalidate existing session
        existing_token = self._user_tokens.get(username)
        if existing_token:
            self._sessions.delete(existing_token)

        token = secrets.token_hex(self.TOKEN_LENGTH)
        session_data = {
            "username": username,
            "created_at": time.time(),
            "expires_at": time.time() + self.SESSION_EXPIRY
        }
        self._sessions.insert(token, session_data)
        self._user_tokens.insert(username, token)
        return token

    def validate_session(self, token: str) -> tuple:
        """
        Validate a session token. O(1)
        Args:
            token (str): Session token to check
        Returns:
            tuple: (is_valid: bool, username: str or None)
        """
        session = self._sessions.get(token)
        if not session:
            return False, None
        if time.time() > session["expires_at"]:
            self.invalidate_session(token)
            return False, None
        return True, session["username"]

    def invalidate_session(self, token: str) -> bool:
        """
        Logout — remove session. O(1)
        Args:
            token (str): Token to invalidate
        Returns:
            bool: True if removed
        """
        session = self._sessions.get(token)
        if session:
            self._user_tokens.delete(session["username"])
            self._sessions.delete(token)
            return True
        return False

    def get_username(self, token: str) -> str | None:
        """Get username for a valid token. O(1)"""
        is_valid, username = self.validate_session(token)
        return username if is_valid else None

    def active_sessions(self) -> list:
        """Return list of all active (non-expired) sessions. O(n)"""
        active = []
        for token in self._sessions.keys():
            is_valid, username = self.validate_session(token)
            if is_valid:
                active.append({"token": token[:8] + "...", "username": username})
        return active


class AuthManager:
    """
    Main authentication manager combining password hashing and sessions.
    Integrates with storage layer for persistence.
    """

    def __init__(self, storage=None):
        """
        Initialize auth manager.
        Args:
            storage: Storage instance (injected dependency)
        """
        self.hasher = PasswordHasher()
        self.sessions = SessionManager()
        self.storage = storage

    def register(self, username: str, password: str) -> tuple:
        """
        Register a new user.
        Args:
            username (str): Desired username
            password (str): Raw password
        Returns:
            tuple: (success: bool, message: str)
        """
        if not username or len(username) < 3:
            return False, "Username must be at least 3 characters"

        if not username.isalnum():
            return False, "Username must be alphanumeric only"

        is_strong, msg, score = self.hasher.validate_password_strength(password)
        if not is_strong:
            return False, f"Weak password: {msg}"

        if self.storage and self.storage.user_exists(username):
            return False, "Username already taken"

        pw_hash = self.hasher.hash_password(password)

        if self.storage:
            self.storage.save_user(username, pw_hash)

        return True, "Registration successful"

    def login(self, username: str, password: str) -> tuple:
        """
        Authenticate a user and create a session.
        Args:
            username (str): Username
            password (str): Raw password
        Returns:
            tuple: (success: bool, token_or_message: str)
        """
        if not self.storage:
            return False, "Storage not initialized"

        stored_hash = self.storage.get_user_hash(username)
        if not stored_hash:
            return False, "Invalid username or password"

        if not self.hasher.verify_password(password, stored_hash):
            return False, "Invalid username or password"

        token = self.sessions.create_session(username)
        return True, token

    def logout(self, token: str) -> bool:
        """Logout user by invalidating their session."""
        return self.sessions.invalidate_session(token)