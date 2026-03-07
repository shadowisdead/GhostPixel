"""
tamper.py - HMAC-SHA256 Tamper Detection
Every message is signed with HMAC-SHA256 before embedding.
On receipt, signature is verified — any pixel/byte change = TAMPERED alert.

Algorithm: HMAC-SHA256
    HMAC(key, message) = SHA256((key XOR opad) || SHA256((key XOR ipad) || message))
    - Provides both integrity and authenticity
    - Even a 1-bit change in the stego image breaks the signature
"""

import hmac
import hashlib
import os
import base64
import time
import json
import secrets


class TamperDetector:
    """
    Signs and verifies message integrity using HMAC-SHA256.
    Used to detect any modification of messages in transit.
    """

    ALGORITHM = "sha256"

    def __init__(self, secret_key: bytes = None):
        """
        Initialize with a shared HMAC secret key.
        Args:
            secret_key (bytes): Shared secret for HMAC. Generated if not provided.
        """
        self.secret_key = secret_key if secret_key is not None else os.urandom(32)

    def sign(self, data: bytes) -> str:
        """
        Generate HMAC-SHA256 signature for data. O(n)
        Args:
            data (bytes): Data to sign
        Returns:
            str: Hex-encoded HMAC signature
        """
        mac = hmac.new(self.secret_key, data, self.ALGORITHM)
        return mac.hexdigest()

    def verify(self, data: bytes, signature: str) -> bool:
        """
        Verify HMAC signature using constant-time comparison. O(n)
        Uses hmac.compare_digest to prevent timing attacks.
        Args:
            data (bytes): Data to verify
            signature (str): Expected hex HMAC signature
        Returns:
            bool: True if valid, False if tampered
        """
        expected = self.sign(data)
        return hmac.compare_digest(expected, signature)

    def get_key_b64(self) -> str:
        """Return HMAC key as base64 string."""
        return base64.b64encode(self.secret_key).decode("utf-8")

    @staticmethod
    def from_key_b64(key_b64: str) -> "TamperDetector":
        """
        Create TamperDetector from base64 key string.
        Args:
            key_b64 (str): Base64-encoded key
        Returns:
            TamperDetector instance
        """
        key = base64.b64decode(key_b64)
        return TamperDetector(secret_key=key)


class NonceManager:
    """
    Nonce + timestamp management to prevent replay attacks.
    Each message gets a unique nonce. Reused nonces are rejected.
    Nonces expire after a time window to bound memory usage.
    """

    NONCE_EXPIRY_SECONDS = 300    # 5 minutes
    MAX_NONCE_STORE = 10_000       # Prevent memory exhaustion

    def __init__(self):
        """Initialize nonce store (custom hash table-backed)."""
        from dsa.hash_table import HashTable
        self._seen_nonces = HashTable(capacity=128)
        self._nonce_timestamps = HashTable(capacity=128)

    def generate_nonce(self) -> str:
        """
        Generate a cryptographically secure random nonce. O(1)
        Returns:
            str: 32-char hex nonce
        """
        return secrets.token_hex(16)

    def create_message_envelope(self, payload: dict) -> dict:
        """
        Wrap a message payload with nonce and timestamp. O(1)
        Args:
            payload (dict): Message data
        Returns:
            dict: Envelope with nonce, timestamp, payload
        """
        return {
            "nonce": self.generate_nonce(),
            "timestamp": time.time(),
            "payload": payload
        }

    def validate_envelope(self, envelope: dict) -> tuple:
        """
        Validate a received message envelope against replay attacks. O(1)
        Args:
            envelope (dict): Received envelope
        Returns:
            tuple: (is_valid: bool, reason: str)
        """
        nonce = envelope.get("nonce")
        timestamp = envelope.get("timestamp")

        if not nonce or not timestamp:
            return False, "Missing nonce or timestamp"

        # Check timestamp freshness (within 5 minutes)
        age = time.time() - timestamp
        if age > self.NONCE_EXPIRY_SECONDS:
            return False, f"Message expired ({age:.0f}s old, max {self.NONCE_EXPIRY_SECONDS}s)"

        if age < -30:  # Allow 30s clock skew
            return False, "Message timestamp is in the future (possible replay)"

        # Check nonce uniqueness
        if self._seen_nonces.contains(nonce):
            return False, "Duplicate nonce detected — REPLAY ATTACK blocked"

        # DoS protection: cap nonce store size
        if self._seen_nonces.size() >= self.MAX_NONCE_STORE:
            self._evict_expired_nonces()

        # Record nonce
        self._seen_nonces.insert(nonce, True)
        self._nonce_timestamps.insert(nonce, timestamp)

        return True, "Valid"

    def _evict_expired_nonces(self):
        """Remove expired nonces to free memory. O(n)"""
        current_time = time.time()
        for key in self._nonce_timestamps.keys():
            ts = self._nonce_timestamps.get(key)
            if ts and (current_time - ts) > self.NONCE_EXPIRY_SECONDS:
                self._seen_nonces.delete(key)
                self._nonce_timestamps.delete(key)


class MessagePacket:
    """
    Complete signed message packet combining:
    - AES-encrypted payload
    - HMAC signature
    - Nonce + timestamp envelope
    - Serialization to/from JSON
    """

    def __init__(self, sender: str, encrypted_payload: dict, signature: str,
                 nonce: str, timestamp: float):
        """
        Initialize a message packet.
        Args:
            sender (str): Sender username
            encrypted_payload (dict): {nonce, ciphertext} from AES
            signature (str): HMAC signature
            nonce (str): Replay-prevention nonce
            timestamp (float): Unix timestamp
        """
        self.sender = sender
        self.encrypted_payload = encrypted_payload
        self.signature = signature
        self.nonce = nonce
        self.timestamp = timestamp

    def to_json(self) -> str:
        """Serialize packet to JSON string."""
        return json.dumps({
            "sender": self.sender,
            "encrypted_payload": self.encrypted_payload,
            "signature": self.signature,
            "nonce": self.nonce,
            "timestamp": self.timestamp
        })

    def to_bytes(self) -> bytes:
        """Serialize packet to bytes for embedding in stego image."""
        return self.to_json().encode("utf-8")

    @staticmethod
    def from_bytes(data: bytes) -> "MessagePacket":
        """
        Deserialize packet from bytes.
        Args:
            data (bytes): JSON bytes
        Returns:
            MessagePacket instance
        Raises:
            ValueError: If data is malformed
        """
        try:
            d = json.loads(data.decode("utf-8"))
            return MessagePacket(
                sender=d["sender"],
                encrypted_payload=d["encrypted_payload"],
                signature=d["signature"],
                nonce=d["nonce"],
                timestamp=d["timestamp"]
            )
        except Exception as e:
            raise ValueError(f"Malformed message packet: {e}")