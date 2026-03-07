"""
crypto.py - AES-256-GCM Encryption + RSA-2048 Key Exchange
Provides end-to-end encryption for GhostPixel.

Algorithms:
    - AES-256-GCM: Authenticated encryption for message content
    - RSA-2048: Asymmetric key exchange (encrypt AES session key)
    - PBKDF2-HMAC-SHA256: Key derivation from passwords
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
from cryptography.hazmat.primitives.asymmetric import rsa, padding #type: ignore
from cryptography.hazmat.primitives import hashes, serialization #type: ignore
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC #type: ignore


class AESCipher:
    """
    AES-256-GCM authenticated encryption/decryption.
    GCM mode provides both confidentiality and integrity (built-in authentication tag).
    """

    KEY_SIZE = 32      # 256 bits
    NONCE_SIZE = 12    # 96 bits (recommended for GCM)

    def __init__(self, key: bytes = None):
        """
        Initialize AES cipher with a 256-bit key.
        Args:
            key (bytes): 32-byte AES key. If None, a new key is generated.
        """
        if key is not None and len(key) != self.KEY_SIZE:
            raise ValueError(f"AES key must be {self.KEY_SIZE} bytes, got {len(key)}")
        self.key = key if key is not None else self.generate_key()

    @staticmethod
    def generate_key() -> bytes:
        """
        Generate a cryptographically secure 256-bit AES key. O(1)
        Returns:
            bytes: 32 random bytes
        """
        return os.urandom(AESCipher.KEY_SIZE)

    def encrypt(self, plaintext: str) -> dict:
        """
        Encrypt a plaintext string using AES-256-GCM. O(n)
        Args:
            plaintext (str): Message to encrypt
        Returns:
            dict: {nonce: bytes, ciphertext: bytes} (base64 encoded strings)
        """
        nonce = os.urandom(self.NONCE_SIZE)
        aesgcm = AESGCM(self.key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return {
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8")
        }

    def decrypt(self, nonce_b64: str, ciphertext_b64: str) -> str:
        """
        Decrypt an AES-256-GCM ciphertext. O(n)
        Args:
            nonce_b64 (str): Base64-encoded nonce
            ciphertext_b64 (str): Base64-encoded ciphertext
        Returns:
            str: Decrypted plaintext
        Raises:
            ValueError: If decryption or authentication fails (tampered data)
        """
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        aesgcm = AESGCM(self.key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode("utf-8")
        except Exception:
            raise ValueError("Decryption failed — message may be tampered or key mismatch.")

    def get_key_b64(self) -> str:
        """Return the AES key as a base64 string for transmission."""
        return base64.b64encode(self.key).decode("utf-8")

    @staticmethod
    def from_key_b64(key_b64: str) -> "AESCipher":
        """
        Construct AESCipher from a base64-encoded key string.
        Args:
            key_b64 (str): Base64-encoded 32-byte key
        Returns:
            AESCipher instance
        """
        key = base64.b64decode(key_b64)
        return AESCipher(key=key)


class RSACipher:
    """
    RSA-2048 asymmetric encryption for AES session key exchange.
    The sender encrypts the AES key with the recipient's RSA public key.
    Only the recipient's private key can decrypt it.
    """

    KEY_SIZE = 2048

    def __init__(self):
        """Generate a new RSA-2048 key pair."""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.KEY_SIZE
        )
        self.public_key = self.private_key.public_key()

    def get_public_key_pem(self) -> str:
        """
        Export public key as PEM string for sharing. O(1)
        Returns:
            str: PEM-encoded public key
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

    def encrypt_with_public_key(self, data: bytes, public_key_pem: str) -> str:
        """
        Encrypt data (AES key) using a recipient's RSA public key. O(1)
        Args:
            data (bytes): Data to encrypt (e.g., AES session key)
            public_key_pem (str): Recipient's PEM public key
        Returns:
            str: Base64-encoded RSA ciphertext
        """
        pub_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        encrypted = pub_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode("utf-8")

    def decrypt_with_private_key(self, encrypted_b64: str) -> bytes:
        """
        Decrypt RSA ciphertext using own private key. O(1)
        Args:
            encrypted_b64 (str): Base64-encoded RSA ciphertext
        Returns:
            bytes: Decrypted plaintext (e.g., AES session key)
        """
        encrypted = base64.b64decode(encrypted_b64)
        decrypted = self.private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted


class KeyDerivation:
    """
    PBKDF2-HMAC-SHA256 password-based key derivation.
    Used to derive AES keys from user passwords for storage encryption.
    """

    ITERATIONS = 260_000   # OWASP recommended minimum 2023
    SALT_SIZE = 32
    KEY_LENGTH = 32

    @staticmethod
    def derive_key(password: str, salt: bytes = None) -> tuple:
        """
        Derive a 256-bit key from a password using PBKDF2. O(iterations)
        Args:
            password (str): User password
            salt (bytes): Optional salt (generated if not provided)
        Returns:
            tuple: (key_bytes, salt_bytes)
        """
        if salt is None:
            salt = os.urandom(KeyDerivation.SALT_SIZE)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KeyDerivation.KEY_LENGTH,
            salt=salt,
            iterations=KeyDerivation.ITERATIONS
        )
        key = kdf.derive(password.encode("utf-8"))
        return key, salt

    @staticmethod
    def verify_key(password: str, salt: bytes, expected_key: bytes) -> bool:
        """
        Verify a password produces the expected derived key. O(iterations)
        Args:
            password (str): Password to verify
            salt (bytes): Original salt
            expected_key (bytes): Expected derived key
        Returns:
            bool: True if password matches
        """
        derived, _ = KeyDerivation.derive_key(password, salt)
        return derived == expected_key