"""
test_all.py - Comprehensive unit tests for GhostPixel.

Run with:
    python tests/test_all.py
or:
    python -m pytest tests/ -v
"""

import os
import base64
import time
import unittest
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]

# Ensure project root (containing core/, dsa/, gui/) is importable
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


class TestLinkedList(unittest.TestCase):
    """Tests for MessageLinkedList data structure."""

    def setUp(self) -> None:
        from dsa.linked_list import MessageLinkedList
        self.lst = MessageLinkedList()

    def test_linked_list_append_size(self) -> None:
        from dsa.linked_list import MessageLinkedList
        self.assertEqual(self.lst.size(), 0)
        self.lst.append({"id": "1"})
        self.lst.append({"id": "2"})
        self.assertEqual(self.lst.size(), 2)

    def test_linked_list_prepend_order(self) -> None:
        self.lst.prepend({"id": "1"})
        self.lst.prepend({"id": "2"})
        ids = [m["id"] for m in self.lst]
        self.assertEqual(ids, ["2", "1"])

    def test_linked_list_search_found(self) -> None:
        self.lst.append({"id": "a"})
        self.lst.append({"id": "b"})
        node = self.lst.search("b")
        self.assertIsNotNone(node)
        self.assertEqual(node.data["id"], "b")

    def test_linked_list_search_not_found(self) -> None:
        self.lst.append({"id": "a"})
        node = self.lst.search("x")
        self.assertIsNone(node)

    def test_linked_list_delete(self) -> None:
        self.lst.append({"id": "1"})
        self.lst.append({"id": "2"})
        self.assertTrue(self.lst.delete("1"))
        self.assertFalse(self.lst.delete("missing"))
        ids = [m["id"] for m in self.lst]
        self.assertEqual(ids, ["2"])

    def test_linked_list_iteration(self) -> None:
        data = [{"id": str(i)} for i in range(3)]
        for d in data:
            self.lst.append(d)
        collected = [m["id"] for m in self.lst]
        self.assertEqual(collected, ["0", "1", "2"])


class TestHashTable(unittest.TestCase):
    """Tests for HashTable implementation."""

    def setUp(self) -> None:
        from dsa.hash_table import HashTable
        self.table = HashTable()

    def test_hash_table_insert_overwrite(self) -> None:
        self.table.insert("key", "a")
        self.table.insert("key", "b")
        self.assertEqual(self.table.get("key"), "b")

    def test_hash_table_delete(self) -> None:
        self.table.insert("k", "v")
        self.assertTrue(self.table.delete("k"))
        self.assertFalse(self.table.delete("k"))
        self.assertIsNone(self.table.get("k"))

    def test_hash_table_resize_on_load(self) -> None:
        # Force resize by inserting many keys
        for i in range(20):
            self.table.insert(f"k{i}", i)
        # All inserted keys should be retrievable
        for i in range(20):
            self.assertEqual(self.table.get(f"k{i}"), i)


class TestQueueAndRateLimiter(unittest.TestCase):
    """Tests for MessageQueue and RateLimiterBucket."""

    def test_queue_fifo_order(self) -> None:
        from dsa.queue import MessageQueue
        q = MessageQueue(max_size=10)
        q.enqueue(1)
        q.enqueue(2)
        q.enqueue(3)
        self.assertEqual(q.dequeue(), 1)
        self.assertEqual(q.dequeue(), 2)
        self.assertEqual(q.dequeue(), 3)
        self.assertIsNone(q.dequeue())

    def test_queue_max_size_protection(self) -> None:
        from dsa.queue import MessageQueue
        q = MessageQueue(max_size=2)
        self.assertTrue(q.enqueue("a"))
        self.assertTrue(q.enqueue("b"))
        self.assertFalse(q.enqueue("c"))
        self.assertEqual(q.size(), 2)

    def test_rate_limiter_allows_within_limit(self) -> None:
        from dsa.queue import RateLimiterBucket
        bucket = RateLimiterBucket(capacity=5, refill_rate=1000.0)
        allowed = [bucket.consume() for _ in range(5)]
        self.assertTrue(all(allowed))

    def test_rate_limiter_blocks_when_exhausted(self) -> None:
        from dsa.queue import RateLimiterBucket
        bucket = RateLimiterBucket(capacity=2, refill_rate=0.0)
        self.assertTrue(bucket.consume())
        self.assertTrue(bucket.consume())
        self.assertFalse(bucket.consume())


class TestCrypto(unittest.TestCase):
    """Tests for AES and RSA cryptographic primitives."""

    def test_aes_encrypt_decrypt_roundtrip(self) -> None:
        from core.crypto import AESCipher
        aes = AESCipher()
        plaintext = "hello secret world"
        enc = aes.encrypt(plaintext)
        dec = aes.decrypt(enc["nonce"], enc["ciphertext"])
        self.assertEqual(dec, plaintext)

    def test_aes_different_nonce_each_time(self) -> None:
        from core.crypto import AESCipher
        aes = AESCipher()
        enc1 = aes.encrypt("msg")
        enc2 = aes.encrypt("msg")
        self.assertNotEqual(enc1["nonce"], enc2["nonce"])

    def test_aes_wrong_key_fails(self) -> None:
        from core.crypto import AESCipher
        aes1 = AESCipher()
        aes2 = AESCipher()
        enc = aes1.encrypt("top secret")
        with self.assertRaises(ValueError):
            _ = aes2.decrypt(enc["nonce"], enc["ciphertext"])

    def test_rsa_encrypt_decrypt_roundtrip(self) -> None:
        from core.crypto import RSACipher
        rsa1 = RSACipher()
        rsa2 = RSACipher()
        secret = b"session-key-123"
        enc = rsa1.encrypt_with_public_key(secret, rsa2.get_public_key_pem())
        dec = rsa2.decrypt_with_private_key(enc)
        self.assertEqual(dec, secret)


class TestSteganography(unittest.TestCase):
    """Tests for SteganographyEngine."""

    def setUp(self) -> None:
        from core.steganography import SteganographyEngine
        self.engine = SteganographyEngine()

    def test_stego_embed_extract_roundtrip(self) -> None:
        message = b"hello stego"
        img_bytes = self.engine.embed(message)
        extracted = self.engine.extract(img_bytes)
        self.assertEqual(extracted, message)

    def test_stego_returns_png(self) -> None:
        message = b"test"
        img_bytes = self.engine.embed(message)
        # PNG files start with the 8-byte PNG signature
        self.assertTrue(img_bytes.startswith(b"\x89PNG\r\n\x1a\n"))

    def test_stego_large_message(self) -> None:
        # 512x512 noise carrier with 6 bits/pixel ≈ 196,608 bytes capacity (minus headers)
        large_message = b"a" * 50_000
        img_bytes = self.engine.embed(large_message)
        extracted = self.engine.extract(img_bytes)
        self.assertEqual(extracted, large_message)

    def test_stego_message_too_large_raises(self) -> None:
        # Build a very large payload that should exceed default carrier capacity
        too_large = b"a" * 300_000
        from core.steganography import SteganographyEngine
        engine = SteganographyEngine()
        with self.assertRaises(ValueError):
            _ = engine.embed(too_large)


class TestTamperDetection(unittest.TestCase):
    """Tests for HMAC tamper detection and NonceManager."""

    def test_hmac_sign_verify_valid(self) -> None:
        from core.tamper import TamperDetector
        det = TamperDetector()
        data = b"important payload"
        sig = det.sign(data)
        self.assertTrue(det.verify(data, sig))

    def test_hmac_tampered_data_fails(self) -> None:
        from core.tamper import TamperDetector
        det = TamperDetector()
        data = b"important payload"
        sig = det.sign(data)
        tampered = b"important payload!"
        self.assertFalse(det.verify(tampered, sig))

    def test_hmac_wrong_key_fails(self) -> None:
        from core.tamper import TamperDetector
        d1 = TamperDetector()
        d2 = TamperDetector()
        data = b"msg"
        sig = d1.sign(data)
        self.assertFalse(d2.verify(data, sig))

    def test_nonce_fresh_valid(self) -> None:
        from core.tamper import NonceManager
        nm = NonceManager()
        env = nm.create_message_envelope({"x": 1})
        is_valid, _ = nm.validate_envelope(env)
        self.assertTrue(is_valid)

    def test_nonce_duplicate_rejected(self) -> None:
        from core.tamper import NonceManager
        nm = NonceManager()
        env = nm.create_message_envelope({"x": 1})
        is_valid, _ = nm.validate_envelope(env)
        self.assertTrue(is_valid)
        # Re-use same nonce and timestamp
        is_valid2, reason2 = nm.validate_envelope(env)
        self.assertFalse(is_valid2)
        self.assertIn("Duplicate nonce", reason2)

    def test_nonce_expired_rejected(self) -> None:
        from core.tamper import NonceManager
        nm = NonceManager()
        env = nm.create_message_envelope({"x": 1})
        # Force timestamp far in the past
        env["timestamp"] = time.time() - (nm.NONCE_EXPIRY_SECONDS + 10)
        is_valid, reason = nm.validate_envelope(env)
        self.assertFalse(is_valid)
        self.assertIn("expired", reason)


class TestAuth(unittest.TestCase):
    """Tests for authentication and password logic."""

    def test_password_hash_verify_correct(self) -> None:
        from core.auth import PasswordHasher
        hasher = PasswordHasher()
        pw = "StrongPass123!"
        stored = hasher.hash_password(pw)
        self.assertTrue(hasher.verify_password(pw, stored))

    def test_password_wrong_fails(self) -> None:
        from core.auth import PasswordHasher
        hasher = PasswordHasher()
        pw = "StrongPass123!"
        stored = hasher.hash_password(pw)
        self.assertFalse(hasher.verify_password("wrong", stored))

    def test_password_different_hashes_same_input(self) -> None:
        from core.auth import PasswordHasher
        hasher = PasswordHasher()
        pw = "StrongPass123!"
        h1 = hasher.hash_password(pw)
        h2 = hasher.hash_password(pw)
        self.assertNotEqual(h1, h2)

    def test_password_strength_weak(self) -> None:
        from core.auth import PasswordHasher
        valid, msg, score = PasswordHasher.validate_password_strength("abc")
        self.assertFalse(valid)
        self.assertLess(score, 3)

    def test_password_strength_strong(self) -> None:
        from core.auth import PasswordHasher
        valid, msg, score = PasswordHasher.validate_password_strength("StrongPass123!")
        self.assertTrue(valid)
        self.assertGreaterEqual(score, 4)

    def test_session_create_validate(self) -> None:
        from core.auth import SessionManager
        sm = SessionManager()
        token = sm.create_session("alice")
        is_valid, username = sm.validate_session(token)
        self.assertTrue(is_valid)
        self.assertEqual(username, "alice")

    def test_session_invalidate(self) -> None:
        from core.auth import SessionManager
        sm = SessionManager()
        token = sm.create_session("bob")
        self.assertTrue(sm.invalidate_session(token))
        is_valid, _ = sm.validate_session(token)
        self.assertFalse(is_valid)

    def test_session_one_per_user(self) -> None:
        from core.auth import SessionManager
        sm = SessionManager()
        t1 = sm.create_session("alice")
        t2 = sm.create_session("alice")
        self.assertNotEqual(t1, t2)
        is_valid1, _ = sm.validate_session(t1)
        is_valid2, _ = sm.validate_session(t2)
        self.assertFalse(is_valid1)
        self.assertTrue(is_valid2)


class TestStorage(unittest.TestCase):
    """Tests for SQLite storage layer."""

    def setUp(self) -> None:
        from core.storage import Storage
        self.temp_db = PROJECT_ROOT / "test_ghostpixel.db"
        if self.temp_db.exists():
            try:
                self.temp_db.unlink()
            except PermissionError:
                # On Windows the SQLite file may still be locked briefly;
                # reuse the existing file for this test run.
                pass
        self.storage = Storage(db_path=str(self.temp_db))
        # Ensure a clean schema for each test even if the file is reused.
        from core.storage import Storage as _S  # type: ignore
        with self.storage._get_connection() as conn:  # type: ignore[attr-defined]
            conn.execute("DELETE FROM messages")
            conn.execute("DELETE FROM security_events")
            conn.execute("DELETE FROM users")
            conn.commit()

    def tearDown(self) -> None:
        if self.temp_db.exists():
            try:
                self.temp_db.unlink()
            except PermissionError:
                # Best-effort cleanup; ignore if locked.
                pass

    def test_storage_save_retrieve_user(self) -> None:
        username = "alice"
        pw_hash = "hash"
        self.storage.save_user(username, pw_hash)
        self.assertTrue(self.storage.user_exists(username))
        self.assertEqual(self.storage.get_user_hash(username), pw_hash)

    def test_storage_user_exists(self) -> None:
        self.assertFalse(self.storage.user_exists("bob"))
        self.storage.save_user("bob", "h")
        self.assertTrue(self.storage.user_exists("bob"))

    def test_storage_save_get_message(self) -> None:
        self.storage.save_user("alice", "h")
        self.storage.save_user("bob", "h")
        self.storage.save_message(
            msg_id="1",
            sender="alice",
            recipient="bob",
            encrypted_content="enc",
            nonce="n",
            signature="s",
            timestamp=time.time(),
        )
        msgs = self.storage.get_messages("alice", "bob")
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0]["sender"], "alice")

    def test_storage_mark_tampered(self) -> None:
        self.storage.save_user("alice", "h")
        self.storage.save_user("bob", "h")
        self.storage.save_message(
            msg_id="2",
            sender="alice",
            recipient="bob",
            encrypted_content="enc",
            nonce="n",
            signature="s",
            timestamp=time.time(),
        )
        self.storage.mark_tampered("2")
        msgs = self.storage.get_messages("alice", "bob")
        self.assertEqual(msgs[0]["tampered"], 1)

    def test_storage_log_security_event(self) -> None:
        self.storage.log_security_event("TEST_EVENT", "desc", username="alice", severity="INFO")
        events = self.storage.get_security_events(limit=10)
        self.assertGreaterEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "TEST_EVENT")

    def test_storage_get_stats(self) -> None:
        self.storage.save_user("alice", "h")
        self.storage.save_message(
            msg_id="3",
            sender="alice",
            recipient="alice",
            encrypted_content="enc",
            nonce="n",
            signature="s",
            timestamp=time.time(),
            stego_image_b64=None,
            tampered=False,
        )
        self.storage.log_security_event("EVT", "d")
        stats = self.storage.get_stats()
        self.assertGreaterEqual(stats["users"], 1)
        self.assertGreaterEqual(stats["messages"], 1)
        self.assertIn("tampered", stats)
        self.assertGreaterEqual(stats["security_events"], 1)


class TestIntegration(unittest.TestCase):
    """High-level integration tests for the full pipeline."""

    def setUp(self) -> None:
        # Use the same shared AES key logic as the chat screen.
        from core.crypto import AESCipher, KeyDerivation
        from core.steganography import SteganographyEngine
        from core.tamper import TamperDetector, NonceManager, MessagePacket

        self.AESCipher = AESCipher
        self.KeyDerivation = KeyDerivation
        self.SteganographyEngine = SteganographyEngine
        self.TamperDetector = TamperDetector
        self.NonceManager = NonceManager
        self.MessagePacket = MessagePacket

        shared_secret = "GhostPixel-SharedSecret-2024"
        shared_salt = b"ghostpixel_salt_"
        shared_key, _ = KeyDerivation.derive_key(shared_secret, shared_salt)
        self.aes_sender = AESCipher(key=shared_key)
        self.aes_receiver = AESCipher(key=shared_key)
        self.stego = SteganographyEngine()
        self.tamper = TamperDetector()
        self.nonce_manager = NonceManager()

    def _build_packet_and_image(self, plaintext: str, sender: str = "alice") -> bytes:
        """Helper to perform encrypt → packet → sign → embed and return image bytes."""
        enc = self.aes_sender.encrypt(plaintext)
        packet = self.MessagePacket(
            sender=sender,
            encrypted_payload=enc,
            signature="",
            nonce=self.nonce_manager.generate_nonce(),
            timestamp=time.time(),
        )
        # HMAC on unsigned bytes
        packet.signature = ""
        unsigned = packet.to_bytes()
        sig = self.tamper.sign(unsigned)
        packet.signature = sig
        final_bytes = packet.to_bytes()
        return self.stego.embed(final_bytes)

    def _extract_and_decrypt(self, image_bytes: bytes) -> tuple[str, bool, str]:
        """Helper to extract packet, verify, check nonce, and decrypt."""
        extracted = self.stego.extract(image_bytes)
        packet = self.MessagePacket.from_bytes(extracted)
        saved_sig = packet.signature
        packet.signature = ""
        unsigned = packet.to_bytes()
        packet.signature = saved_sig
        valid = self.tamper.verify(unsigned, saved_sig)
        env = {"nonce": packet.nonce, "timestamp": packet.timestamp}
        nonce_valid, reason = self.nonce_manager.validate_envelope(env)
        if not nonce_valid:
            return "", False, reason
        enc = packet.encrypted_payload
        plaintext = self.aes_receiver.decrypt(enc["nonce"], enc["ciphertext"])
        return plaintext, valid, ""

    def test_full_pipeline_encrypt_embed_extract_decrypt(self) -> None:
        plaintext = "hello pipeline"
        img_bytes = self._build_packet_and_image(plaintext)
        dec, valid, reason = self._extract_and_decrypt(img_bytes)
        self.assertEqual(dec, plaintext)
        self.assertTrue(valid, msg=reason)

    def test_tamper_detection_breaks_on_modification(self) -> None:
        plaintext = "tamper me"
        img_bytes = self._build_packet_and_image(plaintext)
        tampered_bytes = bytearray(img_bytes)
        tampered_bytes[len(tampered_bytes) // 2] ^= 0xFF
        # Stego extraction or subsequent parsing must fail for tampered data.
        with self.assertRaises((ValueError, OSError)):
            _ = self.stego.extract(bytes(tampered_bytes))

    def test_replay_attack_blocked(self) -> None:
        plaintext = "one-time message"
        img_bytes = self._build_packet_and_image(plaintext)
        extracted = self.stego.extract(img_bytes)
        packet = self.MessagePacket.from_bytes(extracted)

        # First validation should pass
        env = {"nonce": packet.nonce, "timestamp": packet.timestamp}
        valid1, _ = self.nonce_manager.validate_envelope(env)
        self.assertTrue(valid1)

        # Second validation with same nonce should be rejected
        valid2, reason2 = self.nonce_manager.validate_envelope(env)
        self.assertFalse(valid2)
        self.assertIn("Duplicate nonce", reason2)

    def test_auth_register_login_flow(self) -> None:
        from core.storage import Storage
        from core.auth import AuthManager

        temp_db = PROJECT_ROOT / "test_auth_flow.db"
        if temp_db.exists():
            temp_db.unlink()

        try:
            storage = Storage(db_path=str(temp_db))
            auth = AuthManager(storage=storage)

            ok, msg = auth.register("alice", "StrongPass123!")
            self.assertTrue(ok, msg=msg)

            success, token_or_msg = auth.login("alice", "StrongPass123!")
            self.assertTrue(success, msg=token_or_msg)
            token = token_or_msg

            is_valid, username = auth.sessions.validate_session(token)
            self.assertTrue(is_valid)
            self.assertEqual(username, "alice")
        finally:
            if temp_db.exists():
                try:
                    temp_db.unlink()
                except PermissionError:
                    # Ignore if SQLite still has the file open on Windows.
                    pass


if __name__ == "__main__":
    unittest.main(verbosity=2)

