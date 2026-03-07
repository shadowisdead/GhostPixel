"""
network.py - TCP Server and Client for GhostPixel
Handles socket communication, multi-threading, and DoS rate limiting.

Architecture:
    - Server: Multi-threaded, one thread per connected client
    - Client: Connects to server, sends/receives stego images
    - Messages transmitted as length-prefixed binary frames
"""

import socket
import threading
import struct
import json
import time
import os
from dsa.queue import MessageQueue, RateLimiterBucket
from dsa.hash_table import HashTable


class NetworkFrame:
    """
    Binary message frame format for TCP transmission.
    Frame: [4-byte length][1-byte type][payload bytes]
    """

    # Frame types
    TYPE_HANDSHAKE = 0x01
    TYPE_MESSAGE = 0x02
    TYPE_ACK = 0x03
    TYPE_ERROR = 0x04
    TYPE_PING = 0x05
    TYPE_USER_LIST = 0x06

    @staticmethod
    def pack(frame_type: int, payload: bytes) -> bytes:
        """
        Pack a frame for transmission.
        Args:
            frame_type (int): One of TYPE_* constants
            payload (bytes): Data to send
        Returns:
            bytes: Framed data
        """
        length = len(payload) + 1  # +1 for type byte
        return struct.pack(">I", length) + bytes([frame_type]) + payload

    @staticmethod
    def unpack(data: bytes) -> tuple:
        """
        Unpack a received frame.
        Args:
            data (bytes): Raw received bytes (must include header)
        Returns:
            tuple: (frame_type: int, payload: bytes)
        """
        frame_type = data[0]
        payload = data[1:]
        return frame_type, payload

    @staticmethod
    def recv_frame(sock: socket.socket) -> tuple:
        """
        Receive a complete frame from a socket (handles partial reads). O(n)
        Args:
            sock (socket.socket): Connected socket
        Returns:
            tuple: (frame_type: int, payload: bytes) or (None, None) on error
        """
        try:
            # Read 4-byte length header
            raw_len = NetworkFrame._recv_exact(sock, 4)
            if not raw_len:
                return None, None
            length = struct.unpack(">I", raw_len)[0]

            if length > 10 * 1024 * 1024:  # 10MB max frame size (DoS protection
                return None, None

            data = NetworkFrame._recv_exact(sock, length)
            if not data:
                return None, None

            return NetworkFrame.unpack(data)
        except Exception:
            return None, None

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
        """Receive exactly n bytes from socket."""
        buf = b""
        while len(buf) < n:
            try:
                chunk = sock.recv(n - len(buf))
                if not chunk:
                    return None
                buf += chunk
            except Exception:
                return None
        return buf


class ChatServer:
    """
    Multi-threaded TCP chat server.
    Handles multiple clients, authentication, and message routing.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 9999):
        """
        Initialize server.
        Args:
            host (str): Bind address
            port (int): Bind port
        """
        self.host = host
        self.port = port
        self._clients = HashTable(capacity=32)      # username -> socket
        self._rate_limiters = HashTable(capacity=32) # username -> RateLimiterBucket
        self._running = False
        self._server_sock = None
        self._lock = threading.Lock()
        self.on_event = None   # Callback: fn(event_type, data)

    def start(self, on_event=None):
        """
        Start the server in a background thread.
        Args:
            on_event: Callback function for server events
        """
        self.on_event = on_event
        self._running = True
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(10)
        thread = threading.Thread(target=self._accept_loop, daemon=True)
        thread.start()
        self._emit("SERVER_STARTED", {"host": self.host, "port": self.port})

    def stop(self):
        """Stop the server and close all connections."""
        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass

    def _accept_loop(self):
        """Accept incoming connections in a loop."""
        while self._running:
            try:
                client_sock, addr = self._server_sock.accept()
                thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, addr),
                    daemon=True
                )
                thread.start()
            except Exception:
                if self._running:
                    pass

    def _handle_client(self, sock: socket.socket, addr: tuple):
        """Handle a single client connection in its own thread."""
        username = None
        try:
            # Expect handshake first
            frame_type, payload = NetworkFrame.recv_frame(sock)
            if frame_type != NetworkFrame.TYPE_HANDSHAKE:
                sock.close()
                return

            handshake = json.loads(payload.decode("utf-8"))
            username = handshake.get("username")
            public_key = handshake.get("public_key", "")

            if not username:
                sock.close()
                return

            with self._lock:
                self._clients.insert(username, sock)
                self._rate_limiters.insert(username, RateLimiterBucket(capacity=10, refill_rate=2))

            # Send ACK with online users
            users = self._clients.keys()
            ack = json.dumps({"status": "ok", "users": users}).encode("utf-8")
            sock.sendall(NetworkFrame.pack(NetworkFrame.TYPE_ACK, ack))

            self._emit("CLIENT_CONNECTED", {"username": username, "addr": str(addr)})
            self._broadcast_user_list()

            # Message loop
            while self._running:
                frame_type, payload = NetworkFrame.recv_frame(sock)
                if frame_type is None:
                    break

                if frame_type == NetworkFrame.TYPE_PING:
                    sock.sendall(NetworkFrame.pack(NetworkFrame.TYPE_ACK, b"pong"))
                    continue

                if frame_type == NetworkFrame.TYPE_MESSAGE:
                    self._route_message(username, payload)

        except Exception as e:
            pass
        finally:
            if username:
                with self._lock:
                    self._clients.delete(username)
                    self._rate_limiters.delete(username)
                self._emit("CLIENT_DISCONNECTED", {"username": username})
                self._broadcast_user_list()
            try:
                sock.close()
            except Exception:
                pass

    def _route_message(self, sender: str, payload: bytes):
        """Route a message from sender to recipient."""
        try:
            # Rate limiting
            limiter = self._rate_limiters.get(sender)
            if limiter and not limiter.consume():
                self._emit("RATE_LIMITED", {"username": sender})
                return

            msg_data = json.loads(payload.decode("utf-8"))
            recipient = msg_data.get("recipient")

            # Inject the real sender identity into the payload before forwarding
            msg_data["sender"] = sender

            self._emit("MESSAGE_ROUTED", {
                "sender": sender,
                "recipient": recipient,
                "size": len(payload)
            })

            recipient_sock = self._clients.get(recipient)
            if recipient_sock:
                try:
                    forward_payload = json.dumps(msg_data).encode("utf-8")
                    recipient_sock.sendall(
                        NetworkFrame.pack(NetworkFrame.TYPE_MESSAGE, forward_payload)
                    )
                except Exception:
                    self._emit("DELIVERY_FAILED", {"recipient": recipient})
            else:
                self._emit("RECIPIENT_OFFLINE", {"recipient": recipient})

        except Exception as e:
            self._emit("ROUTE_ERROR", {"error": str(e)})

    def _broadcast_user_list(self):
        """Send updated user list to all connected clients."""
        users = self._clients.keys()
        payload = json.dumps({"users": users}).encode("utf-8")
        frame = NetworkFrame.pack(NetworkFrame.TYPE_USER_LIST, payload)
        for sock in self._clients.values():
            try:
                sock.sendall(frame)
            except Exception:
                pass

    def _emit(self, event_type: str, data: dict):
        """Fire server event callback."""
        if self.on_event:
            try:
                self.on_event(event_type, data)
            except Exception:
                pass

    def get_online_users(self) -> list:
        """Return list of currently online usernames."""
        return self._clients.keys()


class ChatClient:
    """
    TCP chat client that connects to ChatServer.
    Handles sending/receiving stego image messages.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 9999):
        """
        Initialize client.
        Args:
            host (str): Server address
            port (int): Server port
        """
        self.host = host
        self.port = port
        self._sock = None
        self._running = False
        self.username = None
        self.on_message = None      # Callback: fn(sender, payload_bytes)
        self.on_user_list = None    # Callback: fn(users: list)
        self.on_disconnect = None   # Callback: fn()
        self._outgoing = MessageQueue(max_size=50)
        self.online_users = []

    def connect(self, username: str, public_key_pem: str = "") -> tuple:
        """
        Connect to server and perform handshake.
        Args:
            username (str): Username to identify as
            public_key_pem (str): RSA public key for key exchange
        Returns:
            tuple: (success: bool, message: str)
        """
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(10)
            self._sock.connect((self.host, self.port))
            self.username = username

            # Send handshake
            handshake = json.dumps({
                "username": username,
                "public_key": public_key_pem
            }).encode("utf-8")
            self._sock.sendall(NetworkFrame.pack(NetworkFrame.TYPE_HANDSHAKE, handshake))

            # Receive ACK
            frame_type, payload = NetworkFrame.recv_frame(self._sock)
            if frame_type != NetworkFrame.TYPE_ACK:
                return False, "Handshake rejected by server"

            ack = json.loads(payload.decode("utf-8"))
            if ack.get("status") != "ok":
                return False, "Server rejected connection"

            self.online_users = ack.get("users", [])
            self._sock.settimeout(None)
            self._running = True

            # Start receive thread
            recv_thread = threading.Thread(target=self._receive_loop, daemon=True)
            recv_thread.start()

            return True, "Connected successfully"

        except ConnectionRefusedError:
            return False, f"Cannot connect to server at {self.host}:{self.port}"
        except socket.timeout:
            return False, "Connection timed out"
        except Exception as e:
            return False, f"Connection error: {e}"

    def send_message(self, recipient: str, payload_bytes: bytes) -> bool:
        """
        Send a stego image message to a recipient. O(1) enqueue
        Args:
            recipient (str): Target username
            payload_bytes (bytes): Complete message packet bytes
        Returns:
            bool: True if queued successfully
        """
        if not self._running or not self._sock:
            return False

        msg_data = json.dumps({
            "recipient": recipient,
            "data": payload_bytes.decode("utf-8") if isinstance(payload_bytes, bytes) else payload_bytes
        }).encode("utf-8")

        try:
            self._sock.sendall(NetworkFrame.pack(NetworkFrame.TYPE_MESSAGE, msg_data))
            return True
        except Exception:
            return False

    def _receive_loop(self):
        """Background thread to receive incoming messages."""
        while self._running:
            try:
                frame_type, payload = NetworkFrame.recv_frame(self._sock)

                if frame_type is None:
                    break

                if frame_type == NetworkFrame.TYPE_MESSAGE:
                    # Pass the raw JSON payload string to the callback so it can
                    # perform the correct nested parsing of the inner message.
                    raw_str = payload.decode("utf-8")
                    msg_data = json.loads(raw_str)
                    sender = msg_data.get("sender", "unknown")
                    if self.on_message:
                        self.on_message(sender, raw_str, msg_data)

                elif frame_type == NetworkFrame.TYPE_USER_LIST:
                    user_data = json.loads(payload.decode("utf-8"))
                    self.online_users = user_data.get("users", [])
                    if self.on_user_list:
                        self.on_user_list(self.online_users)

            except Exception:
                break

        self._running = False
        if self.on_disconnect:
            self.on_disconnect()

    def disconnect(self):
        """Cleanly disconnect from server."""
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def is_connected(self) -> bool:
        """Check if currently connected."""
        return self._running and self._sock is not None

    def ping(self) -> bool:
        """Send ping to server to check connection health."""
        try:
            self._sock.sendall(NetworkFrame.pack(NetworkFrame.TYPE_PING, b"ping"))
            return True
        except Exception:
            return False