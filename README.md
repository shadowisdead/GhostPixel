## GhostPixel

**Tagline**: Hidden in plain sight.

GhostPixel is a steganographic end-to-end encrypted chat application. Messages are encrypted with **AES‑256‑GCM**, signed with **HMAC‑SHA256**, wrapped in a replay‑protected envelope, then hidden inside **PNG** images using **LSB steganography** and transmitted over **TCP sockets**. A dark cyberpunk‑themed **Tkinter** GUI provides login, chat, and a live security dashboard.

### Features

- **Strong crypto**: AES‑256‑GCM, RSA‑2048, PBKDF2‑HMAC‑SHA256 (260,000 iterations)
- **Steganography**: 2‑bit LSB embedding into RGB PNG pixels
- **Tamper detection**: HMAC‑SHA256 signatures on unsigned message packets
- **Replay protection**: Nonce + timestamp validation with expiry
- **Networking**: Length‑prefixed TCP frames, multi‑client server
- **GUI**:
  - Login / register screen with password strength meter
  - Main chat window with message bubbles and stego image preview
  - Security dashboard showing events, tamper alerts, and stats
- **Persistence**: SQLite database (`ghostpixel.db`) plus plaintext security log (`ghostpixel_security.log`)
- **Custom DSA**: Doubly linked list, hash table, FIFO queue, and token‑bucket rate limiter

### Project Structure

- `main.py` – Application entry point, boots Tkinter and screens
- `core/crypto.py` – AES‑256‑GCM, RSA‑2048, PBKDF2 key derivation
- `core/steganography.py` – LSB stego embed/extract into PNG bytes
- `core/tamper.py` – HMAC‑SHA256, `NonceManager`, `MessagePacket`
- `core/auth.py` – PBKDF2 password hashing, sessions over custom hash table
- `core/network.py` – TCP `ChatServer` + `ChatClient` with rate limiting
- `core/storage.py` – SQLite storage for users, messages, and security events
- `dsa/linked_list.py` – `MessageLinkedList` for message history
- `dsa/hash_table.py` – Custom hash table with separate chaining
- `dsa/queue.py` – `MessageQueue` + `RateLimiterBucket`
- `gui/login_screen.py` – Login / register UI
- `gui/chat_screen.py` – Main chat UI (send/receive, stego preview)
- `gui/dashboard.py` – Security dashboard window
- `tests/test_all.py` – Unified unittest suite

### Installation

```bash
python -m venv venv
venv\Scripts\activate  # Windows

pip install -r requirements.txt
```

Python **3.11+** is recommended.

### Running the Application

From the project root:

```bash
python main.py
```

Workflow:

- Register a new user on the login screen (strong password required).
- Login as that user; the chat screen and local TCP server start automatically.
- Register/login as a second user in another process/VM using the same codebase, then select them in the **online users** sidebar.
- Type a message and press **SEND** – the app encrypts, signs, embeds into a PNG, sends over TCP, stores to SQLite, and renders message bubbles.
- Use the **Dashboard** button to open the security dashboard and inspect events (tamper alerts, replay blocks, etc.).

### Running Tests

All tests are in `tests/test_all.py` and can be executed with:

```bash
python tests/test_all.py
```

or:

```bash
python -m pytest tests/ -v
```

The suite covers:

- DSA: linked list, hash table, queue, rate limiter
- Crypto: AES and RSA round‑trips and failure modes
- Steganography: embed/extract, PNG format, capacity limits
- Tamper detection: HMAC verification and nonce handling
- Auth: password hashing, strength, and session management
- Storage: users, messages, security events, and stats
- Integration: full crypto‑stego pipeline and auth flow

### High‑Level Architecture

**Message send path**:

1. GUI collects plaintext → `AESCipher.encrypt()` → `{nonce, ciphertext}`  
2. Build `MessagePacket(sender, encrypted_payload, signature="", nonce, timestamp)`  
3. Compute HMAC over **unsigned** packet bytes and set `signature`  
4. Serialize to bytes and call `SteganographyEngine.embed()` → PNG bytes  
5. Base64 encode and wrap in a JSON envelope → `ChatClient.send_message()` over TCP  
6. Persist encrypted message in SQLite and update GUI bubbles

**Message receive path**:

1. `ChatClient` receives a length‑prefixed TCP frame and parses outer JSON  
2. Decode `stego_b64` → PNG bytes → `SteganographyEngine.extract()` → packet bytes  
3. `MessagePacket.from_bytes()` reconstructs the packet  
4. Clear `signature`, recompute HMAC over unsigned bytes, compare with saved signature  
5. Validate `nonce` and `timestamp` via `NonceManager` (replay detection)  
6. AES‑GCM decrypt using the shared key; display plaintext bubble and log to SQLite

The design deliberately combines **cryptography**, **DSA**, **networking**, and **GUI** to demonstrate secure application engineering in a teaching context.

