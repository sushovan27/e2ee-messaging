# 🔐 End-to-End Encrypted Messaging System (Python)

A terminal-based, end-to-end encrypted messaging system with **forward secrecy** and **authenticated encryption**.  
The server only relays ciphertexts — it never sees plaintexts or private keys.

> ✅ Verified with Wireshark — plaintext never appears on the wire.

---

## ✨ Features

| Feature | Detail |
|---|---|
| 🔒 End-to-end encryption | Only sender and recipient can read messages |
| 🔁 Forward secrecy | Fresh ephemeral key per message — past messages safe even if keys are stolen |
| 🛡️ Authenticated encryption | AES-256-GCM detects any tampering |
| 📥 Offline buffering | Server queues messages for offline users |
| 🖥️ Pure CLI | No frontend — easy to inspect, audit, and extend |

---

## 🧠 How It Works

```
Alice                        Server                        Bob
  │                            │                            │
  │── register (pub key) ─────▶│                            │
  │                            │◀── register (pub key) ─────│
  │                            │                            │
  │── get_pubkey(Bob) ────────▶│                            │
  │◀─ Bob's public key ────────│                            │
  │                            │                            │
  │  [generate ephemeral key]  │                            │
  │  [DH: eph_priv × bob_pub]  │                            │
  │  [AES-GCM encrypt msg]     │                            │
  │                            │                            │
  │── eph_pub + ciphertext ───▶│── eph_pub + ciphertext ───▶│
  │                            │                            │  [DH: bob_priv × eph_pub]
  │                            │                            │  [AES-GCM decrypt]
  │                            │                            │  "Hello!"
```

1. Each user generates a **persistent X25519 key pair** (saved as `.pem`)
2. Alice fetches Bob's public key from the server
3. Alice generates a **one-time ephemeral key pair**
4. ECDH: `ephemeral_private × bob_public` → raw shared secret
5. HKDF derives a 32-byte AES-256-GCM key from that secret
6. Message encrypted → `ephemeral_pub (32 bytes) + nonce + ciphertext + tag` sent to server
7. Server forwards the blob — **it never sees plaintext**
8. Bob derives the same key: `bob_private × ephemeral_pub` → decrypts

---

## 📦 Installation

```bash
git clone https://github.com/yourusername/e2ee-messaging.git
cd e2ee-messaging
pip install -r requirements.txt
```

`requirements.txt`:
```
cryptography
```

---

## 🚀 Usage

**Terminal 1 — Start the server:**
```bash
python server.py
```

**Terminal 2 — Start Alice:**
```bash
python client.py alice
```

**Terminal 3 — Start Bob:**
```bash
python client.py bob
```

**Send a message from Alice:**
```
[alice] /send bob Hello, this is E2EE!
```

**Bob sees:**
```
[Received]: Hello, this is E2EE!
```

### Available commands

| Command | Description |
|---|---|
| `/send <user> <message>` | Encrypt and send a message |
| `/quit` | Exit the client |

---

## 📁 Project Structure

```
e2ee-messaging/
├── client.py          # CLI client — key management, encrypt/decrypt, send/receive
├── server.py          # Relay server — stores public keys, buffers offline messages
├── crypto_utils.py    # Crypto primitives — X25519, HKDF, AES-256-GCM
├── requirements.txt   # Python dependencies
└── README.md
```

---

## 🛡️ Security Properties

| Threat | Mitigation |
|---|---|
| Network eavesdropping | Only ciphertext on the wire — verified via Wireshark |
| Server compromise | No private keys or plaintext ever reach the server |
| Long-term key theft | Forward secrecy — ephemeral keys protect past sessions |
| Message tampering | AES-GCM auth tag — any modification causes decryption failure |
| Key confusion | HKDF derives separate keys — raw DH secret never used directly |

---

## 🔬 Wireshark Verification

Captured traffic on port 5555 shows:

```json
{
  "cmd": "send",
  "sender": "alice",
  "recipient": "bob",
  "ciphertext": "b2e2c5995e8bde4254a8e2ddf7be20721e3084ff77..."
}
```

The string `"hello world"` is **nowhere in the capture**. ✅

---

## 🔧 Possible Extensions

- [ ] Password-protected private key files
- [ ] TLS transport layer (server↔client)
- [ ] Signal-style Double Ratchet (stronger forward secrecy)
- [ ] Group chat (sender-generated symmetric key per group)
- [ ] Replay protection (message counters / timestamps)
- [ ] GUI with Tkinter or a web frontend

---

## ⚠️ Disclaimer

This is an **educational project** demonstrating X25519, HKDF, and AES-256-GCM.  
It has not been audited for production use. For real-world deployment, add server authentication, replay protection, and a full security review.

---

## 📄 License

MIT — free to use, learn, and modify.

---

*Built with Python and the [`cryptography`](https://cryptography.io) library.*
