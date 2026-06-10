# 🔐 End‑to‑End Encrypted Messaging System (Python)

A terminal‑based, end‑to‑encrypted messaging system with **forward secrecy** and **authenticated encryption**.  
The server only relays ciphertexts – it never sees plaintexts or keys.

## ✨ Features

- **End‑to‑end encryption** – only sender and recipient can read messages.
- **Forward secrecy** – each message uses a fresh ephemeral key; past messages stay safe even if a private key is stolen later.
- **Authenticated encryption** – AES‑256‑GCM prevents tampering.
- **Offline message buffering** – server stores messages for offline users.
- **No frontend** – pure CLI, easy to inspect and extend.

## 🧠 How it works (simplified)

1. Each user generates a persistent X25519 key pair.
2. When Alice wants to message Bob:
   - She fetches Bob’s public key from the server.
   - She creates a one‑time ephemeral key pair.
   - She performs Diffie‑Hellman (ephemeral private + Bob’s public) → shared secret.
   - She encrypts her message with AES‑GCM using that shared secret.
   - She sends (ephemeral public key + ciphertext) to the server.
3. Server forwards the blob to Bob.
4. Bob uses his private key + the received ephemeral public key → same shared secret → decrypt.

The server never sees the plaintext.

## 📦 Installation

```bash
git clone https://github.com/yourusername/e2ee-messaging.git
cd e2ee-messaging
pip install -r requirements.txt