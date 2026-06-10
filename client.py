import socket
import json
import threading
import sys
import os
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from crypto_utils import generate_keypair, derive_shared_key, encrypt_message, decrypt_message


def send_framed(sock, data: bytes):
    """Prefix message with 4-byte big-endian length."""
    length = len(data).to_bytes(4, "big")
    sock.sendall(length + data)


def recv_framed(sock) -> bytes:
    """Read exactly one framed message."""
    raw_len = _recv_exactly(sock, 4)
    msg_len = int.from_bytes(raw_len, "big")
    return _recv_exactly(sock, msg_len)


def _recv_exactly(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed mid-read")
        buf += chunk
    return buf


class E2EEClient:
    def __init__(self, username, server_host="127.0.0.1", server_port=5555):
        self.username = username
        self.server_addr = (server_host, server_port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.private_key = None
        self.public_key_bytes = None

        # --- FIX: separate lock + event for get_pubkey responses ---
        self._sock_lock = threading.Lock()          # guards sendall calls
        self._pubkey_event = threading.Event()      # signals a pubkey reply arrived
        self._pending_pubkey = None                 # stores the reply payload

        self.load_or_generate_keys()

    # ------------------------------------------------------------------
    # Key management
    # ------------------------------------------------------------------

    def load_or_generate_keys(self):
        key_file = f"{self.username}_key.pem"
        if os.path.exists(key_file):
            from cryptography.hazmat.primitives import serialization
            with open(key_file, "rb") as f:
                self.private_key = serialization.load_pem_private_key(f.read(), password=None)
            self.public_key_bytes = self.private_key.public_key().public_bytes_raw()
        else:
            self.private_key, self.public_key_bytes = generate_keypair()
            pem = self.private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
            with open(key_file, "wb") as f:
                f.write(pem)
        print(f"[{self.username}] Key loaded/generated.")

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def connect_and_register(self):
        self.sock.connect(self.server_addr)
        reg_msg = {
            "cmd": "register",
            "username": self.username,
            "public_key": self.public_key_bytes.hex(),
        }
        send_framed(self.sock, json.dumps(reg_msg).encode())
        resp = json.loads(recv_framed(self.sock).decode())
        if resp.get("status") != "ok":
            raise Exception(f"Registration failed: {resp}")
        print(f"[{self.username}] Registered with server.")
        threading.Thread(target=self._listen_loop, daemon=True).start()

    # ------------------------------------------------------------------
    # Listener thread  (handles BOTH incoming messages AND pubkey replies)
    # ------------------------------------------------------------------

    def _listen_loop(self):
        """Single reader thread — routes packets by 'type' field."""
        while True:
            try:
                raw = recv_framed(self.sock)
            except Exception as e:
                print(f"\n[Connection lost: {e}]")
                break

            # Peek at the first byte: if it starts with '{' it's a JSON control packet
            if raw[:1] == b"{":
                try:
                    pkt = json.loads(raw.decode())
                except json.JSONDecodeError:
                    print("[ERROR] Malformed JSON control packet")
                    continue

                if pkt.get("type") == "pubkey_response":
                    # Wake up get_public_key() waiting in the main thread
                    self._pending_pubkey = pkt
                    self._pubkey_event.set()
                else:
                    print(f"[WARN] Unknown control packet: {pkt}")

            else:
                # Binary E2EE message: ephemeral_pub (32 bytes) + encrypted payload
                self._handle_encrypted_message(raw)

    def _handle_encrypted_message(self, data: bytes):
        if len(data) < 33:          # 32-byte pub + at least 1 byte payload
            print("[ERROR] Message too short, dropping.")
            return
        try:
            ephemeral_pub_bytes = data[:32]
            enc_payload = data[32:]
            sym_key = derive_shared_key(self.private_key, ephemeral_pub_bytes)
            plaintext = decrypt_message(sym_key, enc_payload)
            print(f"\n[Received]: {plaintext}\n[{self.username}] ", end="", flush=True)
        except Exception as e:
            print(f"\n[Decryption error: {type(e).__name__} – {e}]")

    # ------------------------------------------------------------------
    # Public-key lookup  (runs on main thread, waits for listener to relay reply)
    # ------------------------------------------------------------------

    def get_public_key(self, target_user) -> bytes | None:
        self._pubkey_event.clear()
        self._pending_pubkey = None

        req = json.dumps({"cmd": "get_pubkey", "target": target_user}).encode()
        with self._sock_lock:
            send_framed(self.sock, req)

        if not self._pubkey_event.wait(timeout=5.0):
            print(f"[ERROR] Timeout waiting for public key of {target_user}")
            return None

        resp = self._pending_pubkey
        if resp.get("status") == "ok":
            return bytes.fromhex(resp["public_key"])
        print(f"[ERROR] {resp.get('reason', 'unknown error')}")
        return None

    # ------------------------------------------------------------------
    # Send an E2EE message
    # ------------------------------------------------------------------

    def send_message(self, recipient: str, plaintext: str):
        recipient_pub_bytes = self.get_public_key(recipient)
        if recipient_pub_bytes is None:
            return

        ephemeral_priv, ephemeral_pub_bytes = generate_keypair()
        sym_key = derive_shared_key(ephemeral_priv, recipient_pub_bytes)
        encrypted = encrypt_message(sym_key, plaintext)

        # Binary frame: ephemeral_pub (32 bytes) + nonce + ciphertext+tag
        full_msg = ephemeral_pub_bytes + encrypted

        send_cmd = json.dumps({
            "cmd": "send",
            "sender": self.username,
            "recipient": recipient,
            "ciphertext": full_msg.hex(),
        }).encode()

        with self._sock_lock:
            send_framed(self.sock, send_cmd)

        print(f"[Sent to {recipient}]")

    # ------------------------------------------------------------------
    # CLI
    # ------------------------------------------------------------------

    def run_cli(self):
        self.connect_and_register()
        print(f"Connected as {self.username}. Commands: /send <user> <msg>  |  /quit")
        while True:
            try:
                cmd = input(f"[{self.username}] ")
            except EOFError:
                break

            if cmd.startswith("/send "):
                parts = cmd.split(maxsplit=2)
                if len(parts) < 3:
                    print("Usage: /send <username> <message>")
                    continue
                _, target, msg = parts
                self.send_message(target, msg)
            elif cmd == "/quit":
                break
            else:
                print("Unknown command. Try /send <user> <msg> or /quit")

        self.sock.close()
        sys.exit(0)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python client.py <username>")
        sys.exit(1)
    E2EEClient(sys.argv[1]).run_cli()