import socket
import threading
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("E2EEServer")


# ── Framing helpers (must match client exactly) ────────────────────────────────

def send_framed(sock, data: bytes):
    """Prefix message with 4-byte big-endian length then send."""
    sock.sendall(len(data).to_bytes(4, "big") + data)


def recv_framed(sock) -> bytes:
    """Read exactly one framed message."""
    raw_len = _recv_exactly(sock, 4)
    return _recv_exactly(sock, int.from_bytes(raw_len, "big"))


def _recv_exactly(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed mid-read")
        buf += chunk
    return buf


# ── Server ─────────────────────────────────────────────────────────────────────

class MessagingServer:
    def __init__(self, host="127.0.0.1", port=5555):
        self.host = host
        self.port = port
        self.public_keys = {}          # username -> public_key hex str
        self.pending_messages = {}     # username -> list[bytes]  (framed binary)
        self.active_connections = {}   # username -> socket
        self.lock = threading.Lock()

    def handle_client(self, conn, addr):
        logger.info(f"New connection from {addr}")
        username = None
        try:
            while True:
                data = recv_framed(conn)          # ← framed read
                msg = json.loads(data.decode())
                cmd = msg.get("cmd")

                if cmd == "register":
                    username = msg["username"]
                    pub_key_hex = msg["public_key"]

                    with self.lock:
                        self.public_keys[username] = pub_key_hex
                        self.active_connections[username] = conn
                        # deliver any messages that arrived before this user connected
                        pending = self.pending_messages.pop(username, [])

                    # send pending messages BEFORE the registration ack so the
                    # client's listener thread is already running when they arrive
                    for framed_msg in pending:
                        conn.sendall(framed_msg)   # already framed binary

                    send_framed(conn, json.dumps({"status": "ok"}).encode())
                    logger.info(f"Registered: {username}")

                elif cmd == "get_pubkey":
                    target = msg["target"]
                    with self.lock:
                        pub = self.public_keys.get(target)
                    if pub:
                        resp = {"type": "pubkey_response", "status": "ok",
                                "public_key": pub}
                    else:
                        resp = {"type": "pubkey_response", "status": "error",
                                "reason": "user not found"}
                    send_framed(conn, json.dumps(resp).encode())   # ← framed

                elif cmd == "send":
                    sender    = msg["sender"]
                    recipient = msg["recipient"]
                    # raw binary: ephemeral_pub (32 bytes) + nonce + ciphertext+tag
                    raw_msg = bytes.fromhex(msg["ciphertext"])
                    # frame it once here; store/forward the framed bytes
                    framed_msg = len(raw_msg).to_bytes(4, "big") + raw_msg

                    with self.lock:
                        if recipient in self.active_connections:
                            self.active_connections[recipient].sendall(framed_msg)
                            status = "delivered"
                        else:
                            self.pending_messages.setdefault(recipient, []).append(framed_msg)
                            status = "queued"

                    # NOTE: no ack sent back — client doesn't read one (avoids
                    # the "stolen reply" race that existed in the original code)
                    logger.info(f"[{status}] {sender} → {recipient}")

        except (ConnectionError, json.JSONDecodeError) as e:
            logger.warning(f"Client error ({addr}): {e}")
        except Exception as e:
            logger.error(f"Unexpected error ({addr}): {e}", exc_info=True)
        finally:
            if username:
                with self.lock:
                    self.active_connections.pop(username, None)
            conn.close()
            logger.info(f"Connection closed: {addr}")

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(5)
        logger.info(f"Server listening on {self.host}:{self.port}")
        try:
            while True:
                conn, addr = server.accept()
                threading.Thread(target=self.handle_client,
                                 args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt:
            logger.info("Shutting down")
        finally:
            server.close()


if __name__ == "__main__":
    MessagingServer().start()