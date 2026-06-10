import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes

def generate_keypair():

    """Generate X25519 key pair. Returns (private_key, public_key_bytes)."""

    priv = X25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes_raw()
    return priv, pub_bytes

def derive_shared_key(private_key, peer_public_bytes):

    """Perform DH and derive 32-byte symmetric key using HKDF."""

    peer_pub = X25519PublicKey.from_public_bytes(peer_public_bytes)
    shared_secret = private_key.exchange(peer_pub)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"e2ee-messaging",
    )
    return hkdf.derive(shared_secret)

def encrypt_message(symmetric_key: bytes, plaintext: str) -> bytes:

    """Encrypt plaintext with AES-GCM. Returns nonce + ciphertext + tag."""

    aesgcm = AESGCM(symmetric_key)
    nonce = os.urandom(12)   # 96-bit nonce for GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce + ciphertext   # tag is appended by encrypt()

def decrypt_message(symmetric_key: bytes, encrypted_data: bytes) -> str:

    """Decrypt using AES-GCM. encrypted_data = nonce (12) + ciphertext+tag."""

    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    aesgcm = AESGCM(symmetric_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")