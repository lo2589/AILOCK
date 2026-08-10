"""
Cryptographic primitives: KDF, AEAD encrypt/decrypt, key wrapping.
"""

import json
import os
import base64

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag


# ---------------------------------------------------------------------------
# KDF
# ---------------------------------------------------------------------------

def derive_project_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte key from password + salt using Argon2id."""
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        memory_cost=65536,
        time_cost=3,
        parallelism=1,
        hash_len=32,
        type=Type.ID,
    )


# ---------------------------------------------------------------------------
# V1: direct encryption (legacy, backward compat)
# ---------------------------------------------------------------------------

def encrypt_payload(project_key: bytes, plaintext: bytes, metadata: dict) -> tuple[bytes, bytes]:
    """Encrypt plaintext with project_key directly (v1 format)."""
    nonce = os.urandom(12)

    payload = {
        "metadata": metadata,
        "content": base64.b64encode(plaintext).decode("ascii"),
    }
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    aad = b"v1"
    cipher = ChaCha20Poly1305(project_key)
    ciphertext = cipher.encrypt(nonce, payload_bytes, aad)

    return nonce, ciphertext


def decrypt_payload(project_key: bytes, header: dict, ciphertext: bytes) -> bytes:
    """Decrypt ciphertext using project_key directly (v1 format)."""
    nonce = base64.b64decode(header["nonce"])
    aad = b"v1"

    cipher = ChaCha20Poly1305(project_key)
    try:
        payload_bytes = cipher.decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise ValueError("wrong password or corrupted file")

    payload = json.loads(payload_bytes.decode("utf-8"))
    return base64.b64decode(payload["content"])


def verify_key_or_fail(project_key: bytes, header: dict, ciphertext: bytes) -> None:
    """Verify the key works by attempting decryption."""
    try:
        decrypt_payload(project_key, header, ciphertext)
    except InvalidTag:
        raise ValueError("wrong password or corrupted file")


# ---------------------------------------------------------------------------
# V2: file_key wrapping
# ---------------------------------------------------------------------------

def generate_file_key() -> bytes:
    """Generate a random 32-byte file encryption key."""
    return os.urandom(32)


def wrap_key(wrapping_key: bytes, file_key: bytes) -> tuple[bytes, bytes]:
    """Encrypt file_key with wrapping_key. Returns (nonce, wrapped)."""
    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(wrapping_key)
    wrapped = cipher.encrypt(nonce, file_key, b"wrap")
    return nonce, wrapped


def unwrap_key(wrapping_key: bytes, nonce: bytes, wrapped: bytes) -> bytes:
    """Decrypt file_key from wrapped blob. Raises ValueError on failure."""
    cipher = ChaCha20Poly1305(wrapping_key)
    try:
        return cipher.decrypt(nonce, wrapped, b"wrap")
    except InvalidTag:
        raise ValueError("wrong password or corrupted file")


def encrypt_payload_v2(file_key: bytes, plaintext: bytes, metadata: dict) -> tuple[bytes, bytes]:
    """Encrypt plaintext with file_key (v2 format)."""
    nonce = os.urandom(12)

    payload = {
        "metadata": metadata,
        "content": base64.b64encode(plaintext).decode("ascii"),
    }
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    aad = b"v2"
    cipher = ChaCha20Poly1305(file_key)
    ciphertext = cipher.encrypt(nonce, payload_bytes, aad)

    return nonce, ciphertext


def decrypt_payload_v2(file_key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt ciphertext using file_key (v2 format)."""
    aad = b"v2"
    cipher = ChaCha20Poly1305(file_key)
    try:
        payload_bytes = cipher.decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise ValueError("wrong password or corrupted file")

    payload = json.loads(payload_bytes.decode("utf-8"))
    return base64.b64decode(payload["content"])
