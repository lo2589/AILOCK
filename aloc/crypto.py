import json
import os
import base64

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag


def derive_project_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        memory_cost=65536,
        time_cost=3,
        parallelism=1,
        hash_len=32,
        type=Type.ID,
    )


def encrypt_payload(project_key: bytes, plaintext: bytes, metadata: dict) -> tuple[bytes, bytes]:
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
    nonce = base64.b64decode(header["nonce"])
    aad = b"v1"

    cipher = ChaCha20Poly1305(project_key)
    payload_bytes = cipher.decrypt(nonce, ciphertext, aad)

    payload = json.loads(payload_bytes.decode("utf-8"))
    return base64.b64decode(payload["content"])


def verify_key_or_fail(project_key: bytes, header: dict, ciphertext: bytes) -> None:
    try:
        decrypt_payload(project_key, header, ciphertext)
    except InvalidTag:
        raise ValueError("wrong password or corrupted file")
