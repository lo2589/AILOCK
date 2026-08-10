"""
Recovery key generation, encoding, and file recovery.

Recovery keys provide an alternative decryption path when
the user forgets their password.
"""

import base64
import os

from ailatch.crypto import derive_project_key, unwrap_key, decrypt_payload_v2


# ---------------------------------------------------------------------------
# Recovery key encoding
# ---------------------------------------------------------------------------

# Base32-like alphabet without ambiguous chars (0/O, 1/I/L)
_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"


def _encode_human_readable(raw: bytes) -> str:
    """Encode raw bytes into human-readable groups: AA-XXXX-XXXX-..."""
    # Convert bytes to integer for base conversion
    num = int.from_bytes(raw, "big")
    chars = []
    base = len(_ALPHABET)
    while num > 0:
        chars.append(_ALPHABET[num % base])
        num //= base
    # Pad to consistent length (32 bytes -> ~49 chars in base30)
    while len(chars) < 49:
        chars.append(_ALPHABET[0])
    chars.reverse()

    # Group into 4-char blocks with prefix
    groups = []
    for i in range(0, len(chars), 4):
        groups.append("".join(chars[i:i + 4]))

    return "AA-" + "-".join(groups)


def _decode_human_readable(code: str) -> bytes:
    """Decode human-readable code back to raw bytes."""
    # Strip prefix and dashes
    code = code.upper().strip()
    if code.startswith("AA-"):
        code = code[3:]
    chars = code.replace("-", "")

    # Convert from base alphabet back to integer
    base = len(_ALPHABET)
    num = 0
    for ch in chars:
        idx = _ALPHABET.index(ch)
        num = num * base + idx

    # Convert integer to 32 bytes
    return num.to_bytes(32, "big")


# ---------------------------------------------------------------------------
# Recovery key operations
# ---------------------------------------------------------------------------

def generate_recovery_key() -> tuple[str, bytes]:
    """
    Generate a new recovery key.

    Returns:
        (human_readable_code, raw_32_bytes)
    """
    raw = os.urandom(32)
    code = _encode_human_readable(raw)
    return code, raw


def decode_recovery_key(code: str) -> bytes:
    """Decode a human-readable recovery code to raw bytes."""
    try:
        return _decode_human_readable(code)
    except (ValueError, IndexError) as e:
        raise ValueError(f"invalid recovery key format: {e}")


def derive_recovery_wrapping_key(recovery_raw: bytes, salt: bytes) -> bytes:
    """Derive a wrapping key from recovery key bytes + salt."""
    # Use the same KDF but with recovery bytes as "password"
    return derive_project_key(
        password=base64.b64encode(recovery_raw).decode("ascii"),
        salt=salt,
    )


def recover_file_key(header: dict, recovery_code: str) -> bytes:
    """
    Recover the file_key using a recovery code.

    Looks for a 'recovery' type wrap in header['key_wraps'].
    """
    key_wraps = header.get("key_wraps", [])

    recovery_wrap = None
    for wrap in key_wraps:
        if wrap.get("type") == "recovery":
            recovery_wrap = wrap
            break

    if recovery_wrap is None:
        raise ValueError("no recovery key configured for this file")

    recovery_raw = decode_recovery_key(recovery_code)
    salt = base64.b64decode(header["salt"])
    wrapping_key = derive_recovery_wrapping_key(recovery_raw, salt)

    nonce = base64.b64decode(recovery_wrap["nonce"])
    wrapped = base64.b64decode(recovery_wrap["wrapped"])

    return unwrap_key(wrapping_key, nonce, wrapped)
