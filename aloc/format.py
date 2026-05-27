"""
File format encoding/decoding.

Layout:
  [magic: 4 bytes]
  [version: 1 byte]
  [flags: 1 byte]
  [header_len: 4 bytes BE]
  [header_json: bytes]
  [ciphertext: bytes]
"""

import json

MAGIC = b"\x9d\x2a\x71\x03"
VERSION_V1 = 1
VERSION_V2 = 2
CURRENT_VERSION = VERSION_V2
FLAGS = 0


def is_locked(blob: bytes) -> bool:
    """Check if a blob is in our locked file format."""
    return len(blob) > 10 and blob[:4] == MAGIC


def encode_file(header: dict, ciphertext: bytes, version: int = CURRENT_VERSION) -> bytes:
    """Encode header + ciphertext into the file format."""
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    return (
        MAGIC
        + bytes([version])
        + bytes([FLAGS])
        + len(header_bytes).to_bytes(4, "big")
        + header_bytes
        + ciphertext
    )


def parse_locked_file(blob: bytes) -> tuple[dict, bytes]:
    """Parse a locked file blob. Returns (header, ciphertext)."""
    if blob[:4] != MAGIC:
        raise ValueError("not a locked file")

    header_len = int.from_bytes(blob[6:10], "big")
    header_start = 10
    header_end = header_start + header_len

    header = json.loads(blob[header_start:header_end].decode("utf-8"))
    ciphertext = blob[header_end:]

    return header, ciphertext


def get_version(blob: bytes) -> int:
    """Read the version byte from a locked file blob."""
    if blob[:4] != MAGIC:
        raise ValueError("not a locked file")
    return blob[4]
