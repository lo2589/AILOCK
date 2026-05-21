import json

MAGIC = b"\x9d\x2a\x71\x03"
VERSION = 1
FLAGS = 0


def is_locked(blob: bytes) -> bool:
    return len(blob) > 10 and blob[:4] == MAGIC


def encode_file(header: dict, ciphertext: bytes) -> bytes:
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    return (
        MAGIC
        + bytes([VERSION])
        + bytes([FLAGS])
        + len(header_bytes).to_bytes(4, "big")
        + header_bytes
        + ciphertext
    )


def parse_locked_file(blob: bytes) -> tuple[dict, bytes]:
    if blob[:4] != MAGIC:
        raise ValueError("not a locked file")

    version = blob[4]
    flags = blob[5]
    header_len = int.from_bytes(blob[6:10], "big")

    header_start = 10
    header_end = header_start + header_len

    header = json.loads(blob[header_start:header_end].decode("utf-8"))
    ciphertext = blob[header_end:]

    return header, ciphertext
