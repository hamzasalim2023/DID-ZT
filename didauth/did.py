"""DID utilities for did:key with Ed25519 using base58btc (multibase z)."""

MULTICODEC_ED25519_HEADER = b"\xed\x01"  # Varint 0xed01
MULTIBASE_Z_PREFIX = "did:key:z"


def encode_did_key(public_key_bytes: bytes) -> str:
    """Encode 32-byte Ed25519 public key as did:key string."""
    if len(public_key_bytes) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    raw = MULTICODEC_ED25519_HEADER + public_key_bytes
    return f"{MULTIBASE_Z_PREFIX}{_base58btc_encode(raw)}"


def decode_did_key(did: str) -> bytes:
    """Decode did:key string back to 32-byte public key."""
    if not did.startswith(MULTIBASE_Z_PREFIX):
        raise ValueError(f"Invalid DID format, must start with {MULTIBASE_Z_PREFIX}")
    encoded = did[len(MULTIBASE_Z_PREFIX):]
    raw = _base58btc_decode(encoded)
    if len(raw) != 34 or raw[:2] != MULTICODEC_ED25519_HEADER:
        raise ValueError("Invalid did:key for Ed25519")
    return raw[2:]


def _base58btc_encode(data: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    if not data:
        return ""
    num = int.from_bytes(data, "big")
    res = ""
    while num > 0:
        num, rem = divmod(num, 58)
        res = alphabet[rem] + res
    n_pad = 0
    for b in data:
        if b == 0:
            n_pad += 1
        else:
            break
    return alphabet[0] * n_pad + res


def _base58btc_decode(s: str) -> bytes:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    if not s:
        return b""
    num = 0
    for char in s:
        num = num * 58 + alphabet.index(char)
    res = num.to_bytes((num.bit_length() + 7) // 8 or 1, "big")
    if res == b"\x00" and num == 0:
        res = b""
    n_pad = 0
    for char in s:
        if char == alphabet[0]:
            n_pad += 1
        else:
            break
    return b"\x00" * n_pad + res


def extract_public_key_from_did(did: str) -> bytes:
    return decode_did_key(did)
