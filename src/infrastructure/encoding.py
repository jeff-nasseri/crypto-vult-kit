"""Base58 and other encoding utilities for cryptocurrency addresses."""

import hashlib


def base58_encode(data: bytes) -> str:
    """Base58Check encoding used by Bitcoin and similar cryptocurrencies."""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    num = int.from_bytes(data, "big")

    encoded = ""
    while num > 0:
        num, remainder = divmod(num, 58)
        encoded = alphabet[remainder] + encoded

    for byte in data:
        if byte == 0:
            encoded = "1" + encoded
        else:
            break

    return encoded


def hash160(data: bytes) -> bytes:
    """SHA-256 followed by RIPEMD-160 (used in Bitcoin address generation)."""
    sha256_hash = hashlib.sha256(data).digest()
    ripemd160 = hashlib.new("ripemd160")
    ripemd160.update(sha256_hash)
    return ripemd160.digest()


def double_sha256(data: bytes) -> bytes:
    """Double SHA-256 hash (used for Bitcoin checksums)."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()
