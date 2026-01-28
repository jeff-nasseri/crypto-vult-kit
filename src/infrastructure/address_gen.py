"""Address generation for various cryptocurrency networks."""

import hashlib
from typing import Optional

from src.infrastructure.encoding import base58_encode, hash160, double_sha256


# Version bytes for Base58Check-encoded addresses
_VERSION_BYTES = {
    "BTC": b"\x00",
    "LTC": b"\x30",
    "DOGE": b"\x1e",
    "BCH": b"\x00",
}


def _base58check_address(pubkey_bytes: bytes, version: bytes) -> str:
    """Create a Base58Check-encoded address from a compressed public key."""
    pubkey_hash = hash160(pubkey_bytes)
    versioned = version + pubkey_hash
    checksum = double_sha256(versioned)[:4]
    return base58_encode(versioned + checksum)


def generate_bitcoin_address(pubkey_bytes: bytes) -> str:
    """Generate a Bitcoin P2PKH address from a compressed public key."""
    return _base58check_address(pubkey_bytes, _VERSION_BYTES["BTC"])


def generate_ethereum_address(pubkey_bytes: bytes) -> str:
    """Generate an Ethereum address from a compressed public key.

    This decompresses the public key first, then applies Keccak-256 and takes
    the last 20 bytes as the address.
    """
    try:
        from ecdsa import SECP256k1, VerifyingKey
    except ImportError:
        return "ecdsa library required for Ethereum addresses"
    try:
        from Crypto.Hash import keccak as _keccak_mod
    except ImportError:
        return "pycryptodome library required for Ethereum addresses"

    # Decompress the public key to get 64 bytes (x + y)
    vk = VerifyingKey.from_string(pubkey_bytes, curve=SECP256k1)
    uncompressed = vk.to_string()  # 64 bytes (no 0x04 prefix)

    k = _keccak_mod.new(digest_bits=256)
    k.update(uncompressed)
    return "0x" + k.digest()[-20:].hex()


def generate_litecoin_address(pubkey_bytes: bytes) -> str:
    return _base58check_address(pubkey_bytes, _VERSION_BYTES["LTC"])


def generate_dogecoin_address(pubkey_bytes: bytes) -> str:
    return _base58check_address(pubkey_bytes, _VERSION_BYTES["DOGE"])


def generate_bitcoin_cash_address(pubkey_bytes: bytes) -> str:
    return _base58check_address(pubkey_bytes, _VERSION_BYTES["BCH"])


def generate_address(coin_symbol: str, pubkey_bytes: bytes) -> str:
    """Dispatch to the correct address generator for *coin_symbol*."""
    generators = {
        "BTC": generate_bitcoin_address,
        "ETH": generate_ethereum_address,
        "LTC": generate_litecoin_address,
        "DOGE": generate_dogecoin_address,
        "BCH": generate_bitcoin_cash_address,
    }
    gen = generators.get(coin_symbol)
    if gen is None:
        return f"Address generation not supported for {coin_symbol}"
    return gen(pubkey_bytes)
