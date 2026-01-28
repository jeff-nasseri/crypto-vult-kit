"""BIP-32 / BIP-44 key derivation utilities (pure Python).

This module implements BIP-32 HD key derivation without the ``bip32`` /
``coincurve`` C extension so the project works on systems without a C
compiler.  It relies on ``ecdsa`` (pure Python) for elliptic-curve math and
``mnemonic`` for BIP-39 seed generation.
"""

import hashlib
import hmac
import struct
from typing import List, Tuple

from ecdsa import SECP256k1, SigningKey
from ecdsa.ellipticcurve import INFINITY
from mnemonic import Mnemonic

# ── Constants ───────────────────────────────────────────────────────────────

COIN_TYPES = {
    "BTC": 0,
    "ETH": 60,
    "LTC": 2,
    "DOGE": 3,
    "BCH": 145,
}

SUPPORTED_COINS = list(COIN_TYPES.keys())

SUPPORTED_STRENGTHS = {
    12: 128,
    15: 160,
    18: 192,
    21: 224,
    24: 256,
}

_CURVE_ORDER = SECP256k1.order
_HARDENED = 0x80000000

# ── BIP-32 implementation ──────────────────────────────────────────────────


def _ser32(i: int) -> bytes:
    return struct.pack(">I", i)


def _ser256(k: int) -> bytes:
    return k.to_bytes(32, "big")


def _parse256(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _point(privkey_int: int) -> bytes:
    """Return the SEC1 compressed public key for *privkey_int*."""
    sk = SigningKey.from_secret_exponent(privkey_int, curve=SECP256k1)
    vk = sk.get_verifying_key()
    # vk.to_string() gives 64 bytes (x ‖ y).  Compress manually.
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    prefix = b"\x02" if y % 2 == 0 else b"\x03"
    return prefix + x.to_bytes(32, "big")


def _master_key(seed: bytes):
    """Derive the master key and chain-code from a BIP-39 seed."""
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    IL, IR = I[:32], I[32:]
    key_int = _parse256(IL)
    if key_int == 0 or key_int >= _CURVE_ORDER:
        raise ValueError("Invalid master key derived from seed")
    return key_int, IR


def _ckd_priv(k_par: int, c_par: bytes, index: int):
    """Child key derivation (private parent -> private child)."""
    if index >= _HARDENED:
        # Hardened child
        data = b"\x00" + _ser256(k_par) + _ser32(index)
    else:
        data = _point(k_par) + _ser32(index)

    I = hmac.new(c_par, data, hashlib.sha512).digest()
    IL, IR = I[:32], I[32:]
    il_int = _parse256(IL)
    child_key = (il_int + k_par) % _CURVE_ORDER
    if il_int >= _CURVE_ORDER or child_key == 0:
        raise ValueError("Derived an invalid child key")
    return child_key, IR


def _parse_path(path: str) -> List[int]:
    """Parse a BIP-32 path string like ``m/44'/0'/0'/0/0``."""
    parts = path.strip().split("/")
    if parts[0] != "m":
        raise ValueError(f"Path must start with 'm': {path}")
    indices: List[int] = []
    for part in parts[1:]:
        if part.endswith("'"):
            indices.append(int(part[:-1]) + _HARDENED)
        else:
            indices.append(int(part))
    return indices


def _derive_path(seed: bytes, path: str) -> Tuple[int, bytes]:
    """Return (private_key_int, chain_code) for the given BIP-32 path."""
    key, chain = _master_key(seed)
    for idx in _parse_path(path):
        key, chain = _ckd_priv(key, chain, idx)
    return key, chain


# ── Public API ──────────────────────────────────────────────────────────────

def validate_mnemonic(phrase: str) -> bool:
    """Return True if *phrase* is a valid BIP-39 English mnemonic."""
    m = Mnemonic("english")
    return m.check(phrase.strip())


def mnemonic_to_seed(phrase: str, passphrase: str = "") -> bytes:
    """Convert a validated mnemonic to a 64-byte binary seed."""
    m = Mnemonic("english")
    return m.to_seed(phrase.strip(), passphrase)


def generate_mnemonic(word_count: int = 24) -> str:
    """Generate a new BIP-39 mnemonic with the given word count.

    Supported counts: 12, 15, 18, 21, 24.
    """
    if word_count not in SUPPORTED_STRENGTHS:
        raise ValueError(
            f"Unsupported word count {word_count}. "
            f"Choose from {list(SUPPORTED_STRENGTHS.keys())}."
        )
    m = Mnemonic("english")
    return m.generate(strength=SUPPORTED_STRENGTHS[word_count])


def derive_key_pair(
    seed: bytes,
    coin_symbol: str,
    account: int = 0,
    change: int = 0,
    index: int = 0,
) -> Tuple[str, bytes, bytes]:
    """Derive a single key-pair at a BIP-44 path.

    Returns ``(path_string, private_key_bytes, public_key_bytes)``.
    The public key is in SEC1 compressed form (33 bytes).
    """
    if coin_symbol not in COIN_TYPES:
        raise ValueError(f"Unsupported coin: {coin_symbol}")

    coin_type = COIN_TYPES[coin_symbol]
    path = f"m/44'/{coin_type}'/{account}'/{change}/{index}"

    key_int, _chain = _derive_path(seed, path)
    privkey = _ser256(key_int)
    pubkey = _point(key_int)
    return path, privkey, pubkey


def derive_keys_batch(
    seed: bytes,
    coin_symbol: str,
    account: int = 0,
    num_addresses: int = 5,
    include_change: bool = True,
) -> List[dict]:
    """Derive multiple key-pairs for both receiving and (optionally) change chains.

    Returns a list of dicts with keys: path, index, type, private_key, public_key.
    """
    results: List[dict] = []
    chains = [0, 1] if include_change else [0]
    for ch in chains:
        address_type = "receiving" if ch == 0 else "change"
        for idx in range(num_addresses):
            path, privkey, pubkey = derive_key_pair(
                seed, coin_symbol, account=account, change=ch, index=idx
            )
            results.append(
                {
                    "path": path,
                    "index": idx,
                    "type": address_type,
                    "private_key": privkey.hex(),
                    "public_key": pubkey.hex(),
                }
            )
    return results
