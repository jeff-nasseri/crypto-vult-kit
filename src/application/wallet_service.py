"""Application-layer service that orchestrates wallet operations.

This module exposes the core use-cases:
  * recover_wallet  - derive keys/addresses from an existing seed phrase
  * generate_wallet - create a brand-new seed phrase + first set of addresses
  * generate_seed   - create a new BIP-39 mnemonic (without deriving keys)
"""

from typing import Dict, List, Optional
import json

from src.infrastructure.key_derivation import (
    SUPPORTED_COINS,
    derive_keys_batch,
    generate_mnemonic,
    mnemonic_to_seed,
    validate_mnemonic,
)
from src.infrastructure.address_gen import generate_address


# ── Data helpers ────────────────────────────────────────────────────────────

def _enrich_with_addresses(keys: List[dict], coin_symbol: str) -> List[dict]:
    """Add an 'address' field to each key-pair dict."""
    for entry in keys:
        pubkey_bytes = bytes.fromhex(entry["public_key"])
        entry["address"] = generate_address(coin_symbol, pubkey_bytes)
    return keys


# ── Use-cases ───────────────────────────────────────────────────────────────

def recover_wallet(
    seed_phrase: str,
    passphrase: str = "",
    coins: Optional[List[str]] = None,
    account: int = 0,
    num_addresses: int = 5,
    include_change: bool = True,
) -> Dict[str, dict]:
    """Recover wallets for one or more coins from an existing seed phrase.

    Returns a dict keyed by coin symbol, each value containing:
      coin, account, addresses (list of key/address dicts).
    """
    if not validate_mnemonic(seed_phrase):
        raise ValueError("Invalid BIP-39 seed phrase.")

    seed = mnemonic_to_seed(seed_phrase, passphrase)
    target_coins = coins if coins else SUPPORTED_COINS

    wallets: Dict[str, dict] = {}
    for coin in target_coins:
        coin = coin.upper()
        if coin not in SUPPORTED_COINS:
            raise ValueError(f"Unsupported coin: {coin}")
        keys = derive_keys_batch(
            seed, coin, account=account,
            num_addresses=num_addresses,
            include_change=include_change,
        )
        _enrich_with_addresses(keys, coin)
        wallets[coin] = {
            "coin": coin,
            "account": account,
            "addresses": keys,
        }
    return wallets


def generate_wallet(
    word_count: int = 24,
    passphrase: str = "",
    coins: Optional[List[str]] = None,
    account: int = 0,
    num_addresses: int = 5,
    include_change: bool = True,
) -> Dict:
    """Generate a brand-new seed phrase and derive wallets from it.

    Returns a dict with keys: seed_phrase, wallets.
    """
    seed_phrase = generate_mnemonic(word_count)
    wallets = recover_wallet(
        seed_phrase,
        passphrase=passphrase,
        coins=coins,
        account=account,
        num_addresses=num_addresses,
        include_change=include_change,
    )
    return {
        "seed_phrase": seed_phrase,
        "wallets": wallets,
    }


def generate_seed(word_count: int = 24) -> str:
    """Generate a new BIP-39 mnemonic without deriving any keys."""
    return generate_mnemonic(word_count)


def export_wallets_json(
    wallets: Dict[str, dict],
    filepath: str,
    include_private_keys: bool = True,
) -> None:
    """Serialize wallet data to a JSON file.

    When *include_private_keys* is False the private_key field is replaced with
    'HIDDEN'.
    """
    import copy

    data = copy.deepcopy(wallets)
    if not include_private_keys:
        for coin_data in data.values():
            for addr in coin_data.get("addresses", []):
                addr["private_key"] = "HIDDEN"

    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
