"""Command-line interface for CryptoVaultKit.

Supported commands
------------------
  recover   - Derive wallets from an existing seed phrase
  generate  - Create a new wallet (seed + keys)
  seed      - Generate a new BIP-39 seed phrase only
"""

import argparse
import getpass
import sys
import json

from src.application.wallet_service import (
    export_wallets_json,
    generate_seed,
    generate_wallet,
    recover_wallet,
)
from src.infrastructure.key_derivation import SUPPORTED_COINS


# ── Helpers ─────────────────────────────────────────────────────────────────

_SEP = "=" * 80
_THIN = "-" * 80

_BANNER = r"""
 ======================================================
   CryptoVaultKit  -  Trezor Wallet Recovery & Manager
 ======================================================

  SECURITY WARNINGS:
  * Use only on an OFFLINE / air-gapped computer
  * NEVER share your seed phrase or private keys
  * Delete exported files and clear terminal history
"""


def _print_banner() -> None:
    print(_BANNER)


def _read_seed_phrase(args) -> str:
    """Read the seed phrase from --seed-phrase or prompt interactively."""
    if args.seed_phrase:
        return args.seed_phrase
    print("Enter your seed phrase (words separated by spaces):")
    return getpass.getpass(prompt="> ")


def _print_wallet(wallet: dict, show_private_keys: bool = False) -> None:
    """Pretty-print a single wallet dict."""
    print(f"\n{_SEP}")
    print(f"  {wallet['coin']} Wallet  (account {wallet['account']})")
    print(_SEP)
    for entry in wallet["addresses"]:
        print(f"  Path       : {entry['path']}")
        print(f"  Type       : {entry['type']}  #{entry['index']}")
        print(f"  Address    : {entry['address']}")
        print(f"  Public Key : {entry['public_key']}")
        if show_private_keys:
            print(f"  Private Key: {entry['private_key']}")
        else:
            print(f"  Private Key: {'*' * 64}  (hidden)")
        print(_THIN)


# ── Commands ────────────────────────────────────────────────────────────────

def cmd_recover(args) -> None:
    seed_phrase = _read_seed_phrase(args)
    coins = [c.strip().upper() for c in args.coins.split(",")] if args.coins else None

    wallets = recover_wallet(
        seed_phrase,
        passphrase=args.passphrase or "",
        coins=coins,
        account=args.account,
        num_addresses=args.num_addresses,
        include_change=not args.no_change,
    )

    for wallet in wallets.values():
        _print_wallet(wallet, show_private_keys=args.show_keys)

    if args.export:
        export_wallets_json(wallets, args.export, include_private_keys=args.show_keys)
        print(f"\nExported to {args.export}")


def cmd_generate(args) -> None:
    coins = [c.strip().upper() for c in args.coins.split(",")] if args.coins else None

    result = generate_wallet(
        word_count=args.words,
        passphrase=args.passphrase or "",
        coins=coins,
        account=args.account,
        num_addresses=args.num_addresses,
        include_change=not args.no_change,
    )

    print(f"\n{_SEP}")
    print("  NEW SEED PHRASE  (write this down and store securely!)")
    print(_SEP)
    print(f"\n  {result['seed_phrase']}\n")
    print(f"  Word count: {args.words}")
    print(_SEP)

    for wallet in result["wallets"].values():
        _print_wallet(wallet, show_private_keys=args.show_keys)

    if args.export:
        export_wallets_json(
            result["wallets"], args.export, include_private_keys=args.show_keys
        )
        print(f"\nExported to {args.export}")


def cmd_seed(args) -> None:
    phrase = generate_seed(word_count=args.words)
    print(f"\n{_SEP}")
    print("  NEW SEED PHRASE  (write this down and store securely!)")
    print(_SEP)
    print(f"\n  {phrase}\n")
    print(f"  Word count: {args.words}")
    print(_SEP)


# ── Argument parser ─────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptovaultkit",
        description="CryptoVaultKit - Trezor wallet recovery and generation tool",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # -- recover --
    p_recover = subparsers.add_parser("recover", help="Recover wallets from a seed phrase")
    p_recover.add_argument("--seed-phrase", type=str, default=None,
                           help="BIP-39 seed phrase (prompted if omitted)")
    p_recover.add_argument("--passphrase", type=str, default="",
                           help="Optional BIP-39 passphrase (25th word)")
    p_recover.add_argument("--coins", type=str, default=None,
                           help=f"Comma-separated coin list (default: all). Supported: {','.join(SUPPORTED_COINS)}")
    p_recover.add_argument("--account", type=int, default=0,
                           help="BIP-44 account index (default: 0)")
    p_recover.add_argument("--num-addresses", type=int, default=5,
                           help="Number of addresses per chain (default: 5)")
    p_recover.add_argument("--no-change", action="store_true",
                           help="Skip change-chain addresses")
    p_recover.add_argument("--show-keys", action="store_true",
                           help="Display private keys in output")
    p_recover.add_argument("--export", type=str, default=None,
                           help="Export results to a JSON file")
    p_recover.set_defaults(func=cmd_recover)

    # -- generate --
    p_gen = subparsers.add_parser("generate", help="Generate a new wallet with seed phrase")
    p_gen.add_argument("--words", type=int, default=24, choices=[12, 15, 18, 21, 24],
                       help="Mnemonic word count (default: 24)")
    p_gen.add_argument("--passphrase", type=str, default="",
                       help="Optional BIP-39 passphrase")
    p_gen.add_argument("--coins", type=str, default=None,
                       help=f"Comma-separated coin list (default: all). Supported: {','.join(SUPPORTED_COINS)}")
    p_gen.add_argument("--account", type=int, default=0,
                       help="BIP-44 account index (default: 0)")
    p_gen.add_argument("--num-addresses", type=int, default=5,
                       help="Number of addresses per chain (default: 5)")
    p_gen.add_argument("--no-change", action="store_true",
                       help="Skip change-chain addresses")
    p_gen.add_argument("--show-keys", action="store_true",
                       help="Display private keys in output")
    p_gen.add_argument("--export", type=str, default=None,
                       help="Export results to a JSON file")
    p_gen.set_defaults(func=cmd_generate)

    # -- seed --
    p_seed = subparsers.add_parser("seed", help="Generate a new BIP-39 seed phrase")
    p_seed.add_argument("--words", type=int, default=24, choices=[12, 15, 18, 21, 24],
                        help="Mnemonic word count (default: 24)")
    p_seed.set_defaults(func=cmd_seed)

    return parser


def main(argv=None) -> None:
    _print_banner()
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        sys.exit(0)

    try:
        args.func(args)
    except ValueError as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(130)
