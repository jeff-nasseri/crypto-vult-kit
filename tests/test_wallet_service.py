"""Unit tests for CryptoVaultKit.

The test suite:
  1. Generates valid BIP-39 seed phrases (12 and 24 words).
  2. Creates wallets for every supported coin using the application layer.
  3. Verifies that private keys, public keys, and addresses are produced
     correctly and are non-empty/unique.
  4. Tests seed-only generation.
  5. Tests JSON export round-trip.
"""

import json
import os
import tempfile
import unittest

from src.application.wallet_service import (
    export_wallets_json,
    generate_seed,
    generate_wallet,
    recover_wallet,
)
from src.infrastructure.key_derivation import (
    SUPPORTED_COINS,
    validate_mnemonic,
    generate_mnemonic,
)


class TestSeedGeneration(unittest.TestCase):
    """Tests for BIP-39 mnemonic generation."""

    def test_generate_12_word_seed(self):
        phrase = generate_seed(word_count=12)
        words = phrase.strip().split()
        self.assertEqual(len(words), 12)
        self.assertTrue(validate_mnemonic(phrase))

    def test_generate_24_word_seed(self):
        phrase = generate_seed(word_count=24)
        words = phrase.strip().split()
        self.assertEqual(len(words), 24)
        self.assertTrue(validate_mnemonic(phrase))

    def test_generate_seed_invalid_word_count(self):
        with self.assertRaises(ValueError):
            generate_seed(word_count=13)

    def test_generated_seeds_are_unique(self):
        seeds = {generate_seed(24) for _ in range(5)}
        self.assertEqual(len(seeds), 5, "Generated seeds should be unique")


class TestWalletRecovery(unittest.TestCase):
    """Tests that recover_wallet produces valid key material for all coins."""

    @classmethod
    def setUpClass(cls):
        """Generate a single seed phrase and recover all supported wallets."""
        cls.seed_phrase = generate_mnemonic(word_count=24)
        cls.wallets = recover_wallet(
            cls.seed_phrase,
            passphrase="",
            coins=None,  # all supported
            account=0,
            num_addresses=2,
            include_change=False,
        )

    def test_all_supported_coins_recovered(self):
        for coin in SUPPORTED_COINS:
            self.assertIn(coin, self.wallets, f"{coin} missing from recovered wallets")

    def test_addresses_not_empty(self):
        for coin, wallet in self.wallets.items():
            self.assertGreater(
                len(wallet["addresses"]), 0,
                f"{coin} wallet has no addresses",
            )

    def test_private_keys_are_hex_and_correct_length(self):
        for coin, wallet in self.wallets.items():
            for entry in wallet["addresses"]:
                pk = entry["private_key"]
                self.assertEqual(
                    len(pk), 64,
                    f"{coin} private key length != 64 hex chars: {pk}",
                )
                # Verify it's valid hex
                int(pk, 16)

    def test_public_keys_are_hex(self):
        for coin, wallet in self.wallets.items():
            for entry in wallet["addresses"]:
                pub = entry["public_key"]
                self.assertTrue(len(pub) > 0)
                int(pub, 16)

    def test_addresses_are_non_empty_strings(self):
        for coin, wallet in self.wallets.items():
            for entry in wallet["addresses"]:
                addr = entry["address"]
                self.assertIsInstance(addr, str)
                self.assertTrue(len(addr) > 0, f"{coin} address is empty")

    def test_btc_address_starts_with_1(self):
        """P2PKH Bitcoin addresses start with '1'."""
        for entry in self.wallets["BTC"]["addresses"]:
            self.assertTrue(
                entry["address"].startswith("1"),
                f"BTC address does not start with 1: {entry['address']}",
            )

    def test_ltc_address_starts_with_L(self):
        for entry in self.wallets["LTC"]["addresses"]:
            self.assertTrue(
                entry["address"].startswith("L"),
                f"LTC address does not start with L: {entry['address']}",
            )

    def test_doge_address_starts_with_D(self):
        for entry in self.wallets["DOGE"]["addresses"]:
            self.assertTrue(
                entry["address"].startswith("D"),
                f"DOGE address does not start with D: {entry['address']}",
            )

    def test_eth_address_starts_with_0x(self):
        for entry in self.wallets["ETH"]["addresses"]:
            self.assertTrue(
                entry["address"].startswith("0x"),
                f"ETH address does not start with 0x: {entry['address']}",
            )
            # Ethereum address is 42 chars (0x + 40 hex)
            self.assertEqual(len(entry["address"]), 42)

    def test_unique_addresses_per_coin(self):
        for coin, wallet in self.wallets.items():
            addrs = [e["address"] for e in wallet["addresses"]]
            self.assertEqual(
                len(addrs), len(set(addrs)),
                f"{coin} has duplicate addresses",
            )

    def test_unique_private_keys_per_coin(self):
        for coin, wallet in self.wallets.items():
            keys = [e["private_key"] for e in wallet["addresses"]]
            self.assertEqual(
                len(keys), len(set(keys)),
                f"{coin} has duplicate private keys",
            )

    def test_deterministic_recovery(self):
        """Recovering the same seed phrase twice must produce identical results."""
        wallets2 = recover_wallet(
            self.seed_phrase,
            passphrase="",
            coins=None,
            account=0,
            num_addresses=2,
            include_change=False,
        )
        for coin in SUPPORTED_COINS:
            for i, entry in enumerate(self.wallets[coin]["addresses"]):
                entry2 = wallets2[coin]["addresses"][i]
                self.assertEqual(entry["private_key"], entry2["private_key"])
                self.assertEqual(entry["address"], entry2["address"])


class TestWalletGeneration(unittest.TestCase):
    """Tests for the generate_wallet use-case."""

    def test_generate_wallet_returns_seed_and_wallets(self):
        result = generate_wallet(
            word_count=12,
            coins=["BTC"],
            num_addresses=1,
            include_change=False,
        )
        self.assertIn("seed_phrase", result)
        self.assertIn("wallets", result)
        self.assertTrue(validate_mnemonic(result["seed_phrase"]))
        self.assertIn("BTC", result["wallets"])

    def test_generated_wallet_keys_match_recovery(self):
        """Keys from generate_wallet must match a subsequent recover_wallet."""
        result = generate_wallet(
            word_count=24,
            coins=["BTC", "ETH"],
            num_addresses=2,
            include_change=False,
        )
        recovered = recover_wallet(
            result["seed_phrase"],
            coins=["BTC", "ETH"],
            num_addresses=2,
            include_change=False,
        )
        for coin in ["BTC", "ETH"]:
            for i, entry in enumerate(result["wallets"][coin]["addresses"]):
                rec = recovered[coin]["addresses"][i]
                self.assertEqual(entry["private_key"], rec["private_key"])
                self.assertEqual(entry["address"], rec["address"])


class TestInvalidInputs(unittest.TestCase):
    def test_invalid_seed_phrase_raises(self):
        with self.assertRaises(ValueError):
            recover_wallet("not a valid seed phrase at all")

    def test_unsupported_coin_raises(self):
        seed = generate_seed(12)
        with self.assertRaises(ValueError):
            recover_wallet(seed, coins=["FAKECOIN"])


class TestExportJson(unittest.TestCase):
    def test_export_and_read_back(self):
        seed = generate_seed(12)
        wallets = recover_wallet(seed, coins=["BTC"], num_addresses=1, include_change=False)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as tmp:
            tmp_path = tmp.name

        try:
            export_wallets_json(wallets, tmp_path, include_private_keys=True)
            with open(tmp_path, "r") as fh:
                data = json.load(fh)
            self.assertIn("BTC", data)
            self.assertNotEqual(data["BTC"]["addresses"][0]["private_key"], "HIDDEN")
        finally:
            os.unlink(tmp_path)

    def test_export_hides_private_keys(self):
        seed = generate_seed(12)
        wallets = recover_wallet(seed, coins=["BTC"], num_addresses=1, include_change=False)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as tmp:
            tmp_path = tmp.name

        try:
            export_wallets_json(wallets, tmp_path, include_private_keys=False)
            with open(tmp_path, "r") as fh:
                data = json.load(fh)
            self.assertEqual(data["BTC"]["addresses"][0]["private_key"], "HIDDEN")
        finally:
            os.unlink(tmp_path)


if __name__ == "__main__":
    unittest.main()
