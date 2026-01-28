# CryptoVaultKit

A command-line tool for recovering and generating cryptocurrency wallets using BIP-39 seed phrases. Designed for Trezor hardware wallet users who need to derive private keys and addresses from their seed phrases.

## Security Warnings

- **Use only on an offline / air-gapped computer.**
- **Never share your seed phrase or private keys.**
- **Delete exported files and clear terminal history after use.**

## Supported Cryptocurrencies

| Coin | Symbol | BIP-44 Coin Type |
|------|--------|-----------------|
| Bitcoin | BTC | 0 |
| Ethereum | ETH | 60 |
| Litecoin | LTC | 2 |
| Dogecoin | DOGE | 3 |
| Bitcoin Cash | BCH | 145 |

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Recover wallets from a seed phrase

```bash
python main.py recover --show-keys
python main.py recover --seed-phrase "your seed phrase here" --coins BTC,ETH --show-keys
python main.py recover --coins BTC --num-addresses 10 --export wallets.json --show-keys
```

### Generate a new wallet

```bash
python main.py generate --words 24 --show-keys
python main.py generate --words 12 --coins BTC,ETH --show-keys
```

### Generate a seed phrase only

```bash
python main.py seed --words 24
python main.py seed --words 12
```

## CLI Options

### `recover`
| Option | Description |
|--------|-------------|
| `--seed-phrase` | BIP-39 seed phrase (prompted securely if omitted) |
| `--passphrase` | Optional BIP-39 passphrase (25th word) |
| `--coins` | Comma-separated coin list (default: all supported) |
| `--account` | BIP-44 account index (default: 0) |
| `--num-addresses` | Addresses per chain (default: 5) |
| `--no-change` | Skip change-chain addresses |
| `--show-keys` | Display private keys |
| `--export` | Export to JSON file |

### `generate`
Same options as `recover` (except `--seed-phrase`) plus:
| Option | Description |
|--------|-------------|
| `--words` | Mnemonic word count: 12, 15, 18, 21, 24 (default: 24) |

### `seed`
| Option | Description |
|--------|-------------|
| `--words` | Mnemonic word count: 12, 15, 18, 21, 24 (default: 24) |

## Project Structure

```
CryptoVaultKit/
  main.py                          # Entry point
  src/
    infrastructure/
      encoding.py                  # Base58, hashing utilities
      address_gen.py               # Address generation per coin
      key_derivation.py            # BIP-32/39/44 key derivation
    application/
      wallet_service.py            # Use-cases (recover, generate, export)
    presentation/
      cli.py                       # CLI argument parsing and output
  tests/
    test_wallet_service.py         # Unit tests
```

## License

Proprietary - see [LICENSE](LICENSE).
