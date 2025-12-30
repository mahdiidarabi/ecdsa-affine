# Quick Start Guide

## Installation

First, install the required dependency:

```bash
pip install ecdsa
```

Or install from requirements:

```bash
pip install -r ../requirements.txt
```

## Basic Usage

### Step 1: Prepare Your Signatures

Create a JSON file with your signatures. Each signature needs:
- `z`: Message hash (or `message` field that will be hashed)
- `r`: r component of signature
- `s`: s component of signature

Example (`my_signatures.json`):
```json
[
    {
        "z": "0x1234567890abcdef...",
        "r": "0xabcdef1234567890...",
        "s": "0x567890abcdef1234..."
    },
    {
        "z": "0xfedcba0987654321...",
        "r": "0x0987654321fedcba...",
        "s": "0x4321fedcba098765..."
    }
]
```

### Step 2: Run the Recovery

#### Option A: If you know the affine relationship

If you know that `k2 = a*k1 + b`:

```bash
python main_recovery.py \
    --signatures my_signatures.json \
    --known-a 1 \
    --known-b 1 \
    --public-key <your_public_key_hex>
```

#### Option B: Smart brute-force (recommended)

Tries common patterns first:

```bash
python main_recovery.py \
    --signatures my_signatures.json \
    --smart-brute \
    --public-key <your_public_key_hex>
```

#### Option C: Full brute-force

Searches a range of values:

```bash
python main_recovery.py \
    --signatures my_signatures.json \
    --brute-force \
    --a-range -10,10 \
    --b-range -10,10 \
    --max-pairs 100
```

## Getting Signatures from Blockchain

### Ethereum

For Ethereum transactions, you can extract r, s from transaction data:

```python
from blockchain_helper import extract_signatures_from_address

# Your transaction data (from blockchain explorer API)
transactions = [
    {
        "hash": "0x...",
        "r": "0x...",
        "s": "0x...",
        "from": "0xYourAddress"
    },
    # ... more transactions
]

signatures = extract_signatures_from_address(
    "0xYourAddress",
    transactions,
    blockchain='ethereum'
)
```

### Bitcoin

Similar approach for Bitcoin:

```python
from blockchain_helper import extract_signatures_from_address

signatures = extract_signatures_from_address(
    "YourBitcoinAddress",
    transactions,
    blockchain='bitcoin'
)
```

## Common Affine Relationships

The attack works when nonces have relationships like:
- `k2 = k1 + 1` (counter-based)
- `k2 = k1 - 1`
- `k2 = 2*k1` (doubling)
- `k2 = k1 + c` (constant offset)
- `k2 = a*k1 + b` (general affine)

## Tips

1. **More signatures = better chance**: The more signatures you have, the more pairs you can test
2. **Public key verification**: Always provide `--public-key` if you have it to verify the recovered key
3. **Start with smart-brute**: It's faster and covers common cases
4. **Adjust ranges**: If smart-brute fails, try wider ranges in full brute-force

## Example Output

```
Loading signatures from my_signatures.json...
Loaded 10 signatures
Trying common affine patterns first...
[+] Successfully recovered private key!
    Private key: 1234567890...
    Relationship: k2 = 1*k1 + 1
    Signature pair: (0, 3)
    ✓ Verified against public key!
```

## Troubleshooting

- **"Need at least 2 signatures"**: You need at least 2 signatures to test pairs
- **"Could not recover private key"**: Try wider ranges or check if signatures actually have affine relationship
- **ModuleNotFoundError**: Run `pip install ecdsa`

