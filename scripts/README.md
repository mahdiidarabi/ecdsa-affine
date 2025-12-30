# ECDSA Private Key Recovery from Affinely Related Nonces

This implementation is based on the paper:
**"Breaking ECDSA with Two Affinely Related Nonces"**
by Jamie Gilchrist, William J. Buchanan, Keir Finlow-Bates (arXiv:2504.13737)

---

## 📄 Paper Summary

### The Vulnerability

ECDSA security depends on unique, secret nonces (`k`) for each signature. While it's well-known that **nonce reuse** can leak the private key, this paper shows that even when nonces are **different** but **affinely related**, the private key can still be recovered.

### The Attack

If two signatures use nonces with an affine relationship:
```
k₂ = a·k₁ + b
```
where `a` and `b` are known (or can be guessed), the private key can be recovered using **only two signatures** (even over the same message) through **pure algebra** - no lattice reduction or brute-force search needed.

### Key Formula

The paper derives a closed-form solution (Equation 7):
```
priv = (a·s₂·z₁ - s₁·z₂ + b·s₁·s₂) / (r₂·s₁ - a·r₁·s₂) mod n
```

Where:
- `z₁, z₂`: Message hashes
- `r₁, s₁, r₂, s₂`: Signature components
- `a, b`: Affine relationship coefficients
- `n`: Curve order (secp256k1)

### Real-World Scenarios

This vulnerability occurs when:
- **Counter-based nonces**: `k₂ = k₁ + 1` (common in flawed implementations)
- **Linear recurrence**: `k₂ = 2·k₁ + 1` (predictable patterns)
- **Same nonce reuse**: `k₂ = k₁` (special case: `a=1, b=0`)
- **Any affine relationship**: `k₂ = a·k₁ + b` where `a` and `b` are known

---

## 🏗️ Code Architecture & Flow

### Module Structure

```
test/
├── ecdsa_recovery.py          # Core recovery algorithm
├── signature_parser.py        # Parse signatures from files
├── brute_force_affine.py     # Find affine relationships
├── main_recovery.py           # CLI tool
├── flawed_signer.py           # Generate test signatures
└── test_recovery.py           # Test suite
```

### Code Flow

#### 1. **Signature Input** (`signature_parser.py`)
```
JSON/CSV File → Parse → Extract (z, r, s) tuples
```
- Reads signature files (JSON or CSV)
- Extracts message hashes (`z`) and signature components (`r`, `s`)
- Handles hex strings and integers

#### 2. **Key Recovery** (`ecdsa_recovery.py`)
```
(z₁, r₁, s₁), (z₂, r₂, s₂), (a, b) → recover_private_key_affine() → private_key
```
- Implements the paper's formula
- Calculates numerator and denominator
- Performs modular arithmetic and inversion
- Returns private key or `None` if recovery fails

#### 3. **Relationship Discovery** (`brute_force_affine.py`)
```
Multiple signatures → smart_brute_force() → (a, b, private_key)
```
- **Smart brute-force**: Tries common patterns first (counter, doubling, etc.)
- **Full brute-force**: Searches specified ranges of `a` and `b`
- Tests all signature pairs
- Verifies recovered keys against public key (if provided)

#### 4. **Verification** (`ecdsa_recovery.py`)
```
private_key + public_key → verify_recovered_key() → True/False
```
- Reconstructs public key from private key
- Compares with provided public key
- Ensures recovery accuracy

#### 5. **CLI Interface** (`main_recovery.py`)
```
Command-line arguments → Parse signatures → Recovery → Output
```
- Handles command-line arguments
- Orchestrates the recovery process
- Provides user-friendly output

---

## 🚀 How to Run

### Prerequisites

```bash
pip install ecdsa
```

### Quick Start: Test the Implementation

#### Step 1: Generate Test Signatures

Create signatures with known vulnerabilities:

```bash
cd test
python3 flawed_signer.py
```

This creates:
- `test_signatures_same_nonce.json` - Same nonce reuse
- `test_signatures_counter.json` - Counter-based nonces
- `test_signatures_affine.json` - Affine relationships
- `test_key_info.json` - Original keys for verification

#### Step 2: Run Test Suite

Verify the implementation works:

```bash
python3 test_recovery.py
```

Expected output:
```
✓ Same Nonce                     ✓ PASSED
✓ Counter Nonce                  ✓ PASSED
✓ Affine Nonce                   ✓ PASSED
✓ Smart Brute-Force              ✓ PASSED

Total: 4/4 tests passed
```

### Using with Your Own Signatures

#### Option 1: Known Affine Relationship

If you know the relationship (e.g., `k2 = 2*k1 + 1`):

```bash
python3 main_recovery.py \
    --signatures your_signatures.json \
    --known-a 2 \
    --known-b 1 \
    --public-key 03ade716fc183991226652898ac1b24b6b1847b80bcb9caab9e5e2d16ba81e21fd
```

#### Option 2: Smart Brute-Force (Recommended)

Automatically tries common patterns:

```bash
python3 main_recovery.py \
    --signatures your_signatures.json \
    --smart-brute \
    --public-key 03ade716fc183991226652898ac1b24b6b1847b80bcb9caab9e5e2d16ba81e21fd
```

#### Option 3: Full Brute-Force

Search a range of values:

```bash
python3 main_recovery.py \
    --signatures your_signatures.json \
    --brute-force \
    --a-range -10,10 \
    --b-range -10,10 \
    --max-pairs 100 \
    --public-key 03ade716fc183991226652898ac1b24b6b1847b80bcb9caab9e5e2d16ba81e21fd
```

### Example: Recovering from Test Signatures

```bash
# Get the public key from test data
PUBKEY=$(python3 -c "import json; print(json.load(open('test_key_info.json'))['public_key_hex'])")

# Recover using same nonce (k2 = 1*k1 + 0)
python3 main_recovery.py \
    --signatures test_signatures_same_nonce.json \
    --known-a 1 --known-b 0 \
    --public-key $PUBKEY

# Or use smart brute-force
python3 main_recovery.py \
    --signatures test_signatures_counter.json \
    --smart-brute \
    --public-key $PUBKEY
```

---

## 📋 Signature File Format

### JSON Format

**Option 1: With messages** (will be hashed automatically):
```json
[
    {
        "message": "Transaction 1",
        "r": "0xabcdef1234567890...",
        "s": "0x1234567890abcdef..."
    },
    {
        "message": "Transaction 2",
        "r": "0xfedcba0987654321...",
        "s": "0x654321fedcba0987..."
    }
]
```

**Option 2: With pre-computed hashes**:
```json
[
    {
        "z": "0x1234567890abcdef...",
        "r": "0xabcdef1234567890...",
        "s": "0x1234567890abcdef..."
    }
]
```

### CSV Format

```csv
message,r,s
Transaction 1,0xabcdef...,0x123456...
Transaction 2,0xfedcba...,0x654321...
```

---

## 🔍 Common Nonce Patterns

The smart brute-force automatically tries these patterns:

| Pattern | Relationship | Description |
|---------|-------------|-------------|
| Counter | `k₂ = k₁ + 1` | Sequential nonces |
| Reverse | `k₂ = k₁ - 1` | Decrementing |
| Doubling | `k₂ = 2·k₁` | Multiplicative |
| Offset | `k₂ = k₁ + c` | Constant offset |
| Same | `k₂ = k₁` | Nonce reuse |

---

## 📊 Code Flow Diagram

```
┌─────────────────┐
│  Signatures     │
│  (JSON/CSV)     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ signature_parser│
│ Parse & Extract │
└────────┬────────┘
         │
         ▼
┌─────────────────┐      ┌──────────────────┐
│ Known (a, b)?  │ YES  │ recover_private_ │
│                 ├─────▶│ key_affine()     │
└────────┬────────┘      └────────┬─────────┘
         │                         │
         │ NO                      ▼
         ▼                  ┌──────────────┐
┌─────────────────┐         │ Private Key  │
│ smart_brute_    │         └──────────────┘
│ force()         │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Try common      │
│ patterns        │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Try all pairs   │
│ Test (a, b)     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ verify_recovered│
│ _key()          │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Output Result   │
└─────────────────┘
```

---

## 🔬 Technical Details

### ECDSA Signature Components

For a message `m` and private key `d`:
1. Hash message: `z = H(m) mod n`
2. Generate nonce: `k` (should be random)
3. Calculate point: `(x, y) = k·G`
4. `r = x mod n`
5. `s = k⁻¹(z + r·d) mod n`

### The Attack

Given two signatures with `k₂ = a·k₁ + b`:
- We can algebraically solve for `d` (private key)
- No need to know the actual nonce values
- Works even if messages are the same

### Mathematical Foundation

The paper derives:
```
s₁ = k₁⁻¹(z₁ + r₁·d) mod n
s₂ = k₂⁻¹(z₂ + r₂·d) mod n
```

Substituting `k₂ = a·k₁ + b` and solving for `d` yields the recovery formula.

---

## ⚠️ Important Notes

- **Curve**: Works with secp256k1 (Bitcoin/Ethereum)
- **Minimum signatures**: Requires at least 2 signatures
- **Public key**: Optional but recommended for verification
- **Method**: Pure algebra - no lattice reduction needed
- **Performance**: Very fast (milliseconds for known relationships)

---

## 📚 References

- **Paper**: "Breaking ECDSA with Two Affinely Related Nonces" (arXiv:2504.13737)
- **Curve**: secp256k1 (SEC 2 standard)
- **Standards**: FIPS 186-5 (Digital Signature Standard)

---

## 🛠️ Module Reference

| Module | Purpose |
|--------|---------|
| `ecdsa_recovery.py` | Core recovery algorithm implementation |
| `signature_parser.py` | Parse signatures from JSON/CSV files |
| `brute_force_affine.py` | Discover affine relationships automatically |
| `main_recovery.py` | Command-line interface |
| `flawed_signer.py` | Generate test signatures with vulnerabilities |
| `test_recovery.py` | Comprehensive test suite |
| `blockchain_helper.py` | Utilities for blockchain signature extraction |

---

## 📝 Example Output

```
Loading signatures from test_signatures_counter.json...
Loaded 5 signatures
Trying common affine patterns first...

[+] Successfully recovered private key!
    Private key: 60279824925954705114613904638467962668241393876235654906963848484444800386691
    Relationship: k2 = 1*k1 + 1
    Signature pair: (0, 1)
    ✓ Verified against public key!
```

---

## 🎯 Use Cases

1. **Security Auditing**: Test ECDSA implementations for vulnerabilities
2. **Cryptographic Research**: Study nonce generation flaws
3. **Blockchain Analysis**: Recover keys from vulnerable wallets
4. **Educational**: Understand ECDSA security properties

---

## ⚡ Performance

- **Known relationship**: < 1ms per pair
- **Smart brute-force**: ~10-100ms (depends on signature count)
- **Full brute-force**: Varies with search range

---

For more details, see `QUICKSTART.md` and `TEST_RESULTS.md`.
