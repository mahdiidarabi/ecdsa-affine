# ECDSA Private Key Recovery from Affinely Related Nonces

A Golang implementation for recovering ECDSA private keys when nonces have an affine relationship, with Python scripts for generating test fixtures.

Based on the paper: **"Breaking ECDSA with Two Affinely Related Nonces"**  
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

## 🏗️ Project Structure

```
.
├── cmd/
│   └── recovery/              # Go CLI tool for key recovery
├── internal/
│   ├── recovery/              # Core ECDSA recovery algorithm (Go)
│   ├── parser/                # Signature parsing from JSON/CSV (Go)
│   └── bruteforce/            # Brute-force affine relationship discovery (Go)
├── scripts/                   # Python scripts for generating fixtures
│   ├── generate_fixtures.py  # Generate test signatures
│   └── flawed_signer.py      # Create signatures with vulnerabilities
├── fixtures/                  # Generated test fixtures (gitignored)
└── go.mod                     # Go module definition
```

---

## 🚀 Quick Start

### Prerequisites

**For Go implementation:**
- Go 1.21 or later

**For Python fixture generation:**
```bash
pip install ecdsa
```

### Step 1: Generate Test Fixtures

Create signatures with known vulnerabilities:

```bash
make fixtures
```

Or directly:

```bash
cd scripts && python3 generate_fixtures.py
```

This creates test signatures in the `fixtures/` directory:
- `test_signatures_same_nonce.json` - Same nonce reuse
- `test_signatures_counter.json` - Counter-based nonces
- `test_signatures_affine.json` - Affine relationships
- `test_key_info.json` - Original keys for verification

### Step 2: Build Go Recovery Tool

```bash
make build
```

Or:

```bash
go build -o bin/recovery ./cmd/recovery
```

### Step 3: Recover Private Key

#### Option 1: Known Affine Relationship

If you know the relationship (e.g., `k2 = 2*k1 + 1`):

```bash
./bin/recovery \
    --signatures fixtures/test_signatures_affine.json \
    --known-a 2 \
    --known-b 1 \
    --public-key <public_key_hex>
```

#### Option 2: Smart Brute-Force (Recommended)

Automatically tries common patterns:

```bash
./bin/recovery \
    --signatures fixtures/test_signatures_counter.json \
    --smart-brute \
    --public-key <public_key_hex>
```

#### Option 3: Full Brute-Force (Parallel)

Search a range of values using parallel workers for faster processing:

```bash
./bin/recovery \
    --signatures fixtures/test_signatures_affine.json \
    --brute-force \
    --a-range -10,10 \
    --b-range -10,10 \
    --max-pairs 100 \
    --workers 0 \
    --public-key <public_key_hex>
```

**Note**: The `--workers` flag controls parallel processing:
- `0` (default): Auto-detect based on CPU cores (recommended)
- `N`: Use N parallel workers (e.g., `--workers 8`)

For large search ranges, parallel processing provides significant speedup:
```bash
# Large range search with parallel workers
./bin/recovery \
    --signatures fixtures/test_signatures_counter.json \
    --brute-force \
    --a-range -100000,100000 \
    --b-range -100000,100000 \
    --max-pairs 500 \
    --workers 16 \
    --public-key <public_key_hex>
```

### Example: Recovering from Test Signatures

```bash
# Get the public key from test data
PUBKEY=$(python3 -c "import json; print(json.load(open('fixtures/test_key_info.json'))['public_key_hex'])")

# Recover using same nonce (k2 = 1*k1 + 0)
./bin/recovery \
    --signatures fixtures/test_signatures_same_nonce.json \
    --known-a 1 \
    --known-b 0 \
    --public-key $PUBKEY

# Or use smart brute-force
./bin/recovery \
    --signatures fixtures/test_signatures_counter.json \
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

## 🏗️ Code Architecture & Flow

### Go Module Structure

```
internal/
├── recovery/          # Core recovery algorithm
│   └── ecdsa_recovery.go
├── parser/            # Signature parsing
│   └── signature_parser.go
└── bruteforce/        # Affine relationship discovery
    └── brute_force.go
```

### Code Flow

```
┌─────────────────┐
│  Signatures     │
│  (JSON/CSV)     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ parser           │
│ Parse & Extract  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐      ┌──────────────────┐
│ Known (a, b)?  │ YES  │ RecoverPrivateKey │
│                 ├─────▶│ Affine()         │
└────────┬────────┘      └────────┬─────────┘
         │                         │
         │ NO                      ▼
         ▼                  ┌──────────────┐
┌─────────────────┐         │ Private Key  │
│ SmartBruteForce │         └──────────────┘
│ or BruteForce   │
│ (Parallel)      │
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
│ Parallel Workers│
│ (Goroutines)    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Try all pairs   │
│ Test (a, b)     │
│ (Concurrent)    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ VerifyRecovered │
│ Key()           │
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

## 🛠️ CLI Usage

### Command-Line Options

```bash
./bin/recovery --help
```

Options:
- `--signatures`: Path to signatures file (JSON or CSV) **[required]**
- `--format`: File format (json or csv, default: json)
- `--public-key`: Public key in hex format (compressed, 66 chars) for verification
- `--known-a`: Known affine coefficient a (k2 = a*k1 + b)
- `--known-b`: Known affine offset b (k2 = a*k1 + b)
- `--smart-brute`: Use smart brute-force (tries common patterns first, then parallel search)
- `--brute-force`: Full brute-force search for affine relationship (uses parallel workers)
- `--a-range`: Range for a values in brute-force (format: min,max, default: -100,100)
- `--b-range`: Range for b values in brute-force (format: min,max, default: -100,100)
- `--max-pairs`: Maximum signature pairs to test in brute-force (default: 100)
- `--workers`: Number of parallel workers (0 = auto-detect based on CPU cores, default: 0)

### Example Output

```
Loading signatures from fixtures/test_signatures_counter.json...
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
  - **Sequential**: Linear time complexity
  - **Parallel**: Near-linear speedup with multiple CPU cores
  - Example: 16 workers on 16-core CPU ≈ 10-15x faster for large ranges

### Parallel Processing

The brute-force search uses parallel workers to significantly speed up large searches:

- **Auto-detection**: Automatically uses all available CPU cores (default)
- **Manual control**: Specify worker count with `--workers N`
- **Early termination**: Stops all workers immediately when a result is found
- **Progress reporting**: Shows tested combinations every 50,000 attempts

**Example performance**:
```bash
# Small range (sequential is fine)
--a-range -100,100 --b-range -100,100
# Time: ~100ms

# Large range (parallel recommended)
--a-range -100000,100000 --b-range -100000,100000 --workers 16
# Time: ~10-15x faster than sequential
```

---

## 🧪 Testing

### Run Go Tests

```bash
make test
```

Or:

```bash
go test ./...
```

### Generate Fixtures

```bash
make fixtures
```

### Clean Generated Files

```bash
make clean
```

Removes generated fixtures and build artifacts.

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

## 🛠️ Makefile Commands

- `make fixtures` - Generate test fixtures using Python scripts
- `make build` - Build the Go recovery tool
- `make test` - Run Go tests
- `make clean` - Remove generated files and build artifacts

---

## 📝 Python Scripts (Fixture Generation Only)

The Python scripts are kept **only** for generating test fixtures:

- `scripts/generate_fixtures.py` - Main fixture generator
- `scripts/flawed_signer.py` - Creates signatures with vulnerabilities

All key recovery functionality has been implemented in Go for better performance and type safety.
