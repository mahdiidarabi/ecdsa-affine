# ECDSA/EdDSA Affine Nonce Recovery

**Breaking ECDSA/EdDSA with Two Affinely Related Nonces** - A Go implementation of the key recovery attack described in [arXiv:2504.13737](2504.13737v1.pdf) by Jamie Gilchrist, William J. Buchanan, and Keir Finlow-Bates.

**This is a Go package.** All core logic (recovery, brute-force, parsing) is implemented in Go. Python is used only to generate test fixtures (vulnerable signatures) for testing; it is not required to use the package or the recovery tool.

## 🔬 Overview

**This is a security research tool** for analyzing cryptographic vulnerabilities in ECDSA and EdDSA signature implementations. It recovers private keys from signatures with affinely related nonces, enabling researchers to:

- **Test signature implementations** for nonce generation weaknesses
- **Analyze blockchain transactions** for vulnerable nonce patterns
- **Investigate real-world attacks** (e.g., UpBit 2025 Solana hack)
- **Research cryptographic vulnerabilities** in production systems

**⚠️ IMPORTANT: This tool is for legitimate security research only. Only use on systems you own or have explicit authorization to test.**

**Supported Algorithms:**
- **ECDSA** (secp256k1) - Standard random nonce vulnerabilities (Bitcoin, Ethereum, etc.)
- **EdDSA** (Ed25519) - **Flawed implementations** using random nonces (Solana, etc.)

**Note:** Standard EdDSA uses deterministic nonces and is secure. This tool targets **flawed EdDSA implementations** that use random nonces instead of deterministic ones, making them vulnerable to ECDSA-style attacks.

### Research Workflow

1. **Generate test fixtures** → Use provided scripts to create vulnerable signatures
2. **Run recovery tests** → Use test scripts to verify functionality
3. **Analyze real data** → Extract signatures from blockchain transactions or your implementations
4. **Review documentation** → Study strategy guides and implementation details

## 🚀 Quick Start

### Prerequisites

- **Go 1.21+** (required for building and running)
- **Python 3.6+** (required for generating test fixtures)
- Git (for cloning the repository)

### Installation

```bash
# Clone the repository
git clone https://github.com/mahdiidarabi/ecdsa-affine.git
cd ecdsa-affine

# Install Python dependencies (for fixture generation)
pip install -r scripts/requirements.txt
```

### As a Go Package

#### ECDSA (secp256k1)

```go
import "github.com/mahdiidarabi/ecdsa-affine/pkg/ecdsaaffine"

client := ecdsaaffine.NewClient()
result, err := client.RecoverKey(ctx, "signatures.json", "03...")
```

#### EdDSA (Ed25519)

```go
import "github.com/mahdiidarabi/ecdsa-affine/pkg/eddsaaffine"

client := eddsaaffine.NewClient()
result, err := client.RecoverKey(ctx, "eddsa_signatures.json", "public_key_hex")
```

See [pkg/README.md](pkg/README.md) for detailed package documentation and examples for both ECDSA and EdDSA.

### As a CLI Tool

**Recommended workflow for researchers:**

```bash
# 1. Build the ECDSA recovery tool
make build

# 2. Generate test fixtures (ECDSA and EdDSA)
make fixtures

# 3. Run ECDSA recovery test
./test_recovery.sh

# 4. Run EdDSA recovery test
./test_recovery_eddsa.sh
```

**Manual usage example:**
```bash
# Extract public key from fixtures (optional - for verification)
PUBKEY=$(python3 -c "import json; print(json.load(open('fixtures/test_key_info.json'))['public_key_hex'])")

# Run recovery with smart brute-force (recommended for unknown patterns)
# With public key (verifies recovered key):
./bin/recovery --signatures fixtures/test_signatures_hardcoded_step.json --smart-brute --public-key $PUBKEY

# Without public key (returns candidate keys without verification):
./bin/recovery --signatures fixtures/test_signatures_hardcoded_step.json --smart-brute
```

**Note:** The `--public-key` flag is **optional**. The tool can recover private keys without knowing the public key. When provided, the public key is used to verify that the recovered key is correct. Without it, the tool returns candidate keys that appear valid (in the correct range) but need manual verification.

## ✨ Features

### Multi-Phase Brute-Force Strategy

The tool uses an optimized multi-phase approach to efficiently recover keys:

1. **Phase 0: Statistical Analysis** - Pre-analyzes r values to detect patterns
2. **Phase 1: Fast Checks** - **Same nonce reuse detection** + 40+ common patterns
3. **Phase 2: Adaptive Search** - Progressive range expansion (7 phases)
4. **Phase 3: Wide Search** - Large ranges for unusual patterns
5. **Phase 4: Exhaustive** - Maximum range brute-force

### Key Capabilities

- ✅ **Same nonce reuse detection** - **Instant recovery (< 0.1s)** - Most common vulnerability
- ✅ **Common pattern matching** - **Covers 80% of real-world vulnerabilities** (31+ patterns)
- ✅ **Adaptive range search** - Progressive expansion from small to large ranges
- ✅ **Parallel processing** - **Configurable workers** for fast brute-force
- ✅ **Progress logging** - **Updates every 5 seconds or 1M pairs** - Never appears stuck
- ✅ **Early termination** - Stops immediately when key is found
- ✅ **Unified structure** - **Both ECDSA and EdDSA use identical code structure and logging**
- ✅ **Both ECDSA and EdDSA support** - Comprehensive algorithm coverage with consistent APIs

## Testing

### Automated Test Scripts

The project includes automated test scripts for easy validation:

#### ECDSA Testing (`test_recovery.sh`)

Tests ECDSA key recovery functionality:

```bash
./test_recovery.sh
```

**What it does:**
- Generates ECDSA test fixtures with vulnerable nonce patterns
- Runs the recovery tool with smart brute-force strategy
- Verifies the recovered private key matches the expected key

**Requirements:**
- Python dependencies: `ecdsa` library
- Go 1.21+ for building the recovery tool

#### EdDSA Testing (`test_recovery_eddsa.sh`)

Tests EdDSA key recovery functionality:

```bash
./test_recovery_eddsa.sh
```

**What it does:**
- Generates EdDSA test fixtures with flawed nonce patterns (random nonces)
- Runs the EdDSA recovery example program
- Verifies the recovered private key matches the expected key

**Requirements:**
- Python dependencies: `PyNaCl` library
- Go 1.21+ for running the example program

**Note:** These scripts test **flawed EdDSA implementations** using random nonces. Standard EdDSA uses deterministic nonces and is not vulnerable.

### Installing Python Dependencies

Before running the test scripts, install the required Python dependencies:

```bash
# For Python 3.12+ (externally managed environments)
python3 -m pip install --break-system-packages -r scripts/requirements.txt

# For older Python versions
pip install -r scripts/requirements.txt
```

Or install individually:
```bash
pip install ecdsa      # For ECDSA testing
pip install PyNaCl     # For EdDSA testing
```

## Usage

### Command-Line Options

```bash
./bin/recovery --help

Flags:
  --signatures string     Path to signatures file (JSON or CSV)
  --format string         File format: json or csv (default: json)
  --public-key string     Public key in hex (compressed, 66 chars) for verification (OPTIONAL)
  --known-a int           Known affine coefficient a (k2 = a*k1 + b)
  --known-b int           Known affine offset b (k2 = a*k1 + b)
  --smart-brute           Use smart brute-force (recommended)
  --brute-force           Full brute-force with custom ranges
  --a-range string        Range for a values (format: min,max, default: -100,100)
  --b-range string        Range for b values (format: min,max, default: -100,100)
  --max-pairs int         Maximum signature pairs to test (default: 100)
  --workers int           Number of parallel workers (0 = auto-detect)
```

### Examples

**Known relationship:**
```bash
# With public key (verifies the result):
./bin/recovery \
  --signatures fixtures/test_signatures_hardcoded_step.json \
  --known-a 1 \
  --known-b 12345 \
  --public-key $PUBKEY

# Without public key (returns candidate key):
./bin/recovery \
  --signatures fixtures/test_signatures_hardcoded_step.json \
  --known-a 1 \
  --known-b 12345
```

**Smart brute-force (recommended for researchers):**
```bash
# This is the RECOMMENDED option - tries common patterns first, then expands
# With public key (verifies and stops when correct key found):
./bin/recovery \
  --signatures fixtures/test_signatures_hardcoded_step.json \
  --smart-brute \
  --public-key $PUBKEY

# Without public key (returns first valid-looking candidate):
./bin/recovery \
  --signatures fixtures/test_signatures_hardcoded_step.json \
  --smart-brute
```

**Custom brute-force:**
```bash
# With or without public key (optional for verification):
./bin/recovery \
  --signatures fixtures/test_signatures_hardcoded_step.json \
  --brute-force \
  --a-range 1,10 \
  --b-range -50000,50000 \
  --public-key $PUBKEY  # Optional
```

## Performance

| Pattern Type | Phase | Time | Combinations |
|--------------|-------|------|---------------|
| Same nonce reuse | Phase 1 | < 0.1s | Instant |
| Small step (b < 100) | Phase 2a | < 0.5s | ~200 |
| Medium step (b < 10k) | Phase 2c | < 5s | ~20k |
| Large step (b < 50k) | Phase 3c | 5-15s | ~500k |
| Very large step (b < 5M) | Phase 4 | minutes | ~1B |

## Project Structure

```
.
├── cmd/recovery/          # CLI tool (ECDSA)
├── examples/
│   ├── basic/             # ECDSA example programs
│   └── eddsa/             # EdDSA example programs
├── pkg/
│   ├── ecdsaaffine/       # ECDSA Go package (multi-phase brute-force, parsing, recovery)
│   └── eddsaaffine/       # EdDSA Go package
├── scripts/               # Python scripts for fixture generation
│   ├── flawed_signer.py   # ECDSA signature generator
│   └── flawed_eddsa_signer.py  # EdDSA signature generator
├── fixtures/              # Generated test fixtures
├── test_recovery.sh       # ECDSA automated test script
├── test_recovery_eddsa.sh # EdDSA automated test script
├── TESTING_EDDSA.md       # EdDSA testing guide
├── UPBIT_INVESTIGATION.md # Solana/EdDSA investigation guide
├── BRUTE_FORCE_STRATEGY.md    # Detailed strategy documentation
├── IMPLEMENTATION_SUMMARY.md  # Implementation details
└── 2504.13737v1.pdf      # Research paper
```

## Technical Details

### ECDSA Recovery Formula (Equation 7)

For two ECDSA signatures with affinely related nonces (k₂ = a·k₁ + b):

```
priv = (a·s₂·z₁ - s₁·z₂ + b·s₁·s₂) / (r₂·s₁ - a·r₁·s₂) mod n
```

### EdDSA Recovery Formula

For two EdDSA signatures with affinely related nonces (r₂ = a·r₁ + b), where the EdDSA signature equation is s = r + H(R||A||M)·a:

```
a = (s₂ - a_coeff·s₁ - b_offset) / (h₂ - a_coeff·h₁) mod q
```

Where h = H(R||A||M) mod q (SHA-512 hash of R, public key A, and message M).

### Supported Patterns

- **Same nonce reuse**: k₂ = k₁ (a=1, b=0)
- **Linear counters**: k₂ = k₁ + b (a=1)
- **Multiplicative**: k₂ = a·k₁ (b=0)
- **Affine**: k₂ = a·k₁ + b (general case)

### Common Vulnerabilities

- Counter-based nonces: kᵢ = k₀ + i·step
- Time-based nonces: kᵢ = timestamp + offset
- Weak PRNGs: predictable patterns
- Implementation bugs: nonce reuse, predictable increments

## 🔬 For Security Researchers

**This tool is specifically designed for security research and educational purposes.** It enables researchers to:

### Use Cases

- **🔍 Analyze blockchain transactions** - Detect nonce patterns in Bitcoin, Ethereum, Solana, and other blockchain networks
- **🧪 Test signature implementations** - Identify weaknesses in ECDSA/EdDSA implementations before deployment
- **📚 Research historical attacks** - Investigate real-world incidents (e.g., **UpBit 2025 hack on Solana**)
- **🎓 Educational purposes** - Learn about cryptographic vulnerabilities and nonce generation weaknesses
- **🔐 Security audits** - Assess the security of cryptographic systems and exchange hot wallets

### Getting Started with Research

1. **Generate test fixtures** - Use the provided scripts to create vulnerable signatures for testing
2. **Run recovery tests** - Use the test scripts (`test_recovery.sh` for ECDSA, `test_recovery_eddsa.sh` for EdDSA)
3. **Analyze your own data** - Extract signatures from blockchain transactions or your own implementations
4. **Review documentation** - Study the strategy documentation and implementation details

### Important Documentation

- **[BRUTE_FORCE_STRATEGY.md](BRUTE_FORCE_STRATEGY.md)** - **Detailed attack strategies and multi-phase approach**
- **[UPBIT_INVESTIGATION.md](UPBIT_INVESTIGATION.md)** - **Complete guide for Solana/EdDSA investigation** (real-world case study)
- **[TESTING_EDDSA.md](TESTING_EDDSA.md)** - EdDSA testing guide and examples
- **[IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md)** - Implementation details and performance characteristics

### Research Paper

The implementation is based on the paper: **[Breaking ECDSA with Two Affinely Related Nonces](2504.13737v1.pdf)** (arXiv:2504.13737) by Jamie Gilchrist, William J. Buchanan, and Keir Finlow-Bates.

**⚠️ ETHICAL USE WARNING:** Only use this tool on systems you own or have explicit written authorization to test. Unauthorized access to computer systems is illegal.

## 📋 Requirements

- **Go 1.21+** (required)
- **Python 3.6+** (for fixture generation)
- `github.com/decred/dcrd/dcrec/secp256k1/v4` (Go dependency - installed automatically)

## 📝 License

**This project is for educational and security research purposes only.**

## EdDSA Testing

### Generating Flawed EdDSA Signatures

Generate test signatures with various nonce flaws:

```bash
# Generate EdDSA test fixtures
python3 scripts/flawed_eddsa_signer.py
```

This creates the following test fixtures in `fixtures/`:
- `test_eddsa_signatures_same_nonce.json` - Nonce reuse (r2 = r1)
- `test_eddsa_signatures_counter.json` - Counter-based (r2 = r1 + 1)
- `test_eddsa_signatures_affine.json` - Affine relationship (r2 = 2*r1 + 1)
- `test_eddsa_signatures_hardcoded_step.json` - Hardcoded step (r2 = r1 + 12345)
- `test_eddsa_key_info.json` - Private/public key information for verification

**Note:** These signatures simulate flawed implementations that use random nonces instead of the standard EdDSA deterministic nonces.

### Testing EdDSA Key Recovery

#### Using the Example Program

```bash
# Get the public key
PUBKEY=$(python3 -c "import json; print(json.load(open('fixtures/test_eddsa_key_info.json'))['public_key_hex'])")

# Test same nonce reuse (fastest - should recover instantly)
go run examples/eddsa/main.go fixtures/test_eddsa_signatures_same_nonce.json $PUBKEY

# Test counter-based nonces
go run examples/eddsa/main.go fixtures/test_eddsa_signatures_counter.json $PUBKEY

# Test affine relationship
go run examples/eddsa/main.go fixtures/test_eddsa_signatures_affine.json $PUBKEY

# Test hardcoded step (may take longer)
go run examples/eddsa/main.go fixtures/test_eddsa_signatures_hardcoded_step.json $PUBKEY
```

#### Using the Go Package Directly

```go
package main

import (
    "context"
    "fmt"
    "github.com/mahdiidarabi/ecdsa-affine/pkg/eddsaaffine"
)

func main() {
    client := eddsaaffine.NewClient()
    
    // Load public key (optional, for verification)
    publicKeyHex := "253b7787d6bbd7d4db321e34b9de09b3672b1fdff8654244d05a6c032058fc33"
    
    // Recover key from signatures
    ctx := context.Background()
    result, err := client.RecoverKey(
        ctx, 
        "fixtures/test_eddsa_signatures_same_nonce.json",
        publicKeyHex,
    )
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Recovered key: %s\n", result.PrivateKey.Text(16))
    fmt.Printf("Pattern: %s\n", result.Pattern)
    fmt.Printf("Relationship: r2 = %s*r1 + %s\n",
        result.Relationship.A.Text(10),
        result.Relationship.B.Text(10))
}
```

#### Custom Strategy Configuration

```go
strategy := eddsaaffine.NewSmartBruteForceStrategy().
    WithRangeConfig(eddsaaffine.RangeConfig{
        ARange:     [2]int{1, 10},
        BRange:     [2]int{-50000, 50000},
        MaxPairs:   1000,
        NumWorkers: 8,
    }).
    WithPatternConfig(eddsaaffine.PatternConfig{
        CustomPatterns: []eddsaaffine.Pattern{
            {A: big.NewInt(1), B: big.NewInt(12345), Name: "custom_step"},
        },
    })

client := eddsaaffine.NewClient().WithStrategy(strategy)
result, err := client.RecoverKey(ctx, "signatures.json", publicKeyHex)
```

### Expected Results

| Test Case | Pattern | Expected Recovery Time | Notes |
|-----------|---------|----------------------|-------|
| Same nonce | r2 = r1 | < 0.1s | Instant - Phase 0 |
| Counter | r2 = r1 + 1 | < 1s | Common pattern - Phase 1 |
| Affine | r2 = 2*r1 + 1 | < 1s | Common pattern - Phase 1 |
| Hardcoded step | r2 = r1 + 12345 | 1-10s | Larger b value - Phase 2-3 |

### Verification

The example program automatically verifies recovered keys against the expected private key from `test_eddsa_key_info.json`. If the recovered key matches, you'll see:

```
✅ Key Recovery Successful!
✅ Recovered key matches expected key!
```

## Documentation

This project includes comprehensive documentation for both ECDSA and EdDSA key recovery:

### Core Documentation

- **[pkg/README.md](pkg/README.md)** - Package documentation for both ECDSA and EdDSA Go packages with API reference and usage examples
- **[TESTING_EDDSA.md](TESTING_EDDSA.md)** - Complete guide for testing EdDSA key recovery, including fixture generation and examples
- **[UPBIT_INVESTIGATION.md](UPBIT_INVESTIGATION.md)** - Complete guide for Solana EdDSA key recovery investigation (UpBit 2025 hack)
- **[BRUTE_FORCE_STRATEGY.md](BRUTE_FORCE_STRATEGY.md)** - Detailed brute-force strategy documentation with multi-phase approach
- **[IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md)** - Implementation details, test results, and performance characteristics
- **[API_DESIGN.md](API_DESIGN.md)** - API design documentation and architecture decisions

### Supporting Documentation

- **[scripts/README.md](scripts/README.md)** - Documentation for Python scripts (ECDSA and EdDSA fixture generation)
- **[scripts/QUICKSTART.md](scripts/QUICKSTART.md)** - Quick start guide for using the scripts and extracting signatures from blockchains
- **[scripts/TEST_RESULTS.md](scripts/TEST_RESULTS.md)** - Test results and validation documentation
- **[fixtures/README.md](fixtures/README.md)** - Documentation about test fixtures (ECDSA and EdDSA)

### Research Paper

- **[2504.13737v1.pdf](2504.13737v1.pdf)** - Original research paper: "Breaking ECDSA with Two Affinely Related Nonces" (arXiv:2504.13737) by Jamie Gilchrist, William J. Buchanan, and Keir Finlow-Bates

## References

- **Paper**: [Breaking ECDSA with Two Affinely Related Nonces](2504.13737v1.pdf) (arXiv:2504.13737)
