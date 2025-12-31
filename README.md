# ECDSA/EdDSA Affine Nonce Recovery

**Breaking ECDSA/EdDSA with Two Affinely Related Nonces** - A Go implementation of the key recovery attack described in [arXiv:2504.13737](2504.13737v1.pdf) by Jamie Gilchrist, William J. Buchanan, and Keir Finlow-Bates.

## Overview

This tool recovers **ECDSA** and **EdDSA** private keys from signatures with affinely related nonces. It implements a multi-phase brute-force strategy optimized for real-world vulnerabilities, including patterns seen in the UpBit 2025 hack on Solana.

**Supported Algorithms:**
- **ECDSA** (secp256k1) - Standard random nonce vulnerabilities (Bitcoin, Ethereum, etc.)
- **EdDSA** (Ed25519) - Flawed implementations using random nonces (Solana, etc.)

**Note:** Standard EdDSA uses deterministic nonces and is secure. This tool targets **flawed EdDSA implementations** that use random nonces, making them vulnerable to ECDSA-style attacks.

## Quick Start

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

```bash
# Build the recovery tool
make build

# Generate test fixtures
make fixtures

# Run recovery (example)
PUBKEY=$(python3 -c "import json; print(json.load(open('fixtures/test_key_info.json'))['public_key_hex'])")
./bin/recovery --signatures fixtures/test_signatures_hardcoded_step.json --smart-brute --public-key $PUBKEY

# Or use the test script
./test_recovery.sh
```

## Features

### Multi-Phase Brute-Force Strategy

1. **Phase 0: Statistical Analysis** - Pre-analyzes r values to detect patterns
2. **Phase 1: Fast Checks** - Same nonce reuse detection + 40+ common patterns
3. **Phase 2: Adaptive Search** - Progressive range expansion (7 phases)
4. **Phase 3: Wide Search** - Large ranges for unusual patterns
5. **Phase 4: Exhaustive** - Maximum range brute-force

### Key Capabilities

- ✅ **Same nonce reuse detection** - Instant recovery (< 0.1s)
- ✅ **Common pattern matching** - Covers 80% of real-world vulnerabilities
- ✅ **Adaptive range search** - Progressive expansion from small to large ranges
- ✅ **Parallel processing** - 16+ workers for fast brute-force
- ✅ **Early termination** - Stops immediately when key is found
- ✅ **Statistical pre-analysis** - Detects patterns before brute-forcing

## Usage

### Command-Line Options

```bash
./bin/recovery --help

Flags:
  --signatures string     Path to signatures file (JSON or CSV)
  --format string         File format: json or csv (default: json)
  --public-key string     Public key in hex (compressed, 66 chars) for verification
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
./bin/recovery \
  --signatures fixtures/test_signatures_hardcoded_step.json \
  --known-a 1 \
  --known-b 12345 \
  --public-key $PUBKEY
```

**Smart brute-force (recommended):**
```bash
./bin/recovery \
  --signatures fixtures/test_signatures_hardcoded_step.json \
  --smart-brute \
  --public-key $PUBKEY
```

**Custom brute-force:**
```bash
./bin/recovery \
  --signatures fixtures/test_signatures_hardcoded_step.json \
  --brute-force \
  --a-range 1,10 \
  --b-range -50000,50000 \
  --public-key $PUBKEY
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
│   ├── ecdsaaffine/       # ECDSA Go package
│   └── eddsaaffine/       # EdDSA Go package
├── internal/
│   ├── bruteforce/        # Multi-phase brute-force implementation (ECDSA)
│   ├── parser/            # Signature parsing (JSON/CSV)
│   └── recovery/          # Core recovery algorithm (ECDSA Equation 7)
├── scripts/               # Python scripts for fixture generation
│   ├── flawed_signer.py   # ECDSA signature generator
│   └── flawed_eddsa_signer.py  # EdDSA signature generator
├── fixtures/              # Generated test fixtures
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

## For Security Researchers

This tool is designed for security research on ECDSA and EdDSA nonce vulnerabilities, including:
- Analyzing blockchain transactions for nonce patterns (Bitcoin, Ethereum, Solana, etc.)
- Testing ECDSA/EdDSA implementations for weaknesses
- Researching historical attacks (e.g., UpBit 2025 hack on Solana)
- Educational purposes on cryptographic vulnerabilities
- Investigating exchange hot wallet compromises

**See [BRUTE_FORCE_STRATEGY.md](BRUTE_FORCE_STRATEGY.md) for detailed attack strategies.**
**See [UPBIT_INVESTIGATION.md](UPBIT_INVESTIGATION.md) for Solana/EdDSA investigation guide.**

## Requirements

- Go 1.21+
- Python 3.6+ (for fixture generation)
- `github.com/decred/dcrd/dcrec/secp256k1/v4` (Go dependency)

## License

This project is for educational and security research purposes.

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
