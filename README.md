# ECDSA Affine Nonce Recovery

**Breaking ECDSA with Two Affinely Related Nonces** - A Go implementation of the key recovery attack described in [arXiv:2504.13737](2504.13737v1.pdf) by Jamie Gilchrist, William J. Buchanan, and Keir Finlow-Bates.

## Overview

This tool recovers ECDSA private keys from signatures with affinely related nonces (k₂ = a·k₁ + b). It implements a multi-phase brute-force strategy optimized for real-world vulnerabilities, including patterns seen in the UpBit 2025 hack.

## Quick Start

### As a Go Package

```go
import "github.com/mahdiidarabi/ecdsa-affine/pkg/ecdsaaffine"

client := ecdsaaffine.NewClient()
result, err := client.RecoverKey(ctx, "signatures.json", "03...")
```

See [pkg/README.md](pkg/README.md) for detailed package documentation and examples.

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
├── cmd/recovery/          # CLI tool
├── internal/
│   ├── bruteforce/        # Multi-phase brute-force implementation
│   ├── parser/            # Signature parsing (JSON/CSV)
│   └── recovery/          # Core recovery algorithm (Equation 7)
├── scripts/               # Python scripts for fixture generation
├── fixtures/              # Generated test fixtures
├── BRUTE_FORCE_STRATEGY.md    # Detailed strategy documentation
├── IMPLEMENTATION_SUMMARY.md  # Implementation details
└── 2504.13737v1.pdf      # Research paper
```

## Technical Details

### Recovery Formula (Equation 7)

For two signatures with affinely related nonces (k₂ = a·k₁ + b):

```
priv = (a·s₂·z₁ - s₁·z₂ + b·s₁·s₂) / (r₂·s₁ - a·r₁·s₂) mod n
```

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

This tool is designed for security research on ECDSA nonce vulnerabilities, including:
- Analyzing blockchain transactions for nonce patterns
- Testing ECDSA implementations for weaknesses
- Researching historical attacks (e.g., UpBit 2025 hack)
- Educational purposes on cryptographic vulnerabilities

**See [BRUTE_FORCE_STRATEGY.md](BRUTE_FORCE_STRATEGY.md) for detailed attack strategies.**

## Requirements

- Go 1.21+
- Python 3.6+ (for fixture generation)
- `github.com/decred/dcrd/dcrec/secp256k1/v4` (Go dependency)

## License

This project is for educational and security research purposes.

## References

- **Paper**: [Breaking ECDSA with Two Affinely Related Nonces](2504.13737v1.pdf) (arXiv:2504.13737)
- **Strategy Guide**: [BRUTE_FORCE_STRATEGY.md](BRUTE_FORCE_STRATEGY.md)
- **Implementation Details**: [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md)
