# Testing EdDSA Key Recovery

This guide explains how to generate flawed EdDSA signatures and test the key recovery functionality.

## Overview

The EdDSA key recovery package supports analyzing flawed EdDSA (Ed25519) implementations that use **random nonces** instead of the standard deterministic nonces. Standard EdDSA uses deterministic nonces (SHA-512(private_key || message)), but flawed implementations may use random nonces, making them vulnerable to ECDSA-style attacks.

## Quick Start

### 1. Generate Test Fixtures

Generate EdDSA signatures with various nonce flaws:

```bash
python3 scripts/flawed_eddsa_signer.py
```

This creates the following files in `fixtures/`:
- `test_eddsa_signatures_same_nonce.json` - Nonce reuse (r2 = r1)
- `test_eddsa_signatures_counter.json` - Counter-based (r2 = r1 + 1)
- `test_eddsa_signatures_affine.json` - Affine relationship (r2 = 2*r1 + 1)
- `test_eddsa_signatures_hardcoded_step.json` - Hardcoded step (r2 = r1 + 12345)
- `test_eddsa_key_info.json` - Private/public key information

### 2. Test Key Recovery

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

#### Using the Go Package

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

## Expected Results

| Test Case | Pattern | Expected Recovery Time | Notes |
|-----------|---------|----------------------|-------|
| Same nonce | r2 = r1 | < 0.1s | Instant - Phase 0 (nonce reuse check) |
| Counter | r2 = r1 + 1 | < 1s | Common pattern - Phase 1 |
| Affine | r2 = 2*r1 + 1 | < 1s | Common pattern - Phase 1 |
| Hardcoded step | r2 = r1 + 12345 | 1-10s | Larger b value - Phase 2-3 |

## Verification

The example program (`examples/eddsa/main.go`) automatically verifies recovered keys against the expected private key from `test_eddsa_key_info.json`. If the recovered key matches, you'll see:

```
✅ Key Recovery Successful!
✅ Recovered key matches expected key!
Pattern: same_nonce_reuse
Relationship: r2 = 1 * r1 + 0
```

## Signature Format

The generated signatures use the following JSON format:

```json
[
  {
    "message": "hex_encoded_message",
    "r": "0xhex_value",
    "s": "0xhex_value",
    "public_key": "hex_encoded_public_key"
  }
]
```

**Example:**
```json
[
  {
    "message": "54657374206d6573736167652030",
    "r": "0x4b0b39d379efcad58bbfca18e4cef4cb49c648efe3afd6154069a2df94c5e28",
    "s": "0xbfb3d15cc0e171bbe793a4e9d18455138a5480b65c483f96994c5382a313b06",
    "public_key": "253b7787d6bbd7d4db321e34b9de09b3672b1fdff8654244d05a6c032058fc33"
  }
]
```

## Custom Strategy Configuration

You can customize the brute-force strategy:

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
            {A: big.NewInt(1), B: big.NewInt(12345), Name: "custom_step", Priority: 1},
        },
    })

client := eddsaaffine.NewClient().WithStrategy(strategy)
result, err := client.RecoverKey(ctx, "signatures.json", publicKeyHex)
```

## Troubleshooting

### Parser Errors

If you see parsing errors, check that:
- Signature format matches the expected JSON structure
- Hex values are properly formatted (with or without `0x` prefix)
- All required fields (`message`, `r`, `s`) are present

### Recovery Fails

If recovery fails:
- Verify that signatures have the expected nonce relationship
- Check that enough signature pairs are provided (at least 2)
- Try increasing the search range for brute-force
- Ensure the public key is correct (32 bytes for Ed25519)

### Key Mismatch

If recovered key doesn't match expected:
- Verify the signatures were generated correctly
- Check that the same key pair was used for signing and verification
- Ensure the public key matches the private key used for signing

## Important Notes

1. **These signatures use RANDOM nonces** - This is non-standard EdDSA
2. **Standard EdDSA is secure** - Uses deterministic nonces and is not vulnerable
3. **For testing only** - These tools demonstrate vulnerabilities in flawed implementations
4. **Real-world use** - Only analyze your own signatures or with explicit permission

## Next Steps

- See [README.md](README.md) for general package usage
- See [UPBIT_INVESTIGATION.md](UPBIT_INVESTIGATION.md) for real-world investigation guide
- See [pkg/README.md](pkg/README.md) for detailed API documentation

