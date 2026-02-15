# ECDSA/EdDSA Affine Packages

This repository is a **Go package**. It provides two Go packages for recovering private keys from signatures with affinely related nonces. Python is used only in the project to generate test fixtures (vulnerable signatures); it is not required to use these packages.

**Packages:**

1. **`pkg/ecdsaaffine`** - ECDSA (secp256k1) key recovery
2. **`pkg/eddsaaffine`** - EdDSA (Ed25519) key recovery for flawed implementations

## Installation

### ECDSA Package

```bash
go get github.com/mahdiidarabi/ecdsa-affine/pkg/ecdsaaffine
```

### EdDSA Package

```bash
go get github.com/mahdiidarabi/ecdsa-affine/pkg/eddsaaffine
```

## Quick Start

### ECDSA (secp256k1)

```go
import "github.com/mahdiidarabi/ecdsa-affine/pkg/ecdsaaffine"

// Create a client
client := ecdsaaffine.NewClient()

// Recover key
result, err := client.RecoverKey(ctx, "signatures.json", "03...")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Recovered key: %s\n", result.PrivateKey.Text(16))
```

### EdDSA (Ed25519)

```go
import "github.com/mahdiidarabi/ecdsa-affine/pkg/eddsaaffine"

// Create a client
client := eddsaaffine.NewClient()

// Recover key (public key in hex format)
result, err := client.RecoverKey(ctx, "eddsa_signatures.json", "public_key_hex")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Recovered key: %s\n", result.PrivateKey.Text(16))
fmt.Printf("Pattern: %s\n", result.Pattern)
```

**Note:** EdDSA package targets flawed implementations that use random nonces instead of deterministic ones. Standard EdDSA uses deterministic nonces and is secure.

## Core Interfaces

### BruteForceStrategy

Implement this interface to create custom search strategies:

```go
type BruteForceStrategy interface {
    Search(ctx context.Context, signatures []*Signature, publicKey []byte) *RecoveryResult
    Name() string
}
```

### SignatureParser

Implement this interface to parse signatures from custom sources:

```go
type SignatureParser interface {
    ParseSignatures(source string) ([]*Signature, error)
}
```

## Configuration

### Range Configuration

Control the brute-force search range:

```go
strategy := ecdsaaffine.NewSmartBruteForceStrategy().
    WithRangeConfig(ecdsaaffine.RangeConfig{
        ARange:    [2]int{1, 10},        // a values: [1, 10]
        BRange:    [2]int{-50000, 50000}, // b values: [-50000, 50000]
        MaxPairs:  100,                   // Max signature pairs to test
        NumWorkers: 16,                   // Parallel workers (0 = auto)
        SkipZeroA: true,                  // Skip a=0 (wasteful)
    })
```

### Pattern Configuration

Add custom patterns or use/extend the built-in list:

```go
// Option 1: Add your patterns alongside built-in ones
strategy := ecdsaaffine.NewSmartBruteForceStrategy().
    WithPatternConfig(ecdsaaffine.PatternConfig{
        CustomPatterns: []ecdsaaffine.Pattern{
            {A: big.NewInt(1), B: big.NewInt(12345), Name: "custom_step", Priority: 1},
        },
        IncludeCommonPatterns: true,
    })

// Option 2: Use only your patterns (e.g. extend CommonPatterns and disable built-in)
allPatterns := append(ecdsaaffine.CommonPatterns(), ecdsaaffine.Pattern{
    A: big.NewInt(1), B: big.NewInt(999), Name: "my_step", Priority: 1,
})
strategy := ecdsaaffine.NewSmartBruteForceStrategy().
    WithPatternConfig(ecdsaaffine.PatternConfig{
        CustomPatterns: allPatterns,
        IncludeCommonPatterns: false,
    })
```

### In-memory signatures

If you already have parsed signatures (e.g. from your own parser, blockchain, or API), use `RecoverKeyFromSignatures` so you are not tied to file paths:

```go
signatures, _ := myParser.Parse(someSource) // your parser
result, err := client.RecoverKeyFromSignatures(ctx, signatures, publicKeyHex)
```

## Examples

- **ECDSA**: See `examples/basic/main.go` for complete ECDSA examples
- **EdDSA**: See `examples/eddsa/main.go` for complete EdDSA examples

## Features (Both Packages)

Both packages share **identical APIs and features** with unified structure:

- ✅ **Multi-phase brute-force strategy** - Optimized search from common patterns to wide ranges
- ✅ **Parallel processing** - Configurable worker pools for fast brute-force
- ✅ **Custom patterns** - Add your own patterns to test
- ✅ **Range configuration** - Control search ranges and limits
- ✅ **Progress logging** - Detailed logging with updates every 5 seconds or 1M pairs checked
- ✅ **Signature parsing** - JSON and CSV format support
- ✅ **Key verification** - Optional public key verification
- ✅ **Unified structure** - Both ECDSA and EdDSA use the same code structure and logging format

## API Reference

- **ECDSA**: See [godoc](https://pkg.go.dev/github.com/mahdiidarabi/ecdsa-affine/pkg/ecdsaaffine) for full ECDSA API documentation
- **EdDSA**: See [godoc](https://pkg.go.dev/github.com/mahdiidarabi/ecdsa-affine/pkg/eddsaaffine) for full EdDSA API documentation

## Documentation

- **[README.md](../README.md)** - Main project documentation
- **[TESTING_EDDSA.md](../TESTING_EDDSA.md)** - Complete EdDSA testing guide
- **[UPBIT_INVESTIGATION.md](../UPBIT_INVESTIGATION.md)** - Solana/EdDSA investigation guide

