# ECDSA Affine Package

This package provides a clean, extensible API for recovering ECDSA private keys from signatures with affinely related nonces.

## Installation

```bash
go get github.com/mahdiidarabi/ecdsa-affine/pkg/ecdsaaffine
```

## Quick Start

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

Add custom patterns to test:

```go
strategy := ecdsaaffine.NewSmartBruteForceStrategy().
    WithPatternConfig(ecdsaaffine.PatternConfig{
        CustomPatterns: []ecdsaaffine.Pattern{
            {A: big.NewInt(1), B: big.NewInt(12345), Name: "custom_step", Priority: 1},
        },
        IncludeCommonPatterns: true, // Include built-in common patterns
    })
```

## Examples

See `examples/basic/main.go` for complete examples.

## API Reference

See [godoc](https://pkg.go.dev/github.com/mahdiidarabi/ecdsa-affine/pkg/ecdsaaffine) for full API documentation.

