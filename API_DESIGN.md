# API Design Document

This document describes the design of the `ecdsaaffine` package API for researchers and developers.

## Design Principles

1. **Extensibility**: Core functionality is exposed through interfaces, allowing custom implementations
2. **Simplicity**: High-level `Client` API for common use cases
3. **Flexibility**: Low-level functions for advanced use cases
4. **Composability**: Strategies and parsers can be mixed and matched

## Core Components

### 1. Types

#### `Signature`
Represents an ECDSA signature with message hash:
```go
type Signature struct {
    Z *big.Int // Message hash (SHA-256 mod n)
    R *big.Int // r component
    S *big.Int // s component
}
```

#### `RecoveryResult`
Contains the result of a key recovery operation:
```go
type RecoveryResult struct {
    PrivateKey    *big.Int           // Recovered private key
    Relationship  AffineRelationship // k2 = a*k1 + b
    SignaturePair [2]int             // Indices of signature pair used
    Verified      bool                // Whether verified against public key
    Pattern       string              // Human-readable pattern name
}
```

### 2. Interfaces

#### `BruteForceStrategy`
Allows custom search strategies:

```go
type BruteForceStrategy interface {
    Search(ctx context.Context, signatures []*Signature, publicKey []byte) *RecoveryResult
    Name() string
}
```

**Built-in implementations:**
- `SmartBruteForceStrategy`: Multi-phase strategy with common patterns

**Custom implementation example:**
```go
type MyStrategy struct{}

func (s *MyStrategy) Search(ctx context.Context, signatures []*Signature, publicKey []byte) *RecoveryResult {
    // Your custom search logic
    // Try specific patterns first, then brute-force
    return nil
}

func (s *MyStrategy) Name() string {
    return "MyCustomStrategy"
}
```

#### `SignatureParser`
Allows custom signature parsing:

```go
type SignatureParser interface {
    ParseSignatures(source string) ([]*Signature, error)
}
```

**Built-in implementations:**
- `JSONParser`: Parses JSON files
- `CSVParser`: Parses CSV files

**Custom implementation example:**
```go
type DatabaseParser struct {
    db *sql.DB
}

func (p *DatabaseParser) ParseSignatures(query string) ([]*Signature, error) {
    // Parse signatures from database
    return signatures, nil
}
```

### 3. Configuration

#### `RangeConfig`
Controls brute-force search ranges:

```go
type RangeConfig struct {
    ARange    [2]int // [min, max] for a values
    BRange    [2]int // [min, max] for b values
    MaxPairs  int    // Maximum signature pairs to test
    NumWorkers int   // Parallel workers (0 = auto-detect)
    SkipZeroA  bool  // Skip a=0 (wasteful)
}
```

#### `PatternConfig`
Controls pattern testing:

```go
type PatternConfig struct {
    CustomPatterns        []Pattern // User-defined patterns
    IncludeCommonPatterns bool      // Include built-in patterns
}
```

### 4. High-Level API

#### `Client`
Provides a simple, high-level API:

```go
client := ecdsaaffine.NewClient()

// With custom strategy
client := ecdsaaffine.NewClient().
    WithStrategy(customStrategy).
    WithParser(customParser)

// Recover key
result, err := client.RecoverKey(ctx, "signatures.json", "03...")

// Recover with known relationship
result, err := client.RecoverKeyWithKnownRelationship(ctx, "signatures.json", 1, 12345, "03...")
```

### 5. Low-Level Functions

For advanced use cases:

```go
// Recover private key directly
priv, err := ecdsaaffine.RecoverPrivateKey(sig1, sig2, a, b)

// Verify recovered key
verified, err := ecdsaaffine.VerifyRecoveredKey(priv, publicKeyBytes)

// Hash message
z := ecdsaaffine.HashMessage(message)
```

## Usage Patterns

### Pattern 1: Quick Recovery (Default Strategy)

```go
client := ecdsaaffine.NewClient()
result, err := client.RecoverKey(ctx, "signatures.json", publicKeyHex)
```

### Pattern 2: Custom Range

```go
strategy := ecdsaaffine.NewSmartBruteForceStrategy().
    WithRangeConfig(ecdsaaffine.RangeConfig{
        ARange:    [2]int{1, 5},
        BRange:    [2]int{-100000, 100000},
        MaxPairs:  50,
        NumWorkers: 8,
    })

client := ecdsaaffine.NewClient().WithStrategy(strategy)
result, err := client.RecoverKey(ctx, "signatures.json", publicKeyHex)
```

### Pattern 3: Custom Patterns

```go
strategy := ecdsaaffine.NewSmartBruteForceStrategy().
    WithPatternConfig(ecdsaaffine.PatternConfig{
        CustomPatterns: []ecdsaaffine.Pattern{
            {A: big.NewInt(1), B: big.NewInt(12345), Name: "known_step", Priority: 1},
            {A: big.NewInt(1), B: big.NewInt(17), Name: "step_17", Priority: 2},
        },
        IncludeCommonPatterns: true,
    })

client := ecdsaaffine.NewClient().WithStrategy(strategy)
result, err := client.RecoverKey(ctx, "signatures.json", publicKeyHex)
```

### Pattern 4: Custom Strategy

```go
type ResearchStrategy struct {
    // Your research-specific fields
}

func (s *ResearchStrategy) Search(ctx context.Context, signatures []*ecdsaaffine.Signature, publicKey []byte) *ecdsaaffine.RecoveryResult {
    // Implement your research algorithm
    // Maybe use statistical analysis, machine learning, etc.
    return nil
}

func (s *ResearchStrategy) Name() string {
    return "ResearchStrategy"
}

client := ecdsaaffine.NewClient().WithStrategy(&ResearchStrategy{})
result, err := client.RecoverKey(ctx, "signatures.json", publicKeyHex)
```

### Pattern 5: Direct Function Usage

```go
// Parse signatures
parser := &ecdsaaffine.JSONParser{}
signatures, err := parser.ParseSignatures("signatures.json")

// Try specific relationship
priv, err := ecdsaaffine.RecoverPrivateKey(signatures[0], signatures[1], big.NewInt(1), big.NewInt(12345))

// Verify
verified, err := ecdsaaffine.VerifyRecoveredKey(priv, publicKeyBytes)
```

## Extensibility Points

1. **Custom Strategies**: Implement `BruteForceStrategy` for domain-specific search algorithms
2. **Custom Parsers**: Implement `SignatureParser` for custom data sources
3. **Pattern Injection**: Add custom patterns via `PatternConfig`
4. **Range Control**: Fine-tune search ranges via `RangeConfig`
5. **Direct Functions**: Use low-level functions for maximum control

## Best Practices

1. **Use Context**: Always pass a context for cancellation support
2. **Verify Keys**: Always verify recovered keys when public key is available
3. **Start Small**: Begin with small ranges and expand if needed
4. **Custom Patterns**: Add known patterns before brute-forcing
5. **Parallelization**: Use `NumWorkers` to control resource usage

## Future Extensions

Potential additions:
- Statistical analysis interface
- Pattern detection interface
- Progress reporting interface
- Result streaming interface
- Database integration helpers

