package eddsaaffine

import (
	"context"
	"math/big"
)

// BruteForceStrategy defines the interface for custom brute-force strategies.
// Implement this interface to create custom search strategies.
type BruteForceStrategy interface {
	// Search attempts to find an affine relationship between nonces in the signatures.
	// It should return a RecoveryResult if found, or nil if not found.
	// The context can be used for cancellation.
	Search(ctx context.Context, signatures []*Signature, publicKey []byte) *RecoveryResult

	// Name returns a human-readable name for this strategy.
	Name() string
}

// Pattern represents a specific affine pattern to test.
type Pattern struct {
	A       *big.Int
	B       *big.Int
	Name    string // Human-readable description
	Priority int   // Lower priority = tested first
}

// RangeConfig configures the search range for brute-force operations.
type RangeConfig struct {
	// ARange defines the range for a values [Min, Max] (inclusive)
	ARange [2]int

	// BRange defines the range for b values [Min, Max] (inclusive)
	BRange [2]int

	// MaxPairs limits the number of signature pairs to test
	MaxPairs int

	// NumWorkers controls parallelization (0 = auto-detect)
	NumWorkers int

	// SkipZeroA skips a=0 (which is wasteful)
	SkipZeroA bool
}

// DefaultRangeConfig returns a sensible default configuration.
func DefaultRangeConfig() RangeConfig {
	return RangeConfig{
		ARange:    [2]int{-100, 100},
		BRange:    [2]int{-100, 100},
		MaxPairs:  100,
		NumWorkers: 0, // Auto-detect
		SkipZeroA: true,
	}
}

// PatternConfig configures custom patterns to test.
type PatternConfig struct {
	// CustomPatterns are additional patterns to test before brute-force
	CustomPatterns []Pattern

	// IncludeCommonPatterns includes built-in common patterns
	IncludeCommonPatterns bool
}

// DefaultPatternConfig returns a configuration with common patterns enabled.
func DefaultPatternConfig() PatternConfig {
	return PatternConfig{
		CustomPatterns:        []Pattern{},
		IncludeCommonPatterns: true,
	}
}

// CommonPatterns returns a copy of the built-in patterns used by SmartBruteForceStrategy.
// Researchers can extend or reorder: append to CustomPatterns or set IncludeCommonPatterns: false
// and use only your own patterns.
func CommonPatterns() []Pattern {
	return append([]Pattern(nil), defaultCommonPatterns()...)
}

func defaultCommonPatterns() []Pattern {
	return []Pattern{
		{A: big.NewInt(1), B: big.NewInt(0), Name: "same_nonce", Priority: 1},
		{A: big.NewInt(1), B: big.NewInt(1), Name: "counter_+1", Priority: 2},
		{A: big.NewInt(1), B: big.NewInt(-1), Name: "counter_-1", Priority: 2},
		{A: big.NewInt(1), B: big.NewInt(2), Name: "counter_+2", Priority: 3},
		{A: big.NewInt(1), B: big.NewInt(-2), Name: "counter_-2", Priority: 3},
		{A: big.NewInt(1), B: big.NewInt(3), Name: "counter_+3", Priority: 3},
		{A: big.NewInt(1), B: big.NewInt(-3), Name: "counter_-3", Priority: 3},
		{A: big.NewInt(1), B: big.NewInt(4), Name: "counter_+4", Priority: 3},
		{A: big.NewInt(1), B: big.NewInt(-4), Name: "counter_-4", Priority: 3},
		{A: big.NewInt(1), B: big.NewInt(5), Name: "counter_+5", Priority: 3},
		{A: big.NewInt(1), B: big.NewInt(-5), Name: "counter_-5", Priority: 3},
		{A: big.NewInt(1), B: big.NewInt(8), Name: "step_8", Priority: 4},
		{A: big.NewInt(1), B: big.NewInt(16), Name: "step_16", Priority: 4},
		{A: big.NewInt(1), B: big.NewInt(32), Name: "step_32", Priority: 4},
		{A: big.NewInt(1), B: big.NewInt(64), Name: "step_64", Priority: 4},
		{A: big.NewInt(1), B: big.NewInt(128), Name: "step_128", Priority: 4},
		{A: big.NewInt(1), B: big.NewInt(256), Name: "step_256", Priority: 4},
		{A: big.NewInt(1), B: big.NewInt(512), Name: "step_512", Priority: 4},
		{A: big.NewInt(1), B: big.NewInt(1024), Name: "step_1024", Priority: 4},
		{A: big.NewInt(1), B: big.NewInt(10), Name: "step_10", Priority: 4},
		{A: big.NewInt(1), B: big.NewInt(71), Name: "step_71", Priority: 4},
		{A: big.NewInt(1), B: big.NewInt(73), Name: "step_73", Priority: 4},
		{A: big.NewInt(1), B: big.NewInt(97), Name: "step_97", Priority: 4},
		{A: big.NewInt(1), B: big.NewInt(100), Name: "step_100", Priority: 4},
		{A: big.NewInt(1), B: big.NewInt(1000), Name: "step_1000", Priority: 4},
		{A: big.NewInt(1), B: big.NewInt(10000), Name: "step_10000", Priority: 4},
		{A: big.NewInt(2), B: big.NewInt(0), Name: "multiply_2", Priority: 5},
		{A: big.NewInt(2), B: big.NewInt(1), Name: "multiply_2_+1", Priority: 5},
		{A: big.NewInt(3), B: big.NewInt(0), Name: "multiply_3", Priority: 5},
		{A: big.NewInt(4), B: big.NewInt(0), Name: "multiply_4", Priority: 5},
		{A: big.NewInt(-1), B: big.NewInt(0), Name: "negate", Priority: 6},
	}
}

