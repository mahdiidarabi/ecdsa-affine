package ecdsaaffine

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

