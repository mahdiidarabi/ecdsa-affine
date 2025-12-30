package bruteforce

import (
	"fmt"
	"math/big"

	"github.com/mahdiidarabi/ecdsa-affine/internal/parser"
	"github.com/mahdiidarabi/ecdsa-affine/internal/recovery"
)

// Result contains the result of a brute-force search
type Result struct {
	PrivateKey    *big.Int
	A             *big.Int
	B             *big.Int
	SignaturePair [2]int
	Verified      bool
	Pattern       string
}

// BruteForceAffineRelationship searches for affine relationships between nonces.
//
// Args:
//   - signatures: List of signatures
//   - publicKeyBytes: Optional public key for verification (33 bytes compressed)
//   - aRange: Range of a values to try (min, max)
//   - bRange: Range of b values to try (min, max)
//   - maxPairs: Maximum number of signature pairs to test
//
// Returns:
//   - Result if found, nil otherwise
func BruteForceAffineRelationship(
	signatures []*parser.Signature,
	publicKeyBytes []byte,
	aRange, bRange [2]int,
	maxPairs int,
) *Result {
	fmt.Printf("Testing %d signatures...\n", len(signatures))
	fmt.Printf("Searching a in range [%d, %d]\n", aRange[0], aRange[1])
	fmt.Printf("Searching b in range [%d, %d]\n", bRange[0], bRange[1])

	testedPairs := 0

	// Convert signatures to recovery.Signature format
	recoverySigs := make([]*recovery.Signature, len(signatures))
	for i, sig := range signatures {
		recoverySigs[i] = &recovery.Signature{
			Z: sig.Z,
			R: sig.R,
			S: sig.S,
		}
	}

	// Try all pairs of signatures
	for i := 0; i < len(recoverySigs); i++ {
		for j := i + 1; j < len(recoverySigs); j++ {
			if testedPairs >= maxPairs {
				fmt.Printf("Reached maximum pairs limit (%d)\n", maxPairs)
				return nil
			}

			sig1 := recoverySigs[i]
			sig2 := recoverySigs[j]

			testedPairs++

			// Try different values of a and b
			for a := aRange[0]; a <= aRange[1]; a++ {
				for b := bRange[0]; b <= bRange[1]; b++ {

					aBig := big.NewInt(int64(a))
					bBig := big.NewInt(int64(b))

					// Try to recover private key
					priv, err := recovery.RecoverPrivateKeyAffine(sig1, sig2, aBig, bBig)
					if err != nil {
						continue
					}

					// If public key provided, verify
					if len(publicKeyBytes) > 0 {
						verified, err := recovery.VerifyRecoveredKey(priv, publicKeyBytes)
						if err == nil && verified {
							return &Result{
								PrivateKey:    priv,
								A:             aBig,
								B:             bBig,
								SignaturePair: [2]int{i, j},
								Verified:      true,
							}
						}
					} else {
						// Without public key, return first valid-looking key
						// (keys should be in valid range)
						if priv.Sign() > 0 && priv.Cmp(recovery.Secp256k1CurveOrder) < 0 {
							return &Result{
								PrivateKey:    priv,
								A:             aBig,
								B:             bBig,
								SignaturePair: [2]int{i, j},
								Verified:      false,
							}
						}
					}
				}
			}

			if testedPairs%10 == 0 {
				fmt.Printf("Tested %d signature pairs...\n", testedPairs)
			}
		}
	}

	fmt.Printf("Tested %d signature pairs, no relationship found\n", testedPairs)
	return nil
}

// SmartBruteForce tries common patterns first.
//
// Common patterns:
//   - k2 = k1 + 1 (counter)
//   - k2 = k1 - 1
//   - k2 = 2*k1 (doubling)
//   - k2 = k1 + constant (small constants)
// analyzeRValues performs statistical analysis on r values to detect patterns
// Returns suggested patterns to try based on analysis
func analyzeRValues(signatures []*parser.Signature) []struct {
	a int
	b int
	reason string
} {
	suggestions := []struct {
		a int
		b int
		reason string
	}{}

	if len(signatures) < 2 {
		return suggestions
	}

	// Extract r values
	rValues := make([]*big.Int, len(signatures))
	for i, sig := range signatures {
		rValues[i] = sig.R
	}

	// Check for repeated r values (same nonce reuse)
	rMap := make(map[string][]int)
	for i, r := range rValues {
		rStr := r.String()
		rMap[rStr] = append(rMap[rStr], i)
	}

	for rStr, indices := range rMap {
		if len(indices) > 1 {
			fmt.Printf("  [STAT] Found repeated r value: %s (signatures: %v) - suggests same nonce reuse\n", rStr[:20]+"...", indices)
			suggestions = append(suggestions, struct {
				a int
				b int
				reason string
			}{1, 0, "repeated_r_value"})
		}
	}

	// Check for arithmetic progressions in r values
	// If r values form an arithmetic progression, nonces might be related
	if len(rValues) >= 3 {
		diffs := make([]*big.Int, len(rValues)-1)
		for i := 0; i < len(rValues)-1; i++ {
			diffs[i] = new(big.Int).Sub(rValues[i+1], rValues[i])
		}

		// Check if differences are constant (arithmetic progression)
		if len(diffs) >= 2 {
			firstDiff := diffs[0]
			isArithmetic := true
			for i := 1; i < len(diffs); i++ {
				if diffs[i].Cmp(firstDiff) != 0 {
					isArithmetic = false
					break
				}
			}
			if isArithmetic {
				fmt.Printf("  [STAT] Found arithmetic progression in r values (diff: %s) - suggests linear nonce relationship\n", firstDiff.String()[:20])
				// Try to estimate b from the difference
				// This is a heuristic - actual b might be different
			}
		}
	}

	return suggestions
}

func SmartBruteForce(signatures []*parser.Signature, publicKeyBytes []byte) *Result {
	// Phase 0: Statistical pre-analysis
	fmt.Println("Phase 0: Statistical analysis of r values...")
	statSuggestions := analyzeRValues(signatures)
	if len(statSuggestions) > 0 {
		fmt.Printf("  Found %d pattern suggestions from statistical analysis\n", len(statSuggestions))
	}

	// Phase 1: Check for same nonce reuse first (fastest check)
	// This catches the most common vulnerability - identical r values
	fmt.Println("Phase 1: Checking for same nonce reuse (identical r values)...")
	
	// Convert signatures to recovery.Signature format
	recoverySigs := make([]*recovery.Signature, len(signatures))
	for i, sig := range signatures {
		recoverySigs[i] = &recovery.Signature{
			Z: sig.Z,
			R: sig.R,
			S: sig.S,
		}
	}
	
	// Check all pairs for identical r values (same nonce reuse)
	for i := 0; i < len(recoverySigs); i++ {
		for j := i + 1; j < len(recoverySigs); j++ {
			// If r values are identical, nonces are the same (k2 = k1, so a=1, b=0)
			if recoverySigs[i].R.Cmp(recoverySigs[j].R) == 0 {
				fmt.Printf("Found same nonce reuse in signatures %d and %d (identical r values)\n", i, j)
				a := big.NewInt(1)
				b := big.NewInt(0)
				
				priv, err := recovery.RecoverPrivateKeyAffine(recoverySigs[i], recoverySigs[j], a, b)
				if err != nil {
					continue
				}
				
				// Check if key is in valid range
				if priv.Sign() <= 0 || priv.Cmp(recovery.Secp256k1CurveOrder) >= 0 {
					continue
				}
				
				if len(publicKeyBytes) > 0 {
					verified, err := recovery.VerifyRecoveredKey(priv, publicKeyBytes)
					if err == nil && verified {
						return &Result{
							PrivateKey:    priv,
							A:             a,
							B:             b,
							SignaturePair: [2]int{i, j},
							Verified:      true,
							Pattern:       "same_nonce_reuse",
						}
					}
				} else {
					// Without public key, return first valid key
					return &Result{
						PrivateKey:    priv,
						A:             a,
						B:             b,
						SignaturePair: [2]int{i, j},
						Verified:      false,
						Pattern:       "same_nonce_reuse",
					}
				}
			}
		}
	}
	
	fmt.Println("No same nonce reuse found, trying common affine patterns...")

	// Common patterns: (a, b) tuples
	// Includes small offsets and common counter steps
	// Based on real-world ECDSA vulnerabilities (UpBit 2025, etc.)
	commonPatterns := [][2]int{
		// Same nonce reuse (most common vulnerability) - already checked above, but keep for completeness
		{1, 0}, // k2 = k1 (same nonce reuse)

		// Linear counter patterns (very common)
		{1, 1},  // k2 = k1 + 1
		{1, -1}, // k2 = k1 - 1
		{1, 2},  // k2 = k1 + 2
		{1, -2}, // k2 = k1 - 2
		{1, 3},  // k2 = k1 + 3
		{1, -3}, // k2 = k1 - 3
		{1, 4},  // k2 = k1 + 4
		{1, -4}, // k2 = k1 - 4
		{1, 5},  // k2 = k1 + 5
		{1, -5}, // k2 = k1 - 5

		// Powers of 2 (common in implementations)
		{1, 8},    // k2 = k1 + 8
		{1, 16},   // k2 = k1 + 16
		{1, 32},   // k2 = k1 + 32
		{1, 64},   // k2 = k1 + 64
		{1, 128},  // k2 = k1 + 128
		{1, 256},  // k2 = k1 + 256
		{1, 512},  // k2 = k1 + 512
		{1, 1024}, // k2 = k1 + 1024

		// Round numbers (common step values)
		{1, 10},    // k2 = k1 + 10
		{1, 100},   // k2 = k1 + 100
		{1, 1000},  // k2 = k1 + 1000
		{1, 10000}, // k2 = k1 + 10000

		// Multiplicative patterns
		{2, 0},  // k2 = 2*k1
		{2, 1},  // k2 = 2*k1 + 1
		{2, -1}, // k2 = 2*k1 - 1
		{3, 0},  // k2 = 3*k1
		{4, 0},  // k2 = 4*k1

		// Negative a (rare but possible)
		{-1, 0}, // k2 = -k1
	}

	// recoverySigs already created above, reuse it
	for i, sig := range signatures {
		recoverySigs[i] = &recovery.Signature{
			Z: sig.Z,
			R: sig.R,
			S: sig.S,
		}
	}

	// Try common patterns first
	for i := 0; i < len(recoverySigs); i++ {
		for j := i + 1; j < len(recoverySigs); j++ {
			sig1 := recoverySigs[i]
			sig2 := recoverySigs[j]

			for _, pattern := range commonPatterns {
				a := big.NewInt(int64(pattern[0]))
				b := big.NewInt(int64(pattern[1]))

				priv, err := recovery.RecoverPrivateKeyAffine(sig1, sig2, a, b)
				if err != nil {
					continue
				}

				// Check if key is in valid range first (fast check)
				if priv.Sign() <= 0 || priv.Cmp(recovery.Secp256k1CurveOrder) >= 0 {
					continue
				}

				if len(publicKeyBytes) > 0 {
					verified, err := recovery.VerifyRecoveredKey(priv, publicKeyBytes)
					if err == nil && verified {
						return &Result{
							PrivateKey:    priv,
							A:             a,
							B:             b,
							SignaturePair: [2]int{i, j},
							Verified:      true,
							Pattern:       "common",
						}
					}
				} else {
					// Without public key, return first valid key from common patterns
					return &Result{
						PrivateKey:    priv,
						A:             a,
						B:             b,
						SignaturePair: [2]int{i, j},
						Verified:      false,
						Pattern:       "common",
					}
				}
			}
		}
	}

	fmt.Println("Common patterns didn't work, trying Phase 2: Adaptive range search...")

	// Phase 2: Adaptive Search with Progressive Ranges
	// Strategy: Start with small ranges, expand progressively
	// Prioritize a=1 (most common: k2 = k1 + b)
	
	// Progressive ranges for a=1 (most common case)
	adaptiveRanges := []struct {
		aRange [2]int
		bRange [2]int
		phase  string
	}{
		// Phase 2a: Small range
		{[2]int{1, 1}, [2]int{-100, 100}, "Phase 2a: a=1, b∈[-100,100]"},
		// Phase 2b: Medium range
		{[2]int{1, 1}, [2]int{-1000, 1000}, "Phase 2b: a=1, b∈[-1000,1000]"},
		// Phase 2c: Large range
		{[2]int{1, 1}, [2]int{-10000, 10000}, "Phase 2c: a=1, b∈[-10000,10000]"},
		// Phase 3a: Small a values with medium b
		{[2]int{2, 4}, [2]int{-1000, 1000}, "Phase 3a: a∈[2,4], b∈[-1000,1000]"},
		// Phase 3b: Negative a values
		{[2]int{-5, -1}, [2]int{-1000, 1000}, "Phase 3b: a∈[-5,-1], b∈[-1000,1000]"},
		// Phase 3c: Wide search
		{[2]int{1, 10}, [2]int{-50000, 50000}, "Phase 3c: a∈[1,10], b∈[-50000,50000]"},
		// Phase 4: Maximum range
		{[2]int{1, 100}, [2]int{-5000000, 5000000}, "Phase 4: a∈[1,100], b∈[-5000000,5000000]"},
	}

	// Ensure we test at least all signature pairs
	numPairs := len(signatures) * (len(signatures) - 1) / 2
	maxPairsToTest := numPairs * 2 // Test all pairs with some buffer
	if maxPairsToTest < 10 {
		maxPairsToTest = 10 // Minimum
	}

	// Try each adaptive range in order
	for _, r := range adaptiveRanges {
		fmt.Println(r.phase)
		result := BruteForceAffineRelationshipParallel(
			signatures,
			publicKeyBytes,
			r.aRange,
			r.bRange,
			maxPairsToTest,
			0, // Auto-detect number of workers
		)
		if result != nil {
			return result
		}
	}

	// If all adaptive ranges fail, return nil
	fmt.Println("All adaptive ranges exhausted, no relationship found")
	return nil
}
