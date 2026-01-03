package ecdsaaffine

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
)

// SmartBruteForceStrategy implements a multi-phase brute-force strategy
// that tries common patterns first, then expands the search range.
type SmartBruteForceStrategy struct {
	RangeConfig   RangeConfig
	PatternConfig PatternConfig
}

// NewSmartBruteForceStrategy creates a new smart brute-force strategy with default settings.
func NewSmartBruteForceStrategy() *SmartBruteForceStrategy {
	return &SmartBruteForceStrategy{
		RangeConfig:   DefaultRangeConfig(),
		PatternConfig: DefaultPatternConfig(),
	}
}

// WithRangeConfig sets the range configuration for the strategy.
func (s *SmartBruteForceStrategy) WithRangeConfig(config RangeConfig) *SmartBruteForceStrategy {
	s.RangeConfig = config
	return s
}

// WithPatternConfig sets the pattern configuration for the strategy.
func (s *SmartBruteForceStrategy) WithPatternConfig(config PatternConfig) *SmartBruteForceStrategy {
	s.PatternConfig = config
	return s
}

// Name returns the name of this strategy.
func (s *SmartBruteForceStrategy) Name() string {
	return "SmartBruteForce"
}

// Search implements the BruteForceStrategy interface.
func (s *SmartBruteForceStrategy) Search(ctx context.Context, signatures []*Signature, publicKey []byte) *RecoveryResult {
	if len(signatures) < 2 {
		return nil
	}

	fmt.Printf("Starting key recovery with %d signatures...\n", len(signatures))

	// Phase 0: Check for same nonce reuse (fastest)
	fmt.Println("Phase 0: Checking for same nonce reuse...")
	if result := s.checkSameNonceReuse(signatures, publicKey); result != nil {
		fmt.Println("✓ Found same nonce reuse!")
		return result
	}
	fmt.Println("No same nonce reuse found")

	// Phase 1: Try common patterns
	if s.PatternConfig.IncludeCommonPatterns {
		fmt.Println("Phase 1: Trying common patterns...")
		if result := s.tryCommonPatterns(ctx, signatures, publicKey); result != nil {
			fmt.Printf("✓ Found pattern: %s\n", result.Pattern)
			return result
		}
		fmt.Println("No common patterns matched")
	}

	// Phase 2: Try custom patterns
	if len(s.PatternConfig.CustomPatterns) > 0 {
		fmt.Printf("Phase 2: Trying %d custom patterns...\n", len(s.PatternConfig.CustomPatterns))
		if result := s.tryCustomPatterns(ctx, signatures, publicKey); result != nil {
			fmt.Printf("✓ Found custom pattern: %s\n", result.Pattern)
			return result
		}
		fmt.Println("No custom patterns matched")
	}

	// Phase 3: Adaptive range search
	fmt.Println("Phase 3: Starting adaptive range search (brute-force)...")
	return s.adaptiveRangeSearch(ctx, signatures, publicKey)
}

// checkSameNonceReuse checks for identical r values (same nonce reuse).
func (s *SmartBruteForceStrategy) checkSameNonceReuse(signatures []*Signature, publicKey []byte) *RecoveryResult {
	for i := 0; i < len(signatures); i++ {
		for j := i + 1; j < len(signatures); j++ {
			if signatures[i].R.Cmp(signatures[j].R) == 0 {
				// Same nonce reuse: k2 = k1, so a=1, b=0
				a := big.NewInt(1)
				b := big.NewInt(0)

				priv, err := RecoverPrivateKey(signatures[i], signatures[j], a, b)
				if err != nil {
					continue
				}

				if priv.Sign() <= 0 || priv.Cmp(Secp256k1CurveOrder) >= 0 {
					continue
				}

				verified := false
				if len(publicKey) > 0 {
					verified, _ = VerifyRecoveredKey(priv, publicKey)
				} else {
					verified = true // Assume valid if no public key provided
				}

				if verified || len(publicKey) == 0 {
					return &RecoveryResult{
						PrivateKey:    priv,
						Relationship:  AffineRelationship{A: a, B: b},
						SignaturePair: [2]int{i, j},
						Verified:      verified,
						Pattern:       "same_nonce_reuse",
					}
				}
			}
		}
	}
	return nil
}

// tryCommonPatterns tries built-in common patterns.
func (s *SmartBruteForceStrategy) tryCommonPatterns(ctx context.Context, signatures []*Signature, publicKey []byte) *RecoveryResult {
	commonPatterns := s.getCommonPatterns()

	for _, pattern := range commonPatterns {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if result := s.tryPattern(signatures, publicKey, pattern.A, pattern.B, pattern.Name); result != nil {
			return result
		}
	}
	return nil
}

// tryCustomPatterns tries user-defined custom patterns.
func (s *SmartBruteForceStrategy) tryCustomPatterns(ctx context.Context, signatures []*Signature, publicKey []byte) *RecoveryResult {
	for _, pattern := range s.PatternConfig.CustomPatterns {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if result := s.tryPattern(signatures, publicKey, pattern.A, pattern.B, pattern.Name); result != nil {
			return result
		}
	}
	return nil
}

// tryPattern tries a specific (a, b) pattern across all signature pairs.
func (s *SmartBruteForceStrategy) tryPattern(signatures []*Signature, publicKey []byte, a, b *big.Int, patternName string) *RecoveryResult {
	for i := 0; i < len(signatures); i++ {
		for j := i + 1; j < len(signatures); j++ {
			priv, err := RecoverPrivateKey(signatures[i], signatures[j], a, b)
			if err != nil {
				continue
			}

			if priv.Sign() <= 0 || priv.Cmp(Secp256k1CurveOrder) >= 0 {
				continue
			}

			verified := false
			if len(publicKey) > 0 {
				verified, _ = VerifyRecoveredKey(priv, publicKey)
				if !verified {
					continue
				}
			} else {
				verified = true
			}

			return &RecoveryResult{
				PrivateKey:    priv,
				Relationship:  AffineRelationship{A: a, B: b},
				SignaturePair: [2]int{i, j},
				Verified:      verified,
				Pattern:       patternName,
			}
		}
	}
	return nil
}

// adaptiveRangeSearch performs an adaptive range search with expanding ranges.
func (s *SmartBruteForceStrategy) adaptiveRangeSearch(ctx context.Context, signatures []*Signature, publicKey []byte) *RecoveryResult {
	ranges := []struct {
		aRange [2]int
		bRange [2]int
		name   string
	}{
		{[2]int{1, 1}, [2]int{-100, 100}, "Phase 2a: a=1, small b"},
		{[2]int{1, 1}, [2]int{-1000, 1000}, "Phase 2b: a=1, medium b"},
		{[2]int{1, 1}, [2]int{-10000, 10000}, "Phase 2c: a=1, larger b"},
		{[2]int{2, 4}, [2]int{-1000, 1000}, "Phase 3a: small a, medium b"},
		{[2]int{-5, -1}, [2]int{-1000, 1000}, "Phase 3b: negative a, medium b"},
		{[2]int{1, 10}, [2]int{-50000, 50000}, "Phase 3c: wider a, larger b"},
		{[2]int{1, 100}, [2]int{-500000000, 500000000}, "Phase 4: very wide search"},
	}

	// Use the configured range if it's different from defaults
	if s.RangeConfig.ARange != [2]int{-100, 100} || s.RangeConfig.BRange != [2]int{-100, 100} {
		ranges = []struct {
			aRange [2]int
			bRange [2]int
			name   string
		}{
			{s.RangeConfig.ARange, s.RangeConfig.BRange, "Custom range"},
		}
	}

	for _, r := range ranges {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		aCount := r.aRange[1] - r.aRange[0] + 1
		if s.RangeConfig.SkipZeroA && r.aRange[0] <= 0 && r.aRange[1] >= 0 {
			aCount--
		}
		bCount := r.bRange[1] - r.bRange[0] + 1
		totalCombinations := aCount * bCount
		fmt.Printf("%s: Testing a∈[%d,%d], b∈[%d,%d] (~%d combinations)...\n", r.name, r.aRange[0], r.aRange[1], r.bRange[0], r.bRange[1], totalCombinations)

		if result := s.rangeSearch(ctx, signatures, publicKey, r.aRange, r.bRange, s.RangeConfig.MaxPairs, s.RangeConfig.NumWorkers); result != nil {
			fmt.Printf("✓ Found key in %s!\n", r.name)
			return result
		}
		fmt.Printf("No match in %s, continuing...\n", r.name)
	}

	fmt.Println("All phases completed, key not found")
	return nil
}

// rangeSearch performs a brute-force search over a specific range.
func (s *SmartBruteForceStrategy) rangeSearch(ctx context.Context, signatures []*Signature, publicKey []byte, aRange, bRange [2]int, maxPairs, numWorkers int) *RecoveryResult {
	testedCombinations := int64(0)
	resultChan := make(chan *RecoveryResult, 1)
	workChan := make(chan [2]int, numWorkers*100)

	// Generate work
	go func() {
		defer close(workChan)
		pairCount := 0
		for i := 0; i < len(signatures) && pairCount < maxPairs; i++ {
			for j := i + 1; j < len(signatures) && pairCount < maxPairs; j++ {
				select {
				case <-ctx.Done():
					return
				case workChan <- [2]int{i, j}:
					pairCount++
				}
			}
		}
	}()

	// Start workers
	if numWorkers == 0 {
		numWorkers = 16 // Default
	}

	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case pair, ok := <-workChan:
					if !ok {
						return
					}
					i, j := pair[0], pair[1]

					for a := aRange[0]; a <= aRange[1]; a++ {
						if s.RangeConfig.SkipZeroA && a == 0 {
							continue
						}
						for b := bRange[0]; b <= bRange[1]; b++ {
							combs := atomic.AddInt64(&testedCombinations, 1)
							// Print progress every 10000 combinations
							if combs%10000 == 0 {
								fmt.Printf("  Tested %d combinations...\r", combs)
							}
							aBig := big.NewInt(int64(a))
							bBig := big.NewInt(int64(b))

							priv, err := RecoverPrivateKey(signatures[i], signatures[j], aBig, bBig)
							if err != nil {
								continue
							}

							if priv.Sign() <= 0 || priv.Cmp(Secp256k1CurveOrder) >= 0 {
								continue
							}

							verified := false
							if len(publicKey) > 0 {
								verified, _ = VerifyRecoveredKey(priv, publicKey)
								if !verified {
									continue
								}
							} else {
								verified = true
							}

							select {
							case resultChan <- &RecoveryResult{
								PrivateKey:    priv,
								Relationship:  AffineRelationship{A: aBig, B: bBig},
								SignaturePair: [2]int{i, j},
								Verified:      verified,
								Pattern:       fmt.Sprintf("brute_force_a%d_b%d", a, b),
							}:
							default:
							}
							return
						}
					}
				}
			}
		}()
	}

	// Wait for result or completion
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case result := <-resultChan:
		finalCombs := atomic.LoadInt64(&testedCombinations)
		if finalCombs > 0 {
			fmt.Printf("\n  Tested %d combinations\n", finalCombs)
		}
		return result
	case <-ctx.Done():
		return nil
	case <-done:
		finalCombs := atomic.LoadInt64(&testedCombinations)
		if finalCombs > 0 {
			fmt.Printf("\n  Tested %d combinations\n", finalCombs)
		}
		return nil
	}
}

// getCommonPatterns returns the list of common patterns to try.
func (s *SmartBruteForceStrategy) getCommonPatterns() []Pattern {
	return []Pattern{
		{big.NewInt(1), big.NewInt(0), "same_nonce", 1},
		{big.NewInt(1), big.NewInt(1), "counter_+1", 2},
		{big.NewInt(1), big.NewInt(-1), "counter_-1", 2},
		{big.NewInt(1), big.NewInt(2), "counter_+2", 3},
		{big.NewInt(1), big.NewInt(-2), "counter_-2", 3},
		{big.NewInt(1), big.NewInt(3), "counter_+3", 3},
		{big.NewInt(1), big.NewInt(-3), "counter_-3", 3},
		{big.NewInt(1), big.NewInt(4), "counter_+4", 3},
		{big.NewInt(1), big.NewInt(-4), "counter_-4", 3},
		{big.NewInt(1), big.NewInt(5), "counter_+5", 3},
		{big.NewInt(1), big.NewInt(-5), "counter_-5", 3},
		{big.NewInt(1), big.NewInt(8), "step_8", 4},
		{big.NewInt(1), big.NewInt(16), "step_16", 4},
		{big.NewInt(1), big.NewInt(32), "step_32", 4},
		{big.NewInt(1), big.NewInt(64), "step_64", 4},
		{big.NewInt(1), big.NewInt(128), "step_128", 4},
		{big.NewInt(1), big.NewInt(256), "step_256", 4},
		{big.NewInt(1), big.NewInt(512), "step_512", 4},
		{big.NewInt(1), big.NewInt(1024), "step_1024", 4},
		{big.NewInt(1), big.NewInt(10), "step_10", 4},
		{big.NewInt(1), big.NewInt(100), "step_100", 4},
		{big.NewInt(1), big.NewInt(1000), "step_1000", 4},
		{big.NewInt(1), big.NewInt(10000), "step_10000", 4},
		{big.NewInt(2), big.NewInt(0), "multiply_2", 5},
		{big.NewInt(2), big.NewInt(1), "multiply_2_+1", 5},
		{big.NewInt(3), big.NewInt(0), "multiply_3", 5},
		{big.NewInt(4), big.NewInt(0), "multiply_4", 5},
		{big.NewInt(-1), big.NewInt(0), "negate", 6},
	}
}
