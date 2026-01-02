package eddsaaffine

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
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

	log.Printf("Starting EdDSA key recovery search with %d signatures", len(signatures))

	// Phase 0: Check for same nonce reuse (fastest)
	log.Println("Phase 0: Checking for same nonce reuse...")
	if result := s.checkSameNonceReuse(signatures, publicKey); result != nil {
		log.Printf("✅ Found same nonce reuse in signatures [%d, %d]", result.SignaturePair[0], result.SignaturePair[1])
		return result
	}
	log.Println("No same nonce reuse found")

	// Phase 1: Try common patterns
	if s.PatternConfig.IncludeCommonPatterns {
		log.Println("Phase 1: Trying common patterns...")
		if result := s.tryCommonPatterns(ctx, signatures, publicKey); result != nil {
			log.Printf("✅ Found pattern '%s' in signatures [%d, %d]", result.Pattern, result.SignaturePair[0], result.SignaturePair[1])
			return result
		}
		log.Println("No common patterns matched")
	}

	// Phase 2: Try custom patterns
	if len(s.PatternConfig.CustomPatterns) > 0 {
		log.Printf("Phase 2: Trying %d custom patterns...", len(s.PatternConfig.CustomPatterns))
		if result := s.tryCustomPatterns(ctx, signatures, publicKey); result != nil {
			log.Printf("✅ Found custom pattern '%s' in signatures [%d, %d]", result.Pattern, result.SignaturePair[0], result.SignaturePair[1])
			return result
		}
		log.Println("No custom patterns matched")
	}

	// Phase 3: Adaptive range search
	log.Println("Phase 3: Starting adaptive range search (brute-force)...")
	return s.adaptiveRangeSearch(ctx, signatures, publicKey)
}

// checkSameNonceReuse checks for identical R values (same nonce reuse).
func (s *SmartBruteForceStrategy) checkSameNonceReuse(signatures []*Signature, publicKey []byte) *RecoveryResult {
	for i := 0; i < len(signatures); i++ {
		for j := i + 1; j < len(signatures); j++ {
			if signatures[i].R.Cmp(signatures[j].R) == 0 {
				// Same nonce reuse: r2 = r1, so a=1, b=0
				a := big.NewInt(1)
				b := big.NewInt(0)

				priv, err := RecoverPrivateKey(signatures[i], signatures[j], a, b)
				if err != nil {
					continue
				}

				if priv.Sign() <= 0 || priv.Cmp(Ed25519CurveOrder) >= 0 {
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

// getCommonPatterns returns a list of common patterns to test.
func (s *SmartBruteForceStrategy) getCommonPatterns() []Pattern {
	return []Pattern{
		{big.NewInt(1), big.NewInt(0), "same_nonce", 1},
		{big.NewInt(1), big.NewInt(1), "counter_plus_1", 2},
		{big.NewInt(1), big.NewInt(-1), "counter_minus_1", 3},
		{big.NewInt(1), big.NewInt(2), "step_2", 4},
		{big.NewInt(1), big.NewInt(10), "step_10", 5},
		{big.NewInt(1), big.NewInt(100), "step_100", 6},
		{big.NewInt(1), big.NewInt(123), "step_123", 7},
		{big.NewInt(1), big.NewInt(12345), "step_12345", 8},
		{big.NewInt(2), big.NewInt(0), "double", 9},
		{big.NewInt(2), big.NewInt(1), "double_plus_1", 10},
	}
}

// tryCommonPatterns tries built-in common patterns.
func (s *SmartBruteForceStrategy) tryCommonPatterns(ctx context.Context, signatures []*Signature, publicKey []byte) *RecoveryResult {
	commonPatterns := s.getCommonPatterns()
	log.Printf("Trying %d common patterns", len(commonPatterns))

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
	log.Printf("Trying pattern '%s' (a=%s, b=%s)", patternName, a.Text(10), b.Text(10))
	for i := 0; i < len(signatures); i++ {
		for j := i + 1; j < len(signatures); j++ {
			// Validate that the affine relationship actually holds: r2 = a*r1 + b
			// For a=1, this means: r2 = r1 + b, so r2 - r1 = b
			expectedR2 := new(big.Int).Mul(a, signatures[i].R)
			expectedR2.Add(expectedR2, b)
			expectedR2.Mod(expectedR2, Ed25519CurveOrder)

			// Compare expected r2 with actual r2
			actualR2 := new(big.Int).Set(signatures[j].R)
			if expectedR2.Cmp(actualR2) != 0 {
				// Relationship doesn't hold, skip this pair
				continue
			}

			priv, err := RecoverPrivateKey(signatures[i], signatures[j], a, b)
			if err != nil {
				continue
			}

			if priv.Sign() <= 0 || priv.Cmp(Ed25519CurveOrder) >= 0 {
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

		log.Printf("%s: searching a in [%d, %d], b in [%d, %d]", r.name, r.aRange[0], r.aRange[1], r.bRange[0], r.bRange[1])
		if result := s.rangeSearch(ctx, signatures, publicKey, r.aRange, r.bRange, s.RangeConfig.MaxPairs, s.RangeConfig.NumWorkers); result != nil {
			return result
		}
		log.Printf("%s: no key found", r.name)
	}

	log.Println("All adaptive range search phases completed, no key found")
	return nil
}

// rangeSearch performs a brute-force search over a specific range.
func (s *SmartBruteForceStrategy) rangeSearch(ctx context.Context, signatures []*Signature, publicKey []byte, aRange, bRange [2]int, maxPairs, numWorkers int) *RecoveryResult {
	testedPairs := int64(0)
	resultChan := make(chan *RecoveryResult, 1)
	workChan := make(chan [2]int, numWorkers*100)

	// Log search parameters
	log.Printf("Brute-force search: a in [%d, %d], b in [%d, %d], max %d pairs", aRange[0], aRange[1], bRange[0], bRange[1], maxPairs)

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
		numWorkers = runtime.NumCPU()
	}
	log.Printf("Using %d parallel workers", numWorkers)

	var wg sync.WaitGroup
	var found int32

	// Progress logging goroutine
	progressDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-progressDone:
				return
			case <-ticker.C:
				tested := atomic.LoadInt64(&testedPairs)
				if tested > 0 {
					log.Printf("Progress: tested %d combinations...", tested)
				}
			}
		}
	}()

	for i := 0; i < numWorkers; i++ {
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
					if atomic.LoadInt32(&found) == 1 {
						return
					}

					// Try a=1 first (most common case)
					for a := aRange[0]; a <= aRange[1]; a++ {
						if atomic.LoadInt32(&found) == 1 {
							return
						}
						if a == 0 && s.RangeConfig.SkipZeroA {
							continue
						}

						// Prioritize a=1
						if a != 1 && aRange[0] <= 1 && aRange[1] >= 1 {
							// Try a=1 first
							for b := bRange[0]; b <= bRange[1]; b++ {
								if atomic.LoadInt32(&found) == 1 {
									return
								}
								atomic.AddInt64(&testedPairs, 1)

								aBig := big.NewInt(int64(1))
								bBig := big.NewInt(int64(b))

								// Validate that the affine relationship actually holds: r2 = a*r1 + b
								expectedR2 := new(big.Int).Mul(aBig, signatures[pair[0]].R)
								expectedR2.Add(expectedR2, bBig)
								expectedR2.Mod(expectedR2, Ed25519CurveOrder)
								if expectedR2.Cmp(signatures[pair[1]].R) != 0 {
									continue // Relationship doesn't hold, skip
								}

								priv, err := RecoverPrivateKey(signatures[pair[0]], signatures[pair[1]], aBig, bBig)
								if err == nil && priv.Sign() > 0 && priv.Cmp(Ed25519CurveOrder) < 0 {
									verified := len(publicKey) == 0
									if len(publicKey) > 0 {
										verified, _ = VerifyRecoveredKey(priv, publicKey)
									}

									if verified {
										if atomic.CompareAndSwapInt32(&found, 0, 1) {
											resultChan <- &RecoveryResult{
												PrivateKey:    priv,
												Relationship:  AffineRelationship{A: aBig, B: bBig},
												SignaturePair: [2]int{pair[0], pair[1]},
												Verified:      verified,
												Pattern:       fmt.Sprintf("brute_force_a%d_b%d", 1, b),
											}
										}
										return
									}
								}
							}
						}

						// Try current a value
						for b := bRange[0]; b <= bRange[1]; b++ {
							if atomic.LoadInt32(&found) == 1 {
								return
							}
							atomic.AddInt64(&testedPairs, 1)

							aBig := big.NewInt(int64(a))
							bBig := big.NewInt(int64(b))

							// Validate that the affine relationship actually holds: r2 = a*r1 + b
							expectedR2 := new(big.Int).Mul(aBig, signatures[pair[0]].R)
							expectedR2.Add(expectedR2, bBig)
							expectedR2.Mod(expectedR2, Ed25519CurveOrder)
							if expectedR2.Cmp(signatures[pair[1]].R) != 0 {
								continue // Relationship doesn't hold, skip
							}

							priv, err := RecoverPrivateKey(signatures[pair[0]], signatures[pair[1]], aBig, bBig)
							if err == nil && priv.Sign() > 0 && priv.Cmp(Ed25519CurveOrder) < 0 {
								verified := len(publicKey) == 0
								if len(publicKey) > 0 {
									verified, _ = VerifyRecoveredKey(priv, publicKey)
								}

								if verified {
									if atomic.CompareAndSwapInt32(&found, 0, 1) {
										resultChan <- &RecoveryResult{
											PrivateKey:    priv,
											Relationship:  AffineRelationship{A: aBig, B: bBig},
											SignaturePair: [2]int{pair[0], pair[1]},
											Verified:      verified,
											Pattern:       fmt.Sprintf("brute_force_a%d_b%d", a, b),
										}
									}
									return
								}
							}
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
		close(progressDone) // Stop progress logging
		tested := atomic.LoadInt64(&testedPairs)
		log.Printf("✅ Found key after testing %d combinations (a=%s, b=%s, pair=[%d,%d])",
			tested, result.Relationship.A.Text(10), result.Relationship.B.Text(10),
			result.SignaturePair[0], result.SignaturePair[1])
		return result
	case <-ctx.Done():
		close(progressDone) // Stop progress logging
		tested := atomic.LoadInt64(&testedPairs)
		log.Printf("Search cancelled after testing %d combinations", tested)
		return nil
	case <-done:
		close(progressDone) // Stop progress logging
		tested := atomic.LoadInt64(&testedPairs)
		log.Printf("Search completed: tested %d combinations, no key found", tested)
		return nil
	}
}
