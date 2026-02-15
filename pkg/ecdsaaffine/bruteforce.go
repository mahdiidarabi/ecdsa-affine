package ecdsaaffine

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

	log.Printf("Starting ECDSA key recovery search with %d signatures", len(signatures))

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

// checkSameNonceReuse checks for identical r values (same nonce reuse).
// IMPORTANT: Same r values don't guarantee same nonce - we must verify the recovered key.
// This function tries ALL pairs with same r and returns the first one that verifies.
func (s *SmartBruteForceStrategy) checkSameNonceReuse(signatures []*Signature, publicKey []byte) *RecoveryResult {
	sameRPairs := 0
	for i := 0; i < len(signatures); i++ {
		for j := i + 1; j < len(signatures); j++ {
			if signatures[i].R.Cmp(signatures[j].R) == 0 {
				sameRPairs++
				// Same r value found - MUST be same nonce (discrete log problem)
				// Same nonce reuse: k2 = k1, so a=1, b=0
				a := big.NewInt(1)
				b := big.NewInt(0)


				priv, err := RecoverPrivateKey(signatures[i], signatures[j], a, b)
				if err != nil {
					log.Printf("  Recovery failed: %v", err)
					continue
				}

				if priv.Sign() <= 0 || priv.Cmp(Secp256k1CurveOrder) >= 0 {
					log.Printf("  Recovered key out of range: %s", priv.Text(16))
					continue
				}

				log.Printf("  Recovered private key: %s", priv.Text(16))

				// Verify recovered key against public key (required for real-world use)
				verified := false
				if len(publicKey) > 0 {
					var verifyErr error
					verified, verifyErr = VerifyRecoveredKey(priv, publicKey)
					if !verified {
						log.Printf("  ❌ Verification FAILED: %v", verifyErr)
						log.Printf("  This indicates a BUG - same r MUST mean same nonce!")
						// Continue to try other pairs, but this is suspicious
						continue
					}
					log.Printf("  ✅ Verification SUCCEEDED for pair [%d, %d]", i, j)
				} else {
					// No public key provided - cannot verify in real-world scenario
					// Set verified to false since we cannot confirm the key is correct
					log.Printf("  ⚠️  No public key provided - cannot verify recovered key")
					verified = false
					// Don't return if we can't verify - this is not a real-world scenario
					continue
				}

				// Found a verified same nonce reuse!
				log.Printf("Found %d pairs with same r, verified same nonce in pair [%d, %d]", sameRPairs, i, j)
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
	if sameRPairs > 0 {
		log.Printf("⚠️  Found %d pairs with same r values, but NONE verified as same nonce reuse", sameRPairs)
		log.Printf("   This indicates a BUG - same r MUST mean same nonce (discrete log problem)")
		log.Printf("   Possible causes:")
		log.Printf("   1. z values are incorrect (message hash calculation)")
		log.Printf("   2. r/s values are parsed incorrectly")
		log.Printf("   3. Recovery formula has a bug")
		log.Printf("   4. Public key verification has a bug")
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

// tryPattern tries a specific (a, b) pattern across ALL signature pairs.
// IMPORTANT: This checks every pair (i, j) where i < j, regardless of r values.
// Each pair is tested independently - we don't assume all pairs have the same relationship.
func (s *SmartBruteForceStrategy) tryPattern(signatures []*Signature, publicKey []byte, a, b *big.Int, patternName string) *RecoveryResult {
	totalPairs := len(signatures) * (len(signatures) - 1) / 2
	log.Printf("Trying pattern '%s' (a=%s, b=%s) on all %d signature pairs", patternName, a.Text(10), b.Text(10), totalPairs)
	checkedPairs := 0
	lastLogTime := time.Now()

	// Check ALL pairs (i, j) where i < j
	for i := 0; i < len(signatures); i++ {
		for j := i + 1; j < len(signatures); j++ {
			checkedPairs++

			// Log progress every 5 seconds or every 1M pairs
			now := time.Now()
			if now.Sub(lastLogTime) >= 5*time.Second || checkedPairs%1000000 == 0 {
				log.Printf("  Progress: checked %d/%d pairs (%.1f%%)", checkedPairs, totalPairs, float64(checkedPairs)/float64(totalPairs)*100)
				lastLogTime = now
			}

			// Try to recover private key using this pattern for this pair
			priv, err := RecoverPrivateKey(signatures[i], signatures[j], a, b)
			if err != nil {
				// Recovery failed (e.g., denominator zero) - try next pair
				continue
			}

			// Check if recovered key is in valid range
			if priv.Sign() <= 0 || priv.Cmp(Secp256k1CurveOrder) >= 0 {
				// Key out of range - try next pair
				continue
			}

			// Verify recovered key against public key
			verified := false
			if len(publicKey) > 0 {
				verified, _ = VerifyRecoveredKey(priv, publicKey)
				if !verified {
					// Verification failed - this pair doesn't match this pattern, try next pair
					continue
				}
			} else {
				// No public key provided - cannot verify in real-world scenario
				// Set verified to false since we cannot confirm the key is correct
				verified = false
			}

			// Found a verified match for this pattern!
			log.Printf("✅ Found key with pattern '%s' after checking %d/%d pairs (signature pair [%d, %d])",
				patternName, checkedPairs, totalPairs, i, j)
			return &RecoveryResult{
				PrivateKey:    priv,
				Relationship:  AffineRelationship{A: a, B: b},
				SignaturePair: [2]int{i, j},
				Verified:      verified,
				Pattern:       patternName,
			}
		}
	}
	// Checked all pairs for this pattern, none matched
	log.Printf("Pattern '%s': checked all %d pairs, no key found", patternName, totalPairs)
	return nil
}

// adaptiveRangeSearch performs an adaptive range search with expanding ranges.
func (s *SmartBruteForceStrategy) adaptiveRangeSearch(ctx context.Context, signatures []*Signature, publicKey []byte) *RecoveryResult {
	ranges := []struct {
		aRange [2]int
		bRange [2]int
		name   string
	}{
		{[2]int{1, 1}, [2]int{-10, 100}, "Phase 2a: a=1, small b"},
		{[2]int{1, 1}, [2]int{-100, 1000}, "Phase 2b: a=1, medium b"},
		{[2]int{1, 1}, [2]int{-1000, 10000}, "Phase 2c: a=1, larger b"},
		{[2]int{2, 4}, [2]int{-100, 1000}, "Phase 3a: small a, medium b"},
		{[2]int{-5, -1}, [2]int{-100, 1000}, "Phase 3b: negative a, medium b"},
		{[2]int{1, 10}, [2]int{-5000, 50000}, "Phase 3c: wider a, larger b"},
		{[2]int{1, 100}, [2]int{-500000, 500000000}, "Phase 4: very wide search"},
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
		log.Printf("%s: searching a in [%d, %d], b in [%d, %d] (~%d combinations)", r.name, r.aRange[0], r.aRange[1], r.bRange[0], r.bRange[1], totalCombinations)

		// Use sequential search for smaller ranges (faster due to no goroutine overhead)
		// Use parallel for larger ranges (Phase 3c and beyond)
		useParallel := totalCombinations > 100000 // Threshold: use parallel for >100k combinations

		var result *RecoveryResult
		if useParallel {
			result = s.rangeSearchParallel(ctx, signatures, publicKey, r.aRange, r.bRange, s.RangeConfig.MaxPairs, s.RangeConfig.NumWorkers)
		} else {
			result = s.rangeSearchSequential(ctx, signatures, publicKey, r.aRange, r.bRange, s.RangeConfig.MaxPairs)
		}

		if result != nil {
			return result
		}
		log.Printf("%s: no key found", r.name)
	}

	log.Println("All adaptive range search phases completed, no key found")
	return nil
}

// rangeSearchSequential performs a sequential brute-force search (faster for smaller ranges).
func (s *SmartBruteForceStrategy) rangeSearchSequential(ctx context.Context, signatures []*Signature, publicKey []byte, aRange, bRange [2]int, maxPairs int) *RecoveryResult {
	pairCount := 0
	for i := 0; i < len(signatures) && pairCount < maxPairs; i++ {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		for j := i + 1; j < len(signatures) && pairCount < maxPairs; j++ {
			pairCount++

			for a := aRange[0]; a <= aRange[1]; a++ {
				if s.RangeConfig.SkipZeroA && a == 0 {
					continue
				}
				aBig := big.NewInt(int64(a))
				for b := bRange[0]; b <= bRange[1]; b++ {
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
						// No public key provided - cannot verify in real-world scenario
						// Set verified to false since we cannot confirm the key is correct
						verified = false
					}

					return &RecoveryResult{
						PrivateKey:    priv,
						Relationship:  AffineRelationship{A: aBig, B: bBig},
						SignaturePair: [2]int{i, j},
						Verified:      verified,
						Pattern:       fmt.Sprintf("brute_force_a%d_b%d", a, b),
					}
				}
			}
		}
	}
	return nil
}

// rangeSearchParallel performs a parallel brute-force search (faster for larger ranges).
func (s *SmartBruteForceStrategy) rangeSearchParallel(ctx context.Context, signatures []*Signature, publicKey []byte, aRange, bRange [2]int, maxPairs, numWorkers int) *RecoveryResult {
	return s.rangeSearch(ctx, signatures, publicKey, aRange, bRange, maxPairs, numWorkers)
}

// rangeSearch performs a brute-force search over a specific range using parallel workers.
func (s *SmartBruteForceStrategy) rangeSearch(ctx context.Context, signatures []*Signature, publicKey []byte, aRange, bRange [2]int, maxPairs, numWorkers int) *RecoveryResult {
	var testedPairs int64
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

								priv, err := RecoverPrivateKey(signatures[pair[0]], signatures[pair[1]], aBig, bBig)
								if err == nil && priv.Sign() > 0 && priv.Cmp(Secp256k1CurveOrder) < 0 {
									// Verify recovered key against public key (required for real-world use)
									verified := false
									if len(publicKey) > 0 {
										verified, _ = VerifyRecoveredKey(priv, publicKey)
									} else {
										// No public key provided - cannot verify in real-world scenario
										// Skip this key since we cannot confirm it's correct
										continue
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

							priv, err := RecoverPrivateKey(signatures[pair[0]], signatures[pair[1]], aBig, bBig)
							if err == nil && priv.Sign() > 0 && priv.Cmp(Secp256k1CurveOrder) < 0 {
								// Verify recovered key against public key (required for real-world use)
								verified := false
								if len(publicKey) > 0 {
									verified, _ = VerifyRecoveredKey(priv, publicKey)
								} else {
									// No public key provided - cannot verify in real-world scenario
									// Skip this key since we cannot confirm it's correct
									continue
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

// getCommonPatterns returns the list of common patterns to try (uses shared default).
func (s *SmartBruteForceStrategy) getCommonPatterns() []Pattern {
	return defaultCommonPatterns()
}
