package bruteforce

import (
	"context"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/mahdiidarabi/ecdsa-affine/internal/parser"
	"github.com/mahdiidarabi/ecdsa-affine/internal/recovery"
)

// WorkItem represents a single work item for brute-force search
type WorkItem struct {
	SigPair    [2]int
	A          int
	B          int
	Sig1       *recovery.Signature
	Sig2       *recovery.Signature
}

// BruteForceAffineRelationshipParallel searches for affine relationships using parallel workers.
//
// Args:
//   - signatures: List of signatures
//   - publicKeyBytes: Optional public key for verification (33 bytes compressed)
//   - aRange: Range of a values to try (min, max)
//   - bRange: Range of b values to try (min, max)
//   - maxPairs: Maximum number of signature pairs to test
//   - numWorkers: Number of parallel workers (0 = auto-detect based on CPU cores)
//
// Returns:
//   - Result if found, nil otherwise
func BruteForceAffineRelationshipParallel(
	signatures []*parser.Signature,
	publicKeyBytes []byte,
	aRange, bRange [2]int,
	maxPairs int,
	numWorkers int,
) *Result {
	fmt.Printf("Testing %d signatures...\n", len(signatures))
	fmt.Printf("Searching a in range [%d, %d]\n", aRange[0], aRange[1])
	fmt.Printf("Searching b in range [%d, %d]\n", bRange[0], bRange[1])

	// Auto-detect number of workers if not specified
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}
	fmt.Printf("Using %d parallel workers\n", numWorkers)

	// Convert signatures to recovery.Signature format
	recoverySigs := make([]*recovery.Signature, len(signatures))
	for i, sig := range signatures {
		recoverySigs[i] = &recovery.Signature{
			Z: sig.Z,
			R: sig.R,
			S: sig.S,
		}
	}

	// Create context for cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Channels for work distribution and results
	workChan := make(chan WorkItem, numWorkers*10) // Buffered channel
	resultChan := make(chan *Result, 1)

	// Counter for tested pairs
	var testedPairs int64

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			worker(ctx, workChan, resultChan, publicKeyBytes, &testedPairs, workerID)
		}(i)
	}

	// Generate work items in a separate goroutine
	go func() {
		defer close(workChan)
		pairsTested := 0

		for i := 0; i < len(recoverySigs); i++ {
			for j := i + 1; j < len(recoverySigs); j++ {
				if pairsTested >= maxPairs {
					return
				}
				pairsTested++

				sig1 := recoverySigs[i]
				sig2 := recoverySigs[j]

				// Generate work items for this signature pair
				for a := aRange[0]; a <= aRange[1]; a++ {
					// Check if context is cancelled (result found)
					select {
					case <-ctx.Done():
						return
					default:
					}

					for b := bRange[0]; b <= bRange[1]; b++ {
						select {
						case <-ctx.Done():
							return
						case workChan <- WorkItem{
							SigPair: [2]int{i, j},
							A:       a,
							B:       b,
							Sig1:    sig1,
							Sig2:    sig2,
						}:
						}
					}
				}
			}
		}
	}()

	// Wait for result or completion
	select {
	case result := <-resultChan:
		cancel() // Cancel all workers
		wg.Wait() // Wait for workers to finish
		fmt.Printf("Tested %d combinations\n", atomic.LoadInt64(&testedPairs))
		return result
	case <-ctx.Done():
		// This shouldn't happen, but handle it
		wg.Wait()
		return nil
	}
}

// worker processes work items from the work channel
func worker(
	ctx context.Context,
	workChan <-chan WorkItem,
	resultChan chan<- *Result,
	publicKeyBytes []byte,
	testedPairs *int64,
	workerID int,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case work, ok := <-workChan:
			if !ok {
				return // Channel closed, no more work
			}

			atomic.AddInt64(testedPairs, 1)

			// Try to recover private key
			aBig := big.NewInt(int64(work.A))
			bBig := big.NewInt(int64(work.B))

			priv, err := recovery.RecoverPrivateKeyAffine(work.Sig1, work.Sig2, aBig, bBig)
			if err != nil {
				continue
			}

			// If public key provided, verify
			if len(publicKeyBytes) > 0 {
				verified, err := recovery.VerifyRecoveredKey(priv, publicKeyBytes)
				if err == nil && verified {
					select {
					case resultChan <- &Result{
						PrivateKey:    priv,
						A:             aBig,
						B:             bBig,
						SignaturePair: work.SigPair,
						Verified:      true,
					}:
					case <-ctx.Done():
						return
					}
					return
				}
			} else {
				// Without public key, return first valid-looking key
				if priv.Sign() > 0 && priv.Cmp(recovery.Secp256k1CurveOrder) < 0 {
					select {
					case resultChan <- &Result{
						PrivateKey:    priv,
						A:             aBig,
						B:             bBig,
						SignaturePair: work.SigPair,
						Verified:      false,
					}:
					case <-ctx.Done():
						return
					}
					return
				}
			}

			// Progress reporting (every 50000 combinations to reduce noise)
			tested := atomic.LoadInt64(testedPairs)
			if tested > 0 && tested%50000 == 0 {
				fmt.Printf("Tested %d combinations...\n", tested)
			}
		}
	}
}

// BruteForceAffineRelationshipBatch processes work in batches to avoid memory issues
// This is an alternative approach that processes work in chunks
func BruteForceAffineRelationshipBatch(
	signatures []*parser.Signature,
	publicKeyBytes []byte,
	aRange, bRange [2]int,
	maxPairs int,
	batchSize int,
	numWorkers int,
) *Result {
	fmt.Printf("Testing %d signatures...\n", len(signatures))
	fmt.Printf("Searching a in range [%d, %d]\n", aRange[0], aRange[1])
	fmt.Printf("Searching b in range [%d, %d]\n", bRange[0], bRange[1])

	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}
	if batchSize <= 0 {
		batchSize = 10000 // Default batch size
	}

	fmt.Printf("Using %d parallel workers with batch size %d\n", numWorkers, batchSize)

	// Convert signatures to recovery.Signature format
	recoverySigs := make([]*recovery.Signature, len(signatures))
	for i, sig := range signatures {
		recoverySigs[i] = &recovery.Signature{
			Z: sig.Z,
			R: sig.R,
			S: sig.S,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resultChan := make(chan *Result, 1)
	var testedPairs int64

	// Generate batches of work
	type Batch struct {
		SigPair [2]int
		AStart  int
		AEnd    int
		BStart  int
		BEnd    int
		Sig1    *recovery.Signature
		Sig2    *recovery.Signature
	}

	batchChan := make(chan Batch, numWorkers*2)

	// Generate batches
	go func() {
		defer close(batchChan)
		pairsTested := 0

		for i := 0; i < len(recoverySigs); i++ {
			for j := i + 1; j < len(recoverySigs); j++ {
				if pairsTested >= maxPairs {
					return
				}
				pairsTested++

				sig1 := recoverySigs[i]
				sig2 := recoverySigs[j]

				// Create batches for a range
				for aStart := aRange[0]; aStart <= aRange[1]; aStart += batchSize {
					aEnd := aStart + batchSize - 1
					if aEnd > aRange[1] {
						aEnd = aRange[1]
					}

					for bStart := bRange[0]; bStart <= bRange[1]; bStart += batchSize {
						bEnd := bStart + batchSize - 1
						if bEnd > bRange[1] {
							bEnd = bRange[1]
						}

						select {
						case <-ctx.Done():
							return
						case batchChan <- Batch{
							SigPair: [2]int{i, j},
							AStart:  aStart,
							AEnd:    aEnd,
							BStart:  bStart,
							BEnd:    bEnd,
							Sig1:    sig1,
							Sig2:    sig2,
						}:
						}
					}
				}
			}
		}
	}()

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case batch, ok := <-batchChan:
					if !ok {
						return
					}

					// Process batch
					for a := batch.AStart; a <= batch.AEnd; a++ {
						for b := batch.BStart; b <= batch.BEnd; b++ {
							select {
							case <-ctx.Done():
								return
							default:
							}

							atomic.AddInt64(&testedPairs, 1)

							aBig := big.NewInt(int64(a))
							bBig := big.NewInt(int64(b))

							priv, err := recovery.RecoverPrivateKeyAffine(batch.Sig1, batch.Sig2, aBig, bBig)
							if err != nil {
								continue
							}

							if len(publicKeyBytes) > 0 {
								verified, err := recovery.VerifyRecoveredKey(priv, publicKeyBytes)
								if err == nil && verified {
									select {
									case resultChan <- &Result{
										PrivateKey:    priv,
										A:             aBig,
										B:             bBig,
										SignaturePair: batch.SigPair,
										Verified:      true,
									}:
									case <-ctx.Done():
									}
									return
								}
							} else {
								if priv.Sign() > 0 && priv.Cmp(recovery.Secp256k1CurveOrder) < 0 {
									select {
									case resultChan <- &Result{
										PrivateKey:    priv,
										A:             aBig,
										B:             bBig,
										SignaturePair: batch.SigPair,
										Verified:      false,
									}:
									case <-ctx.Done():
									}
									return
								}
							}
						}
					}

					// Progress reporting (every 50000 combinations)
					tested := atomic.LoadInt64(&testedPairs)
					if tested > 0 && tested%50000 == 0 {
						fmt.Printf("Tested %d combinations...\n", tested)
					}
				}
			}
		}()
	}

	// Wait for result
	select {
	case result := <-resultChan:
		cancel()
		wg.Wait()
		fmt.Printf("Tested %d combinations\n", atomic.LoadInt64(&testedPairs))
		return result
	case <-ctx.Done():
		wg.Wait()
		fmt.Printf("Tested %d combinations, no relationship found\n", atomic.LoadInt64(&testedPairs))
		return nil
	}
}

