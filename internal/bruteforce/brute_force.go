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
func SmartBruteForce(signatures []*parser.Signature, publicKeyBytes []byte) *Result {
	fmt.Println("Trying common affine patterns first...")

	// Common patterns: (a, b) tuples
	commonPatterns := [][2]int{
		{1, 0},     // k2 = k1 (same nonce reuse)
		{1, 1},     // k2 = k1 + 1
		{1, -1},    // k2 = k1 - 1
		{1, 2},     // k2 = k1 + 2
		{1, -2},    // k2 = k1 - 2
		{1, 1234},  // k2 = k1 + 1234 (common counter step)
		{1, -1234}, // k2 = k1 - 1234
		{2, 0},     // k2 = 2*k1
		{2, 1},     // k2 = 2*k1 + 1
		{2, -1},    // k2 = 2*k1 - 1
		{3, 0},     // k2 = 3*k1
		{-1, 0},    // k2 = -k1 (unlikely but possible)
	}

	// Convert signatures to recovery.Signature format
	recoverySigs := make([]*recovery.Signature, len(signatures))
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
					if priv.Sign() > 0 && priv.Cmp(recovery.Secp256k1CurveOrder) < 0 {
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
	}

	fmt.Println("Common patterns didn't work, trying wider search with parallel workers...")

	// If common patterns fail, try wider search with parallel processing
	return BruteForceAffineRelationshipParallel(
		signatures,
		publicKeyBytes,
		[2]int{-100000, 100000},
		[2]int{-100000, 100000},
		500,
		0, // Auto-detect number of workers
	)
}
