// Package eddsaaffine provides tools for recovering EdDSA (Ed25519) private keys
// when nonces used in signing have an affine relationship (r2 = a*r1 + b).
//
// This package is designed for analyzing flawed EdDSA implementations that use
// random nonces instead of the standard deterministic nonces. Standard EdDSA uses
// deterministic nonces derived from SHA-512(private_key || message), but flawed
// implementations may use random nonces, making them vulnerable to the same
// attacks as ECDSA.
//
// WARNING: This package is for security research and testing purposes only.
// It should only be used to analyze your own signatures or with explicit permission.
//
// Basic Usage:
//
//	client := eddsaaffine.NewClient()
//	result, err := client.RecoverKey(ctx, "path/to/signatures.json", "public_key_hex")
//	// Or from in-memory signatures (e.g. your own parser):
//	// result, err := client.RecoverKeyFromSignatures(ctx, signatures, "public_key_hex")
//
// Customizing the strategy (defaults are sensible; override as needed):
//
//	strategy := eddsaaffine.NewSmartBruteForceStrategy().
//		WithRangeConfig(eddsaaffine.RangeConfig{
//			ARange:    [2]int{1, 10},
//			BRange:    [2]int{-50000, 50000},
//			NumWorkers: 8,
//		}).
//		WithPatternConfig(eddsaaffine.PatternConfig{
//			CustomPatterns: append(eddsaaffine.CommonPatterns(), eddsaaffine.Pattern{
//				A: big.NewInt(1), B: big.NewInt(12345), Name: "custom_step", Priority: 1,
//			}),
//			IncludeCommonPatterns: false,
//		})
//	client = eddsaaffine.NewClient().WithStrategy(strategy)
//
// Key Differences from ECDSA:
//
// - EdDSA signature equation: s = r + H(R||A||M) * a mod q
// - ECDSA signature equation: s = k^-1 * (z + r * a) mod n
// - EdDSA uses SHA-512 for hashing, ECDSA uses SHA-256
// - EdDSA uses Ed25519 curve, ECDSA uses secp256k1
//
// See the examples/eddsa directory for more detailed usage examples.
package eddsaaffine

