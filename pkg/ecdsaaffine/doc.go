// Package ecdsaaffine provides tools for recovering ECDSA private keys from signatures
// with affinely related nonces (k₂ = a·k₁ + b).
//
// This package implements the key recovery attack described in:
// "Breaking ECDSA with Two Affinely Related Nonces" (arXiv:2504.13737)
// by Jamie Gilchrist, William J. Buchanan, and Keir Finlow-Bates.
//
// # Quick Start
//
//	import "github.com/mahdiidarabi/ecdsa-affine/pkg/ecdsaaffine"
//
//	// Create a client with default settings
//	client := ecdsaaffine.NewClient()
//
//	// Recover key with smart brute-force
//	result, err := client.RecoverKey(ctx, "signatures.json", "03...")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	fmt.Printf("Recovered key: %s\n", result.PrivateKey.Text(16))
//
// # Customization
//
// You can customize the brute-force strategy:
//
//	strategy := ecdsaaffine.NewSmartBruteForceStrategy().
//	    WithRangeConfig(ecdsaaffine.RangeConfig{
//	        ARange:    [2]int{1, 10},
//	        BRange:    [2]int{-50000, 50000},
//	        MaxPairs:  100,
//	        NumWorkers: 16,
//	    }).
//	    WithPatternConfig(ecdsaaffine.PatternConfig{
//	        CustomPatterns: []ecdsaaffine.Pattern{
//	            {A: big.NewInt(1), B: big.NewInt(12345), Name: "custom_step", Priority: 1},
//	        },
//	        IncludeCommonPatterns: true,
//	    })
//
//	client := ecdsaaffine.NewClient().WithStrategy(strategy)
//
// # Custom Strategies
//
// Implement the BruteForceStrategy interface to create custom search strategies:
//
//	type MyStrategy struct{}
//
//	func (s *MyStrategy) Search(ctx context.Context, signatures []*Signature, publicKey []byte) *RecoveryResult {
//	    // Your custom search logic
//	}
//
//	func (s *MyStrategy) Name() string {
//	    return "MyCustomStrategy"
//	}
//
//	client := ecdsaaffine.NewClient().WithStrategy(&MyStrategy{})
package ecdsaaffine

