// Package main demonstrates how to use the ecdsaaffine package.
//
// Run this example from the project root:
//
//	go run examples/basic/main.go
//
// Make sure fixtures are generated first:
//
//	make fixtures
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/mahdiidarabi/ecdsa-affine/pkg/ecdsaaffine"
)

func main() {
	ctx := context.Background()

	// Load public key from test_key_info.json
	publicKeyHex, err := loadPublicKey("fixtures/test_key_info.json")
	if err != nil {
		log.Fatalf("Failed to load public key: %v", err)
	}

	// Example 1: Basic usage with default settings
	fmt.Println("=== Example 1: Basic Usage ===")
	client := ecdsaaffine.NewClient()

	result, err := client.RecoverKey(ctx, "fixtures/test_signatures_hardcoded_step.json", publicKeyHex)
	if err != nil {
		log.Printf("Recovery failed: %v", err)
	} else {
		fmt.Printf("✓ Recovered private key!\n")
		fmt.Printf("  Key: %s\n", result.PrivateKey.Text(16))
		fmt.Printf("  Relationship: k2 = %s*k1 + %s\n", result.Relationship.A.Text(10), result.Relationship.B.Text(10))
		fmt.Printf("  Pattern: %s\n", result.Pattern)
		fmt.Printf("  Verified: %v\n", result.Verified)
	}

	// Example 2: Custom range configuration
	fmt.Println("\n=== Example 2: Custom Range ===")
	strategy := ecdsaaffine.NewSmartBruteForceStrategy().
		WithRangeConfig(ecdsaaffine.RangeConfig{
			ARange:     [2]int{1, 10},
			BRange:     [2]int{-50000, 50000},
			MaxPairs:   100,
			NumWorkers: 8,
			SkipZeroA:  true,
		})

	client2 := ecdsaaffine.NewClient().WithStrategy(strategy)
	result2, err := client2.RecoverKey(ctx, "fixtures/test_signatures_hardcoded_step.json", publicKeyHex)
	if err != nil {
		log.Printf("Recovery failed: %v", err)
	} else {
		fmt.Printf("✓ Recovered with custom range!\n")
		fmt.Printf("  Key: %s\n", result2.PrivateKey.Text(16))
	}

	// Example 3: Known relationship
	fmt.Println("\n=== Example 3: Known Relationship ===")
	result3, err := client.RecoverKeyWithKnownRelationship(ctx, "fixtures/test_signatures_counter.json", 1, 1, publicKeyHex)
	if err != nil {
		log.Printf("Recovery failed: %v", err)
	} else {
		fmt.Printf("✓ Recovered with known relationship!\n")
		fmt.Printf("  Key: %s\n", result3.PrivateKey.Text(16))
	}

	// Example 4: Custom patterns
	fmt.Println("\n=== Example 4: Custom Patterns ===")
	customStrategy := ecdsaaffine.NewSmartBruteForceStrategy().
		WithPatternConfig(ecdsaaffine.PatternConfig{
			CustomPatterns: []ecdsaaffine.Pattern{
				{A: big.NewInt(1), B: big.NewInt(12345), Name: "hardcoded_step", Priority: 1},
				{A: big.NewInt(1), B: big.NewInt(17), Name: "step_17", Priority: 2},
			},
			IncludeCommonPatterns: true,
		})

	client4 := ecdsaaffine.NewClient().WithStrategy(customStrategy)
	result4, err := client4.RecoverKey(ctx, "fixtures/test_signatures_hardcoded_step.json", publicKeyHex)
	if err != nil {
		log.Printf("Recovery failed: %v", err)
	} else {
		fmt.Printf("✓ Recovered with custom patterns!\n")
		fmt.Printf("  Key: %s\n", result4.PrivateKey.Text(16))
	}
}

// loadPublicKey reads the public key from test_key_info.json
func loadPublicKey(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var keyInfo struct {
		PublicKeyHex string `json:"public_key_hex"`
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&keyInfo); err != nil {
		return "", fmt.Errorf("failed to parse JSON: %w", err)
	}

	if keyInfo.PublicKeyHex == "" {
		return "", fmt.Errorf("public_key_hex not found in file")
	}

	return keyInfo.PublicKeyHex, nil
}
