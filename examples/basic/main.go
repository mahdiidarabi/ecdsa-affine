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
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mahdiidarabi/ecdsa-affine/pkg/ecdsaaffine"
)

func main() {
	ctx := context.Background()

	// Check if signature file is provided as command-line argument
	var signatureFile string
	var publicKeyHex string

	if len(os.Args) > 1 {
		signatureFile = os.Args[1]
		// Try to extract public key from signature file
		if pk, err := extractPublicKeyFromSignatures(signatureFile); err == nil && pk != "" {
			publicKeyHex = pk
			fmt.Printf("Using public key from signature file: %s...\n", publicKeyHex[:20])
		}
	} else {
		signatureFile = "fixtures/test_signatures_hardcoded_step.json"
	}

	// Load public key from test_key_info.json if not found in signature file
	if publicKeyHex == "" {
		pk, err := loadPublicKey("fixtures/test_key_info.json")
		if err == nil {
			publicKeyHex = pk
		}
	}

	// Create output file based on JSON filename
	var outputFile *os.File
	var multiWriter io.Writer = os.Stdout
	if signatureFile != "" {
		// Get directory and base name of signature file
		sigDir := filepath.Dir(signatureFile)
		baseName := strings.TrimSuffix(filepath.Base(signatureFile), filepath.Ext(signatureFile))
		// Create output file in the same directory as the signature file
		outputFileName := filepath.Join(sigDir, baseName+".txt")

		// Open file in append mode (create if doesn't exist)
		var err error
		outputFile, err = os.OpenFile(outputFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			defer outputFile.Close()
			// Write header to both stdout and file
			multiWriter = io.MultiWriter(os.Stdout, outputFile)
			fmt.Fprintf(multiWriter, "\n%s\n", strings.Repeat("=", 80))
			fmt.Fprintf(multiWriter, "Recovery run for: %s\n", signatureFile)
			fmt.Fprintf(multiWriter, "Timestamp: %s\n", getTimestamp())
			fmt.Fprintf(multiWriter, "%s\n\n", strings.Repeat("=", 80))
		}
	}

	// Helper function to print to stdout only
	printf := func(format string, args ...interface{}) {
		fmt.Printf(format, args...)
	}

	// Helper function to write key recovery results to file
	writeToFile := func(format string, args ...interface{}) {
		if outputFile != nil {
			fmt.Fprintf(outputFile, format, args...)
		}
	}

	// Example 1: Basic usage with default settings
	printf("=== Example 1: Basic Usage ===\n")
	client := ecdsaaffine.NewClient()

	result, err := client.RecoverKey(ctx, signatureFile, publicKeyHex)
	if err != nil {
		printf("Recovery failed: %v\n", err)
		log.Printf("Recovery failed: %v", err)
		writeToFile("Recovery failed: %v\n", err)
	} else {
		printf("✓ Recovered private key!\n")
		printf("  Key: %s\n", result.PrivateKey.Text(16))
		printf("  Relationship: k2 = %s*k1 + %s\n", result.Relationship.A.Text(10), result.Relationship.B.Text(10))
		printf("  Pattern: %s\n", result.Pattern)
		printf("  Verified: %v\n", result.Verified)

		// Write key recovery results to file
		writeToFile("✓ Recovered private key!\n")
		writeToFile("  Key: %s\n", result.PrivateKey.Text(16))
		writeToFile("  Relationship: k2 = %s*k1 + %s\n", result.Relationship.A.Text(10), result.Relationship.B.Text(10))
		writeToFile("  Pattern: %s\n", result.Pattern)
		writeToFile("  Verified: %v\n", result.Verified)
		writeToFile("  Signature pair: [%d, %d]\n", result.SignaturePair[0], result.SignaturePair[1])

		// Terminate if key is verified
		if result.Verified {
			printf("\n✅ Verified key found! Terminating.\n")
			writeToFile("\n✅ Verified key found! Terminating.\n")
			return
		}
	}

	// Example 2: Custom range configuration
	printf("\n=== Example 2: Custom Range ===\n")
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
		printf("Recovery failed: %v\n", err)
		log.Printf("Recovery failed: %v", err)
		writeToFile("Recovery failed (custom range): %v\n", err)
	} else {
		printf("✓ Recovered with custom range!\n")
		printf("  Key: %s\n", result2.PrivateKey.Text(16))
		printf("  Verified: %v\n", result2.Verified)
		writeToFile("✓ Recovered with custom range!\n")
		writeToFile("  Key: %s\n", result2.PrivateKey.Text(16))
		writeToFile("  Verified: %v\n", result2.Verified)

		// Terminate if key is verified
		if result2.Verified {
			printf("\n✅ Verified key found! Terminating.\n")
			writeToFile("\n✅ Verified key found! Terminating.\n")
			return
		}
	}

	// Example 3: Known relationship
	printf("\n=== Example 3: Known Relationship ===\n")
	result3, err := client.RecoverKeyWithKnownRelationship(ctx, "fixtures/test_signatures_counter.json", 1, 1, publicKeyHex)
	if err != nil {
		printf("Recovery failed: %v\n", err)
		log.Printf("Recovery failed: %v", err)
		writeToFile("Recovery failed (known relationship): %v\n", err)
	} else {
		printf("✓ Recovered with known relationship!\n")
		printf("  Key: %s\n", result3.PrivateKey.Text(16))
		printf("  Verified: %v\n", result3.Verified)
		writeToFile("✓ Recovered with known relationship!\n")
		writeToFile("  Key: %s\n", result3.PrivateKey.Text(16))
		writeToFile("  Verified: %v\n", result3.Verified)

		// Terminate if key is verified
		if result3.Verified {
			printf("\n✅ Verified key found! Terminating.\n")
			writeToFile("\n✅ Verified key found! Terminating.\n")
			return
		}
	}

	// Example 4: Custom patterns
	printf("\n=== Example 4: Custom Patterns ===\n")
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
		printf("Recovery failed: %v\n", err)
		log.Printf("Recovery failed: %v", err)
		writeToFile("Recovery failed (custom patterns): %v\n", err)
	} else {
		printf("✓ Recovered with custom patterns!\n")
		printf("  Key: %s\n", result4.PrivateKey.Text(16))
		printf("  Verified: %v\n", result4.Verified)
		writeToFile("✓ Recovered with custom patterns!\n")
		writeToFile("  Key: %s\n", result4.PrivateKey.Text(16))
		writeToFile("  Verified: %v\n", result4.Verified)

		// Terminate if key is verified
		if result4.Verified {
			printf("\n✅ Verified key found! Terminating.\n")
			writeToFile("\n✅ Verified key found! Terminating.\n")
			return
		}
	}
}

func getTimestamp() string {
	return time.Now().Format("2006-01-02 15:04:05")
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

// extractPublicKeyFromSignatures extracts the public key from the first signature in the JSON file
func extractPublicKeyFromSignatures(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var signatures []map[string]interface{}
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&signatures); err != nil {
		return "", err
	}

	if len(signatures) == 0 {
		return "", fmt.Errorf("no signatures found")
	}

	// Try to get public_key from first signature
	if pk, ok := signatures[0]["public_key"].(string); ok && pk != "" {
		return pk, nil
	}

	return "", fmt.Errorf("public_key not found in signature file")
}
