package main

import (
	"context"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mahdiidarabi/ecdsa-affine/pkg/eddsaaffine"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <signature_file.json> [public_key_hex]")
		fmt.Println("\nExample:")
		fmt.Println("  go run main.go ../../fixtures/test_eddsa_signatures_same_nonce.json")
		fmt.Println("  go run main.go ../../fixtures/test_eddsa_signatures_counter.json <public_key>")
		os.Exit(1)
	}

	signatureFile := os.Args[1]
	var publicKeyHex string
	if len(os.Args) > 2 {
		publicKeyHex = os.Args[2]
	}

	// Load key info if available (for verification)
	// Try multiple possible paths
	var keyInfo KeyInfo
	for _, path := range []string{"fixtures/test_eddsa_key_info.json", "../../fixtures/test_eddsa_key_info.json"} {
		if info := loadKeyInfo(path); info.PrivateKey != "" || info.PublicKeyHex != "" {
			keyInfo = info
			break
		}
	}
	if keyInfo.PublicKeyHex != "" && publicKeyHex == "" {
		publicKeyHex = keyInfo.PublicKeyHex
	}

	// Create output file based on JSON filename
	var outputFile *os.File
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
			fmt.Fprintf(os.Stdout, "\n%s\n", strings.Repeat("=", 80))
			fmt.Fprintf(os.Stdout, "Recovery run for: %s\n", signatureFile)
			fmt.Fprintf(os.Stdout, "Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05"))
			fmt.Fprintf(os.Stdout, "%s\n\n", strings.Repeat("=", 80))

			fmt.Fprintf(outputFile, "\n%s\n", strings.Repeat("=", 80))
			fmt.Fprintf(outputFile, "Recovery run for: %s\n", signatureFile)
			fmt.Fprintf(outputFile, "Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05"))
			fmt.Fprintf(outputFile, "%s\n\n", strings.Repeat("=", 80))
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

	printf("EdDSA Key Recovery Test\n")
	printf("%s\n", strings.Repeat("=", 50))
	printf("Signature file: %s\n", signatureFile)
	if publicKeyHex != "" {
		printf("Public key: %s\n", publicKeyHex[:32]+"...")
	}
	printf("\n")

	// Create client with default strategy
	client := eddsaaffine.NewClient()

	// Recover key
	ctx := context.Background()
	result, err := client.RecoverKey(ctx, signatureFile, publicKeyHex)
	if err != nil {
		printf("❌ Recovery failed: %v\n", err)
		writeToFile("❌ Recovery failed: %v\n", err)
		os.Exit(1)
	}

	// Display results
	printf("✅ Key Recovery Successful!\n")
	printf("%s\n", strings.Repeat("=", 50))
	printf("Private Key: %s\n", result.PrivateKey.Text(16))

	// Write key recovery results to file
	writeToFile("✅ Key Recovery Successful!\n")
	writeToFile("%s\n", strings.Repeat("=", 50))
	writeToFile("Private Key: %s\n", result.PrivateKey.Text(16))

	if keyInfo.PrivateKey != "" {
		// The key_info.json stores the SEED (original 32-byte private key)
		// But recovery returns the DERIVED SCALAR (after SHA-512 and clamping)
		// We need to derive the scalar from the seed to compare correctly
		seed := new(big.Int)
		seed.SetString(keyInfo.PrivateKey, 10)

		// Derive the scalar from the seed (Ed25519 standard)
		// 1. Hash the seed with SHA-512
		seedBytes := make([]byte, 32)
		seedBytesBE := seed.Bytes()
		// Convert big-endian to little-endian and pad to 32 bytes
		for i := 0; i < len(seedBytesBE) && i < 32; i++ {
			seedBytes[i] = seedBytesBE[len(seedBytesBE)-1-i]
		}

		// 2. SHA-512 hash
		h := sha512.Sum512(seedBytes)

		// 3. Clamp the first 32 bytes (Ed25519 requirement)
		aBytes := make([]byte, 32)
		copy(aBytes, h[:32])
		aBytes[0] &= 0xf8  // Clear bottom 3 bits
		aBytes[31] &= 0x7f // Clear top bit
		aBytes[31] |= 0x40 // Set second-highest bit

		// 4. Convert to big.Int (little-endian)
		expectedScalar := big.NewInt(0)
		for i := 0; i < len(aBytes); i++ {
			byteVal := big.NewInt(int64(aBytes[i]))
			byteVal.Lsh(byteVal, uint(i*8))
			expectedScalar.Add(expectedScalar, byteVal)
		}

		// Take modulo curve order
		curveOrder, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
		expectedScalarMod := new(big.Int).Mod(expectedScalar, curveOrder)
		recoveredMod := new(big.Int).Mod(result.PrivateKey, curveOrder)

		printf("Expected (derived scalar): %s\n", expectedScalarMod.Text(16))
		printf("Recovered (scalar): %s\n", recoveredMod.Text(16))
		// Write expected/recovered scalar info to file
		writeToFile("Expected (derived scalar): %s\n", expectedScalarMod.Text(16))
		writeToFile("Recovered (scalar): %s\n", recoveredMod.Text(16))

		if recoveredMod.Cmp(expectedScalarMod) == 0 {
			printf("✅ Recovered key matches expected key!\n")
			writeToFile("✅ Recovered key matches expected key!\n")
		} else {
			printf("⚠️  Recovered key does NOT match expected key\n")
			printf("Expected (mod curve order): %s\n", expectedScalarMod.Text(16))
			printf("Recovered (mod curve order): %s\n", recoveredMod.Text(16))
			writeToFile("⚠️  Recovered key does NOT match expected key\n")
			writeToFile("Expected (mod curve order): %s\n", expectedScalarMod.Text(16))
			writeToFile("Recovered (mod curve order): %s\n", recoveredMod.Text(16))
		}
	}
	printf("Pattern: %s\n", result.Pattern)
	printf("Relationship: r2 = %s * r1 + %s\n",
		result.Relationship.A.Text(10),
		result.Relationship.B.Text(10))
	printf("Signature Pair: [%d, %d]\n",
		result.SignaturePair[0],
		result.SignaturePair[1])
	printf("Verified: %v\n", result.Verified)

	// Write all key recovery details to file
	writeToFile("Pattern: %s\n", result.Pattern)
	writeToFile("Relationship: r2 = %s * r1 + %s\n",
		result.Relationship.A.Text(10),
		result.Relationship.B.Text(10))
	writeToFile("Signature Pair: [%d, %d]\n",
		result.SignaturePair[0],
		result.SignaturePair[1])
	writeToFile("Verified: %v\n", result.Verified)
}

type KeyInfo struct {
	PrivateKey   string `json:"private_key"`
	PublicKeyHex string `json:"public_key_hex"`
}

func loadKeyInfo(filename string) KeyInfo {
	var keyInfo KeyInfo
	file, err := os.Open(filename)
	if err != nil {
		return keyInfo
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	decoder.UseNumber()

	var rawData map[string]interface{}
	if err := decoder.Decode(&rawData); err != nil {
		return keyInfo
	}

	// Handle private_key
	if privKeyVal, ok := rawData["private_key"]; ok {
		switch v := privKeyVal.(type) {
		case string:
			keyInfo.PrivateKey = v
		case json.Number:
			keyInfo.PrivateKey = string(v)
		default:
			keyInfo.PrivateKey = fmt.Sprintf("%v", v)
		}
	}

	// Handle public_key_hex
	if pubKeyVal, ok := rawData["public_key_hex"]; ok {
		if pubKeyStr, ok := pubKeyVal.(string); ok {
			keyInfo.PublicKeyHex = pubKeyStr
		}
	}

	return keyInfo
}
