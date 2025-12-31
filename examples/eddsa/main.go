package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"

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

	fmt.Println("EdDSA Key Recovery Test")
	fmt.Println("=" + string(make([]byte, 50)))
	fmt.Printf("Signature file: %s\n", signatureFile)
	if publicKeyHex != "" {
		fmt.Printf("Public key: %s\n", publicKeyHex[:32]+"...")
	}
	fmt.Println()

	// Create client with default strategy
	client := eddsaaffine.NewClient()

	// Recover key
	ctx := context.Background()
	result, err := client.RecoverKey(ctx, signatureFile, publicKeyHex)
	if err != nil {
		fmt.Printf("❌ Recovery failed: %v\n", err)
		os.Exit(1)
	}

	// Display results
	fmt.Println("✅ Key Recovery Successful!")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("Private Key: %s\n", result.PrivateKey.Text(16))
	if keyInfo.PrivateKey != "" {
		expectedKey := new(big.Int)
		expectedKey.SetString(keyInfo.PrivateKey, 10)
		// Take modulo curve order for comparison (Ed25519 keys are mod curve order)
		curveOrder, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
		expectedKeyMod := new(big.Int).Mod(expectedKey, curveOrder)
		recoveredMod := new(big.Int).Mod(result.PrivateKey, curveOrder)

		fmt.Printf("Expected: %s\n", expectedKeyMod.Text(16))
		fmt.Printf("Recovered: %s\n", recoveredMod.Text(16))

		if recoveredMod.Cmp(expectedKeyMod) == 0 {
			fmt.Println("✅ Recovered key matches expected key!")
		} else {
			fmt.Println("⚠️  Recovered key does NOT match expected key")
			fmt.Printf("Expected (mod curve order): %s\n", expectedKeyMod.Text(16))
			fmt.Printf("Recovered (mod curve order): %s\n", recoveredMod.Text(16))
		}
	}
	fmt.Printf("Pattern: %s\n", result.Pattern)
	fmt.Printf("Relationship: r2 = %s * r1 + %s\n",
		result.Relationship.A.Text(10),
		result.Relationship.B.Text(10))
	fmt.Printf("Signature Pair: [%d, %d]\n",
		result.SignaturePair[0],
		result.SignaturePair[1])
	fmt.Printf("Verified: %v\n", result.Verified)
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
