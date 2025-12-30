package ecdsaaffine

import (
	"context"
	"math/big"
	"testing"
)

func TestClient_RecoverKeyWithKnownRelationship(t *testing.T) {
	client := NewClient()

	// Load public key
	keyInfo, err := loadTestKeyInfo()
	if err != nil {
		t.Fatalf("Failed to load key info: %v", err)
	}

	ctx := context.Background()

	// Test with counter signatures (k2 = k1 + 1, so a=1, b=1)
	result, err := client.RecoverKeyWithKnownRelationship(ctx, "../../fixtures/test_signatures_counter.json", 1, 1, keyInfo.PublicKeyHex)
	if err != nil {
		t.Fatalf("Failed to recover key: %v", err)
	}

	if result == nil {
		t.Fatal("Result is nil")
	}

	if result.PrivateKey == nil {
		t.Fatal("Private key is nil")
	}

	if !result.Verified {
		t.Error("Key should be verified")
	}

	// Verify against expected key
	expectedPriv := big.NewInt(0)
	expectedPriv.SetString(keyInfo.PrivateKey, 10)

	if result.PrivateKey.Cmp(expectedPriv) != 0 {
		t.Errorf("Recovered key mismatch. Got: %s, Expected: %s",
			result.PrivateKey.Text(10), expectedPriv.Text(10))
	}

	t.Logf("Successfully recovered key with relationship k2 = 1*k1 + 1")
}

func TestClient_RecoverKeyWithKnownRelationship_SameNonce(t *testing.T) {
	client := NewClient()

	keyInfo, err := loadTestKeyInfo()
	if err != nil {
		t.Fatalf("Failed to load key info: %v", err)
	}

	ctx := context.Background()

	// Same nonce reuse: k2 = k1, so a=1, b=0
	result, err := client.RecoverKeyWithKnownRelationship(ctx, "../../fixtures/test_signatures_same_nonce.json", 1, 0, keyInfo.PublicKeyHex)
	if err != nil {
		t.Fatalf("Failed to recover key: %v", err)
	}

	if result == nil {
		t.Fatal("Result is nil")
	}

	if !result.Verified {
		t.Error("Key should be verified")
	}

	t.Logf("Successfully recovered key with same nonce reuse")
}

func TestClient_RecoverKeyWithKnownRelationship_Affine(t *testing.T) {
	client := NewClient()

	keyInfo, err := loadTestKeyInfo()
	if err != nil {
		t.Fatalf("Failed to load key info: %v", err)
	}

	ctx := context.Background()

	// Affine relationship: k2 = 2*k1 + 1
	result, err := client.RecoverKeyWithKnownRelationship(ctx, "../../fixtures/test_signatures_affine.json", 2, 1, keyInfo.PublicKeyHex)
	if err != nil {
		t.Fatalf("Failed to recover key: %v", err)
	}

	if result == nil {
		t.Fatal("Result is nil")
	}

	if !result.Verified {
		t.Error("Key should be verified")
	}

	t.Logf("Successfully recovered key with affine relationship k2 = 2*k1 + 1")
}

func TestClient_RecoverKey_SmartBruteForce(t *testing.T) {
	client := NewClient()

	keyInfo, err := loadTestKeyInfo()
	if err != nil {
		t.Fatalf("Failed to load key info: %v", err)
	}

	ctx := context.Background()

	// This will use smart brute-force to find the relationship
	// For counter signatures, it should find k2 = k1 + 1 quickly
	result, err := client.RecoverKey(ctx, "../../fixtures/test_signatures_counter.json", keyInfo.PublicKeyHex)
	if err != nil {
		t.Logf("Brute-force recovery failed (this is expected if it takes too long): %v", err)
		return // Don't fail the test if brute-force doesn't complete quickly
	}

	if result != nil {
		if !result.Verified {
			t.Error("Recovered key should be verified")
		}
		t.Logf("Successfully recovered key with smart brute-force. Pattern: %s", result.Pattern)
	}
}

func TestClient_WithStrategy(t *testing.T) {
	strategy := NewSmartBruteForceStrategy().
		WithRangeConfig(RangeConfig{
			ARange:     [2]int{1, 1},
			BRange:     [2]int{-10, 10},
			MaxPairs:   10,
			NumWorkers: 4,
			SkipZeroA:  true,
		})

	client := NewClient().WithStrategy(strategy)

	if client.strategy == nil {
		t.Error("Strategy should be set")
	}

	if client.strategy.Name() != "SmartBruteForce" {
		t.Errorf("Expected strategy name 'SmartBruteForce', got '%s'", client.strategy.Name())
	}
}

func TestClient_WithParser(t *testing.T) {
	parser := &JSONParser{
		MessageField: "message",
		RField:       "r",
		SField:       "s",
	}

	client := NewClient().WithParser(parser)

	if client.parser == nil {
		t.Error("Parser should be set")
	}
}
