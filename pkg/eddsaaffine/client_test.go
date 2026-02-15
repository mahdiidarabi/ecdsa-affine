package eddsaaffine

import (
	"context"
	"path/filepath"
	"testing"
)

func TestClient_RecoverKeyWithKnownRelationship_Counter(t *testing.T) {
	client := NewClient()
	keyInfo, err := loadTestKeyInfo()
	if err != nil {
		t.Fatalf("Failed to load key info: %v", err)
	}

	ctx := context.Background()
	result, err := client.RecoverKeyWithKnownRelationship(ctx, filepath.Join(fixturesDir(), "test_eddsa_signatures_counter.json"), 1, 1, keyInfo.PublicKeyHex)
	if err != nil {
		t.Fatalf("Failed to recover key: %v", err)
	}

	if result == nil || result.PrivateKey == nil {
		t.Fatal("Result is nil")
	}
	if !result.Verified {
		t.Error("Key should be verified")
	}
	// EdDSA fixture stores the seed; recovery yields the signing scalar — do not compare to keyInfo.PrivateKey.
}

func TestClient_RecoverKeyWithKnownRelationship_SameNonce(t *testing.T) {
	client := NewClient()
	keyInfo, err := loadTestKeyInfo()
	if err != nil {
		t.Fatalf("Failed to load key info: %v", err)
	}

	ctx := context.Background()
	result, err := client.RecoverKeyWithKnownRelationship(ctx, filepath.Join(fixturesDir(), "test_eddsa_signatures_same_nonce.json"), 1, 0, keyInfo.PublicKeyHex)
	if err != nil {
		t.Fatalf("Failed to recover key: %v", err)
	}

	if result == nil {
		t.Fatal("Result is nil")
	}
	if !result.Verified {
		t.Error("Key should be verified")
	}
}

func TestClient_RecoverKeyWithKnownRelationship_Affine(t *testing.T) {
	client := NewClient()
	keyInfo, err := loadTestKeyInfo()
	if err != nil {
		t.Fatalf("Failed to load key info: %v", err)
	}

	ctx := context.Background()
	result, err := client.RecoverKeyWithKnownRelationship(ctx, filepath.Join(fixturesDir(), "test_eddsa_signatures_affine.json"), 2, 1, keyInfo.PublicKeyHex)
	if err != nil {
		t.Fatalf("Failed to recover key: %v", err)
	}

	if result == nil {
		t.Fatal("Result is nil")
	}
	if !result.Verified {
		t.Error("Key should be verified")
	}
}

func TestClient_RecoverKeyFromSignatures(t *testing.T) {
	client := NewClient()
	keyInfo, err := loadTestKeyInfo()
	if err != nil {
		t.Fatalf("Failed to load key info: %v", err)
	}
	signatures, err := loadTestSignatures("test_eddsa_signatures_counter.json")
	if err != nil {
		t.Fatalf("Failed to load signatures: %v", err)
	}

	ctx := context.Background()
	result, err := client.RecoverKeyFromSignatures(ctx, signatures, keyInfo.PublicKeyHex)
	if err != nil {
		t.Fatalf("RecoverKeyFromSignatures failed: %v", err)
	}
	if result == nil || !result.Verified {
		t.Fatal("Expected verified result")
	}
	// EdDSA recovery yields the signing scalar; fixture stores the seed — verification is done via result.Verified.
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
	parser := &JSONParser{}
	client := NewClient().WithParser(parser)
	if client.parser == nil {
		t.Error("Parser should be set")
	}
}

func TestCommonPatterns(t *testing.T) {
	patterns := CommonPatterns()
	if len(patterns) == 0 {
		t.Fatal("CommonPatterns() should return non-empty list")
	}
	patterns[0].Name = "mutated"
	patterns2 := CommonPatterns()
	if patterns2[0].Name == "mutated" {
		t.Error("CommonPatterns() should return a copy")
	}
}
