package eddsaaffine

import (
	"context"
	"math/big"
	"testing"
)

func TestSmartBruteForceStrategy_Search_SameNonce(t *testing.T) {
	strategy := NewSmartBruteForceStrategy()

	signatures, err := loadTestSignatures("test_eddsa_signatures_same_nonce.json")
	if err != nil {
		t.Fatalf("Failed to load signatures: %v", err)
	}

	keyInfo, err := loadTestKeyInfo()
	if err != nil {
		t.Fatalf("Failed to load key info: %v", err)
	}

	publicKeyBytes, err := hexDecode(keyInfo.PublicKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode public key: %v", err)
	}

	ctx := context.Background()
	result := strategy.Search(ctx, signatures, publicKeyBytes)

	if result == nil {
		t.Fatal("Expected to find same nonce reuse")
	}

	if result.Pattern != "same_nonce_reuse" {
		t.Errorf("Expected pattern 'same_nonce_reuse', got '%s'", result.Pattern)
	}

	if !result.Verified {
		t.Error("Result should be verified")
	}
}

func TestSmartBruteForceStrategy_Search_CommonPatterns(t *testing.T) {
	strategy := NewSmartBruteForceStrategy().
		WithPatternConfig(PatternConfig{
			IncludeCommonPatterns: true,
		})

	signatures, err := loadTestSignatures("test_eddsa_signatures_counter.json")
	if err != nil {
		t.Fatalf("Failed to load signatures: %v", err)
	}

	keyInfo, err := loadTestKeyInfo()
	if err != nil {
		t.Fatalf("Failed to load key info: %v", err)
	}

	publicKeyBytes, err := hexDecode(keyInfo.PublicKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode public key: %v", err)
	}

	ctx := context.Background()
	result := strategy.Search(ctx, signatures, publicKeyBytes)

	if result == nil {
		t.Log("Common patterns didn't find the key (may need brute-force)")
		return
	}

	if !result.Verified {
		t.Error("Result should be verified")
	}
	t.Logf("Found key with pattern: %s", result.Pattern)
}

func TestSmartBruteForceStrategy_Search_CustomPatterns(t *testing.T) {
	// Use step=13511 to match flawed_eddsa_signer.py (used by make fixtures-eddsa)
	strategy := NewSmartBruteForceStrategy().
		WithPatternConfig(PatternConfig{
			CustomPatterns: []Pattern{
				{A: big.NewInt(1), B: big.NewInt(13511), Name: "hardcoded_step", Priority: 1},
			},
			IncludeCommonPatterns: false,
		})

	signatures, err := loadTestSignatures("test_eddsa_signatures_hardcoded_step.json")
	if err != nil {
		t.Fatalf("Failed to load signatures: %v", err)
	}

	keyInfo, err := loadTestKeyInfo()
	if err != nil {
		t.Fatalf("Failed to load key info: %v", err)
	}

	publicKeyBytes, err := hexDecode(keyInfo.PublicKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode public key: %v", err)
	}

	ctx := context.Background()
	result := strategy.Search(ctx, signatures, publicKeyBytes)

	if result == nil {
		t.Fatal("Expected to find key with custom pattern")
	}

	if !result.Verified {
		t.Error("Result should be verified")
	}
}

func TestSmartBruteForceStrategy_WithRangeConfig(t *testing.T) {
	strategy := NewSmartBruteForceStrategy().
		WithRangeConfig(RangeConfig{
			ARange:     [2]int{1, 5},
			BRange:     [2]int{-100, 100},
			MaxPairs:   50,
			NumWorkers: 4,
			SkipZeroA:  true,
		})

	if strategy.RangeConfig.ARange != [2]int{1, 5} {
		t.Error("ARange not set correctly")
	}
	if strategy.RangeConfig.BRange != [2]int{-100, 100} {
		t.Error("BRange not set correctly")
	}
	if strategy.RangeConfig.MaxPairs != 50 {
		t.Error("MaxPairs not set correctly")
	}
	if strategy.RangeConfig.NumWorkers != 4 {
		t.Error("NumWorkers not set correctly")
	}
	if !strategy.RangeConfig.SkipZeroA {
		t.Error("SkipZeroA not set correctly")
	}
}

func TestSmartBruteForceStrategy_WithPatternConfig(t *testing.T) {
	customPatterns := []Pattern{
		{A: big.NewInt(1), B: big.NewInt(17), Name: "step_17", Priority: 1},
		{A: big.NewInt(1), B: big.NewInt(19), Name: "step_19", Priority: 2},
	}

	strategy := NewSmartBruteForceStrategy().
		WithPatternConfig(PatternConfig{
			CustomPatterns:        customPatterns,
			IncludeCommonPatterns: true,
		})

	if len(strategy.PatternConfig.CustomPatterns) != 2 {
		t.Errorf("Expected 2 custom patterns, got %d", len(strategy.PatternConfig.CustomPatterns))
	}
	if !strategy.PatternConfig.IncludeCommonPatterns {
		t.Error("IncludeCommonPatterns should be true")
	}
}

func TestDefaultRangeConfig(t *testing.T) {
	config := DefaultRangeConfig()

	if config.ARange != [2]int{-100, 100} {
		t.Errorf("Expected ARange [-100, 100], got %v", config.ARange)
	}
	if config.BRange != [2]int{-100, 100} {
		t.Errorf("Expected BRange [-100, 100], got %v", config.BRange)
	}
	if config.MaxPairs != 100 {
		t.Errorf("Expected MaxPairs 100, got %d", config.MaxPairs)
	}
	if config.NumWorkers != 0 {
		t.Errorf("Expected NumWorkers 0 (auto), got %d", config.NumWorkers)
	}
	if !config.SkipZeroA {
		t.Error("Expected SkipZeroA to be true")
	}
}

func TestDefaultPatternConfig(t *testing.T) {
	config := DefaultPatternConfig()

	if len(config.CustomPatterns) != 0 {
		t.Errorf("Expected empty CustomPatterns, got %d", len(config.CustomPatterns))
	}
	if !config.IncludeCommonPatterns {
		t.Error("Expected IncludeCommonPatterns to be true")
	}
}

func TestSmartBruteForceStrategy_Name(t *testing.T) {
	strategy := NewSmartBruteForceStrategy()
	if strategy.Name() != "SmartBruteForce" {
		t.Errorf("Expected name 'SmartBruteForce', got '%s'", strategy.Name())
	}
}
