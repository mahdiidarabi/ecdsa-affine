package eddsaaffine

import (
	"path/filepath"
	"testing"
)

func TestJSONParser_ParseSignatures(t *testing.T) {
	parser := &JSONParser{}

	signatures, err := parser.ParseSignatures(filepath.Join(fixturesDir(), "test_eddsa_signatures_counter.json"))
	if err != nil {
		t.Fatalf("Failed to parse signatures: %v", err)
	}

	if len(signatures) == 0 {
		t.Fatal("Expected at least one signature")
	}

	for i, sig := range signatures {
		if sig.R == nil {
			t.Errorf("Signature %d: R is nil", i)
		}
		if sig.S == nil {
			t.Errorf("Signature %d: S is nil", i)
		}
		if len(sig.Message) == 0 {
			t.Errorf("Signature %d: Message is empty", i)
		}
	}
}

func TestJSONParser_ParseSignatures_AllFixtures(t *testing.T) {
	parser := &JSONParser{}
	fixtures := []string{
		"test_eddsa_signatures_same_nonce.json",
		"test_eddsa_signatures_counter.json",
		"test_eddsa_signatures_hardcoded_step.json",
		"test_eddsa_signatures_affine.json",
	}

	for _, fixture := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			signatures, err := parser.ParseSignatures(filepath.Join(fixturesDir(), fixture))
			if err != nil {
				t.Fatalf("Failed to parse %s: %v", fixture, err)
			}
			if len(signatures) < 2 {
				t.Errorf("Expected at least 2 signatures in %s, got %d", fixture, len(signatures))
			}
		})
	}
}

func TestJSONParser_ParseSignatures_InvalidFile(t *testing.T) {
	parser := &JSONParser{}
	_, err := parser.ParseSignatures(filepath.Join(fixturesDir(), "nonexistent.json"))
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}
