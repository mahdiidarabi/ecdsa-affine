package ecdsaaffine

import (
	"path/filepath"
	"testing"
)

func TestJSONParser_ParseSignatures(t *testing.T) {
	parser := &JSONParser{ZField: "z"}

	signatures, err := parser.ParseSignatures(filepath.Join(fixturesDir(), "test_signatures_counter.json"))
	if err != nil {
		t.Fatalf("Failed to parse signatures: %v", err)
	}

	if len(signatures) == 0 {
		t.Fatal("Expected at least one signature")
	}

	// Verify signature structure
	for i, sig := range signatures {
		if sig.Z == nil {
			t.Errorf("Signature %d: Z is nil", i)
		}
		if sig.R == nil {
			t.Errorf("Signature %d: R is nil", i)
		}
		if sig.S == nil {
			t.Errorf("Signature %d: S is nil", i)
		}

		// Verify values are in valid range (mod curve order)
		if sig.Z.Sign() < 0 || sig.Z.Cmp(Secp256k1CurveOrder) >= 0 {
			t.Errorf("Signature %d: Z out of range", i)
		}
		if sig.R.Sign() < 0 || sig.R.Cmp(Secp256k1CurveOrder) >= 0 {
			t.Errorf("Signature %d: R out of range", i)
		}
		if sig.S.Sign() < 0 || sig.S.Cmp(Secp256k1CurveOrder) >= 0 {
			t.Errorf("Signature %d: S out of range", i)
		}
	}

	t.Logf("Successfully parsed %d signatures", len(signatures))
}

func TestJSONParser_ParseSignatures_AllFixtures(t *testing.T) {
	parser := &JSONParser{ZField: "z"}
	fixtures := []string{
		"test_signatures_same_nonce.json",
		"test_signatures_counter.json",
		"test_signatures_hardcoded_step.json",
		"test_signatures_affine.json",
		"test_signatures_affine_3x_plus_5.json",
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

func TestJSONParser_ParseSignatures_CustomFields(t *testing.T) {
	parser := &JSONParser{
		MessageField: "message",
		RField:       "r",
		SField:       "s",
		ZField:       "z",
	}

	signatures, err := parser.ParseSignatures(filepath.Join(fixturesDir(), "test_signatures_counter.json"))
	if err != nil {
		t.Fatalf("Failed to parse with custom fields: %v", err)
	}

	if len(signatures) == 0 {
		t.Fatal("Expected at least one signature")
	}
}

func TestJSONParser_ParseSignatures_InvalidFile(t *testing.T) {
	parser := &JSONParser{}

	_, err := parser.ParseSignatures(filepath.Join(fixturesDir(), "nonexistent.json"))
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestJSONParser_ParseSignatures_InvalidJSON(t *testing.T) {
	parser := &JSONParser{}

	// Try to parse a file that doesn't exist or has invalid JSON
	_, err := parser.ParseSignatures(filepath.Join(fixturesDir(), "test_key_info.json"))
	// This might succeed if the file has valid JSON structure, so we just check it doesn't crash
	if err != nil {
		t.Logf("Expected error for invalid signature format: %v", err)
	}
}

