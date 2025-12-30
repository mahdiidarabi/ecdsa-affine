package ecdsaaffine

import (
	"math/big"
	"testing"
)

func TestRecoverPrivateKey(t *testing.T) {
	// Load test fixtures
	signatures, err := loadTestSignatures("test_signatures_counter.json")
	if err != nil {
		t.Fatalf("Failed to load test signatures: %v", err)
	}

	if len(signatures) < 2 {
		t.Fatalf("Need at least 2 signatures, got %d", len(signatures))
	}

	// Test with known relationship: k2 = k1 + 1 (a=1, b=1)
	// For counter-based nonces, the relationship between consecutive signatures is k2 = k1 + 1
	a := big.NewInt(1)
	b := big.NewInt(1)

	priv, err := RecoverPrivateKey(signatures[0], signatures[1], a, b)
	if err != nil {
		t.Fatalf("Failed to recover private key: %v", err)
	}

	if priv == nil {
		t.Fatal("Recovered private key is nil")
	}

	// Verify the key is in valid range
	if priv.Sign() <= 0 {
		t.Error("Recovered private key is not positive")
	}

	if priv.Cmp(Secp256k1CurveOrder) >= 0 {
		t.Error("Recovered private key is not less than curve order")
	}

	t.Logf("Recovered private key: %s", priv.Text(16))
}

func TestRecoverPrivateKey_SameNonce(t *testing.T) {
	// Load same nonce reuse signatures
	signatures, err := loadTestSignatures("test_signatures_same_nonce.json")
	if err != nil {
		t.Fatalf("Failed to load test signatures: %v", err)
	}

	if len(signatures) < 2 {
		t.Fatalf("Need at least 2 signatures, got %d", len(signatures))
	}

	// Same nonce reuse: k2 = k1, so a=1, b=0
	a := big.NewInt(1)
	b := big.NewInt(0)

	priv, err := RecoverPrivateKey(signatures[0], signatures[1], a, b)
	if err != nil {
		t.Fatalf("Failed to recover private key: %v", err)
	}

	if priv == nil {
		t.Fatal("Recovered private key is nil")
	}

	// Verify against known key
	keyInfo, err := loadTestKeyInfo()
	if err != nil {
		t.Fatalf("Failed to load key info: %v", err)
	}

	expectedPriv := big.NewInt(0)
	expectedPriv.SetString(keyInfo.PrivateKey, 10)

	if priv.Cmp(expectedPriv) != 0 {
		t.Errorf("Recovered key mismatch. Got: %s, Expected: %s", priv.Text(10), expectedPriv.Text(10))
	}
}

func TestRecoverPrivateKey_AffineRelationship(t *testing.T) {
	// Load affine relationship signatures (k2 = 2*k1 + 1)
	signatures, err := loadTestSignatures("test_signatures_affine.json")
	if err != nil {
		t.Fatalf("Failed to load test signatures: %v", err)
	}

	if len(signatures) < 2 {
		t.Fatalf("Need at least 2 signatures, got %d", len(signatures))
	}

	// Affine relationship: k2 = 2*k1 + 1
	a := big.NewInt(2)
	b := big.NewInt(1)

	priv, err := RecoverPrivateKey(signatures[0], signatures[1], a, b)
	if err != nil {
		t.Fatalf("Failed to recover private key: %v", err)
	}

	if priv == nil {
		t.Fatal("Recovered private key is nil")
	}

	// Verify the key is in valid range
	if priv.Sign() <= 0 || priv.Cmp(Secp256k1CurveOrder) >= 0 {
		t.Error("Recovered private key is not in valid range")
	}
}

func TestRecoverPrivateKey_InvalidDenominator(t *testing.T) {
	// Create signatures that would cause denominator to be zero
	sig1 := &Signature{
		Z: big.NewInt(100),
		R: big.NewInt(200),
		S: big.NewInt(300),
	}
	sig2 := &Signature{
		Z: big.NewInt(100),
		R: big.NewInt(200),
		S: big.NewInt(300),
	}

	a := big.NewInt(1)
	b := big.NewInt(0)

	_, err := RecoverPrivateKey(sig1, sig2, a, b)
	if err == nil {
		t.Error("Expected error for invalid denominator, got nil")
	}
}

func TestHashMessage(t *testing.T) {
	message := []byte("test message")
	z := HashMessage(message)

	if z == nil {
		t.Fatal("Hash result is nil")
	}

	if z.Sign() <= 0 {
		t.Error("Hash result is not positive")
	}

	if z.Cmp(Secp256k1CurveOrder) >= 0 {
		t.Error("Hash result is not less than curve order")
	}

	// Test that same message produces same hash
	z2 := HashMessage(message)
	if z.Cmp(z2) != 0 {
		t.Error("Same message should produce same hash")
	}

	// Test that different messages produce different hashes
	z3 := HashMessage([]byte("different message"))
	if z.Cmp(z3) == 0 {
		t.Error("Different messages should produce different hashes")
	}
}

func TestVerifyRecoveredKey(t *testing.T) {
	keyInfo, err := loadTestKeyInfo()
	if err != nil {
		t.Fatalf("Failed to load key info: %v", err)
	}

	// Parse private key
	priv := big.NewInt(0)
	priv.SetString(keyInfo.PrivateKey, 10)

	// Parse public key
	publicKeyBytes, err := hexDecode(keyInfo.PublicKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode public key: %v", err)
	}

	// Verify
	verified, err := VerifyRecoveredKey(priv, publicKeyBytes)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	if !verified {
		t.Error("Key verification should succeed")
	}
}

func TestVerifyRecoveredKey_InvalidKey(t *testing.T) {
	keyInfo, err := loadTestKeyInfo()
	if err != nil {
		t.Fatalf("Failed to load key info: %v", err)
	}

	publicKeyBytes, err := hexDecode(keyInfo.PublicKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode public key: %v", err)
	}

	// Test with wrong private key
	wrongPriv := big.NewInt(12345)
	verified, err := VerifyRecoveredKey(wrongPriv, publicKeyBytes)
	if err != nil {
		t.Fatalf("Verification should not error: %v", err)
	}

	if verified {
		t.Error("Wrong key should not verify")
	}
}

func TestVerifyRecoveredKey_InvalidPublicKey(t *testing.T) {
	keyInfo, err := loadTestKeyInfo()
	if err != nil {
		t.Fatalf("Failed to load key info: %v", err)
	}

	priv := big.NewInt(0)
	priv.SetString(keyInfo.PrivateKey, 10)

	// Test with invalid public key length
	invalidKey := []byte{1, 2, 3}
	_, err = VerifyRecoveredKey(priv, invalidKey)
	if err == nil {
		t.Error("Expected error for invalid public key length")
	}
}
