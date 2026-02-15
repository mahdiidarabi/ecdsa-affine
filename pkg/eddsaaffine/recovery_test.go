package eddsaaffine

import (
	"math/big"
	"testing"
)

func TestRecoverPrivateKey_Counter(t *testing.T) {
	signatures, err := loadTestSignatures("test_eddsa_signatures_counter.json")
	if err != nil {
		t.Fatalf("Failed to load test signatures: %v", err)
	}
	if len(signatures) < 2 {
		t.Fatalf("Need at least 2 signatures, got %d", len(signatures))
	}

	a := big.NewInt(1)
	b := big.NewInt(1)

	priv, err := RecoverPrivateKey(signatures[0], signatures[1], a, b)
	if err != nil {
		t.Fatalf("Failed to recover private key: %v", err)
	}
	if priv == nil {
		t.Fatal("Recovered private key is nil")
	}
	if priv.Sign() <= 0 || priv.Cmp(Ed25519CurveOrder) >= 0 {
		t.Error("Recovered private key is not in valid range")
	}
}

func TestRecoverPrivateKey_SameNonce(t *testing.T) {
	signatures, err := loadTestSignatures("test_eddsa_signatures_same_nonce.json")
	if err != nil {
		t.Fatalf("Failed to load test signatures: %v", err)
	}
	if len(signatures) < 2 {
		t.Fatalf("Need at least 2 signatures, got %d", len(signatures))
	}

	a := big.NewInt(1)
	b := big.NewInt(0)

	priv, err := RecoverPrivateKey(signatures[0], signatures[1], a, b)
	if err != nil {
		t.Fatalf("Failed to recover private key: %v", err)
	}
	if priv == nil {
		t.Fatal("Recovered private key is nil")
	}

	// EdDSA fixture stores the seed; recovery yields the signing scalar. Verify against public key.
	keyInfo, err := loadTestKeyInfo()
	if err != nil {
		t.Fatalf("Failed to load key info: %v", err)
	}
	publicKeyBytes, err := hexDecode(keyInfo.PublicKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode public key: %v", err)
	}
	verified, err := VerifyRecoveredKey(priv, publicKeyBytes)
	if err != nil {
		t.Fatalf("VerifyRecoveredKey: %v", err)
	}
	if !verified {
		t.Error("Recovered key should verify against public key")
	}
}

func TestRecoverPrivateKey_Affine(t *testing.T) {
	signatures, err := loadTestSignatures("test_eddsa_signatures_affine.json")
	if err != nil {
		t.Fatalf("Failed to load test signatures: %v", err)
	}
	if len(signatures) < 2 {
		t.Fatalf("Need at least 2 signatures, got %d", len(signatures))
	}

	a := big.NewInt(2)
	b := big.NewInt(1)

	priv, err := RecoverPrivateKey(signatures[0], signatures[1], a, b)
	if err != nil {
		t.Fatalf("Failed to recover private key: %v", err)
	}
	if priv == nil {
		t.Fatal("Recovered private key is nil")
	}
	if priv.Sign() <= 0 || priv.Cmp(Ed25519CurveOrder) >= 0 {
		t.Error("Recovered private key is not in valid range")
	}
}

func TestRecoverPrivateKey_InvalidDenominator(t *testing.T) {
	sig1 := &Signature{
		R: big.NewInt(200),
		S: big.NewInt(300),
	}
	sig2 := &Signature{
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

func TestVerifyRecoveredKey(t *testing.T) {
	// EdDSA fixture stores the seed; VerifyRecoveredKey expects the signing scalar.
	// Recover the scalar from same_nonce signatures, then verify it against the public key.
	signatures, err := loadTestSignatures("test_eddsa_signatures_same_nonce.json")
	if err != nil {
		t.Fatalf("Failed to load signatures: %v", err)
	}
	if len(signatures) < 2 {
		t.Fatalf("Need at least 2 signatures, got %d", len(signatures))
	}
	priv, err := RecoverPrivateKey(signatures[0], signatures[1], big.NewInt(1), big.NewInt(0))
	if err != nil {
		t.Fatalf("Failed to recover private key: %v", err)
	}
	keyInfo, err := loadTestKeyInfo()
	if err != nil {
		t.Fatalf("Failed to load key info: %v", err)
	}
	publicKeyBytes, err := hexDecode(keyInfo.PublicKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode public key: %v", err)
	}
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

	wrongPriv := big.NewInt(12345)
	verified, err := VerifyRecoveredKey(wrongPriv, publicKeyBytes)
	if err != nil {
		t.Fatalf("Verification should not error: %v", err)
	}
	if verified {
		t.Error("Wrong key should not verify")
	}
}
