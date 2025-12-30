package ecdsaaffine

import (
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Secp256k1CurveOrder is the order of the secp256k1 curve
var Secp256k1CurveOrder, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

// RecoverPrivateKey recovers the private key from two ECDSA signatures with affinely related nonces.
//
// This implements Equation 7 from the paper:
// priv = (a*s2*z1 - s1*z2 + b*s1*s2) / (r2*s1 - a*r1*s2) mod n
//
// Args:
//   - sig1, sig2: Two signatures with affinely related nonces
//   - a: Affine coefficient (k2 = a*k1 + b)
//   - b: Affine offset (k2 = a*k1 + b)
//
// Returns:
//   - Private key if recovery successful, error otherwise
func RecoverPrivateKey(sig1, sig2 *Signature, a, b *big.Int) (*big.Int, error) {
	n := Secp256k1CurveOrder

	// Calculate numerator: (a * s2 * z1 - s1 * z2 + b * s1 * s2) mod n
	as2z1 := new(big.Int).Mul(a, sig2.S)
	as2z1.Mul(as2z1, sig1.Z)

	s1z2 := new(big.Int).Mul(sig1.S, sig2.Z)

	bs1s2 := new(big.Int).Mul(b, sig1.S)
	bs1s2.Mul(bs1s2, sig2.S)

	numerator := new(big.Int).Sub(as2z1, s1z2)
	numerator.Add(numerator, bs1s2)
	numerator.Mod(numerator, n)

	// Calculate denominator: (r2 * s1 - a * r1 * s2) mod n
	r2s1 := new(big.Int).Mul(sig2.R, sig1.S)

	ar1s2 := new(big.Int).Mul(a, sig1.R)
	ar1s2.Mul(ar1s2, sig2.S)

	denominator := new(big.Int).Sub(r2s1, ar1s2)
	denominator.Mod(denominator, n)

	// Check if denominator is zero (division by zero)
	if denominator.Sign() == 0 {
		return nil, errors.New("denominator is zero: cannot recover private key")
	}

	// Calculate modular inverse of denominator
	denominatorInv := new(big.Int).ModInverse(denominator, n)
	if denominatorInv == nil {
		return nil, errors.New("failed to compute modular inverse")
	}

	// Recover private key: priv = (denominator_inv * numerator) mod n
	priv := new(big.Int).Mul(denominatorInv, numerator)
	priv.Mod(priv, n)

	return priv, nil
}

// HashMessage hashes a message using SHA-256 and returns it as an integer mod n.
func HashMessage(message []byte) *big.Int {
	h := sha256.Sum256(message)
	z := new(big.Int).SetBytes(h[:])
	z.Mod(z, Secp256k1CurveOrder)
	return z
}

// VerifyRecoveredKey verifies that a recovered private key matches the given public key.
//
// Args:
//   - privateKey: Recovered private key
//   - publicKeyBytes: Public key in compressed format (33 bytes)
//
// Returns:
//   - True if the private key matches the public key, false otherwise
func VerifyRecoveredKey(privateKey *big.Int, publicKeyBytes []byte) (bool, error) {
	if len(publicKeyBytes) != 33 {
		return false, errors.New("public key must be 33 bytes (compressed format)")
	}

	privKey := new(big.Int).Set(privateKey)
	if privKey.Cmp(big.NewInt(0)) <= 0 || privKey.Cmp(Secp256k1CurveOrder) >= 0 {
		return false, errors.New("private key out of valid range")
	}

	// Convert private key to 32-byte array (pad if needed)
	privKeyBytes := privKey.Bytes()
	if len(privKeyBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(privKeyBytes):], privKeyBytes)
		privKeyBytes = padded
	} else if len(privKeyBytes) > 32 {
		privKeyBytes = privKeyBytes[len(privKeyBytes)-32:]
	}

	// Get the private key as a secp256k1 private key
	privKeySecp256k1 := secp256k1.PrivKeyFromBytes(privKeyBytes)

	// Get the public key
	pubKey := privKeySecp256k1.PubKey()

	// Serialize as compressed
	recoveredPubKey := pubKey.SerializeCompressed()

	// Compare with provided public key
	if len(recoveredPubKey) != len(publicKeyBytes) {
		return false, nil
	}

	for i := range publicKeyBytes {
		if recoveredPubKey[i] != publicKeyBytes[i] {
			return false, nil
		}
	}

	return true, nil
}

