package eddsaaffine

import (
	"crypto/sha512"
	"errors"
	"math/big"

	"filippo.io/edwards25519"
)

// Ed25519CurveOrder is the order of the Ed25519 curve
var Ed25519CurveOrder, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)

// RecoverPrivateKey recovers the private key from two EdDSA signatures with affinely related nonces.
//
// EdDSA signature equation: s = r + H(R||A||M) * a mod q
// Where: r is nonce, a is private key, A is public key, M is message
//
// If nonces have affine relationship: r2 = a_coeff*r1 + b_offset
//
// Solving for private key a:
//
//	s1 = r1 + h1 * a
//	s2 = r2 + h2 * a
//	r2 = a_coeff * r1 + b_offset
//
// Substituting:
//
//	s2 = (a_coeff * r1 + b_offset) + h2 * a
//	s2 = a_coeff * r1 + b_offset + h2 * a
//	s2 = a_coeff * (s1 - h1 * a) + b_offset + h2 * a
//	s2 = a_coeff * s1 - a_coeff * h1 * a + b_offset + h2 * a
//	s2 - a_coeff * s1 - b_offset = a * (h2 - a_coeff * h1)
//
// Therefore:
//
//	a = (s2 - a_coeff * s1 - b_offset) / (h2 - a_coeff * h1) mod q
//
// Args:
//   - sig1, sig2: Two signatures with affinely related nonces
//   - a: Affine coefficient (r2 = a*r1 + b)
//   - b: Affine offset (r2 = a*r1 + b)
//
// Returns:
//   - Private key if recovery successful, error otherwise
func RecoverPrivateKey(sig1, sig2 *Signature, a, b *big.Int) (*big.Int, error) {
	q := Ed25519CurveOrder

	// Compute H(R||A||M) for both signatures
	h1 := ComputeH(sig1.R, sig1.PublicKey, sig1.Message)
	h2 := ComputeH(sig2.R, sig2.PublicKey, sig2.Message)

	// Calculate numerator: (s2 - a_coeff * s1 - b_offset) mod q
	as1 := new(big.Int).Mul(a, sig1.S)
	numerator := new(big.Int).Sub(sig2.S, as1)
	numerator.Sub(numerator, b)
	numerator.Mod(numerator, q)

	// Calculate denominator: (h2 - a_coeff * h1) mod q
	ah1 := new(big.Int).Mul(a, h1)
	denominator := new(big.Int).Sub(h2, ah1)
	denominator.Mod(denominator, q)

	// Check if denominator is zero (division by zero)
	if denominator.Sign() == 0 {
		return nil, errors.New("denominator is zero: cannot recover private key")
	}

	// Calculate modular inverse of denominator
	denominatorInv := new(big.Int).ModInverse(denominator, q)
	if denominatorInv == nil {
		return nil, errors.New("failed to compute modular inverse")
	}

	// Recover private key: a = (numerator * denominator_inv) mod q
	priv := new(big.Int).Mul(numerator, denominatorInv)
	priv.Mod(priv, q)

	return priv, nil
}

// ComputeH computes H(R||A||M) for EdDSA signature verification.
//
// Args:
//   - r: R point (32 bytes, as big.Int)
//   - publicKey: Public key A (32 bytes)
//   - message: Message bytes
//
// Returns:
//   - Hash value as integer mod curve order
func ComputeH(r *big.Int, publicKey, message []byte) *big.Int {
	// Convert r to 32 bytes (little-endian for Ed25519)
	// big.Int.Bytes() returns big-endian bytes, so we need to convert to little-endian
	rBytes := make([]byte, 32)
	rBytesBE := r.Bytes()
	// Reverse bytes for little-endian and pad with zeros at the end
	// For example: 0x3039 (12345) in BE is [0x30, 0x39]
	// In LE 32 bytes it should be [0x39, 0x30, 0x00, ..., 0x00]
	for i := 0; i < len(rBytesBE) && i < 32; i++ {
		rBytes[i] = rBytesBE[len(rBytesBE)-1-i]
	}

	// Concatenate: R || A || M
	data := make([]byte, 0, len(rBytes)+len(publicKey)+len(message))
	data = append(data, rBytes...)
	data = append(data, publicKey...)
	data = append(data, message...)

	// Hash with SHA-512
	h := sha512.Sum512(data)

	// Convert to big.Int and reduce mod curve order
	// SHA-512 produces 64 bytes, we interpret as little-endian integer (Ed25519 standard)
	// Python: int.from_bytes(h, 'little') means h[0] + h[1]*256 + h[2]*256^2 + ...
	hInt := big.NewInt(0)
	for i := 0; i < len(h); i++ {
		byteVal := big.NewInt(int64(h[i]))
		byteVal.Lsh(byteVal, uint(i*8))
		hInt.Add(hInt, byteVal)
	}
	hInt.Mod(hInt, Ed25519CurveOrder)

	return hInt
}

// HashMessage hashes a message using SHA-512 (EdDSA standard).
func HashMessage(message []byte) []byte {
	h := sha512.Sum512(message)
	return h[:]
}

// VerifyRecoveredKey verifies that a recovered private key matches the given public key.
//
// In Ed25519, the private key is a scalar 'a', and the public key is computed as:
// A = a * B, where B is the base point.
//
// The recovered scalar is already mod curve order from the recovery algorithm.
// We use SetUniformBytes which requires 64 bytes (padded from 32 bytes).
//
// Args:
//   - privateKey: Recovered private key scalar
//   - publicKey: Expected public key (32 bytes, compressed format)
//
// Returns:
//   - True if the private key matches the public key, false otherwise
//   - Error if verification fails
func VerifyRecoveredKey(privateKey *big.Int, publicKey []byte) (bool, error) {
	if len(publicKey) != 32 {
		return false, errors.New("public key must be 32 bytes")
	}

	// Check if private key is in valid range
	if privateKey.Sign() <= 0 || privateKey.Cmp(Ed25519CurveOrder) >= 0 {
		return false, errors.New("private key out of valid range")
	}

	// Convert private key scalar to 32 bytes (little-endian)
	privKeyBytes := make([]byte, 32)
	privKeyBE := privateKey.Bytes()
	// Copy to little-endian format (reverse bytes)
	for i := 0; i < len(privKeyBE) && i < 32; i++ {
		privKeyBytes[i] = privKeyBE[len(privKeyBE)-1-i]
	}

	// Pad to 64 bytes for SetUniformBytes (required by edwards25519)
	privKeyBytes64 := make([]byte, 64)
	copy(privKeyBytes64, privKeyBytes) // Copy 32 bytes, rest are zeros (little-endian)

	privScalar, err := edwards25519.NewScalar().SetUniformBytes(privKeyBytes64)
	if err != nil {
		return false, err
	}

	// Compute public key: A = a * B (where B is the base point)
	computedPubKey := edwards25519.NewIdentityPoint().ScalarBaseMult(privScalar)

	// Parse expected public key
	expectedPubKey, err := edwards25519.NewIdentityPoint().SetBytes(publicKey)
	if err != nil {
		return false, err
	}

	// Compare computed and expected public keys
	return computedPubKey.Equal(expectedPubKey) == 1, nil
}
