package eddsaaffine

import "math/big"

// Signature represents an EdDSA signature with message.
// EdDSA uses (R, s) where R is a point and s is a scalar.
type Signature struct {
	R         *big.Int // R point (32 bytes, encoded as integer)
	S         *big.Int // s scalar component of the signature
	Message   []byte   // Original message
	PublicKey []byte   // Public key A (32 bytes)
}

// AffineRelationship represents the relationship between two nonces.
// r2 = a*r1 + b
type AffineRelationship struct {
	A *big.Int // Affine coefficient
	B *big.Int // Affine offset
}

// RecoveryResult contains the result of a key recovery operation.
type RecoveryResult struct {
	PrivateKey    *big.Int           // Recovered private key
	Relationship  AffineRelationship // The affine relationship found (r2 = a*r1 + b)
	SignaturePair [2]int             // Indices of the signature pair used
	Verified      bool                // Whether the key was verified against a public key
	Pattern       string              // Human-readable pattern description
}

