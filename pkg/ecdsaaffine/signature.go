package ecdsaaffine

import "math/big"

// Signature represents an ECDSA signature with message hash.
// This is the core type used throughout the package.
type Signature struct {
	Z *big.Int // Message hash (SHA-256 of message, mod n)
	R *big.Int // r component of the signature
	S *big.Int // s component of the signature
}

// AffineRelationship represents the relationship between two nonces.
// k2 = a*k1 + b
type AffineRelationship struct {
	A *big.Int // Affine coefficient
	B *big.Int // Affine offset
}

// RecoveryResult contains the result of a key recovery operation.
type RecoveryResult struct {
	PrivateKey    *big.Int           // Recovered private key
	Relationship  AffineRelationship // The affine relationship found (k2 = a*k1 + b)
	SignaturePair [2]int             // Indices of the signature pair used
	Verified      bool                // Whether the key was verified against a public key
	Pattern       string              // Human-readable pattern description
}

