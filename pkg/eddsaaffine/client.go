package eddsaaffine

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// Client provides a high-level API for EdDSA key recovery operations.
type Client struct {
	strategy BruteForceStrategy
	parser   SignatureParser
}

// NewClient creates a new client with default settings.
func NewClient() *Client {
	return &Client{
		strategy: NewSmartBruteForceStrategy(),
		parser:   &JSONParser{},
	}
}

// WithStrategy sets a custom brute-force strategy.
func (c *Client) WithStrategy(strategy BruteForceStrategy) *Client {
	c.strategy = strategy
	return c
}

// WithParser sets a custom signature parser.
func (c *Client) WithParser(parser SignatureParser) *Client {
	c.parser = parser
	return c
}

// RecoverKey attempts to recover a private key from signatures in a file.
//
// Args:
//   - ctx: Context for cancellation.
//   - source: Path to signature file (JSON or CSV).
//   - publicKeyHex: Optional public key in hex format for verification.
//
// Returns:
//   - RecoveryResult if successful, error otherwise.
func (c *Client) RecoverKey(ctx context.Context, source string, publicKeyHex string) (*RecoveryResult, error) {
	signatures, err := c.parser.ParseSignatures(source)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signatures: %w", err)
	}
	return c.RecoverKeyFromSignatures(ctx, signatures, publicKeyHex)
}

// RecoverKeyFromSignatures attempts to recover a private key from in-memory signatures.
// Use this when you have already parsed signatures (e.g. from your own parser or API).
// Public key is optional; when provided, the recovered key is verified.
func (c *Client) RecoverKeyFromSignatures(ctx context.Context, signatures []*Signature, publicKeyHex string) (*RecoveryResult, error) {
	if len(signatures) < 2 {
		return nil, fmt.Errorf("need at least 2 signatures, got %d", len(signatures))
	}

	var publicKey []byte
	if publicKeyHex != "" {
		var err error
		publicKey, err = hex.DecodeString(strings.TrimPrefix(publicKeyHex, "0x"))
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		if len(publicKey) != 32 {
			return nil, fmt.Errorf("public key must be 32 bytes (Ed25519 format), got %d", len(publicKey))
		}
	}

	result := c.strategy.Search(ctx, signatures, publicKey)
	if result == nil {
		return nil, fmt.Errorf("failed to recover private key")
	}
	return result, nil
}

// RecoverKeyWithKnownRelationship recovers a private key when the affine relationship is known.
//
// Args:
//   - ctx: Context for cancellation.
//   - source: Path to signature file.
//   - a: Affine coefficient (r2 = a*r1 + b).
//   - b: Affine offset (r2 = a*r1 + b).
//   - publicKeyHex: Optional public key for verification.
//
// Returns:
//   - RecoveryResult if successful, error otherwise.
func (c *Client) RecoverKeyWithKnownRelationship(ctx context.Context, source string, a, b int64, publicKeyHex string) (*RecoveryResult, error) {
	// Parse signatures
	signatures, err := c.parser.ParseSignatures(source)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signatures: %w", err)
	}

	if len(signatures) < 2 {
		return nil, fmt.Errorf("need at least 2 signatures, got %d", len(signatures))
	}

	// Parse public key if provided
	var publicKey []byte
	if publicKeyHex != "" {
		publicKey, err = hex.DecodeString(strings.TrimPrefix(publicKeyHex, "0x"))
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		if len(publicKey) != 32 {
			return nil, fmt.Errorf("public key must be 32 bytes (Ed25519 format), got %d", len(publicKey))
		}
	}

	// Try all signature pairs
	aBig := big.NewInt(a)
	bBig := big.NewInt(b)

	for i := 0; i < len(signatures); i++ {
		for j := i + 1; j < len(signatures); j++ {
			priv, err := RecoverPrivateKey(signatures[i], signatures[j], aBig, bBig)
			if err != nil {
				continue
			}

			// Verify recovered key against public key (required for real-world use)
			verified := false
			if len(publicKey) > 0 {
				verified, _ = VerifyRecoveredKey(priv, publicKey)
				if !verified {
					continue
				}
			} else {
				// No public key provided - cannot verify in real-world scenario
				// Set verified to false since we cannot confirm the key is correct
				verified = false
			}

			return &RecoveryResult{
				PrivateKey:    priv,
				Relationship:  AffineRelationship{A: aBig, B: bBig},
				SignaturePair: [2]int{i, j},
				Verified:      verified,
				Pattern:       fmt.Sprintf("known_a%d_b%d", a, b),
			}, nil
		}
	}

	return nil, fmt.Errorf("failed to recover private key with known relationship a=%d, b=%d", a, b)
}

