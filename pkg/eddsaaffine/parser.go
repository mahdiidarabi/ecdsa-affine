package eddsaaffine

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
)

// SignatureParser defines the interface for parsing signatures from various sources.
type SignatureParser interface {
	// ParseSignatures parses signatures from a source and returns them.
	ParseSignatures(source string) ([]*Signature, error)
}

// JSONParser parses signatures from JSON files.
type JSONParser struct {
	MessageField string // Field name for message (default: "message")
	RField       string // Field name for r (default: "r")
	SField       string // Field name for s (default: "s")
	PublicKeyField string // Field name for public_key (default: "public_key")
}

// ParseSignatures parses signatures from a JSON file.
//
// Expected format:
// [
//   {"message": "hex_string", "r": "hex_string", "s": "hex_string", "public_key": "hex_string"},
//   ...
// ]
func (p *JSONParser) ParseSignatures(jsonFile string) ([]*Signature, error) {
	file, err := os.Open(jsonFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	decoder.UseNumber() // Preserve large numbers as json.Number instead of float64

	var items []map[string]interface{}
	if err := decoder.Decode(&items); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	signatures := make([]*Signature, 0, len(items))

	messageField := p.MessageField
	if messageField == "" {
		messageField = "message"
	}
	rField := p.RField
	if rField == "" {
		rField = "r"
	}
	sField := p.SField
	if sField == "" {
		sField = "s"
	}
	publicKeyField := p.PublicKeyField
	if publicKeyField == "" {
		publicKeyField = "public_key"
	}

	for _, item := range items {
		sig := &Signature{}

		// Get message
		if msgVal, ok := item[messageField]; ok {
			var message []byte
			switch v := msgVal.(type) {
			case string:
				// Try hex decode first
				if strings.HasPrefix(v, "0x") || len(v) > 20 {
					message, err = hex.DecodeString(strings.TrimPrefix(v, "0x"))
					if err != nil {
						message = []byte(v)
					}
				} else {
					message = []byte(v)
				}
			case []byte:
				message = v
			default:
				return nil, fmt.Errorf("message field must be string or bytes")
			}
			sig.Message = message
		} else {
			return nil, fmt.Errorf("missing message field")
		}

		// Get r
		rVal, ok := item[rField]
		if !ok {
			return nil, fmt.Errorf("missing r field")
		}
		r, err := parseBigInt(rVal)
		if err != nil {
			return nil, fmt.Errorf("failed to parse r: %w", err)
		}
		sig.R = r

		// Get s (can be hex string like "0x..." or number)
		sVal, ok := item[sField]
		if !ok {
			return nil, fmt.Errorf("missing s field")
		}
		s, err := parseBigInt(sVal)
		if err != nil {
			return nil, fmt.Errorf("failed to parse s: %w", err)
		}
		sig.S = s

		// Get public key (optional)
		if pubKeyVal, ok := item[publicKeyField]; ok {
			var publicKey []byte
			switch v := pubKeyVal.(type) {
			case string:
				publicKey, err = hex.DecodeString(strings.TrimPrefix(v, "0x"))
				if err != nil {
					return nil, fmt.Errorf("failed to parse public_key: %w", err)
				}
			case []byte:
				publicKey = v
			default:
				return nil, fmt.Errorf("public_key field must be string or bytes")
			}
			sig.PublicKey = publicKey
		}

		signatures = append(signatures, sig)
	}

	return signatures, nil
}

// parseBigInt parses a big integer from various formats (hex string, decimal string, json.Number).
func parseBigInt(val interface{}) (*big.Int, error) {
	switch v := val.(type) {
	case string:
		s := strings.TrimSpace(v)
		z := new(big.Int)

		// Try hex first (with or without 0x prefix)
		if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
			// Remove 0x prefix and try hex
			s = s[2:]
			if _, ok := z.SetString(s, 16); ok {
				return z, nil
			}
		} else if strings.ContainsAny(s, "abcdefABCDEF") || len(s) > 20 {
			// Likely hex (contains hex chars or long string)
			// Try hex first
			if _, ok := z.SetString(s, 16); ok {
				return z, nil
			}
		}

		// Try decimal
		if _, ok := z.SetString(s, 10); ok {
			return z, nil
		}

		return nil, fmt.Errorf("invalid number format: %s", v)

	case json.Number:
		// json.Number preserves precision for large integers
		z := new(big.Int)
		if _, ok := z.SetString(string(v), 10); !ok {
			return nil, fmt.Errorf("invalid number format: %s", v)
		}
		return z, nil

	case float64:
		// Fallback for cases where UseNumber wasn't used
		// This will lose precision for very large numbers
		s := fmt.Sprintf("%.0f", v)
		z := new(big.Int)
		if _, ok := z.SetString(s, 10); !ok {
			return nil, fmt.Errorf("invalid number format: %v", v)
		}
		return z, nil

	case int64:
		return big.NewInt(v), nil

	case int:
		return big.NewInt(int64(v)), nil

	default:
		return nil, fmt.Errorf("unsupported type: %T", val)
	}
}

