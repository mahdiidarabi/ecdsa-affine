package parser

import (
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"

	"github.com/mahdiidarabi/ecdsa-affine/internal/recovery"
)

// Signature represents an ECDSA signature with message hash
type Signature struct {
	Z *big.Int // Message hash
	R *big.Int // r component
	S *big.Int // s component
}

// ParseSignaturesFromJSON parses signatures from a JSON file.
//
// Expected format:
// [
//
//	{"message": "...", "r": "...", "s": "..."},
//	{"z": "0x...", "r": "0x...", "s": "0x..."}
//
// ]
func ParseSignaturesFromJSON(jsonFile string, messageField, rField, sField, zField string) ([]*Signature, error) {
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

	for _, item := range items {
		sig := &Signature{}

		// Get z (message hash)
		if zField != "" {
			if zVal, ok := item[zField]; ok {
				z, err := parseBigInt(zVal)
				if err != nil {
					return nil, fmt.Errorf("failed to parse z: %w", err)
				}
				sig.Z = z
			}
		}

		// If z not found, hash the message
		if sig.Z == nil {
			if messageField == "" {
				messageField = "message"
			}
			if msgVal, ok := item[messageField]; ok {
				var message []byte
				switch v := msgVal.(type) {
				case string:
					message = []byte(v)
				case []byte:
					message = v
				default:
					return nil, fmt.Errorf("message field must be string or bytes")
				}
				sig.Z = recovery.HashMessage(message)
			} else {
				return nil, fmt.Errorf("missing message or z field")
			}
		}

		// Get r
		if rField == "" {
			rField = "r"
		}
		rVal, ok := item[rField]
		if !ok {
			return nil, fmt.Errorf("missing r field")
		}
		r, err := parseBigInt(rVal)
		if err != nil {
			return nil, fmt.Errorf("failed to parse r: %w", err)
		}
		sig.R = r

		// Get s
		if sField == "" {
			sField = "s"
		}
		sVal, ok := item[sField]
		if !ok {
			return nil, fmt.Errorf("missing s field")
		}
		s, err := parseBigInt(sVal)
		if err != nil {
			return nil, fmt.Errorf("failed to parse s: %w", err)
		}
		sig.S = s

		signatures = append(signatures, sig)
	}

	return signatures, nil
}

// ParseSignaturesFromCSV parses signatures from a CSV file.
func ParseSignaturesFromCSV(csvFile string, messageCol, rCol, sCol, zCol string) ([]*Signature, error) {
	file, err := os.Open(csvFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.TrimLeadingSpace = true

	// Read header
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	// Find column indices
	messageIdx := -1
	rIdx := -1
	sIdx := -1
	zIdx := -1

	if messageCol == "" {
		messageCol = "message"
	}
	if rCol == "" {
		rCol = "r"
	}
	if sCol == "" {
		sCol = "s"
	}

	for i, col := range header {
		if col == messageCol {
			messageIdx = i
		}
		if col == rCol {
			rIdx = i
		}
		if col == sCol {
			sIdx = i
		}
		if zCol != "" && col == zCol {
			zIdx = i
		}
	}

	if rIdx == -1 || sIdx == -1 {
		return nil, fmt.Errorf("missing required columns: r or s")
	}

	signatures := make([]*Signature, 0)

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read record: %w", err)
		}

		sig := &Signature{}

		// Get z
		if zIdx >= 0 && zIdx < len(record) {
			z, err := parseBigInt(record[zIdx])
			if err != nil {
				return nil, fmt.Errorf("failed to parse z: %w", err)
			}
			sig.Z = z
		} else if messageIdx >= 0 && messageIdx < len(record) {
			message := []byte(record[messageIdx])
			sig.Z = recovery.HashMessage(message)
		} else {
			return nil, fmt.Errorf("missing message or z column")
		}

		// Get r
		if rIdx >= len(record) {
			return nil, fmt.Errorf("r column index out of range")
		}
		r, err := parseBigInt(record[rIdx])
		if err != nil {
			return nil, fmt.Errorf("failed to parse r: %w", err)
		}
		sig.R = r

		// Get s
		if sIdx >= len(record) {
			return nil, fmt.Errorf("s column index out of range")
		}
		s, err := parseBigInt(record[sIdx])
		if err != nil {
			return nil, fmt.Errorf("failed to parse s: %w", err)
		}
		sig.S = s

		signatures = append(signatures, sig)
	}

	return signatures, nil
}

// parseBigInt parses a big integer from various formats (hex string, decimal string, number).
func parseBigInt(val interface{}) (*big.Int, error) {
	switch v := val.(type) {
	case string:
		// Remove 0x prefix if present
		s := strings.TrimPrefix(v, "0x")
		s = strings.TrimPrefix(s, "0X")

		// Try hex first
		if strings.ContainsAny(s, "abcdefABCDEF") || len(s) > 20 {
			// Likely hex
			bytes, err := hex.DecodeString(s)
			if err != nil {
				// Try as decimal
				z := new(big.Int)
				if _, ok := z.SetString(s, 10); !ok {
					return nil, fmt.Errorf("invalid number format: %s", v)
				}
				return z, nil
			}
			return new(big.Int).SetBytes(bytes), nil
		}

		// Try decimal
		z := new(big.Int)
		if _, ok := z.SetString(s, 10); !ok {
			return nil, fmt.Errorf("invalid number format: %s", v)
		}
		return z, nil

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
		// Try to preserve as much as possible
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
