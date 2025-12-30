package ecdsaaffine

import (
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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
	ZField       string // Field name for z/hash (default: "z", empty = hash message)
}

// ParseSignatures parses signatures from a JSON file.
//
// Expected format:
// [
//   {"message": "...", "r": "...", "s": "..."},
//   {"z": "0x...", "r": "0x...", "s": "0x..."}
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

	for _, item := range items {
		sig := &Signature{}

		// Get z (message hash)
		if p.ZField != "" {
			if zVal, ok := item[p.ZField]; ok {
				z, err := parseBigInt(zVal)
				if err != nil {
					return nil, fmt.Errorf("failed to parse z: %w", err)
				}
				sig.Z = z
			}
		}

		// If z not found, hash the message
		if sig.Z == nil {
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
				sig.Z = HashMessage(message)
			} else {
				return nil, fmt.Errorf("missing message or z field")
			}
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

		// Get s
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

// CSVParser parses signatures from CSV files.
type CSVParser struct {
	MessageCol string // Column name for message (default: "message")
	RCol       string // Column name for r (default: "r")
	SCol       string // Column name for s (default: "s")
	ZCol       string // Column name for z/hash (default: empty = hash message)
}

// ParseSignatures parses signatures from a CSV file.
func (p *CSVParser) ParseSignatures(csvFile string) ([]*Signature, error) {
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
	messageCol := p.MessageCol
	if messageCol == "" {
		messageCol = "message"
	}
	rCol := p.RCol
	if rCol == "" {
		rCol = "r"
	}
	sCol := p.SCol
	if sCol == "" {
		sCol = "s"
	}

	messageIdx := -1
	rIdx := -1
	sIdx := -1
	zIdx := -1

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
		if p.ZCol != "" && col == p.ZCol {
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
			sig.Z = HashMessage(message)
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
		z := new(big.Int)
		if _, ok := z.SetString(string(v), 10); !ok {
			return nil, fmt.Errorf("invalid number format: %s", v)
		}
		return z, nil

	case float64:
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

