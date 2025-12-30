package ecdsaaffine

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
)

// loadTestKeyInfo reads the test key information from fixtures/test_key_info.json
func loadTestKeyInfo() (struct {
	PrivateKey   string `json:"private_key"`
	PublicKeyHex string `json:"public_key_hex"`
}, error) {
	var keyInfo struct {
		PrivateKey   string `json:"private_key"`
		PublicKeyHex string `json:"public_key_hex"`
	}

	file, err := os.Open("../../fixtures/test_key_info.json")
	if err != nil {
		return keyInfo, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	decoder.UseNumber()

	var rawData map[string]interface{}
	if err := decoder.Decode(&rawData); err != nil {
		return keyInfo, err
	}

	// Handle private_key as number or string
	if privKeyVal, ok := rawData["private_key"]; ok {
		switch v := privKeyVal.(type) {
		case string:
			keyInfo.PrivateKey = v
		case json.Number:
			keyInfo.PrivateKey = string(v)
		case float64:
			keyInfo.PrivateKey = big.NewInt(int64(v)).Text(10)
		default:
			keyInfo.PrivateKey = fmt.Sprintf("%v", v)
		}
	}

	// Handle public_key_hex
	if pubKeyVal, ok := rawData["public_key_hex"]; ok {
		if pubKeyStr, ok := pubKeyVal.(string); ok {
			keyInfo.PublicKeyHex = pubKeyStr
		}
	}

	return keyInfo, nil
}

// hexDecode decodes a hex string, handling 0x prefix
func hexDecode(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	return hex.DecodeString(s)
}

// loadTestSignatures loads test signatures from the fixtures directory
func loadTestSignatures(filename string) ([]*Signature, error) {
	parser := &JSONParser{}
	return parser.ParseSignatures("../../fixtures/" + filename)
}
