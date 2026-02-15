package eddsaaffine

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// fixturesDir returns the path to the fixtures directory (works regardless of test cwd).
func fixturesDir() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "fixtures")
}

// loadTestKeyInfo reads the test key information from fixtures/test_eddsa_key_info.json
func loadTestKeyInfo() (struct {
	PrivateKey   string `json:"private_key"`
	PublicKeyHex string `json:"public_key_hex"`
}, error) {
	var keyInfo struct {
		PrivateKey   string `json:"private_key"`
		PublicKeyHex string `json:"public_key_hex"`
	}

	file, err := os.Open(filepath.Join(fixturesDir(), "test_eddsa_key_info.json"))
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

	if privKeyVal, ok := rawData["private_key"]; ok {
		switch v := privKeyVal.(type) {
		case string:
			keyInfo.PrivateKey = v
		case json.Number:
			keyInfo.PrivateKey = string(v)
		default:
			keyInfo.PrivateKey = fmt.Sprintf("%v", v)
		}
	}

	if pubKeyVal, ok := rawData["public_key_hex"]; ok {
		if pubKeyStr, ok := pubKeyVal.(string); ok {
			keyInfo.PublicKeyHex = pubKeyStr
		}
	}

	return keyInfo, nil
}

func hexDecode(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	return hex.DecodeString(s)
}

// loadTestSignatures loads test signatures from the fixtures directory
func loadTestSignatures(filename string) ([]*Signature, error) {
	parser := &JSONParser{}
	return parser.ParseSignatures(filepath.Join(fixturesDir(), filename))
}
