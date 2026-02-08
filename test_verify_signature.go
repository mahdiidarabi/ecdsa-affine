package main

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"filippo.io/edwards25519"
)

type SignatureData struct {
	Message   string `json:"message"`
	R         string `json:"r"`
	S         string `json:"s"`
	PublicKey string `json:"public_key"`
}

// Ed25519 curve order
var CURVE_ORDER, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)

func decodeHex(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	// Pad with leading zero if odd length
	if len(s)%2 != 0 {
		s = "0" + s
	}
	return hex.DecodeString(s)
}

// computeH computes H(R_bytes || A || M) mod CURVE_ORDER
// This matches the Python implementation and pkg/eddsaaffine/recovery.go
func computeH(rInt *big.Int, publicKeyBytes, messageBytes []byte) *big.Int {
	// Convert rInt to 32 bytes (little-endian for Ed25519)
	// big.Int.Bytes() returns big-endian bytes, so we need to convert to little-endian
	rBytes := make([]byte, 32)
	rBytesBE := rInt.Bytes()
	// Reverse bytes for little-endian and pad with zeros at the end
	for i := 0; i < len(rBytesBE) && i < 32; i++ {
		rBytes[i] = rBytesBE[len(rBytesBE)-1-i]
	}

	// Concatenate: R || A || M
	data := make([]byte, 0, len(rBytes)+len(publicKeyBytes)+len(messageBytes))
	data = append(data, rBytes...)
	data = append(data, publicKeyBytes...)
	data = append(data, messageBytes...)

	// Hash with SHA-512
	h := sha512.Sum512(data)

	// Convert to big.Int and reduce mod curve order
	// SHA-512 produces 64 bytes, we interpret as little-endian integer (Ed25519 standard)
	hInt := big.NewInt(0)
	for i := 0; i < len(h); i++ {
		byteVal := big.NewInt(int64(h[i]))
		byteVal.Lsh(byteVal, uint(i*8))
		hInt.Add(hInt, byteVal)
	}
	hInt.Mod(hInt, CURVE_ORDER)

	return hInt
}

func VerifyEd25519Signature(data SignatureData) (bool, error) {
	// 1. Decode all hex inputs
	rHex := strings.TrimPrefix(data.R, "0x")
	sHex := strings.TrimPrefix(data.S, "0x")

	// Parse R as big integer (from hex string, big-endian)
	rInt, ok := new(big.Int).SetString(rHex, 16)
	if !ok {
		return false, fmt.Errorf("invalid R hex: %s", data.R)
	}

	// Parse S as big integer
	sInt, ok := new(big.Int).SetString(sHex, 16)
	if !ok {
		return false, fmt.Errorf("invalid S hex: %s", data.S)
	}

	publicKeyBytes, err := decodeHex(data.PublicKey)
	if err != nil {
		return false, fmt.Errorf("invalid public key hex: %v", err)
	}

	messageBytes, err := decodeHex(data.Message)
	if err != nil {
		return false, fmt.Errorf("invalid message hex: %v", err)
	}

	// 2. Parse the public key point A
	publicKey, err := edwards25519.NewIdentityPoint().SetBytes(publicKeyBytes)
	if err != nil {
		return false, fmt.Errorf("invalid public key point: %v", err)
	}

	// 3. Parse R as a point (R is stored as integer, but represents a point encoding)
	// Convert rInt to 32 bytes (little-endian)
	rBytes := make([]byte, 32)
	rBytesBE := rInt.Bytes()
	// Reverse for little-endian
	for i := 0; i < len(rBytesBE) && i < 32; i++ {
		rBytes[i] = rBytesBE[len(rBytesBE)-1-i]
	}

	// Parse R as a point
	R, err := edwards25519.NewIdentityPoint().SetBytes(rBytes)
	if err != nil {
		return false, fmt.Errorf("invalid R point: %v (R bytes: %x)", err, rBytes)
	}

	// 4. Parse scalar S (convert to 32 bytes, little-endian)
	// S is stored as integer, convert to little-endian bytes
	sBytes := make([]byte, 32)
	sBytesBE := sInt.Bytes()
	// Reverse for little-endian
	for i := 0; i < len(sBytesBE) && i < 32; i++ {
		sBytes[i] = sBytesBE[len(sBytesBE)-1-i]
	}

	// Debug: Check if S needs clamping
	// Ed25519 scalars must be < 2^252, so the top 4 bits of the last byte should be 0
	// But SetCanonicalBytes should handle this

	sScalar, err := edwards25519.NewScalar().SetCanonicalBytes(sBytes)
	if err != nil {
		// Try with uniform bytes if canonical fails (for non-standard signatures)
		sScalar, err = edwards25519.NewScalar().SetUniformBytes(sBytes)
		if err != nil {
			return false, fmt.Errorf("invalid S scalar: %v (S bytes: %x, S int: %v)", err, sBytes, sInt)
		}
	}

	// 5. Compute h = H(R_bytes || A || M) mod q
	// CRITICAL: We need to use the R point bytes (rBytes) for computing H, not rInt
	// But computeH expects rInt and converts it internally, which is correct
	hInt := computeH(rInt, publicKeyBytes, messageBytes)

	// Debug output
	fmt.Printf("\n🔧 Debug Info:\n")
	fmt.Printf("  R point bytes (LE): %x\n", rBytes)
	fmt.Printf("  R integer: %v\n", rInt)
	fmt.Printf("  S integer: %v\n", sInt)
	fmt.Printf("  H (hash): %v\n", hInt)
	fmt.Printf("  Public key bytes: %x\n", publicKeyBytes)
	fmt.Printf("  Message bytes: %x\n", messageBytes)

	// Convert hInt to edwards25519 scalar (little-endian)
	hBytes := make([]byte, 32)
	hBytesBE := hInt.Bytes()
	// Reverse for little-endian
	for i := 0; i < len(hBytesBE) && i < 32; i++ {
		hBytes[i] = hBytesBE[len(hBytesBE)-1-i]
	}

	hScalar, err := edwards25519.NewScalar().SetCanonicalBytes(hBytes)
	if err != nil {
		return false, fmt.Errorf("failed to create h scalar: %v", err)
	}

	// 6. Compute verification equation: [S]B == R + [h]A
	//    where B is the base point, R is the point, A is the public key
	//    This is the correct EdDSA verification: s*B = R + h*A

	// Compute [S]B
	sB := edwards25519.NewIdentityPoint().ScalarBaseMult(sScalar)

	// Compute [h]A
	hA := edwards25519.NewIdentityPoint().ScalarMult(hScalar, publicKey)

	// Compute RHS = R + [h]A
	rhs := edwards25519.NewIdentityPoint().Add(R, hA)

	// 7. Compare
	if sB.Equal(rhs) == 1 {
		return true, nil
	}
	return false, nil
}

func main() {
	// Test with newly generated signature data (after fixing the signer)
	data := SignatureData{
		Message:   "02000205688b5cc4ef886098fa535dd03c48b48980e33d1a92afaf331c4058a5e62c0059a5b88de3cd97f23e51de370df1d66acf67cf950eb890c5c7b335d64a7acab1075d62fbe8950a929a3ce002cbdb560b53fba2945f57262285cea1e5680a75cf00000000000000000000000000000000000000000000000000000000000000000306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a4000000025f75f4d90109042545b2087771897dda65a719addf773a9fa46deb8b856f439030400090340420f00000000000400050240420f00030201020c0200000002bbeea000000000",
		R:         "0x93eca87189f99e8ee653415074962f88a5cbd7c1de741f3ecc6ad6ab0cb17593",
		S:         "0x051221ed9e369f597b4d081fdb5f85670a82b8312c8c812fd0521895c4ca6e2e",
		PublicKey: "688b5ccaa4ef886098fa535dd03c48b48980e33d1a92afaf331c4058a5e62c00",
	}

	fmt.Println("🔍 Testing Ed25519 signature verification...")
	fmt.Printf("Message (hex): %s\n", data.Message)
	fmt.Printf("Message (text): %s\n", hexToText(data.Message))
	fmt.Printf("R (hex): %s\n", data.R)
	fmt.Printf("S (hex): %s\n", data.S)
	fmt.Printf("Public Key (hex): %s\n", data.PublicKey)

	isValid, err := VerifyEd25519Signature(data)
	if err != nil {
		fmt.Printf("❌ Verification error: %v\n", err)
		return
	}

	if isValid {
		fmt.Println("✅ Signature is VALID.")
	} else {
		fmt.Println("❌ Signature is INVALID.")
	}
}

func hexToText(hexStr string) string {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return hexStr
	}
	return string(bytes)
}
