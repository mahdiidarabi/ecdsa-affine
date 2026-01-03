package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/mahdiidarabi/ecdsa-affine/internal/bruteforce"
	"github.com/mahdiidarabi/ecdsa-affine/internal/parser"
	"github.com/mahdiidarabi/ecdsa-affine/internal/recovery"
)

func main() {
	var (
		signaturesFile = flag.String("signatures", "", "Path to signatures file (JSON or CSV)")
		format         = flag.String("format", "json", "Signature file format (json or csv)")
		publicKey      = flag.String("public-key", "", "Public key in hex format (compressed, 66 chars) for verification")
		knownA         = flag.Int("known-a", 0, "Known affine coefficient a (k2 = a*k1 + b)")
		knownB         = flag.Int("known-b", 0, "Known affine offset b (k2 = a*k1 + b)")
		bruteForce     = flag.Bool("brute-force", false, "Brute-force search for affine relationship")
		smartBrute     = flag.Bool("smart-brute", false, "Use smart brute-force (tries common patterns first)")
		aRange         = flag.String("a-range", "-100,100", "Range for a values in brute-force (format: min,max)")
		bRange         = flag.String("b-range", "-100,100", "Range for b values in brute-force (format: min,max)")
		maxPairs       = flag.Int("max-pairs", 100, "Maximum signature pairs to test in brute-force")
		numWorkers     = flag.Int("workers", 0, "Number of parallel workers (0 = auto-detect based on CPU cores)")
	)
	flag.Parse()

	if *signaturesFile == "" {
		fmt.Fprintf(os.Stderr, "Error: --signatures is required\n")
		flag.Usage()
		os.Exit(1)
	}

	// Parse signatures
	fmt.Printf("Loading signatures from %s...\n", *signaturesFile)
	var signatures []*parser.Signature
	var err error

	if *format == "json" {
		signatures, err = parser.ParseSignaturesFromJSON(*signaturesFile, "message", "r", "s", "z")
	} else {
		signatures, err = parser.ParseSignaturesFromCSV(*signaturesFile, "message", "r", "s", "z")
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading signatures: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Loaded %d signatures\n", len(signatures))

	if len(signatures) < 2 {
		fmt.Fprintf(os.Stderr, "Error: Need at least 2 signatures\n")
		os.Exit(1)
	}

	// Parse public key if provided
	var publicKeyBytes []byte
	if *publicKey != "" {
		var err error
		publicKeyBytes, err = hex.DecodeString(strings.TrimPrefix(*publicKey, "0x"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing public key: %v\n", err)
			os.Exit(1)
		}
		if len(publicKeyBytes) != 33 {
			fmt.Fprintf(os.Stderr, "Error: Public key must be 33 bytes (compressed format)\n")
			os.Exit(1)
		}
	}

	// Convert signatures to recovery format
	recoverySigs := make([]*recovery.Signature, len(signatures))
	for i, sig := range signatures {
		recoverySigs[i] = &recovery.Signature{
			Z: sig.Z,
			R: sig.R,
			S: sig.S,
		}
	}

	// Recover key based on mode
	if *knownA != 0 || *knownB != 0 {
		// Known relationship
		fmt.Printf("Using known relationship: k2 = %d*k1 + %d\n", *knownA, *knownB)

		a := big.NewInt(int64(*knownA))
		b := big.NewInt(int64(*knownB))

		// Try all pairs
		found := false
		for i := 0; i < len(recoverySigs); i++ {
			for j := i + 1; j < len(recoverySigs); j++ {
				priv, err := recovery.RecoverPrivateKeyAffine(recoverySigs[i], recoverySigs[j], a, b)
				if err != nil {
					// Debug: uncomment to see errors
					// fmt.Printf("  Pair (%d, %d): %v\n", i, j, err)
					continue
				}

				found = true
				fmt.Printf("\n[+] Recovered private key from signatures %d and %d:\n", i, j)
				fmt.Printf("    Private key: %s\n", priv.String())

				if len(publicKeyBytes) > 0 {
					verified, err := recovery.VerifyRecoveredKey(priv, publicKeyBytes)
					if err == nil && verified {
						fmt.Println("    ✓ Verified against public key!")
						return
					} else {
						if err != nil {
							fmt.Printf("    ✗ Verification error: %v\n", err)
						} else {
							fmt.Println("    ✗ Does not match public key")
						}
						// Continue trying other pairs if verification fails
					}
				} else {
					// No public key provided, just return the first recovered key
					return
				}
			}
		}

		if !found {
			fmt.Println("\n[-] Could not recover private key with known relationship")
			os.Exit(1)
		} else {
			// Found key(s) but none verified
			fmt.Println("\n[-] Recovered key(s) but none matched the provided public key")
			os.Exit(1)
		}

	} else if *smartBrute {
		// Smart brute-force
		result := bruteforce.SmartBruteForce(signatures, publicKeyBytes)

		if result != nil {
			fmt.Printf("\n[+] Successfully recovered private key!\n")
			fmt.Printf("    Private key: %s\n", result.PrivateKey.String())
			fmt.Printf("    Relationship: k2 = %s*k1 + %s\n", result.A.String(), result.B.String())
			fmt.Printf("    Signature pair: (%d, %d)\n", result.SignaturePair[0], result.SignaturePair[1])
			if result.Verified {
				fmt.Println("    ✓ Verified against public key!")
			}
		} else {
			fmt.Println("\n[-] Could not recover private key")
			os.Exit(1)
		}

	} else if *bruteForce {
		// Brute-force - try common patterns first for efficiency
		fmt.Println("Trying common patterns first (fast path)...")
		commonResult := bruteforce.SmartBruteForce(signatures, publicKeyBytes)
		if commonResult != nil {
			fmt.Printf("\n[+] Successfully recovered private key!\n")
			fmt.Printf("    Private key: %s\n", commonResult.PrivateKey.String())
			fmt.Printf("    Relationship: k2 = %s*k1 + %s\n", commonResult.A.String(), commonResult.B.String())
			fmt.Printf("    Signature pair: (%d, %d)\n", commonResult.SignaturePair[0], commonResult.SignaturePair[1])
			if commonResult.Verified {
				fmt.Println("    ✓ Verified against public key!")
			}
			return
		}

		// If common patterns didn't work, use specified ranges
		fmt.Println("Common patterns didn't work, using specified ranges...")
		aMin, aMax, err := parseRange(*aRange)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing a-range: %v\n", err)
			os.Exit(1)
		}

		bMin, bMax, err := parseRange(*bRange)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing b-range: %v\n", err)
			os.Exit(1)
		}

		result := bruteforce.BruteForceAffineRelationshipParallel(
			signatures,
			publicKeyBytes,
			[2]int{aMin, aMax},
			[2]int{bMin, bMax},
			*maxPairs,
			*numWorkers,
		)

		if result != nil {
			fmt.Printf("\n[+] Successfully recovered private key!\n")
			fmt.Printf("    Private key: %s\n", result.PrivateKey.String())
			fmt.Printf("    Relationship: k2 = %s*k1 + %s\n", result.A.String(), result.B.String())
			fmt.Printf("    Signature pair: (%d, %d)\n", result.SignaturePair[0], result.SignaturePair[1])
			if result.Verified {
				fmt.Println("    ✓ Verified against public key!")
			}
		} else {
			fmt.Println("\n[-] Could not recover private key")
			os.Exit(1)
		}

	} else {
		fmt.Fprintf(os.Stderr, "Error: Must specify --known-a/--known-b, --brute-force, or --smart-brute\n")
		flag.Usage()
		os.Exit(1)
	}
}

func parseRange(s string) (int, int, error) {
	parts := strings.Split(s, ",")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid range format: %s", s)
	}

	min, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, err
	}

	max, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, err
	}

	return min, max, nil
}
