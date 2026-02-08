package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/mahdiidarabi/ecdsa-affine/pkg/ecdsaaffine"
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

	// Set up parser based on format
	var parser ecdsaaffine.SignatureParser
	if *format == "json" {
		parser = &ecdsaaffine.JSONParser{
			MessageField: "message",
			RField:       "r",
			SField:       "s",
			ZField:       "z",
		}
	} else {
		parser = &ecdsaaffine.CSVParser{
			MessageCol: "message",
			RCol:       "r",
			SCol:       "s",
			ZCol:       "z",
		}
	}

	// Create client with parser
	client := ecdsaaffine.NewClient().WithParser(parser)

	ctx := context.Background()

	// Recover key based on mode
	if *knownA != 0 || *knownB != 0 {
		// Known relationship
		fmt.Printf("Using known relationship: k2 = %d*k1 + %d\n", *knownA, *knownB)

		publicKeyStr := ""
		if *publicKey != "" {
			publicKeyStr = *publicKey
		}

		result, err := client.RecoverKeyWithKnownRelationship(ctx, *signaturesFile, int64(*knownA), int64(*knownB), publicKeyStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("\n[+] Recovered private key from signatures %d and %d:\n", result.SignaturePair[0], result.SignaturePair[1])
		fmt.Printf("    Private key: %s\n", result.PrivateKey.String())
		if result.Verified {
			fmt.Println("    ✓ Verified against public key!")
		}

	} else if *smartBrute {
		// Smart brute-force (uses default multi-phase strategy)
		fmt.Printf("Loading signatures from %s...\n", *signaturesFile)

		publicKeyStr := ""
		if *publicKey != "" {
			publicKeyStr = *publicKey
		}

		result, err := client.RecoverKey(ctx, *signaturesFile, publicKeyStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("\n[+] Successfully recovered private key!\n")
		fmt.Printf("    Private key: %s\n", result.PrivateKey.String())
		fmt.Printf("    Relationship: k2 = %s*k1 + %s\n", result.Relationship.A.String(), result.Relationship.B.String())
		fmt.Printf("    Signature pair: (%d, %d)\n", result.SignaturePair[0], result.SignaturePair[1])
		fmt.Printf("    Pattern: %s\n", result.Pattern)
		if result.Verified {
			fmt.Println("    ✓ Verified against public key!")
		}

	} else if *bruteForce {
		// Brute-force - try common patterns first for efficiency
		fmt.Printf("Loading signatures from %s...\n", *signaturesFile)
		fmt.Println("Trying common patterns first (fast path)...")

		publicKeyStr := ""
		if *publicKey != "" {
			publicKeyStr = *publicKey
		}

		// First try with default smart brute-force (common patterns)
		result, err := client.RecoverKey(ctx, *signaturesFile, publicKeyStr)
		if err == nil && result != nil {
			fmt.Printf("\n[+] Successfully recovered private key!\n")
			fmt.Printf("    Private key: %s\n", result.PrivateKey.String())
			fmt.Printf("    Relationship: k2 = %s*k1 + %s\n", result.Relationship.A.String(), result.Relationship.B.String())
			fmt.Printf("    Signature pair: (%d, %d)\n", result.SignaturePair[0], result.SignaturePair[1])
			fmt.Printf("    Pattern: %s\n", result.Pattern)
			if result.Verified {
				fmt.Println("    ✓ Verified against public key!")
			}
			return
		}

		// If common patterns didn't work, use specified ranges
		fmt.Println("Common patterns didn't work, using specified ranges...")

		// Parse ranges
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

		// Create strategy with custom ranges
		strategy := ecdsaaffine.NewSmartBruteForceStrategy().
			WithRangeConfig(ecdsaaffine.RangeConfig{
				ARange:     [2]int{aMin, aMax},
				BRange:     [2]int{bMin, bMax},
				MaxPairs:   *maxPairs,
				NumWorkers: *numWorkers,
				SkipZeroA:  true,
			}).
			WithPatternConfig(ecdsaaffine.PatternConfig{
				IncludeCommonPatterns: false, // Skip common patterns, use only custom range
			})

		client = client.WithStrategy(strategy)

		result, err = client.RecoverKey(ctx, *signaturesFile, publicKeyStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("\n[+] Successfully recovered private key!\n")
		fmt.Printf("    Private key: %s\n", result.PrivateKey.String())
		fmt.Printf("    Relationship: k2 = %s*k1 + %s\n", result.Relationship.A.String(), result.Relationship.B.String())
		fmt.Printf("    Signature pair: (%d, %d)\n", result.SignaturePair[0], result.SignaturePair[1])
		if result.Verified {
			fmt.Println("    ✓ Verified against public key!")
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
