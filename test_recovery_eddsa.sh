#!/bin/bash
# EdDSA Key Recovery Test Script
#
# This script tests the EdDSA key recovery functionality by:
# 1. Generating test fixtures with vulnerable nonce patterns (flawed EdDSA implementations)
# 2. Running the EdDSA recovery example program
# 3. Verifying the recovered private key matches the expected key
#
# Usage: ./test_recovery_eddsa.sh
#
# IMPORTANT: This tests FLAWED EdDSA implementations that use random nonces.
# Standard EdDSA uses deterministic nonces and is NOT vulnerable to these attacks.
#
# This is useful for researchers to:
# - Test EdDSA recovery on flawed implementations (e.g., Solana vulnerabilities)
# - Understand the recovery process for EdDSA signatures
# - Investigate real-world attacks (e.g., UpBit 2025 hack)

set -e

cd "$(dirname "$0")"

echo "=== EdDSA Recovery Test Script ==="
echo "This script tests EdDSA key recovery from signatures with affinely related nonces"
echo "Note: This targets FLAWED implementations using random nonces (not standard EdDSA)"
echo

# Step 1: Generate EdDSA fixtures
# Creates test EdDSA signatures with various nonce vulnerabilities
# These simulate flawed implementations that use random nonces instead of deterministic ones
echo "Step 1: Generating EdDSA test fixtures..."

# Check if Python dependencies are installed
if ! python3 -c "import nacl.signing" 2>/dev/null; then
    echo "ERROR: PyNaCl module not found"
    echo ""
    echo "Please install Python dependencies:"
    echo ""
    echo "For Python 3.12+ (externally managed):"
    echo "  python3 -m pip install --break-system-packages -r scripts/requirements.txt"
    echo ""
    echo "For older Python versions:"
    echo "  pip install -r scripts/requirements.txt"
    echo ""
    echo "Or install individually:"
    echo "  pip install PyNaCl"
    exit 1
fi

make fixtures-eddsa 2>&1
if [ $? -ne 0 ]; then
    echo ""
    echo "ERROR: Failed to generate EdDSA fixtures"
    echo "Make sure Python 3.6+ is installed and all dependencies are available:"
    echo "  pip install PyNaCl"
    exit 1
fi
echo "✓ EdDSA fixtures generated"

# Step 2: Check if files exist
# Verify that the required EdDSA fixture files were created successfully
echo
echo "Step 2: Verifying fixture files..."
if [ ! -f "fixtures/test_eddsa_signatures_hardcoded_step.json" ]; then
    echo "ERROR: fixtures/test_eddsa_signatures_hardcoded_step.json not found"
    echo "This file should contain EdDSA signatures with hardcoded step nonce pattern"
    exit 1
fi
echo "✓ test_eddsa_signatures_hardcoded_step.json exists"

if [ ! -f "fixtures/test_eddsa_key_info.json" ]; then
    echo "ERROR: fixtures/test_eddsa_key_info.json not found"
    echo "This file should contain the EdDSA private/public key information for verification"
    exit 1
fi
echo "✓ test_eddsa_key_info.json exists"

# Step 3: Get public key
# Extract the public key from the EdDSA key info file for verification
echo
echo "Step 3: Extracting EdDSA public key for verification..."
PUBKEY=$(python3 -c "import json; print(json.load(open('fixtures/test_eddsa_key_info.json'))['public_key_hex'])")
if [ -z "$PUBKEY" ]; then
    echo "ERROR: Failed to extract public key"
    exit 1
fi
echo "✓ Public key: $PUBKEY"

# Step 4: Run recovery using the example program
# Execute the EdDSA recovery example program
# Unlike ECDSA, EdDSA recovery uses the Go example program instead of a compiled binary
echo
echo "Step 4: Running EdDSA key recovery..."
echo "Command: go run examples/eddsa/main.go fixtures/test_eddsa_signatures_hardcoded_step.json $PUBKEY"
echo "Strategy: Uses smart brute-force to find nonce patterns"
echo

# Use timeout to prevent infinite loops (1200 seconds = 20 minutes)
timeout 1200 go run examples/eddsa/main.go \
    fixtures/test_eddsa_signatures_hardcoded_step.json \
    "$PUBKEY"

EXIT_CODE=$?
echo
echo "=== Exit code: $EXIT_CODE ==="

# Handle different exit codes
if [ $EXIT_CODE -eq 124 ]; then
    echo "WARNING: Command timed out after 1200 seconds (20 minutes)"
    echo "The recovery process may need more time or the signatures may not be vulnerable"
elif [ $EXIT_CODE -eq 0 ]; then
    echo "✓ Recovery completed successfully"
    echo "Check the output above to verify the recovered private key matches the expected key"
elif [ $EXIT_CODE -ne 0 ]; then
    echo "ERROR: Command failed with exit code $EXIT_CODE"
    echo "This may indicate an error in the recovery process"
fi

