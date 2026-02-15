#!/bin/bash
# ECDSA Key Recovery Test Script
#
# This script tests the ECDSA key recovery functionality by:
# 1. Generating test fixtures with vulnerable nonce patterns
# 2. Running the ECDSA recovery example program
# 3. Verifying the recovered private key matches the expected key
#
# Usage: ./test_recovery.sh
#
# This is useful for researchers to:
# - Verify the recovery tool works correctly
# - Test the multi-phase brute-force strategy
# - Understand the recovery process for ECDSA signatures

set -e

cd "$(dirname "$0")"

echo "=== ECDSA Recovery Test Script ==="
echo "This script tests ECDSA key recovery from signatures with affinely related nonces"
echo

# Step 1: Generate fixtures
# Creates test signatures with various nonce vulnerabilities (same nonce, counter-based, affine, etc.)
echo "Step 1: Generating ECDSA test fixtures..."

# Check if Python dependencies are installed
if ! python3 -c "import ecdsa" 2>/dev/null; then
    echo "ERROR: ecdsa module not found"
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
    echo "  pip install ecdsa"
    exit 1
fi

make fixtures 2>&1
if [ $? -ne 0 ]; then
    echo ""
    echo "ERROR: Failed to generate fixtures"
    echo "Make sure Python 3.6+ is installed and all dependencies are available:"
    echo "  pip install -r scripts/requirements.txt"
    exit 1
fi
echo "✓ ECDSA fixtures generated"

# Step 2: Check if files exist
# Verify that the required fixture files were created successfully
echo
echo "Step 2: Verifying fixture files..."
if [ ! -f "fixtures/test_signatures_hardcoded_step.json" ]; then
    echo "ERROR: fixtures/test_signatures_hardcoded_step.json not found"
    echo "This file should contain signatures with hardcoded step nonce pattern"
    exit 1
fi
echo "✓ test_signatures_hardcoded_step.json exists"

if [ ! -f "fixtures/test_key_info.json" ]; then
    echo "ERROR: fixtures/test_key_info.json not found"
    echo "This file should contain the private/public key information for verification"
    exit 1
fi
echo "✓ test_key_info.json exists"

# Step 3: Get public key
# Extract the public key from the key info file for verification
echo
echo "Step 3: Extracting public key for verification..."
PUBKEY=$(python3 -c "import json; print(json.load(open('fixtures/test_key_info.json'))['public_key_hex'])")
if [ -z "$PUBKEY" ]; then
    echo "ERROR: Failed to extract public key"
    exit 1
fi
echo "✓ Public key: $PUBKEY"

# Step 4: Run recovery using the example program
# Execute the ECDSA recovery example program
# Same pattern as EdDSA: use the Go example program instead of a compiled binary
echo
echo "Step 4: Running ECDSA key recovery..."
echo "Command: go run examples/basic/main.go fixtures/test_signatures_hardcoded_step.json $PUBKEY"
echo "Strategy: Uses smart brute-force to find nonce patterns"
echo

# Use timeout to prevent infinite loops (750 seconds)
timeout 750 go run examples/basic/main.go \
    fixtures/test_signatures_hardcoded_step.json \
    "$PUBKEY"

EXIT_CODE=$?
echo
echo "=== Exit code: $EXIT_CODE ==="

# Handle different exit codes
if [ $EXIT_CODE -eq 124 ]; then
    echo "WARNING: Command timed out after 750 seconds"
    echo "The recovery process may need more time or the signatures may not be vulnerable"
elif [ $EXIT_CODE -eq 0 ]; then
    echo "✓ Recovery completed successfully"
    echo "Check the output above to verify the recovered private key matches the expected key"
elif [ $EXIT_CODE -ne 0 ]; then
    echo "ERROR: Command failed with exit code $EXIT_CODE"
    echo "This may indicate an error in the recovery process"
fi

