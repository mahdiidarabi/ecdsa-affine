#!/bin/bash
# Test script to diagnose EdDSA recovery issues

set -e

cd "$(dirname "$0")"

echo "=== EdDSA Recovery Test Script ==="
echo

# Step 1: Generate EdDSA fixtures
echo "Step 1: Generating EdDSA fixtures..."
make fixtures-eddsa > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to generate EdDSA fixtures"
    exit 1
fi
echo "✓ EdDSA fixtures generated"

# Step 2: Check if files exist
echo
echo "Step 2: Checking files..."
if [ ! -f "fixtures/test_eddsa_signatures_hardcoded_step.json" ]; then
    echo "ERROR: fixtures/test_eddsa_signatures_hardcoded_step.json not found"
    exit 1
fi
echo "✓ test_eddsa_signatures_hardcoded_step.json exists"

if [ ! -f "fixtures/test_eddsa_key_info.json" ]; then
    echo "ERROR: fixtures/test_eddsa_key_info.json not found"
    exit 1
fi
echo "✓ test_eddsa_key_info.json exists"

# Step 3: Get public key
echo
echo "Step 3: Extracting public key..."
PUBKEY=$(python3 -c "import json; print(json.load(open('fixtures/test_eddsa_key_info.json'))['public_key_hex'])")
if [ -z "$PUBKEY" ]; then
    echo "ERROR: Failed to extract public key"
    exit 1
fi
echo "✓ Public key: $PUBKEY"

# Step 4: Run recovery using the example program
echo
echo "Step 4: Running EdDSA recovery..."
echo "Command: go run examples/eddsa/main.go fixtures/test_eddsa_signatures_hardcoded_step.json $PUBKEY"
echo

timeout 600 go run examples/eddsa/main.go \
    fixtures/test_eddsa_signatures_hardcoded_step.json \
    "$PUBKEY"

EXIT_CODE=$?
echo
echo "=== Exit code: $EXIT_CODE ==="

if [ $EXIT_CODE -eq 124 ]; then
    echo "WARNING: Command timed out after 600 seconds"
elif [ $EXIT_CODE -ne 0 ]; then
    echo "ERROR: Command failed with exit code $EXIT_CODE"
fi

