#!/bin/bash
# Test script to diagnose recovery issues

set -e

cd "$(dirname "$0")"

echo "=== Recovery Test Script ==="
echo

# Step 1: Generate fixtures
echo "Step 1: Generating fixtures..."
make fixtures > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to generate fixtures"
    exit 1
fi
echo "✓ Fixtures generated"

# Step 2: Check if files exist
echo
echo "Step 2: Checking files..."
if [ ! -f "fixtures/test_signatures_counter.json" ]; then
    echo "ERROR: fixtures/test_signatures_counter.json not found"
    exit 1
fi
echo "✓ test_signatures_counter.json exists"

if [ ! -f "fixtures/test_key_info.json" ]; then
    echo "ERROR: fixtures/test_key_info.json not found"
    exit 1
fi
echo "✓ test_key_info.json exists"

# Step 3: Get public key
echo
echo "Step 3: Extracting public key..."
PUBKEY=$(python3 -c "import json; print(json.load(open('fixtures/test_key_info.json'))['public_key_hex'])")
if [ -z "$PUBKEY" ]; then
    echo "ERROR: Failed to extract public key"
    exit 1
fi
echo "✓ Public key: $PUBKEY"

# Step 4: Check if binary exists
echo
echo "Step 4: Checking binary..."
if [ ! -f "./bin/recovery" ]; then
    echo "Building recovery tool..."
    make build
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to build recovery tool"
        exit 1
    fi
fi
echo "✓ Recovery binary exists"

# Step 5: Run recovery
echo
echo "Step 5: Running recovery..."
echo "Command: ./bin/recovery --signatures fixtures/test_signatures_counter.json --smart-brute --public-key $PUBKEY"
echo

timeout 600 ./bin/recovery \
    --signatures fixtures/test_signatures_counter.json \
    --smart-brute \
    --public-key "$PUBKEY"

EXIT_CODE=$?
echo
echo "=== Exit code: $EXIT_CODE ==="

if [ $EXIT_CODE -eq 124 ]; then
    echo "WARNING: Command timed out after 60 seconds"
elif [ $EXIT_CODE -ne 0 ]; then
    echo "ERROR: Command failed with exit code $EXIT_CODE"
fi

