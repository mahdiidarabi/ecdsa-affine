# Solana Signature Tools

This directory contains tools for fetching and processing Solana transaction signatures for EdDSA key recovery analysis.

## Tools Overview

1. **`fetch_signatures.py`**: Fetches transaction signature hashes for Solana addresses
2. **`process_signatures.py`**: Processes signature hashes into EdDSA format with full transaction messages and verification

## Setup

### Install Dependencies

```bash
pip install -r ../scripts/requirements.txt
```

Or install individually:
```bash
pip install solders solana base58 cryptography
```

**Note**: The `cryptography` library is required for signature verification in `process_signatures.py`.

### RPC Endpoint

By default, the script uses the public Solana RPC endpoint. For better performance and rate limits, you can:

1. Use a custom RPC endpoint via environment variable:
   ```bash
   export SOLANA_RPC_URL="https://your-rpc-endpoint.com"
   ```

2. Or use the `--rpc-url` flag:
   ```bash
   python3 fetch_signatures.py --rpc-url "https://your-rpc-endpoint.com" <address>
   ```

**Recommended RPC Providers:**
- [Helius](https://www.helius.dev/) - Free tier available
- [QuickNode](https://www.quicknode.com/) - Free tier available
- [Alchemy](https://www.alchemy.com/) - Free tier available

## Usage

### Step 1: Fetch Signature Hashes (`fetch_signatures.py`)

#### Fetch Signatures for All Addresses (Default)

By default, the script processes all addresses from `addresses.json` and saves each to `solana_signatures/signatures/<address>.json`:

```bash
python3 fetch_signatures.py
```

Or explicitly:
```bash
python3 fetch_signatures.py --all
```

### Fetch Signatures for a Single Address

To process a single address:

```bash
python3 fetch_signatures.py <solana_address>
```

Example:
```bash
python3 fetch_signatures.py 2nE99H3e9gfbxKaGodnTwixMgZwgTtKg45aoCFwdEfJS
```

This will save the signatures to `solana_signatures/signatures/2nE99H3e9gfbxKaGodnTwixMgZwgTtKg45aoCFwdEfJS.json`

### Custom Addresses File

```bash
python3 fetch_signatures.py --all --addresses path/to/addresses.json
```

### Limit Number of Signatures

```bash
python3 fetch_signatures.py <address> --limit 100
```

### Custom Output Directory

By default, files are saved to `solana_signatures/signatures/`. To use a different directory:

```bash
python3 fetch_signatures.py --output-dir my_signatures
```

#### Output Format (fetch_signatures.py)

The `fetch_signatures.py` script generates JSON files containing a simple list of base58-encoded signature hashes:

```json
[
  "signature_hash_1_base58",
  "signature_hash_2_base58",
  ...
]
```

Files are saved to `solana_signatures/signatures/<main_address>.json` where `<main_address>` is the main signer address (not sub-addresses).

### Step 2: Process Signatures (`process_signatures.py`)

The `process_signatures.py` script converts signature hash files into the full EdDSA format required for key recovery, including:
- Extracting `r` and `s` components from signature hashes
- Fetching transaction messages via RPC
- Verifying signatures to ensure data correctness
- Formatting output compatible with `pkg/eddsaaffine`

#### Process All Signature Files

By default, processes all JSON files in `solana_signatures/signatures/`:

```bash
python3 process_signatures.py
```

#### Process a Specific File

```bash
python3 process_signatures.py --file 2nE99H3e9gfbxKaGodnTwixMgZwgTtKg45aoCFwdEfJS.json
```

#### Process with Limit (for testing)

```bash
python3 process_signatures.py --file address.json --limit 100
```

#### Custom Input/Output Directories

```bash
python3 process_signatures.py --input-dir my_signatures --output-dir my_processed
```

#### Debug Mode

Enable detailed logging for troubleshooting:

```bash
DEBUG_SIG=1 python3 process_signatures.py --file address.json --limit 5
```

#### Strict Verification Mode

Only include signatures that pass Ed25519 verification:

```bash
STRICT_VERIFY=1 python3 process_signatures.py
```

#### Output Format (process_signatures.py)

The processed files are saved to `solana_signatures/processed_signatures/<address>.json` with the following format:

```json
[
  {
    "message": "hex_encoded_transaction_message",
    "r": "0xhex_r_component",
    "s": "0xhex_s_component",
    "public_key": "hex_encoded_public_key"
  },
  ...
]
```

This format matches `fixtures/test_eddsa_signatures_affine.json` and is compatible with the EdDSA key recovery tool (`pkg/eddsaaffine`).

**Key Features:**
- **Message**: Serialized transaction message bytes (hex, no 0x prefix) - required for key recovery
- **r**: R point component (hex with 0x prefix)
- **s**: Scalar component (hex with 0x prefix)
- **public_key**: Public key from main address (hex, no 0x prefix)

**Signature Verification:**
- Each signature is verified using Ed25519 verification
- Ensures r, s, message, and public_key are correct
- Invalid signatures are logged (or skipped in strict mode)

## How It Works

### fetch_signatures.py

1. **Address Validation**: Validates that the address is a valid Solana address
2. **PDA Detection**: If the address is a Program Derived Address (PDA), it finds the main signer address by examining recent transactions
3. **Signature Fetching**: Fetches all transaction signature hashes (base58-encoded) where the address is a signer
4. **Deduplication**: If multiple sub-addresses map to the same main address, signatures are only fetched once
5. **JSON Storage**: Saves signature hashes as a simple list to `signatures/<main_address>.json`

### process_signatures.py

1. **Read Signature Hashes**: Loads signature hash files from `signatures/` directory
2. **Extract Components**: Decodes each base58 signature hash to extract `r` (32 bytes) and `s` (32 bytes) components
3. **Fetch Messages**: For each signature, fetches the full transaction via RPC to get the serialized message that was signed
4. **Extract Public Key**: Uses the filename (main address) as the public key
5. **Verify Signatures**: Verifies each signature using Ed25519 to ensure r, s, message, and public_key are correct
6. **Format Output**: Saves processed signatures in EdDSA format to `processed_signatures/<address>.json`

## Sub-Address Handling

If you provide a sub-address (PDA), the script will:
1. Check recent transactions for that address
2. Identify the main signer address (the account that actually signed the transactions)
3. Fetch all signatures for the main signer address
4. Save the results with a filename based on the original address

## Rate Limiting

Both scripts include rate limiting to be respectful to RPC endpoints:

**fetch_signatures.py:**
- 0.5s delay between pagination requests
- 2.0s delay between addresses
- Automatic retry with exponential backoff for rate limit errors (429)

**process_signatures.py:**
- 0.1s delay between RPC requests
- Automatic retry with exponential backoff for rate limit errors (429)

For large address lists, consider using a dedicated RPC endpoint with higher rate limits.

## Troubleshooting

### "Missing required dependency" Error

Install dependencies:
```bash
pip install solders solana base58 cryptography
```

Or use the requirements file:
```bash
pip install -r ../scripts/requirements.txt
```

### "Invalid Solana address" Error

Verify the address is a valid base58-encoded Solana address.

### Rate Limit Errors (429 Too Many Requests)

The public Solana RPC endpoint has strict rate limits. If you encounter 429 errors:

1. **Use a custom RPC endpoint** (recommended):
   ```bash
   python3 fetch_signatures.py --rpc-url "https://your-rpc-endpoint.com"
   ```

2. **The script includes automatic retry logic** with exponential backoff for rate limit errors

3. **Reduce the number of signatures** per address:
   ```bash
   python3 fetch_signatures.py --limit 100
   ```

4. **Process addresses one at a time** instead of all at once

**Recommended RPC Providers:**
- [Helius](https://www.helius.dev/) - Free tier: 100k requests/day
- [QuickNode](https://www.quicknode.com/) - Free tier available
- [Alchemy](https://www.alchemy.com/) - Free tier available

### No Signatures Found

- Verify the address has signed transactions
- Check if the address is a PDA (sub-address) - the script will find the main signer
- Ensure you're using the correct network (mainnet-beta by default)

## Integration with Key Recovery

After processing signatures, you can use them with the EdDSA key recovery tool:

```bash
# Get the public key from the processed signatures file
PUBKEY=$(python3 -c "import json; print(json.load(open('solana_signatures/processed_signatures/ADDRESS.json'))[0]['public_key'])")

# Run key recovery
go run examples/eddsa/main.go solana_signatures/processed_signatures/ADDRESS.json $PUBKEY
```

Or using the Go package directly:
```go
client := eddsaaffine.NewClient()
result, err := client.RecoverKey(ctx, "solana_signatures/processed_signatures/ADDRESS.json", publicKeyHex)
```

## Complete Workflow

### Full Pipeline

```bash
# Step 1: Fetch signature hashes for all addresses
python3 fetch_signatures.py
# Output: solana_signatures/signatures/<main_address>.json (list of signature hashes)

# Step 2: Process signature hashes into EdDSA format with messages
python3 process_signatures.py
# Output: solana_signatures/processed_signatures/<address>.json (full EdDSA format)

# Step 3: Run key recovery analysis
PUBKEY=$(python3 -c "import json; print(json.load(open('solana_signatures/processed_signatures/2nE99H3e9gfbxKaGodnTwixMgZwgTtKg45aoCFwdEfJS.json'))[0]['public_key'])")
go run examples/eddsa/main.go solana_signatures/processed_signatures/2nE99H3e9gfbxKaGodnTwixMgZwgTtKg45aoCFwdEfJS.json $PUBKEY
```

### Quick Test Workflow

```bash
# 1. Fetch signatures for a single address (limit for testing)
python3 fetch_signatures.py 2nE99H3e9gfbxKaGodnTwixMgZwgTtKg45aoCFwdEfJS --limit 100

# 2. Process with debug mode to see verification details
DEBUG_SIG=1 python3 process_signatures.py --file 2nE99H3e9gfbxKaGodnTwixMgZwgTtKg45aoCFwdEfJS.json --limit 10

# 3. Verify the output format
python3 -c "import json; print(json.dumps(json.load(open('solana_signatures/processed_signatures/2nE99H3e9gfbxKaGodnTwixMgZwgTtKg45aoCFwdEfJS.json'))[0], indent=2))"
```

### Directory Structure

```
solana_signatures/
├── addresses.json                    # Input: List of addresses to process
├── signatures/                        # Step 1 output: Signature hashes
│   ├── <main_address_1>.json         # List of base58 signature hashes
│   └── <main_address_2>.json
└── processed_signatures/             # Step 2 output: Full EdDSA format
    ├── <main_address_1>.json         # Array of {message, r, s, public_key}
    └── <main_address_2>.json
```

## Signature Verification

The `process_signatures.py` script includes built-in Ed25519 signature verification to ensure data correctness:

- **Verification Method**: Uses the same Ed25519 verification as the `eddsaaffine` package
- **What's Verified**: Confirms that r, s, message, and public_key form a valid signature
- **Modes**:
  - **Normal**: Verifies signatures, includes all (even if verification fails) with warnings
  - **Strict** (`STRICT_VERIFY=1`): Only includes signatures that pass verification
- **Benefits**: Ensures 100% correctness of extracted data before key recovery analysis

**Note**: Verification requires the `cryptography` library. If not available, verification is disabled and a warning is shown.

