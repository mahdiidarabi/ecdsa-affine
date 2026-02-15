# Scripts Directory

The project is a **Go package**; all recovery logic is in Go. This directory contains **Python scripts used only to generate test fixtures** (vulnerable signatures for ECDSA and EdDSA) and to demonstrate flawed signature generation. Python is not required to use the Go packages or the recovery tool.

## Scripts

### `flawed_signer.py` - ECDSA Signature Generator

Generates ECDSA (secp256k1) signatures with various nonce flaws for testing the recovery tool.

**Structure:** This script follows the same structure as `flawed_eddsa_signer.py` - all signing methods delegate to `sign_with_affine_nonces` for consistency.

**Usage:**
```bash
python3 scripts/flawed_signer.py
```

**Generates:**
- `fixtures/test_signatures_same_nonce.json` - Nonce reuse (k2 = k1)
- `fixtures/test_signatures_counter.json` - Counter-based (k2 = k1 + 1)
- `fixtures/test_signatures_affine.json` - Affine relationship (k2 = 2*k1 + 1)
- `fixtures/test_signatures_hardcoded_step.json` - Hardcoded step (k2 = k1 + 12345)
- `fixtures/test_key_info.json` - Private/public key information

### `flawed_eddsa_signer.py` - EdDSA Signature Generator

Generates EdDSA (Ed25519) signatures with various nonce flaws for testing the EdDSA key recovery tool. 

**Structure:** This script serves as the reference implementation - `flawed_signer.py` (ECDSA) follows the same structure for consistency.

**Important:** Standard EdDSA uses deterministic nonces (SHA-512(private_key || message)) and is secure. This script simulates **flawed implementations** that use random nonces instead, making them vulnerable to ECDSA-style affine nonce attacks. This is useful for:
- Testing the EdDSA key recovery implementation
- Researching vulnerabilities in flawed EdDSA implementations
- Investigating real-world attacks (e.g., UpBit 2025 hack on Solana)

**Usage:**
```bash
python3 scripts/flawed_eddsa_signer.py
```

**Generates:**
- `fixtures/test_eddsa_signatures_same_nonce.json` - Nonce reuse (r2 = r1)
- `fixtures/test_eddsa_signatures_counter.json` - Counter-based (r2 = r1 + 1)
- `fixtures/test_eddsa_signatures_affine.json` - Affine relationship (r2 = 2*r1 + 1)
- `fixtures/test_eddsa_signatures_hardcoded_step.json` - Hardcoded step (r2 = r1 + 12345)
- `fixtures/test_eddsa_key_info.json` - Private/public key information

**Testing Recovery:**

After generating fixtures, test the recovery:

```bash
# Get public key
PUBKEY=$(python3 -c "import json; print(json.load(open('fixtures/test_eddsa_key_info.json'))['public_key_hex'])")

# Test recovery using the example program
go run ../examples/eddsa/main.go fixtures/test_eddsa_signatures_same_nonce.json $PUBKEY
```

### `generate_fixtures.py` - Batch Fixture Generator

Generates multiple fixture sets for comprehensive testing.

**Usage:**
```bash
python3 scripts/generate_fixtures.py
```

## Requirements

Install Python dependencies:

```bash
pip install -r scripts/requirements.txt
```

Required packages:
- `ecdsa` - For ECDSA signature generation
- `PyNaCl` - For EdDSA signature generation

## Testing Workflow

1. **Generate test fixtures:**
   ```bash
   python3 scripts/flawed_eddsa_signer.py
   ```

2. **Run recovery tests:**
   ```bash
   # Same nonce reuse (fastest)
   go run examples/eddsa/main.go fixtures/test_eddsa_signatures_same_nonce.json $PUBKEY
   
   # Counter-based
   go run examples/eddsa/main.go fixtures/test_eddsa_signatures_counter.json $PUBKEY
   
   # Affine relationship
   go run examples/eddsa/main.go fixtures/test_eddsa_signatures_affine.json $PUBKEY
   ```

3. **Verify results:**
   - The example program automatically verifies against the expected key
   - Check that recovered key matches the private key in `test_eddsa_key_info.json`

## Notes

- All generated signatures are for **testing purposes only**
- EdDSA signatures use **random nonces** (non-standard) to simulate flawed implementations
- Standard EdDSA uses deterministic nonces and is not vulnerable to these attacks
- These scripts demonstrate vulnerabilities that can occur in custom implementations
