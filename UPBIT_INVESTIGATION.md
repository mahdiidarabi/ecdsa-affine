# Upbit 2025 Hack Investigation Plan
## Complete Guide for Solana EdDSA Key Recovery

---

## 🎯 Executive Summary

This document provides a focused, practical approach to investigating the Upbit 2025 hack on Solana. The strategy prioritizes attack vectors most likely to succeed against large-scale exchange infrastructure, starting with the simplest checks before moving to complex attacks.

**Key Insight:** Standard EdDSA uses deterministic nonces, but flawed implementations may use random nonces, making them vulnerable to ECDSA-style attacks.

---

## 📊 Investigation Priority Matrix

| Priority | Attack Vector | Likelihood for Upbit | Action Required | Expected Time |
|----------|--------------|---------------------|-----------------|---------------|
| **🔴 CRITICAL** | **Nonce Reuse** | **VERY HIGH** | Check for duplicate `R` values | Minutes |
| **🟠 HIGH** | **Implementation Bugs (Random Nonces)** | **HIGH** | Check if `R` varies for identical messages | Hours |
| **🟡 MEDIUM** | **Weak/Biased RNG** | **MEDIUM** | Statistical analysis → lattice attacks | Days |
| **🟡 MEDIUM** | **Key Derivation Bugs** | **MEDIUM** | Analyze wallet generation patterns | Days |
| **⚪ LOW** | Fault Injection, Side-Channels, Pure Math | **VERY LOW** | Skip for remote exchange investigation | N/A |

---

## 📋 Step-by-Step Investigation Plan

### Phase 0: Data Collection (Day 1)

#### 1. Identify Attacker Addresses
- Extract from Upbit's official notice/announcement
- List all compromised Solana addresses
- **Note:** Attacker addresses = destination, we need to find **source hot wallet(s)**

#### 2. Trace Back to Source Wallet(s)
- Use Solana block explorer (Solscan, Solana Explorer)
- For each attacker address, trace **incoming transactions**
- Identify the **source wallet address(es)** that sent funds
- This is your **target wallet** for signature analysis

#### 3. Collect Signature Data
- Export full transaction history for source wallet(s)
- Extract for each transaction:
  - `signature` field (contains R and s)
  - `message` (transaction data)
  - `publicKey` (wallet address)
  - `timestamp`
  - `blockHeight`

**Tools Needed:**
- Solana CLI or `@solana/web3.js` for programmatic access
- Block explorer API or direct RPC calls

**Example using Solana CLI:**
```bash
# Install Solana CLI
sh -c "$(curl -sSfL https://release.solana.com/stable/install)"

# Fetch transaction history
solana transaction-history <wallet_address> --output json > transactions.json
```

**Example using Python:**
```python
from solana.rpc.api import Client

client = Client("https://api.mainnet-beta.solana.com")
response = client.get_signatures_for_address(wallet_address, limit=1000)

# Extract signatures from transactions
for sig_info in response.value:
    tx = client.get_transaction(sig_info.signature, encoding="jsonParsed")
    # Extract R and s from signature
```

---

### Phase 1: Quick Wins (Days 1-2) - HIGHEST PRIORITY

#### ✅ Check 1: Nonce Reuse Detection (CRITICAL - Check First!)

**Why:** Simplest bug, most catastrophic, easiest to detect. A single find is a smoking gun.

**Method:**
```python
# Pseudo-code
r_values = {}
for sig in signatures:
    r = extract_r_from_signature(sig)
    if r in r_values:
        # SMOKING GUN: Nonce reuse found!
        recover_key_from_nonce_reuse(sig, r_values[r])
    r_values[r] = sig
```

**EdDSA Nonce Reuse Recovery:**
- EdDSA signature: `s = r + H(R||A||M)·a mod q`
- If nonce `r` is reused: `s₁ = r + H(R||A||M₁)·a`, `s₂ = r + H(R||A||M₂)·a`
- Can solve for private key: `a = (s₁ - s₂) / (H(R||A||M₁) - H(R||A||M₂)) mod q`

**Expected Result:**
- If found: **Key recovery is straightforward** → Investigation complete!
- If not found: Proceed to Check 2

**Implementation:**
```go
// Using the eddsaaffine package
client := eddsaaffine.NewClient()
result, err := client.RecoverKey(ctx, "signatures.json", publicKeyHex)
// The SmartBruteForceStrategy automatically checks for nonce reuse first
```

---

#### ✅ Check 2: Determinism Analysis (HIGH PRIORITY)

**Why:** Detects implementation bugs (non-standard EdDSA). If random nonces are detected, your ECDSA affine attack code becomes relevant.

**Method:**
```python
# Group signatures by message hash
message_groups = {}
for sig in signatures:
    msg_hash = hash(sig.message)
    if msg_hash not in message_groups:
        message_groups[msg_hash] = []
    message_groups[msg_hash].append(sig.r)

# Check if R varies for same message
for msg_hash, r_values in message_groups.items():
    if len(set(r_values)) > 1:
        # RED FLAG: Non-deterministic nonces!
        # Implementation bug - not using standard EdDSA
        # Your ECDSA affine attack code becomes relevant
        print("🚨 Random nonces detected - ECDSA attacks apply!")
```

**Expected Result:**
- **Deterministic (standard EdDSA):** Same message → same R
  - If this is the case, nonce reuse attack doesn't apply
  - Need to look for other vulnerabilities (bias, side-channels, etc.)
  
- **Random Nonces (non-standard):** Same message → different R
  - **MAJOR FINDING:** Implementation bug
  - Your ECDSA affine nonce attack code can be adapted
  - Proceed to Phase 2

**Key Difference:**
- **Standard EdDSA:** Nonce = SHA-512(private_key || message) → deterministic
- **Flawed Implementation:** Nonce = random() → vulnerable to affine attacks

---

### Phase 2: Deeper Analysis (Days 3-5)

#### 🔬 Analysis 1: Affine Relationship Detection (If Random Nonces Found)

**Goal:** Find affine relationships r₂ = a·r₁ + b in nonces

**Method:**
1. Extract nonces from signatures (if possible)
2. Adapt your existing ECDSA affine attack code
3. Key difference: EdDSA signature equation
   - EdDSA: `s = r + H(R||A||M)·a mod q`
   - ECDSA: `s = k⁻¹(z + r·a) mod n`

**Recovery Formula for EdDSA:**
```
EdDSA equations:
  s1 = r1 + h1·a
  s2 = r2 + h2·a
  r2 = a_coeff·r1 + b_offset

Solving for private key a:
  s2 = (a_coeff·r1 + b_offset) + h2·a
  s2 = a_coeff·r1 + b_offset + h2·a
  s2 = a_coeff·(s1 - h1·a) + b_offset + h2·a
  s2 = a_coeff·s1 - a_coeff·h1·a + b_offset + h2·a
  s2 - a_coeff·s1 - b_offset = a·(h2 - a_coeff·h1)

Therefore:
  a = (s2 - a_coeff·s1 - b_offset) / (h2 - a_coeff·h1) mod q
```

**Implementation:**
```go
// Using the eddsaaffine package
strategy := eddsaaffine.NewSmartBruteForceStrategy().
    WithRangeConfig(eddsaaffine.RangeConfig{
        ARange:     [2]int{1, 100},
        BRange:     [2]int{-5000000, 5000000},
        MaxPairs:   1000,
        NumWorkers: 8,
    })

client := eddsaaffine.NewClient().WithStrategy(strategy)
result, err := client.RecoverKey(ctx, "signatures.json", publicKeyHex)
```

**Common Patterns to Test:**
- `r2 = r1 + 1` (counter)
- `r2 = r1 + step` (hardcoded step)
- `r2 = 2*r1 + 1` (affine)
- `r2 = a*r1 + b` (general affine)

---

#### 🔬 Analysis 2: Statistical Nonce Analysis

**Goal:** Detect biases in nonce generation

**Tests to Perform:**
1. **Uniformity Test:** Are nonces uniformly distributed?
2. **Small Nonce Test:** Are any nonces suspiciously small?
3. **MSB/LSB Bias:** Do nonces have biased most/least significant bits?
4. **Pattern Detection:** Any predictable patterns?

**If Bias Found:**
- Proceed to lattice attacks (SageMath)
- Use LLL/BKZ reduction
- Papers: "Biased Nonce Sense", "Lattice Attacks on Digital Signature Schemes"

**Implementation:**
```python
import statistics
from collections import Counter

# Extract nonces from signatures
nonces = [extract_nonce(sig) for sig in signatures]

# Check for small nonces
small_nonces = [n for n in nonces if n < 2**32]
if small_nonces:
    print(f"⚠️ Found {len(small_nonces)} suspiciously small nonces")

# Check MSB bias
msb_counts = Counter([n >> 240 for n in nonces])
if len(msb_counts) < 10:
    print("⚠️ MSB bias detected - possible weak RNG")

# Check uniformity
# Use chi-square test or similar
```

---

#### 🔬 Analysis 3: Key Derivation Analysis

**Goal:** Check if keys are from weak seeds or predictable derivation

**Method:**
- Analyze public key patterns
- Check if keys follow common derivation paths
- Test for weak mnemonic phrases (if applicable)

**Tools:**
- BIP39 mnemonic brute-forcer
- Derivation path analyzer

---

### Phase 3: Documentation & Hypothesis (Day 6+)

#### 📝 Document Findings

**Structure:**
1. **Data Collection:**
   - Number of signatures analyzed
   - Time period covered
   - Source wallet addresses

2. **Phase 1 Results:**
   - Nonce reuse: Found/Not Found
   - Determinism: Standard EdDSA / Random Nonces / Unknown

3. **Phase 2 Results:**
   - Affine relationships: Found/Not Found
   - Statistical analysis: Results
   - Key recovery: Success/Failure

4. **Limitations:**
   - What couldn't be tested
   - Missing data
   - Assumptions made

#### 🎯 Formulate Hypothesis

**Example Hypothesis (Nonce Reuse):**
> "Analysis of 10,000 historical signatures from the compromised Upbit hot wallet (address: `...`) revealed nonce reuse in 15% of transactions, indicating a critical implementation bug that directly enabled private key recovery. The vulnerability allowed recovery of the private key from a single pair of signatures with identical R values."

**Example Hypothesis (Random Nonces):**
> "Analysis of 10,000 historical signatures from the compromised Upbit hot wallet revealed non-deterministic nonce generation with a statistically significant bias in the 3 most significant bytes, consistent with a flawed PRNG implementation. This vulnerability would enable a lattice-based key recovery attack requiring approximately X signatures and Y computational resources."

**Example Hypothesis (Affine Relationship):**
> "Investigation of the Upbit hot wallet signatures found non-deterministic nonce generation with an affine relationship r₂ = 1·r₁ + 12345 between consecutive signatures. This pattern, consistent with a counter-based nonce generation bug, enabled private key recovery using the adapted ECDSA affine attack methodology."

---

## 🛠️ Tools and Implementation

### Using the EdDSA Affine Package

The project includes a complete Go package for EdDSA key recovery:

**Package Location:** `pkg/eddsaaffine/`

**Basic Usage:**
```go
import "github.com/mahdiidarabi/ecdsa-affine/pkg/eddsaaffine"

// Create client with default strategy
client := eddsaaffine.NewClient()

// Recover key from signatures
ctx := context.Background()
result, err := client.RecoverKey(ctx, "signatures.json", publicKeyHex)
if err != nil {
    log.Fatalf("Recovery failed: %v", err)
}

fmt.Printf("Recovered key: %s\n", result.PrivateKey.Text(16))
fmt.Printf("Pattern: %s\n", result.Pattern)
fmt.Printf("Relationship: r2 = %s*r1 + %s\n", 
    result.Relationship.A.Text(10), 
    result.Relationship.B.Text(10))
```

**Custom Strategy:**
```go
strategy := eddsaaffine.NewSmartBruteForceStrategy().
    WithRangeConfig(eddsaaffine.RangeConfig{
        ARange:     [2]int{1, 10},
        BRange:     [2]int{-50000, 50000},
        MaxPairs:   1000,
        NumWorkers: 8,
        SkipZeroA:  true,
    }).
    WithPatternConfig(eddsaaffine.PatternConfig{
        CustomPatterns: []eddsaaffine.Pattern{
            {A: big.NewInt(1), B: big.NewInt(12345), Name: "custom_step", Priority: 1},
        },
        IncludeCommonPatterns: true,
    })

client := eddsaaffine.NewClient().WithStrategy(strategy)
```

**Known Relationship:**
```go
// If you know the affine relationship (e.g., r2 = 1*r1 + 12345)
result, err := client.RecoverKeyWithKnownRelationship(
    ctx, 
    "signatures.json", 
    1,      // a
    12345,  // b
    publicKeyHex,
)
```

### Signature Format

**Expected JSON Format:**
```json
[
  {
    "message": "hex_encoded_message",
    "r": "0xhex_or_decimal",
    "s": "0xhex_or_decimal",
    "public_key": "hex_encoded_public_key"
  },
  ...
]
```

**Example:**
```json
[
  {
    "message": "54657374206d6573736167652031",
    "r": "0x1234567890abcdef...",
    "s": "0xabcdef1234567890...",
    "public_key": "029d0be24ab418a0b47b765446b5d511293755e89b1b70a66818b30bd143ebec51"
  }
]
```

### Generating Test Fixtures

**EdDSA Test Signatures:**
```bash
cd scripts
python3 flawed_eddsa_signer.py
# Generates: ../fixtures/test_eddsa_signatures_*.json
```

**Available Test Cases:**
- `test_eddsa_signatures_same_nonce.json` - Nonce reuse
- `test_eddsa_signatures_counter.json` - Counter-based (r2 = r1 + 1)
- `test_eddsa_signatures_affine.json` - Affine relationship (r2 = 2*r1 + 1)
- `test_eddsa_signatures_hardcoded_step.json` - Hardcoded step (r2 = r1 + 12345)

---

## 📊 Expected Outcomes

### Best Case Scenario:
- **Nonce reuse found** → Immediate key recovery
- **Paper Title:** "Nonce Reuse Vulnerability in Upbit's Solana Hot Wallet Implementation"
- **Time:** Minutes to hours

### Good Case Scenario:
- **Random nonces with affine relationships** → Key recovery with brute-force
- **Paper Title:** "Exploiting Non-Deterministic Nonce Generation in EdDSA Implementations"
- **Time:** Hours to days

### Moderate Case Scenario:
- **Biased nonces** → Lattice attack recovery
- **Paper Title:** "Lattice-Based Key Recovery from Biased EdDSA Nonces"
- **Time:** Days to weeks

### Worst Case Scenario:
- **No vulnerabilities found** → Document methodology and null results
- **Paper Title:** "Forensic Analysis of Upbit Hack: A Case Study in EdDSA Security"
- **Value:** Still valuable - documents secure implementation or need for deeper analysis

---

## 🔍 Why This Strategy Works for Exchange Infrastructure

### Exchange-Specific Considerations:

1. **Automated Signing Systems:**
   - High transaction volume → More signatures to analyze
   - Automated systems → Higher chance of implementation bugs
   - Hot wallet infrastructure → May use non-standard implementations

2. **Most Likely Vulnerabilities:**
   - **Nonce reuse:** Simplest bug, most catastrophic
   - **Random nonces:** Common in custom implementations
   - **Weak RNG:** System-level RNG issues affect all signatures

3. **Why Other Attacks Are Less Likely:**
   - **Fault injection:** Requires physical access (unlikely for remote exchange)
   - **Side-channels:** Requires device access (unlikely)
   - **Pure math attacks:** Ed25519 is well-studied and secure

---

## 📚 Technical Background

### EdDSA vs ECDSA

**ECDSA (secp256k1):**
- Uses random nonces `k`
- Signature: `s = k⁻¹(z + r·a) mod n`
- Vulnerable to affine relationships: `k₂ = a·k₁ + b`

**EdDSA (Ed25519):**
- Uses deterministic nonces: `r = SHA-512(private_key || message)`
- Signature: `s = r + H(R||A||M)·a mod q`
- **Standard EdDSA is secure**, but flawed implementations may use random nonces

### When ECDSA Attacks Apply to EdDSA

If an EdDSA implementation:
- Uses random nonces instead of deterministic
- Has nonce reuse bugs
- Uses weak RNG

Then ECDSA-style attacks (including affine nonce attacks) become applicable.

---

## 🚀 Quick Start Checklist

- [ ] Extract attacker addresses from Upbit notice
- [ ] Trace back to source hot wallet(s)
- [ ] Collect transaction signatures (R and s values)
- [ ] Run nonce reuse check (Phase 1, Check 1)
- [ ] Run determinism check (Phase 1, Check 2)
- [ ] If random nonces found, run affine attack (Phase 2)
- [ ] Document findings and formulate hypothesis
- [ ] Write paper with methodology and results

---

## 📞 Next Steps

1. **Get Upbit hot wallet address(es)** from public notices
2. **Extract signatures** using Solana RPC or block explorer
3. **Run Phase 1 checks** using the `eddsaaffine` package
4. **Adapt attack** based on findings
5. **Document** for paper

---

## 📖 References

- RFC 8032: EdDSA specification
- "Breaking ECDSA with Two Affinely Related Nonces" (2504.13737v1.pdf)
- "Biased Nonce Sense" - De Mulder et al.
- "Lattice Attacks on Digital Signature Schemes" - Howgrave-Graham, Smart
- Solana Documentation: https://docs.solana.com/

---

## ⚠️ Important Notes

1. **Start with nonce reuse check** - it's the quickest win
2. **If random nonces found** - your ECDSA code applies
3. **If deterministic** - need other attack vectors
4. **Document everything** - even null results are valuable
5. **Ethical considerations** - only analyze publicly available data

---

**Good luck with your investigation!** 🎯

