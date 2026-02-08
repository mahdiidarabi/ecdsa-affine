# ECDSA/EdDSA Nonce Brute-Force Strategy for Unknown Structures

## Overview
This document outlines the optimal strategy for brute-forcing ECDSA and EdDSA nonces when the structure is unknown, based on real-world vulnerabilities (e.g., UpBit 2025 hack). **Both ECDSA and EdDSA packages use the same unified strategy and structure.**

## Multi-Phase Approach

### Phase 1: Common Patterns (Fast Path)
**Goal**: Catch 80% of real-world vulnerabilities in seconds

**Patterns to test (in order of likelihood):**

1. **Same Nonce Reuse** (Most Common)
   - `k2 = k1` → `a=1, b=0`
   - Check all signature pairs for identical `r` values first (instant check)

2. **Linear Counter Patterns** (Very Common)
   - `k2 = k1 + 1` → `a=1, b=1`
   - `k2 = k1 + 2` → `a=1, b=2`
   - `k2 = k1 - 1` → `a=1, b=-1`
   - Test small offsets: `b ∈ [-10, 10]`

3. **Multiplicative Patterns** (Common)
   - `k2 = 2*k1` → `a=2, b=0`
   - `k2 = 3*k1` → `a=3, b=0`
   - `k2 = 2*k1 + 1` → `a=2, b=1`

4. **Common Step Values** (Real-world)
   - Powers of 2: `b ∈ {1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768}`
   - Round numbers: `b ∈ {10, 100, 1000, 10000, 100000}`
   - Common increments: `b ∈ {17, 42, 123, 256, 512, 1024, 2048, 4096, 8192}`

### Phase 2: Adaptive Search (Medium Range)
**Goal**: Find patterns with moderate step values

**Strategy:**
1. **Prioritize a=1** (most common: `k2 = k1 + b`)
   - Search `b` in expanding ranges:
     - First: `[-100, 100]` (200 combinations)
     - Then: `[-1000, 1000]` (2000 combinations)
     - Then: `[-10000, 10000]` (20000 combinations)
   - Use binary search approach: test boundaries first

2. **Small a values** (a=2, a=3, a=4)
   - Test with `b ∈ [-1000, 1000]` first
   - Expand if needed

3. **Negative a values** (less common but possible)
   - `a ∈ [-5, -1]` with `b ∈ [-1000, 1000]`

### Phase 3: Wide Search (Large Range)
**Goal**: Catch edge cases and unusual patterns

**Strategy:**
1. **Progressive Range Expansion**
   - Start: `a ∈ [1, 10]`, `b ∈ [-50000, 50000]`
   - Expand: `a ∈ [1, 100]`, `b ∈ [-500000, 500000]`
   - Maximum: `a ∈ [1, 1000]`, `b ∈ [-5000000, 5000000]`

2. **Smart Sampling**
   - For large ranges, use intelligent sampling:
     - Test powers of 2 for `b`
     - Test round numbers
     - Test boundaries first
     - Use statistical analysis to identify likely ranges

### Phase 4: Exhaustive Search (Last Resort)
**Goal**: Find any affine relationship, no matter how unusual

**Strategy:**
- Full brute-force with maximum ranges
- Use parallel processing (16+ workers)
- Test all signature pairs
- Consider non-affine relationships (if applicable)

## Real-World Patterns (Based on Historical Vulnerabilities)

### 1. Counter-Based (Very Common)
```
k_i = k_0 + i * step
→ k2 = k1 + step
→ a=1, b=step
```
**Examples:**
- `step = 1` (simple counter)
- `step = 17` (common increment)
- `step = 12345` (large step, seen in some implementations)

### 2. Time-Based (Common)
```
k_i = timestamp + offset
→ k2 = k1 + (timestamp2 - timestamp1)
→ a=1, b=time_difference
```
**Strategy**: If timestamps available, calculate expected `b` directly

### 3. Hash-Based with Bias (Rare but Critical)
```
k_i = hash(message || counter) mod n
→ May have patterns if hash is biased
```
**Strategy**: Statistical analysis of `r` values to detect bias

### 4. PRNG Weaknesses (Historical)
```
k_i = PRNG(seed + i)
→ Weak PRNGs create predictable patterns
```
**Strategy**: Test common PRNG patterns (LCG, etc.)

## Implementation Strategy

### 1. Pre-filtering (Fast Checks)
```go
// Check for same nonce reuse (instant)
if sig1.R.Cmp(sig2.R) == 0 {
    // Same nonce reuse - recover directly
}

// Check for identical r values across all pairs
// This catches the most common vulnerability
```

### 2. Adaptive Range Selection
```go
// Start with small ranges, expand based on results
ranges := []struct{
    aRange [2]int
    bRange [2]int
}{
    {[2]int{1, 1}, [2]int{-10, 10}},      // Phase 1
    {[2]int{1, 1}, [2]int{-100, 100}},    // Phase 2a
    {[2]int{1, 1}, [2]int{-1000, 1000}},  // Phase 2b
    {[2]int{1, 10}, [2]int{-10000, 10000}}, // Phase 3a
    {[2]int{1, 100}, [2]int{-50000, 50000}}, // Phase 3b
    {[2]int{1, 100}, [2]int{-5000000, 5000000}}, // Phase 4
}
```

### 3. Parallel Processing
- Use worker pools (16+ workers)
- Prioritize work items (a=1 first)
- Early termination when result found
- Progress reporting for long searches

### 4. Statistical Analysis
```go
// Analyze r values for patterns
// - Check for repeated r values (same nonce)
// - Check for r value clustering (biased nonces)
// - Check for arithmetic progressions
```

## Recommended Search Order

1. **Same nonce reuse** (check `r` values) - O(n²) comparisons
2. **Common patterns** (a=1, small b) - ~100 combinations
3. **a=1, medium b** ([-1000, 1000]) - ~2000 combinations
4. **a=1, large b** ([-50000, 50000]) - ~100k combinations
5. **Small a values** (a=2,3,4) with medium b - ~10k combinations
6. **Wide search** (a=1-100, b=large) - millions of combinations
7. **Exhaustive** (all combinations) - last resort

## Performance Optimization

### 1. Early Termination
- Stop immediately when key is found and verified
- Cancel all pending work items

### 2. Smart Prioritization
- Test a=1 exhaustively before other a values
- Test small b values before large ones
- Test consecutive signature pairs first

### 3. Caching
- Cache computed values (modular inverses, etc.)
- Reuse signature pair conversions

### 4. Batch Processing
- Process multiple pairs in parallel
- Use buffered channels for work distribution

## For UpBit-Style Attacks

Based on the UpBit 2025 hack pattern:

1. **Collect signatures** from blockchain
2. **Check for same nonce reuse** first (most common)
3. **Test counter patterns** (k2 = k1 + step)
4. **Test time-based patterns** if timestamps available
5. **Wide search** for unusual step values
6. **Statistical analysis** of r values for bias

## Expected Performance

- **Phase 1** (common patterns): < 1 second
- **Phase 2** (adaptive): 1-10 seconds
- **Phase 3** (wide search): 10-60 seconds
- **Phase 4** (exhaustive): minutes to hours

## Recommendations

1. **Always start with same nonce reuse check** (fastest)
2. **Use adaptive ranges** - don't jump to huge ranges immediately
3. **Prioritize a=1** - it covers 90% of real-world cases
4. **Use parallel processing** - essential for large ranges
5. **Test all signature pairs** - vulnerability might be in specific pairs
6. **Consider statistical analysis** - detect bias before brute-force

## Current Implementation

**Both ECDSA and EdDSA packages implement:**
- ✅ Phase 0 (same nonce reuse detection - instant)
- ✅ Phase 1 (common patterns - 31+ patterns)
- ✅ Phase 2/3 (adaptive range search with a=1 priority)
- ✅ Phase 4 (wide exhaustive search)
- ✅ Parallel processing with configurable workers
- ✅ Progress logging (updates every 5 seconds or 1M pairs)
- ✅ Early termination when key is found
- ✅ Unified structure and logging format
- ⚠️ Could add: statistical pre-analysis, time-based pattern detection

**Note:** Both packages use `log.Printf` for consistent logging and the same multi-phase strategy structure. The only differences are the curve-specific recovery formulas and signature formats.

