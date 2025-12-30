#!/usr/bin/env python3
"""
Script to generate test fixtures for the ECDSA affine project.

This script generates test fixtures based on the paper:
"Breaking ECDSA with Two Affinely Related Nonces"
by Jamie Gilchrist, William J. Buchanan, Keir Finlow-Bates

It creates signatures with:
1. Same nonce reuse (k1 = k2)
2. Counter-based nonces (k2 = k1 + 1)
3. Affine relationships (k2 = a*k1 + b)
"""

import json
import os
import sys

# Add scripts directory to path to import modules
sys.path.insert(0, os.path.dirname(__file__))

from flawed_signer import FlawedSigner


def generate_fixtures():
    """Generate test fixtures for ECDSA affine nonce attacks."""
    print("="*70)
    print("Generating ECDSA Test Fixtures")
    print("="*70)
    
    # Ensure fixtures directory exists
    fixtures_dir = os.path.join(os.path.dirname(__file__), "..", "fixtures")
    os.makedirs(fixtures_dir, exist_ok=True)
    
    # Create a signer
    signer = FlawedSigner()
    key_info = signer.get_key_info()
    
    print(f"\n[Generated Keys]")
    print(f"Private Key: {key_info['private_key']}")
    print(f"Public Key:  {key_info['public_key_hex']}")
    
    # Save key info
    key_info_path = os.path.join(fixtures_dir, 'test_key_info.json')
    with open(key_info_path, 'w') as f:
        json.dump(key_info, f, indent=2)
    print(f"\nSaved key info to: {key_info_path}")
    
    # Test messages
    messages = [
        b"Transaction 1: Send 1 ETH",
        b"Transaction 2: Send 2 ETH",
        b"Transaction 3: Send 3 ETH",
        b"Transaction 4: Send 4 ETH",
        b"Transaction 5: Send 5 ETH"
    ]
    
    # Generate fixtures for different attack scenarios
    
    # 1. Same nonce reuse (k1 = k2 = k3 = ...)
    print("\n" + "="*70)
    print("Generating: Same Nonce Reuse (k1 = k2 = k3 = ...)")
    print("="*70)
    signatures_same = signer.sign_with_same_nonce(messages)
    signer.save_signatures(signatures_same, 'test_signatures_same_nonce.json')
    
    # 2. Counter-based nonces (k2 = k1 + 1, k3 = k1 + 2, ...)
    print("\n" + "="*70)
    print("Generating: Counter-Based Nonces (k2 = k1 + 1, k3 = k1 + 2, ...)")
    print("="*70)
    signatures_counter = signer.sign_with_counter_nonce(messages)
    signer.save_signatures(signatures_counter, 'test_signatures_counter.json')
    
    # 2b. Hardcoded step for brute-force testing (k2 = k1 + 12345)
    print("\n" + "="*70)
    print("Generating: Hardcoded Step Nonces (k2 = k1 + 12345, k3 = k1 + 24690, ...)")
    print("="*70)
    signatures_hardcoded = signer.sign_with_hardcoded_step(messages, step=12345)
    signer.save_signatures(signatures_hardcoded, 'test_signatures_hardcoded_step.json')
    
    # 3. Affine relationship (k2 = 2*k1 + 1, k3 = 2*k2 + 1, ...)
    print("\n" + "="*70)
    print("Generating: Affine Relationship (k2 = 2*k1 + 1, k3 = 2*k2 + 1, ...)")
    print("="*70)
    signatures_affine = signer.sign_with_affine_nonces(messages, a=2, b=1)
    signer.save_signatures(signatures_affine, 'test_signatures_affine.json')
    
    # 4. Additional affine relationship (k2 = 3*k1 + 5)
    print("\n" + "="*70)
    print("Generating: Affine Relationship (k2 = 3*k1 + 5, k3 = 3*k2 + 5, ...)")
    print("="*70)
    signatures_affine2 = signer.sign_with_affine_nonces(messages, a=3, b=5)
    signer.save_signatures(signatures_affine2, 'test_signatures_affine_3x_plus_5.json')
    
    print("\n" + "="*70)
    print("All fixtures generated successfully!")
    print("="*70)
    print(f"\nFixtures saved in: {fixtures_dir}")
    print("\nGenerated files:")
    print("  - test_key_info.json (contains private key for verification)")
    print("  - test_signatures_same_nonce.json")
    print("  - test_signatures_counter.json (k2 = k1 + 1)")
    print("  - test_signatures_hardcoded_step.json (k2 = k1 + 12345, for brute-force testing)")
    print("  - test_signatures_affine.json")
    print("  - test_signatures_affine_3x_plus_5.json")
    print("\nYou can now use these fixtures to test key recovery with the Go tool:")
    print("  ./bin/recovery --signatures fixtures/test_signatures_same_nonce.json --known-a 1 --known-b 0")
    print("  ./bin/recovery --signatures fixtures/test_signatures_counter.json --known-a 1 --known-b 1")
    print("  ./bin/recovery --signatures fixtures/test_signatures_affine.json --known-a 2 --known-b 1")
    print("\nOr use smart brute-force (recommended for testing brute-force):")
    print("  ./bin/recovery --signatures fixtures/test_signatures_hardcoded_step.json --smart-brute")


if __name__ == "__main__":
    generate_fixtures()

