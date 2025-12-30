#!/usr/bin/env python3
"""
Flawed ECDSA Signer - Demonstrates nonce reuse and affine nonce relationships.

This module creates signatures with:
1. Same nonce reuse (k1 = k2) - simplest attack case
2. Affinely related nonces (k2 = a*k1 + b) - as described in the paper

WARNING: This is for testing/educational purposes only!
"""

import hashlib
import json
import os
from typing import List, Tuple, Optional
from ecdsa import SigningKey, SECP256k1, VerifyingKey


# secp256k1 curve order
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class FlawedSigner:
    """
    A flawed ECDSA signer that reuses nonces or uses affinely related nonces.
    """
    
    def __init__(self, private_key: Optional[int] = None):
        """
        Initialize the signer.
        
        Args:
            private_key: Optional private key (generates new one if not provided)
        """
        if private_key:
            self.sk = SigningKey.from_secret_exponent(private_key, curve=SECP256k1)
            self.private_key = private_key
        else:
            self.sk = SigningKey.generate(curve=SECP256k1)
            self.private_key = self.sk.privkey.secret_multiplier
        
        self.vk = self.sk.verifying_key
        
        # Get public key
        x = self.vk.pubkey.point.x()
        y = self.vk.pubkey.point.y()
        prefix = b'\x02' if y % 2 == 0 else b'\x03'
        self.public_key = prefix + x.to_bytes(32, 'big')
    
    def hash_message(self, message: bytes) -> int:
        """Hash a message using SHA-256."""
        h = hashlib.sha256(message).digest()
        return int.from_bytes(h, 'big') % CURVE_ORDER
    
    def sign_with_same_nonce(
        self,
        messages: List[bytes],
        nonce: Optional[int] = None
    ) -> List[dict]:
        """
        Sign multiple messages using the SAME nonce (nonce reuse attack).
        
        This is a special case of affine relationship: k2 = 1*k1 + 0
        
        Args:
            messages: List of messages to sign
            nonce: Optional nonce to reuse (generates random one if not provided)
        
        Returns:
            List of signature dictionaries with z, r, s values
        """
        if nonce is None:
            # Generate a random nonce
            import secrets
            nonce = secrets.randbelow(CURVE_ORDER)
        
        signatures = []
        curve = SECP256k1
        G = curve.generator
        n = curve.order
        
        # Calculate r once (since nonce is the same)
        r = (nonce * G).x() % n
        
        for message in messages:
            z = self.hash_message(message)
            
            # Calculate s
            s = (pow(nonce, -1, n) * (z + r * self.private_key)) % n
            
            signatures.append({
                'message': message.decode('utf-8') if isinstance(message, bytes) else message,
                'z': z,
                'r': r,
                's': s
            })
        
        return signatures
    
    def sign_with_affine_nonces(
        self,
        messages: List[bytes],
        base_nonce: Optional[int] = None,
        a: int = 2,
        b: int = 1
    ) -> List[dict]:
        """
        Sign messages using affinely related nonces: k_i = a*k_{i-1} + b
        
        Args:
            messages: List of messages to sign
            base_nonce: Optional base nonce k1 (generates random one if not provided)
            a: Affine coefficient
            b: Affine offset
        
        Returns:
            List of signature dictionaries with z, r, s values
        """
        if base_nonce is None:
            import secrets
            base_nonce = secrets.randbelow(CURVE_ORDER)
        
        signatures = []
        curve = SECP256k1
        G = curve.generator
        n = curve.order
        
        current_nonce = base_nonce
        
        for i, message in enumerate(messages):
            z = self.hash_message(message)
            
            # Calculate r for current nonce
            r = (current_nonce * G).x() % n
            
            # Calculate s
            s = (pow(current_nonce, -1, n) * (z + r * self.private_key)) % n
            
            signatures.append({
                'message': message.decode('utf-8') if isinstance(message, bytes) else message,
                'z': z,
                'r': r,
                's': s,
                'nonce_index': i,
                'nonce_relation': f"k{i+1} = {a}*k{i} + {b}" if i > 0 else "k1 (base)"
            })
            
            # Calculate next nonce: k_{i+1} = a*k_i + b
            current_nonce = (a * current_nonce + b) % n
        
        return signatures
    
    def sign_with_counter_nonce(
        self,
        messages: List[bytes],
        start_nonce: Optional[int] = None
    ) -> List[dict]:
        """
        Sign messages using counter-based nonces: k_i = k_1 + (i-1)
        
        This is a special case: k2 = 1*k1 + 1, k3 = 1*k1 + 2, etc.
        
        Args:
            messages: List of messages to sign
            start_nonce: Optional starting nonce (generates random one if not provided)
        
        Returns:
            List of signature dictionaries with z, r, s values
        """
        if start_nonce is None:
            import secrets
            start_nonce = secrets.randbelow(CURVE_ORDER)
        
        signatures = []
        curve = SECP256k1
        G = curve.generator
        n = curve.order
        
        for i, message in enumerate(messages):
            # Calculate nonce: k_i = k_1 + (i-1)
            nonce = (start_nonce + i*123456) % n
            # nonce = secrets.randbelow(CURVE_ORDER)
            
            z = self.hash_message(message)
            r = (nonce * G).x() % n
            s = (pow(nonce, -1, n) * (z + r * self.private_key)) % n
            
            signatures.append({
                'message': message.decode('utf-8') if isinstance(message, bytes) else message,
                'z': z,
                'r': r,
                's': s,
                'nonce_index': i
            })
        
        return signatures
    
    def save_signatures(self, signatures: List[dict], filename: str):
        """Save signatures to a JSON file in the fixtures folder."""
        # Ensure fixtures directory exists
        fixtures_dir = os.path.join(os.path.dirname(__file__), "..", "fixtures")
        os.makedirs(fixtures_dir, exist_ok=True)
        
        # Save to fixtures folder
        fixtures_path = os.path.join(fixtures_dir, filename)
        with open(fixtures_path, 'w') as f:
            json.dump(signatures, f, indent=2)
        print(f"Saved {len(signatures)} signatures to {fixtures_path}")
    
    def get_key_info(self) -> dict:
        """Get private and public key information."""
        return {
            'private_key': self.private_key,
            'public_key_hex': self.public_key.hex(),
            'public_key_compressed': self.public_key.hex()
        }


def create_test_signatures():
    """Create test signatures for demonstration."""
    print("="*60)
    print("Creating Flawed ECDSA Signatures")
    print("="*60)
    
    # Create a signer
    signer = FlawedSigner()
    
    key_info = signer.get_key_info()
    print(f"\n[Generated Keys]")
    print(f"Private Key: {key_info['private_key']}")
    print(f"Public Key:  {key_info['public_key_hex']}")
    
    # Test messages
    messages = [
        b"Transaction 1: Send 1 ETH",
        b"Transaction 2: Send 2 ETH",
        b"Transaction 3: Send 3 ETH",
        b"Transaction 4: Send 4 ETH",
        b"Transaction 5: Send 5 ETH"
    ]
    
    # Ensure fixtures directory exists
    fixtures_dir = os.path.join(os.path.dirname(__file__), "..", "fixtures")
    os.makedirs(fixtures_dir, exist_ok=True)
    
    # Test 1: Same nonce reuse
    print("\n" + "="*60)
    print("Test 1: Same Nonce Reuse (k1 = k2 = k3 = ...)")
    print("="*60)
    signatures_same = signer.sign_with_same_nonce(messages)
    signer.save_signatures(signatures_same, 'test_signatures_same_nonce.json')
    
    # Save key info for verification
    key_info_path = os.path.join(fixtures_dir, 'test_key_info.json')
    with open(key_info_path, 'w') as f:
        json.dump(key_info, f, indent=2)
    print(f"Saved key info to {key_info_path}")
    
    # Test 2: Counter-based nonces (k2 = k1 + 1)
    print("\n" + "="*60)
    print("Test 2: Counter-Based Nonces (k2 = k1 + 1, k3 = k1 + 2, ...)")
    print("="*60)
    signatures_counter = signer.sign_with_counter_nonce(messages)
    signer.save_signatures(signatures_counter, 'test_signatures_counter.json')
    
    # Test 3: Affine relationship (k2 = 2*k1 + 1)
    print("\n" + "="*60)
    print("Test 3: Affine Relationship (k2 = 2*k1 + 1, k3 = 2*k2 + 1, ...)")
    print("="*60)
    signatures_affine = signer.sign_with_affine_nonces(messages, a=2, b=1)
    signer.save_signatures(signatures_affine, 'test_signatures_affine.json')
    
    print("\n" + "="*60)
    print("All test signatures created!")
    print("="*60)
    print(f"\nFiles created in {fixtures_dir}:")
    print("  - test_signatures_same_nonce.json")
    print("  - test_signatures_counter.json")
    print("  - test_signatures_affine.json")
    print("  - test_key_info.json (contains the private key for verification)")
    
    return key_info


if __name__ == '__main__':
    create_test_signatures()

