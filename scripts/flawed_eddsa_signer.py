#!/usr/bin/env python3
"""
Flawed EdDSA Signer - Demonstrates nonce reuse and affine nonce relationships.

This module creates EdDSA (Ed25519) signatures with:
1. Same nonce reuse (r1 = r2) - simplest attack case
2. Affinely related nonces (r2 = a*r1 + b) - for testing recovery attacks
3. Random nonces (non-standard EdDSA) - implementation bug scenario

WARNING: This is for testing/educational purposes only!
Standard EdDSA uses deterministic nonces, but this simulates flawed implementations.
"""

import hashlib
import json
import os
import secrets
from typing import List, Tuple, Optional
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import RawEncoder, HexEncoder
import nacl.bindings


# Ed25519 curve order
CURVE_ORDER = 2**252 + 27742317777372353535851937790883648493


class FlawedEdDSASigner:
    """
    A flawed EdDSA signer that uses random nonces (non-standard) with reuse or affine relationships.
    
    Note: Standard EdDSA uses deterministic nonces (SHA-512(private_key || message)).
    This class simulates a flawed implementation that uses random nonces, making it
    vulnerable to the same attacks as ECDSA.
    """
    
    def __init__(self, private_key: Optional[bytes] = None):
        """
        Initialize the signer.
        
        Args:
            private_key: Optional 32-byte private key (generates new one if not provided)
        """
        if private_key:
            if len(private_key) != 32:
                raise ValueError("Private key must be 32 bytes")
            self.sk = SigningKey(private_key)
            self.private_key = private_key
        else:
            self.sk = SigningKey.generate()
            self.private_key = self.sk.encode(encoder=RawEncoder)
        
        self.vk = self.sk.verify_key
        self.public_key = self.vk.encode(encoder=RawEncoder)
    
    def hash_message(self, message: bytes) -> bytes:
        """Hash a message using SHA-512 (EdDSA standard)."""
        return hashlib.sha512(message).digest()
    
    def compute_h(self, r: bytes, public_key: bytes, message: bytes) -> int:
        """
        Compute H(R||A||M) for EdDSA signature.
        
        Args:
            r: R point (32 bytes)
            public_key: Public key A (32 bytes)
            message: Message bytes
            
        Returns:
            Integer hash value mod curve order
        """
        data = r + public_key + message
        h = hashlib.sha512(data).digest()
        # Reduce mod curve order
        return int.from_bytes(h, 'little') % CURVE_ORDER
    
    def sign_with_same_nonce(
        self,
        messages: List[bytes],
        nonce: Optional[int] = None
    ) -> List[dict]:
        """
        Sign multiple messages using the SAME nonce (nonce reuse attack).
        
        This is a special case of affine relationship: r2 = 1*r1 + 0
        
        Args:
            messages: List of messages to sign
            nonce: Optional nonce scalar (generates random one if not provided)
        
        Returns:
            List of signature dictionaries with r, s, message values
        """
        if nonce is None:
            nonce = secrets.randbelow(CURVE_ORDER)
        
        signatures = []
        
        # Generate R point from nonce
        # For Ed25519, we need to compute R = nonce * B (base point)
        # For simplicity in testing, we'll use the nonce value directly as R
        # In real Ed25519, R would be a point on the curve
        # This is a simplified representation for testing purposes
        r_int = nonce % CURVE_ORDER
        r_bytes = r_int.to_bytes(32, 'little')
        
        for message in messages:
            h = self.compute_h(r_bytes, self.public_key, message)
            
            # EdDSA signature: s = r + H(R||A||M) * a mod q
            # Where a is the private key scalar
            # Extract private key scalar from seed
            # In Ed25519, the private key is derived from the seed via SHA-512
            # For simplicity, we use the first 32 bytes as the scalar
            a = int.from_bytes(self.private_key[:32], 'little') % CURVE_ORDER
            s = (nonce + h * a) % CURVE_ORDER
            
            signatures.append({
                'message': message.hex(),
                'r': hex(r_int),
                's': hex(s),
                'public_key': self.public_key.hex(),
            })
        
        return signatures
    
    def sign_with_affine_nonces(
        self,
        messages: List[bytes],
        a: int,
        b: int,
        start_nonce: Optional[int] = None
    ) -> List[dict]:
        """
        Sign messages using affinely related nonces: r_i = a*r_{i-1} + b.
        
        This simulates a flawed implementation where nonces have an affine relationship.
        
        Args:
            messages: List of messages to sign
            a: Affine coefficient (r2 = a*r1 + b)
            b: Affine offset (r2 = a*r1 + b)
            start_nonce: Optional starting nonce (generates random one if not provided)
        
        Returns:
            List of signature dictionaries with r, s, message values
        """
        if start_nonce is None:
            start_nonce = secrets.randbelow(CURVE_ORDER)
        
        signatures = []
        current_nonce = start_nonce
        
        for i, message in enumerate(messages):
            # Generate R from current nonce
            r_int = current_nonce % CURVE_ORDER
            r_bytes = r_int.to_bytes(32, 'little')
            
            h = self.compute_h(r_bytes, self.public_key, message)
            
            # EdDSA signature: s = r + H(R||A||M) * a mod q
            a_priv = int.from_bytes(self.private_key[:32], 'little') % CURVE_ORDER
            s = (current_nonce + h * a_priv) % CURVE_ORDER
            
            signatures.append({
                'message': message.hex(),
                'r': hex(r_int),
                's': hex(s),
                'public_key': self.public_key.hex(),
            })
            
            # Calculate next nonce: r_{i+1} = a*r_i + b
            if i < len(messages) - 1:
                current_nonce = (a * current_nonce + b) % CURVE_ORDER
        
        return signatures
    
    def sign_with_counter_nonce(
        self,
        messages: List[bytes],
        start_nonce: Optional[int] = None
    ) -> List[dict]:
        """
        Sign messages with counter-based nonces: r_i = r_0 + i.
        
        This is a special case of affine relationship: r_i = 1*r_0 + i
        
        Args:
            messages: List of messages to sign
            start_nonce: Optional starting nonce (generates random one if not provided)
        
        Returns:
            List of signature dictionaries
        """
        return self.sign_with_affine_nonces(messages, a=1, b=1, start_nonce=start_nonce)
    
    def sign_with_hardcoded_step(
        self,
        messages: List[bytes],
        step: int,
        start_nonce: Optional[int] = None
    ) -> List[dict]:
        """
        Sign messages with hardcoded step: r_i = r_0 + i*step.
        
        This is a special case: r_i = 1*r_0 + i*step
        
        Args:
            messages: List of messages to sign
            step: Step size between nonces
            start_nonce: Optional starting nonce
        
        Returns:
            List of signature dictionaries
        """
        if start_nonce is None:
            start_nonce = secrets.randbelow(CURVE_ORDER)
        
        signatures = []
        
        for i, message in enumerate(messages):
            nonce = (start_nonce + i * step) % CURVE_ORDER
            r_int = nonce % CURVE_ORDER
            r_bytes = r_int.to_bytes(32, 'little')
            
            h = self.compute_h(r_bytes, self.public_key, message)
            a_priv = int.from_bytes(self.private_key[:32], 'little') % CURVE_ORDER
            s = (nonce + h * a_priv) % CURVE_ORDER
            
            signatures.append({
                'message': message.hex(),
                'r': hex(r_int),
                's': hex(s),
                'public_key': self.public_key.hex(),
            })
        
        return signatures
    
    def get_key_info(self) -> dict:
        """Get private and public key information."""
        return {
            'private_key': int.from_bytes(self.private_key[:32], 'little'),
            'public_key_hex': self.public_key.hex(),
            'public_key': self.public_key.hex(),
        }


def main():
    """Generate test fixtures with various nonce flaws."""
    print("Generating EdDSA test fixtures with flawed nonce generation...")
    
    # Create signer
    signer = FlawedEdDSASigner()
    key_info = signer.get_key_info()
    
    # Save key info
    os.makedirs('fixtures', exist_ok=True)
    with open('fixtures/test_eddsa_key_info.json', 'w') as f:
        json.dump(key_info, f, indent=2)
    print(f"Saved key info to fixtures/test_eddsa_key_info.json")
    print(f"Private key: {key_info['private_key']}")
    print(f"Public key: {key_info['public_key_hex']}\n")
    
    # Generate test messages
    messages = [f"Test message {i}".encode() for i in range(5)]
    
    # 1. Same nonce reuse
    print("1. Generating same nonce reuse signatures...")
    same_nonce_sigs = signer.sign_with_same_nonce(messages)
    with open('fixtures/test_eddsa_signatures_same_nonce.json', 'w') as f:
        json.dump(same_nonce_sigs, f, indent=2)
    print(f"   Saved {len(same_nonce_sigs)} signatures to fixtures/test_eddsa_signatures_same_nonce.json")
    
    # 2. Counter nonces (r_i = r_0 + i)
    print("2. Generating counter nonce signatures...")
    counter_sigs = signer.sign_with_counter_nonce(messages)
    with open('fixtures/test_eddsa_signatures_counter.json', 'w') as f:
        json.dump(counter_sigs, f, indent=2)
    print(f"   Saved {len(counter_sigs)} signatures to fixtures/test_eddsa_signatures_counter.json")
    
    # 3. Affine relationship (r2 = 2*r1 + 1)
    print("3. Generating affine relationship signatures (r2 = 2*r1 + 1)...")
    affine_sigs = signer.sign_with_affine_nonces(messages, a=2, b=1)
    with open('fixtures/test_eddsa_signatures_affine.json', 'w') as f:
        json.dump(affine_sigs, f, indent=2)
    print(f"   Saved {len(affine_sigs)} signatures to fixtures/test_eddsa_signatures_affine.json")
    
    # 4. Hardcoded step (r_i = r_0 + i*12345)
    print("4. Generating hardcoded step signatures (r_i = r_0 + i*1234567)...")
    step_sigs = signer.sign_with_hardcoded_step(messages, step=1234567)
    with open('fixtures/test_eddsa_signatures_hardcoded_step.json', 'w') as f:
        json.dump(step_sigs, f, indent=2)
    print(f"   Saved {len(step_sigs)} signatures to fixtures/test_eddsa_signatures_hardcoded_step.json")
    
    print("\n✅ All test fixtures generated successfully!")
    print("\nNote: These signatures use RANDOM nonces (non-standard EdDSA).")
    print("Standard EdDSA uses deterministic nonces, but this simulates a flawed implementation.")


if __name__ == '__main__':
    main()

