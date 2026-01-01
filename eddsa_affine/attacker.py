#!/usr/bin/env python3
"""
EdDSA Affine Nonce Attack - Recovers private key from affinely related nonces.

This module implements the attack described in the paper to recover EdDSA private keys
when nonces have an affine relationship: r2 = alpha*r1 + beta.
"""

import hashlib
from typing import Tuple, Optional

# Ed25519 curve order
CURVE_ORDER = 2**252 + 27742317777372353535851937790883648493


def compute_h(r: int, public_key: bytes, message: bytes) -> int:
    """
    Compute H(R||A||M) for EdDSA signature.
    
    Args:
        r: R point as integer
        public_key: Public key A (32 bytes)
        message: Message bytes
        
    Returns:
        Integer hash value mod curve order
    """
    # Convert r to 32 bytes (little-endian for Ed25519)
    r_bytes = r.to_bytes(32, 'little')
    
    # Concatenate: R || A || M
    data = r_bytes + public_key + message
    
    # Hash with SHA-512
    h = hashlib.sha512(data).digest()
    
    # Convert to integer (little-endian) and reduce mod curve order
    return int.from_bytes(h, 'little') % CURVE_ORDER


def attack(
    sig1: Tuple[int, int, bytes, bytes],  # (r1, s1, public_key, message1)
    sig2: Tuple[int, int, bytes, bytes],  # (r2, s2, public_key, message2)
    alpha: int,
    beta: int
) -> Optional[int]:
    """
    Recover EdDSA private key from two signatures with affinely related nonces.
    
    EdDSA signature equation: s = r + H(R||A||M) * a mod q
    Where: r is nonce, a is private key, A is public key, M is message
    
    If nonces have affine relationship: r2 = alpha*r1 + beta
    
    Solving for private key a:
        s1 = r1 + h1 * a
        s2 = r2 + h2 * a
        r2 = alpha * r1 + beta
    
    Substituting:
        s2 = (alpha * r1 + beta) + h2 * a
        s2 = alpha * r1 + beta + h2 * a
        s2 = alpha * (s1 - h1 * a) + beta + h2 * a
        s2 = alpha * s1 - alpha * h1 * a + beta + h2 * a
        s2 - alpha * s1 - beta = a * (h2 - alpha * h1)
    
    Therefore:
        a = (s2 - alpha * s1 - beta) / (h2 - alpha * h1) mod q
    
    Args:
        sig1: First signature tuple (r1, s1, public_key, message1)
        sig2: Second signature tuple (r2, s2, public_key, message2)
        alpha: Affine coefficient (r2 = alpha*r1 + beta)
        beta: Affine offset (r2 = alpha*r1 + beta)
    
    Returns:
        Private key if recovery successful, None if denominator is zero
    """
    r1, s1, public_key1, message1 = sig1
    r2, s2, public_key2, message2 = sig2
    
    # Ensure both signatures use the same public key
    if public_key1 != public_key2:
        raise ValueError("Signatures must use the same public key")
    
    public_key = public_key1
    q = CURVE_ORDER
    
    # Compute H(R||A||M) for both signatures
    h1 = compute_h(r1, public_key, message1)
    h2 = compute_h(r2, public_key, message2)
    
    # Calculate numerator: (s2 - alpha * s1 - beta) mod q
    numerator = (s2 - alpha * s1 - beta) % q
    
    # Calculate denominator: (h2 - alpha * h1) mod q
    denominator = (h2 - alpha * h1) % q
    
    # Check if denominator is zero (division by zero)
    # This check prevents modular inverse error
    if denominator == 0:
        return None
    
    # Calculate modular inverse of denominator
    try:
        denominator_inv = pow(denominator, -1, q)
    except ValueError:
        # This shouldn't happen if denominator != 0, but handle it anyway
        return None
    
    # Recover private key: a = (numerator * denominator_inv) mod q
    private_key = (numerator * denominator_inv) % q
    
    return private_key

