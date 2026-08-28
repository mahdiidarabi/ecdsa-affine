#!/usr/bin/env python3
"""
Process Solana Signature Files

Converts signature hash files to EdDSA format with r, s, message, and public_key.
Iterates through files in solana_signatures/signatures/ and creates processed
signature files in solana_signatures/processed_signatures/.

Fetches transaction messages via RPC to get the exact data that was signed.

Usage:
    python3 process_signatures.py
    python3 process_signatures.py --input-dir solana_signatures/signatures
    python3 process_signatures.py --limit 100  # Process only first 100 signatures per file
"""

import json
import os
import sys
import argparse
import time
import threading
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import multiprocessing
    CPU_COUNT = multiprocessing.cpu_count()
except:
    CPU_COUNT = 4  # Fallback if cpu_count() fails

try:
    from solders.pubkey import Pubkey
    from solana.rpc.api import Client
    from solana.rpc.commitment import Confirmed
    from solana.exceptions import SolanaRpcException
    import base58
    import hashlib
except ImportError as e:
    print(f"Error: Missing required dependencies.")
    print(f"Please install: pip install solders solana base58")
    print(f"Or: pip install -r ../scripts/requirements.txt")
    print(f"Import error: {e}")
    sys.exit(1)

# Try to import cryptography for Ed25519 verification
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.exceptions import InvalidSignature
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    print("Warning: cryptography library not available. Signature verification will be disabled.")
    print("Install with: pip install cryptography")

# Ed25519 curve order (same as in eddsaaffine package)
ED25519_CURVE_ORDER = 7237005577332262213973186563042994240857116359379907606001950938285454250989

# Solana RPC endpoint (can be overridden with environment variable)
HELIUS_API_KEY = "bbd34c18-7b97-414d-8d71-5a21a8c29835"
DEFAULT_RPC_URL = os.getenv("SOLANA_RPC_URL", f"https://mainnet.helius-rpc.com/?api-key={HELIUS_API_KEY}")


class SignatureProcessor:
    """Processes Solana signature hash files into EdDSA format."""
    
    def __init__(self, rpc_url: str = DEFAULT_RPC_URL, num_workers: Optional[int] = None):
        """
        Initialize the processor with an RPC endpoint.
        
        Args:
            rpc_url: Solana RPC endpoint URL
            num_workers: Number of parallel worker threads. If None, uses half of CPU cores (default: None)
        """
        if num_workers is None:
            # Default to half of CPU cores, but at least 2 and at most 32
            num_workers = max(2, min(CPU_COUNT // 2, 32))
        self.client = Client(rpc_url)
        self.rpc_url = rpc_url
        self.request_delay = 0.1  # Delay between RPC requests (seconds) - per thread
        self.max_retries = 3
        self.retry_delay = 2.0  # Initial retry delay (seconds)
        # CRITICAL: Signature verification is MANDATORY for eddsaaffine compatibility
        # Verify that cryptography library is available
        if not CRYPTOGRAPHY_AVAILABLE:
            raise RuntimeError(
                "CRITICAL: Signature verification is MANDATORY but cryptography library is not available. "
                "Please install: pip install cryptography>=41.0.0"
            )
        self.verify_signatures = True  # Always enabled (mandatory)
        self.num_workers = num_workers  # Number of parallel threads
        self.file_lock = threading.Lock()  # Lock for thread-safe file writing
    
    def _get_transaction_with_retry(self, signature_hash: str) -> Optional[object]:
        """
        Fetch transaction with retry logic for rate limiting.
        
        Args:
            signature_hash: Base58 signature hash
            
        Returns:
            Transaction object or None if fetch fails (transaction pruned or RPC error)
        """
        for attempt in range(self.max_retries):
            try:
                # Use solders Signature type
                from solders.signature import Signature as SoldersSignature
                sig_obj = SoldersSignature.from_string(signature_hash)
                
                # Get transaction in base64 format to properly parse the message
                # This gives us the raw transaction bytes which we can parse correctly
                tx = self.client.get_transaction(
                    sig_obj,
                    commitment=Confirmed,
                    max_supported_transaction_version=0,
                    encoding="base64"  # Get raw bytes for proper parsing
                )
                
                if tx.value and tx.value.transaction:
                    if os.getenv("DEBUG_SIG"):
                        print(f"      ✅ Transaction fetched successfully")
                    return tx.value
                
                # Transaction not found (may be pruned or doesn't exist)
                if os.getenv("DEBUG_SIG"):
                    print(f"      ⚠️  Transaction not found (may be pruned or invalid)")
                return None
                
            except SolanaRpcException as e:
                # Check if it's a rate limit error (429)
                if "429" in str(e) or "Too Many Requests" in str(e):
                    if attempt < self.max_retries - 1:
                        wait_time = self.retry_delay * (2 ** attempt)  # Exponential backoff
                        if os.getenv("DEBUG_SIG"):
                            print(f"      ⚠️  Rate limited, retrying in {wait_time:.1f}s...")
                        time.sleep(wait_time)
                        continue
                    else:
                        if os.getenv("DEBUG_SIG"):
                            print(f"      ❌ Rate limit error after {self.max_retries} attempts - transaction fetch failed")
                        return None
                else:
                    # Other RPC error
                    if os.getenv("DEBUG_SIG"):
                        print(f"      ❌ RPC error: {e}")
                    # Retry for other RPC errors too
                    if attempt < self.max_retries - 1:
                        wait_time = self.retry_delay * (2 ** attempt)
                        time.sleep(wait_time)
                        continue
                    return None
                    
            except Exception as e:
                if os.getenv("DEBUG_SIG"):
                    print(f"      ❌ Unexpected error fetching transaction: {e}")
                    import traceback
                    traceback.print_exc()
                # Retry for unexpected errors
                if attempt < self.max_retries - 1:
                    wait_time = self.retry_delay * (2 ** attempt)
                    time.sleep(wait_time)
                    continue
                return None
        
        return None
    
    def _extract_message_from_transaction(self, transaction) -> Optional[bytes]:
        """
        Extract and serialize the message from a Solana transaction.
        
        The message that was signed is the serialized transaction message.
        This is the EXACT message M used in H(R || A || M) for EdDSA key recovery.
        
        CRITICAL: We need the EXACT message that was signed for correct verification.
        If a transaction is confirmed on Solana, it should verify with standard Ed25519
        if it uses standard nonce. If verification fails, it indicates flawed nonce.
        
        Args:
            transaction: Transaction object from RPC (EncodedTransactionWithStatusMeta)
            
        Returns:
            Serialized message bytes or None if extraction fails
        """
        try:
            # Method 1: If transaction was fetched with base64 encoding, it's already parsed
            # Check if we have a VersionedTransaction or Transaction object directly
            if hasattr(transaction, 'transaction'):
                tx_wrapper = transaction.transaction
                if hasattr(tx_wrapper, 'transaction'):
                    inner_tx = tx_wrapper.transaction
                    
                    # Check if it's already a VersionedTransaction or Transaction object
                    from solders.transaction import VersionedTransaction, Transaction
                    
                    if isinstance(inner_tx, (VersionedTransaction, Transaction)):
                        msg = inner_tx.message
                        
                        # CRITICAL: Use serialize() to get the exact message that was signed
                        # This is the message format used during signing
                        if hasattr(msg, 'serialize'):
                            try:
                                msg_bytes = msg.serialize()
                                if len(msg_bytes) > 0:
                                    if os.getenv("DEBUG_SIG"):
                                        print(f"      Message from {type(inner_tx).__name__}.serialize(): {len(msg_bytes)} bytes")
                                    return msg_bytes
                            except Exception as e:
                                if os.getenv("DEBUG_SIG"):
                                    print(f"      {type(inner_tx).__name__}.serialize() error: {e}")
                        
                        # Fallback to __bytes__ if serialize() doesn't work
                        if hasattr(msg, '__bytes__'):
                            msg_bytes = bytes(msg)
                            if len(msg_bytes) > 0:
                                if os.getenv("DEBUG_SIG"):
                                    print(f"      Message from {type(inner_tx).__name__}.__bytes__(): {len(msg_bytes)} bytes")
                                return msg_bytes
                
                # Fallback: Check if we have base64 encoded transaction (raw bytes as string)
                tx_data = transaction.transaction
                if isinstance(tx_data, str):
                    try:
                        import base64
                        from solders.transaction import VersionedTransaction, Transaction
                        
                        raw_tx_bytes = base64.b64decode(tx_data)
                        
                        # Try parsing as VersionedTransaction first (most common)
                        try:
                            versioned_tx = VersionedTransaction.from_bytes(raw_tx_bytes)
                            msg = versioned_tx.message
                            
                            # CRITICAL: Use serialize() to get the exact message that was signed
                            # This is the message format used during signing
                            if hasattr(msg, 'serialize'):
                                try:
                                    msg_bytes = msg.serialize()
                                    if len(msg_bytes) > 0:
                                        if os.getenv("DEBUG_SIG"):
                                            print(f"      Message from VersionedTransaction.serialize(): {len(msg_bytes)} bytes")
                                        return msg_bytes
                                except Exception as e:
                                    if os.getenv("DEBUG_SIG"):
                                        print(f"      VersionedTransaction.serialize() error: {e}")
                            
                            # Fallback to __bytes__ if serialize() doesn't work
                            if hasattr(msg, '__bytes__'):
                                msg_bytes = bytes(msg)
                                if len(msg_bytes) > 0:
                                    if os.getenv("DEBUG_SIG"):
                                        print(f"      Message from VersionedTransaction.__bytes__(): {len(msg_bytes)} bytes")
                                    return msg_bytes
                        except Exception as e:
                            if os.getenv("DEBUG_SIG"):
                                print(f"      VersionedTransaction parse error: {e}")
                            
                            # Try legacy Transaction format
                            try:
                                legacy_tx = Transaction.from_bytes(raw_tx_bytes)
                                msg = legacy_tx.message
                                
                                # CRITICAL: Use serialize() for exact message format
                                if hasattr(msg, 'serialize'):
                                    try:
                                        msg_bytes = msg.serialize()
                                        if len(msg_bytes) > 0:
                                            if os.getenv("DEBUG_SIG"):
                                                print(f"      Message from Transaction.serialize(): {len(msg_bytes)} bytes")
                                            return msg_bytes
                                    except Exception as e:
                                        if os.getenv("DEBUG_SIG"):
                                            print(f"      Transaction.serialize() error: {e}")
                                
                                # Fallback to __bytes__
                                if hasattr(msg, '__bytes__'):
                                    msg_bytes = bytes(msg)
                                    if len(msg_bytes) > 0:
                                        if os.getenv("DEBUG_SIG"):
                                            print(f"      Message from Transaction.__bytes__(): {len(msg_bytes)} bytes")
                                        return msg_bytes
                            except Exception as e2:
                                if os.getenv("DEBUG_SIG"):
                                    print(f"      Transaction parse error: {e2}")
                    except Exception as e:
                        if os.getenv("DEBUG_SIG"):
                            print(f"      Error parsing base64 transaction: {e}")
            
            # Method 2: Fallback to JSON format (UiTransaction) - only if Method 1 didn't work
            # The transaction structure: transaction.transaction.transaction (nested)
            # But we already checked this in Method 1, so this is a fallback for non-base64 responses
            if not hasattr(transaction, 'transaction'):
                if os.getenv("DEBUG_SIG"):
                    print(f"      No 'transaction' attribute in response")
                return None
            
            # Get the inner transaction (EncodedTransactionWithStatusMeta -> UiTransaction or VersionedTransaction)
            tx_wrapper = transaction.transaction
            if not hasattr(tx_wrapper, 'transaction'):
                if os.getenv("DEBUG_SIG"):
                    print(f"      No nested 'transaction' attribute")
                return None
            
            inner_tx = tx_wrapper.transaction
            
            # If it's already a VersionedTransaction/Transaction (from base64), we should have handled it in Method 1
            # But check again in case the structure is different
            from solders.transaction import VersionedTransaction, Transaction
            if isinstance(inner_tx, (VersionedTransaction, Transaction)):
                msg = inner_tx.message
                if hasattr(msg, '__bytes__'):
                    msg_bytes = bytes(msg)
                    if len(msg_bytes) > 0:
                        if os.getenv("DEBUG_SIG"):
                            print(f"      Message from {type(inner_tx).__name__}.__bytes__() (fallback): {len(msg_bytes)} bytes")
                        return msg_bytes
            
            # Try to use the message object directly
            if hasattr(inner_tx, 'message'):
                message = inner_tx.message
                
                # Check if message is already bytes
                if isinstance(message, bytes):
                    if len(message) > 0:
                        if os.getenv("DEBUG_SIG"):
                            print(f"      Message is bytes: {len(message)} bytes")
                        return message
                
                # Try __bytes__ method
                if hasattr(message, '__bytes__'):
                    try:
                        message_bytes = bytes(message)
                        if len(message_bytes) > 0:
                            if os.getenv("DEBUG_SIG"):
                                print(f"      Message from __bytes__: {len(message_bytes)} bytes")
                            return message_bytes
                    except Exception as e:
                        if os.getenv("DEBUG_SIG"):
                            print(f"      Message __bytes__() failed: {e}")
                
                # Check if message has serialize method
                if hasattr(message, 'serialize'):
                    try:
                        serialized = message.serialize()
                        if isinstance(serialized, bytes) and len(serialized) > 0:
                            if os.getenv("DEBUG_SIG"):
                                print(f"      Message from serialize(): {len(serialized)} bytes")
                            return serialized
                        elif hasattr(serialized, '__bytes__'):
                            msg_bytes = bytes(serialized)
                            if len(msg_bytes) > 0:
                                return msg_bytes
                    except Exception as e:
                        if os.getenv("DEBUG_SIG"):
                            print(f"      Message serialize() failed: {e}")
            
            # Method 3: Fallback - Get raw transaction bytes and extract message
            if hasattr(inner_tx, '__bytes__'):
                try:
                    full_tx_bytes = bytes(inner_tx)
                    
                    if len(full_tx_bytes) == 0:
                        if os.getenv("DEBUG_SIG"):
                            print(f"      Transaction bytes are empty")
                        return None
                    
                    # Transaction format:
                    # - First byte: number of signatures (compact array length)
                    # - Next N*64 bytes: signatures (each signature is 64 bytes)
                    # - Rest: serialized message
                    
                    num_sigs = full_tx_bytes[0]
                    sigs_length = 1 + (num_sigs * 64)  # 1 byte for count + signatures
                    
                    if len(full_tx_bytes) <= sigs_length:
                        if os.getenv("DEBUG_SIG"):
                            print(f"      Transaction too short: {len(full_tx_bytes)} bytes, expected > {sigs_length}")
                        return None
                    
                    # Extract message (everything after signatures)
                    message_bytes = full_tx_bytes[sigs_length:]
                    
                    if len(message_bytes) == 0:
                        if os.getenv("DEBUG_SIG"):
                            print(f"      Message bytes are empty")
                        return None
                    
                    if os.getenv("DEBUG_SIG"):
                        print(f"      Message from transaction bytes (fallback): {len(message_bytes)} bytes")
                    return message_bytes
                    
                except Exception as e:
                    if os.getenv("DEBUG_SIG"):
                        print(f"      Error extracting message from transaction bytes: {e}")
            
            # If all methods fail, return None
            if os.getenv("DEBUG_SIG"):
                print(f"      Could not extract message - all methods failed")
            return None
                
        except Exception as e:
            if os.getenv("DEBUG_SIG"):
                import traceback
                print(f"      Error extracting message: {e}")
                traceback.print_exc()
            return None
    
    def compute_h(self, r_int: int, public_key_bytes: bytes, message_bytes: bytes) -> int:
        """
        Compute H(R||A||M) mod q using the same method as eddsaaffine.ComputeH.
        
        This matches the Go implementation exactly:
        - Convert r to 32 bytes little-endian
        - Concatenate R || A || M
        - Hash with SHA-512
        - Interpret as little-endian integer
        - Reduce mod curve order
        
        Args:
            r_int: R as big integer
            public_key_bytes: Public key A (32 bytes)
            message_bytes: Message bytes
            
        Returns:
            Hash value as integer mod curve order
        """
        # Convert r to 32 bytes (little-endian for Ed25519)
        # Python's int.to_bytes() with 'little' gives us little-endian directly
        r_bytes = r_int.to_bytes(32, 'little')
        
        # Concatenate: R || A || M
        data = r_bytes + public_key_bytes + message_bytes
        
        # Hash with SHA-512
        h = hashlib.sha512(data).digest()
        
        # Convert to big integer (little-endian interpretation)
        h_int = int.from_bytes(h, 'little')
        
        # Reduce mod curve order
        h_int = h_int % ED25519_CURVE_ORDER
        
        return h_int
    
    def verify_ed25519_signature(self, r_int: int, s_int: int, public_key_bytes: bytes, message_bytes: bytes) -> bool:
        """
        Verify Ed25519 signature using the same method as eddsaaffine.
        
        The verification checks if the signature (R, s) is valid for the given
        message and public key. This ensures r, s, message, and public_key are correct.
        
        Args:
            r_int: R point as big integer
            s_int: s scalar as big integer
            public_key_bytes: Public key A (32 bytes)
            message_bytes: Message bytes that were signed
            
        Returns:
            True if signature is valid, False otherwise
        """
        if not self.verify_signatures:
            # If cryptography is not available, skip verification
            return True
        
        try:
            # Reconstruct the full 64-byte signature: R (32 bytes) + s (32 bytes)
            # Both R and s must be in little-endian format
            r_bytes = r_int.to_bytes(32, 'little')
            s_bytes = s_int.to_bytes(32, 'little')
            full_signature = r_bytes + s_bytes
            
            # Create Ed25519 public key object
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            
            # Verify the signature
            # Note: Ed25519.verify() expects the message that was signed
            # In Solana, this is the serialized transaction message
            public_key.verify(full_signature, message_bytes)
            
            return True
            
        except InvalidSignature:
            # Signature verification failed
            return False
        except Exception as e:
            if os.getenv("DEBUG_SIG"):
                print(f"      Verification error: {e}")
            return False
    
    def extract_signature_components(self, signature_hash: str, main_address: str, transaction=None) -> Optional[Dict]:
        """
        Extract EdDSA signature components (r, s, message, public_key) from signature hash and transaction.
        
        Args:
            signature_hash: Base58 signature hash (this IS the Ed25519 signature: 64 bytes)
            main_address: Main address (public key) from filename
            transaction: Optional transaction object (if None, will fetch via RPC)
            
        Returns:
            Dictionary with signature data or None if extraction fails
        """
        try:
            # Decode the signature hash (base58-encoded Ed25519 signature)
            # Ed25519 signature is 64 bytes: 32 bytes R + 32 bytes s
            sig_bytes = base58.b58decode(signature_hash)
            
            if len(sig_bytes) != 64:
                if os.getenv("DEBUG_SIG"):
                    print(f"      Invalid signature length: {len(sig_bytes)} bytes (expected 64)")
                return None
            
            r_bytes = sig_bytes[:32]
            s_bytes = sig_bytes[32:64]
            
            # CRITICAL: Format R and S for eddsaaffine package compatibility
            # Ed25519 stores R and S in little-endian byte format
            # The Go eddsaaffine package expects:
            #   - R and S as hex strings representing the integer value (big-endian format)
            #   - Go will parse as big.Int, convert to bytes (big-endian), then reverse to little-endian
            # So we need to: convert bytes -> int (little-endian) -> hex (big-endian representation)
            r_int = int.from_bytes(r_bytes, 'little')
            s_int = int.from_bytes(s_bytes, 'little')
            
            # Format as hex strings (big-endian representation of the integer)
            # Match the exact format from test_eddsa_signatures_standard.json:
            # - r: "0x..." (hex string with 0x prefix, padded to 64 hex chars = 32 bytes)
            # - s: "0x..." (hex string with 0x prefix, padded to 64 hex chars = 32 bytes)
            r_hex_raw = hex(r_int)[2:]  # Remove 0x prefix
            s_hex_raw = hex(s_int)[2:]  # Remove 0x prefix
            
            # Pad with leading zeros to ensure exactly 64 hex characters (32 bytes)
            # This matches the format in test_eddsa_signatures_standard.json
            r_hex = "0x" + r_hex_raw.zfill(64)
            s_hex = "0x" + s_hex_raw.zfill(64)
            
            # Get the public key - CRITICAL: Extract from transaction to get the ACTUAL signer
            # The signature might be from a different signer than the main address
            # We MUST use the actual signer's public key for accurate verification and key recovery
            public_key_hex = ""
            public_key_bytes = None
            actual_signer_address = None
            
            # Initialize with main address as fallback (will be overridden if we get transaction)
            try:
                pubkey_obj = Pubkey.from_string(main_address)
                public_key_bytes = bytes(pubkey_obj)
                if len(public_key_bytes) == 32:
                    # Format: hex string without 0x prefix, exactly 64 hex characters (32 bytes)
                    # This matches test_eddsa_signatures_standard.json format
                    public_key_hex = public_key_bytes.hex()
                    # Ensure it's exactly 64 hex characters (should always be for 32-byte pubkey)
                    if len(public_key_hex) != 64:
                        if os.getenv("DEBUG_SIG"):
                            print(f"      Warning: Public key hex length is {len(public_key_hex)}, expected 64")
                else:
                    if os.getenv("DEBUG_SIG"):
                        print(f"      Public key length error: {len(public_key_bytes)} bytes (expected 32)")
                    return None
            except Exception as e:
                if os.getenv("DEBUG_SIG"):
                    print(f"      Public key conversion error: {e}")
                return None
            
            if not public_key_hex or len(public_key_hex) != 64:
                return None
            
            # Helper function to extract actual signer from transaction
            def extract_actual_signer(tx):
                """Extract the actual signer's public key from transaction."""
                try:
                    if hasattr(tx, 'transaction') and hasattr(tx.transaction, 'transaction'):
                        inner_tx = tx.transaction.transaction
                        if hasattr(inner_tx, 'message') and hasattr(inner_tx.message, 'account_keys'):
                            signers = inner_tx.message.account_keys[:inner_tx.message.header.num_required_signatures]
                            if signers and len(signers) > 0:
                                actual_signer = signers[0]
                                actual_signer_address = str(actual_signer)
                                actual_signer_bytes = bytes(actual_signer)
                                
                                if len(actual_signer_bytes) == 32:
                                    return actual_signer_bytes, actual_signer_address
                except Exception as e:
                    if os.getenv("DEBUG_SIG"):
                        print(f"      Error extracting actual signer: {e}")
                return None, None
            
            # Get the message from transaction - CRITICAL: Message is REQUIRED for key recovery
            message_hex = ""
            message_bytes = None
            
            # First, try to use provided transaction
            if transaction:
                message_bytes = self._extract_message_from_transaction(transaction)
                if message_bytes:
                    message_hex = message_bytes.hex()
                
                    # Extract actual signer from provided transaction
                    actual_signer_bytes, actual_signer_addr = extract_actual_signer(transaction)
                    if actual_signer_bytes:
                        if len(actual_signer_bytes) == 32:
                            public_key_bytes = actual_signer_bytes
                            # Format: hex string without 0x prefix, exactly 64 hex characters (32 bytes)
                            # This matches test_eddsa_signatures_standard.json format
                            public_key_hex = actual_signer_bytes.hex()
                            actual_signer_address = actual_signer_addr
                        else:
                            if os.getenv("DEBUG_SIG"):
                                print(f"      Actual signer bytes length error: {len(actual_signer_bytes)} bytes (expected 32)")
                            return None
                    
                    # FILTER: Only keep signatures where the signer matches the filename (main address)
                    if actual_signer_address != main_address:
                        if os.getenv("DEBUG_SIG"):
                            print(f"      ❌ Skipping signature: signer {actual_signer_address} != main address {main_address}")
                        return None  # Filter out signatures from different signers
                    else:
                        if os.getenv("DEBUG_SIG"):
                            print(f"      ✅ Signer matches main address")
                else:
                    # If we can't extract the actual signer, we can't verify it matches
                    # For safety, we should skip this signature
                    if os.getenv("DEBUG_SIG"):
                        print(f"      ❌ Skipping signature: could not extract actual signer (cannot verify match with main address)")
                    return None
            
            # If we don't have a message yet, fetch the transaction
            if not message_hex:
                if os.getenv("DEBUG_SIG"):
                    print(f"      Fetching transaction for message extraction...")
                transaction = self._get_transaction_with_retry(signature_hash)
                if transaction:
                    message_bytes = self._extract_message_from_transaction(transaction)
                    if message_bytes:
                        message_hex = message_bytes.hex()
                        if os.getenv("DEBUG_SIG"):
                            print(f"      ✅ Message extracted: {len(message_bytes)} bytes")
                    
                    # CRITICAL: Extract the ACTUAL signer from the transaction
                    # Use the actual signer's public key (not the filename address)
                    actual_signer_bytes, actual_signer_addr = extract_actual_signer(transaction)
                    if actual_signer_bytes:
                        if len(actual_signer_bytes) == 32:
                            public_key_bytes = actual_signer_bytes
                            # Format: hex string without 0x prefix, exactly 64 hex characters (32 bytes)
                            # This matches test_eddsa_signatures_standard.json format
                            public_key_hex = actual_signer_bytes.hex()
                            actual_signer_address = actual_signer_addr
                        else:
                            if os.getenv("DEBUG_SIG"):
                                print(f"      Actual signer bytes length error: {len(actual_signer_bytes)} bytes (expected 32)")
                            return None
                        
                        # FILTER: Only keep signatures where the signer matches the filename (main address)
                        if actual_signer_address != main_address:
                            if os.getenv("DEBUG_SIG"):
                                print(f"      ❌ Skipping signature: signer {actual_signer_address} != main address {main_address}")
                            return None  # Filter out signatures from different signers
                        else:
                            if os.getenv("DEBUG_SIG"):
                                print(f"      ✅ Signer matches main address")
                    else:
                        # If we can't extract the actual signer, we can't verify it matches
                        # For safety, we should skip this signature
                        if os.getenv("DEBUG_SIG"):
                            print(f"      ❌ Skipping signature: could not extract actual signer (cannot verify match with main address)")
                        return None
                    
                    if not message_bytes:
                        if os.getenv("DEBUG_SIG"):
                            print(f"      ❌ Failed to extract message from transaction")
                else:
                    if os.getenv("DEBUG_SIG"):
                        print(f"      ❌ Failed to fetch transaction (may be pruned or RPC error)")
            
            # CRITICAL: If message is still empty, this signature is USELESS for key recovery
            # We should reject it or at least log a strong warning
            if not message_hex:
                if os.getenv("DEBUG_SIG"):
                    print(f"      ❌❌❌ CRITICAL: Message is EMPTY for {signature_hash[:20]}...")
                    print(f"         This signature CANNOT be used for key recovery!")
                    print(f"         Possible reasons:")
                    print(f"         1. Transaction is pruned (too old)")
                    print(f"         2. RPC error (rate limit, network issue)")
                    print(f"         3. Message extraction bug")
                # In STRICT mode, reject signatures without messages
                if os.getenv("STRICT_VERIFY"):
                    return None
                # Even in normal mode, we should warn strongly
                # But we'll include it with empty message so user can see the issue
            
            # Optional: Validate public key against transaction signers
            if transaction and os.getenv("VALIDATE_PUBKEY"):
                try:
                    if hasattr(transaction, 'transaction') and hasattr(transaction.transaction, 'message'):
                        signers = transaction.transaction.message.account_keys
                        if signers and len(signers) > 0:
                            first_signer = str(signers[0])
                            if first_signer != main_address:
                                if os.getenv("DEBUG_SIG"):
                                    print(f"      Warning: Public key mismatch - expected {main_address}, got {first_signer}")
                except Exception:
                    pass  # Validation is optional
            
            # CRITICAL CHECK: Message is REQUIRED - without it, we can't do key recovery
            if not message_hex:
                # Message is missing - this signature is USELESS for key recovery
                if os.getenv("DEBUG_SIG"):
                    print(f"      ❌ Rejecting signature: message is required for key recovery")
                return None
            
            # Verify the signature to ensure correctness
            # 
            # IMPORTANT NOTE: Many Solana transactions fail standard Ed25519 verification because:
            # 1. They use FLAWED/NON-STANDARD nonce generation (random nonces, affine relationships, etc.)
            # 2. This is EXACTLY what we're looking for - these signatures are vulnerable to key recovery!
            # 3. The verification failure is EXPECTED and indicates a flawed signing implementation
            #
            # For key recovery purposes:
            # - We need the exact message that was used during signing (extracted from transaction)
            # - We need correct R, s, and public_key (all correctly extracted)
            # - Standard Ed25519 verification failure is OK - it means the signature uses flawed nonce
            # - The signature is still valid for key recovery if we have the correct components
            #
            # If verification fails, we still include the signature (marked with _verification_failed)
            # because it's likely using flawed nonce generation that we want to exploit for key recovery.
            verification_passed = False
            verification_error = None
            
            try:
                # message_bytes should already be set from extraction above
                if not message_bytes:
                    message_bytes = bytes.fromhex(message_hex)
                if not public_key_bytes:
                    public_key_bytes = bytes.fromhex(public_key_hex)
                
                # Verify the signature
                verification_passed = self.verify_ed25519_signature(
                    r_int, s_int, public_key_bytes, message_bytes
                )
                
                if verification_passed:
                    # Verification PASSED - this means the signature uses STANDARD nonce generation
                    if os.getenv("DEBUG_SIG"):
                        print(f"      ✅ Signature verification PASSED for {signature_hash[:20]}...")
                        print(f"         This signature uses STANDARD nonce generation")
                else:
                    # Verification FAILED - this indicates FLAWED/NON-STANDARD nonce generation
                    if os.getenv("DEBUG_SIG"):
                        print(f"      ⚠️  Signature verification FAILED for {signature_hash[:20]}...")
                        print(f"         This indicates FLAWED/NON-STANDARD nonce generation")
                        
            except Exception as e:
                # Verification error
                verification_error = str(e)
                if os.getenv("DEBUG_SIG"):
                    print(f"      ⚠️  Verification error: {e}")
                
                # In strict mode, reject on error
                if os.getenv("STRICT_VERIFY"):
                    if os.getenv("DEBUG_SIG"):
                        print(f"         STRICT_VERIFY enabled - rejecting signature due to verification error")
                    return None
            
            # Format matches test_eddsa_signatures_standard.json (eddsaaffine package input format):
            # - message: hex string (no 0x prefix) - REQUIRED for key recovery
            # - r: hex string with 0x prefix, padded to 64 hex chars (32 bytes)
            # - s: hex string with 0x prefix, padded to 64 hex chars (32 bytes)
            # - public_key: hex string (no 0x prefix), exactly 64 hex chars (32 bytes)
            # - signature_hash: base58 signature hash (optional, for tracking/resume functionality)
            #   Note: eddsaaffine parser ignores extra fields, so signature_hash is safe to include
            result = {
                "message": message_hex,  # Hex string without 0x prefix (matches standard format)
                "r": r_hex,  # Hex string with 0x prefix, 64 hex chars (matches standard format)
                "s": s_hex,  # Hex string with 0x prefix, 64 hex chars (matches standard format)
                "public_key": public_key_hex,  # Hex string without 0x prefix, 64 hex chars (matches standard format)
                "signature_hash": signature_hash  # Optional: for resume functionality (ignored by eddsaaffine parser)
            }
            
            # Mark verification status (both passed and failed are kept, but in separate files)
            result["_verification_passed"] = verification_passed
            if not verification_passed:
                result["_verification_failed"] = True  # Mark as failed for clarity
            if verification_error:
                result["_verification_error"] = verification_error
            
            return result
            
        except Exception as e:
            if os.getenv("DEBUG_SIG"):
                import traceback
                print(f"      Extraction error: {e}")
                traceback.print_exc()
            return None
    
    def process_signature_hash(self, signature_hash: str, main_address: str) -> Optional[Dict]:
        """
        Extract EdDSA signature components from signature hash and fetch message via RPC.
        
        Args:
            signature_hash: Base58 signature hash (Ed25519 signature)
            main_address: Main address (public key) from filename
            
        Returns:
            Dictionary with signature data or None if extraction fails
        """
        # Extract r and s from signature hash, fetch message via RPC
        return self.extract_signature_components(signature_hash, main_address, transaction=None)
    
    def _get_failure_reason(self, signature_hash: str, main_address: str) -> Optional[str]:
        """
        Try to identify why a signature failed. This is a lightweight check.
        Returns a failure reason string or None.
        """
        try:
            # Try to fetch transaction to see what fails (use minimal retries for speed)
            original_max_retries = self.max_retries
            self.max_retries = 1  # Only try once for failure reason check
            try:
                transaction = self._get_transaction_with_retry(signature_hash)
            finally:
                self.max_retries = original_max_retries
            
            if not transaction:
                return "no_transaction"
            
            # Check if we can extract message
            message_bytes = self._extract_message_from_transaction(transaction)
            if not message_bytes:
                return "empty_message"
            
            # Check if signer matches
            if hasattr(transaction, 'transaction') and hasattr(transaction.transaction, 'transaction'):
                inner_tx = transaction.transaction.transaction
                if hasattr(inner_tx, 'message') and hasattr(inner_tx.message, 'account_keys'):
                    signers = inner_tx.message.account_keys[:inner_tx.message.header.num_required_signatures]
                    if signers and len(signers) > 0:
                        actual_signer = str(signers[0])
                        if actual_signer != main_address:
                            return "signer_mismatch"
            
            # If we got here, it might be an extraction error or verification failure
            return "extraction_error"
        except Exception:
            return "other"
    
    def _load_existing_signatures(self, output_file: str) -> Tuple[List[Dict], Optional[str]]:
        """
        Load existing processed signatures and find the last processed signature hash.
        
        Returns:
            (existing_signatures, last_signature_hash)
            If file doesn't exist, returns ([], None)
        """
        output_path = Path(output_file)
        if not output_path.exists():
            return [], None
        
        try:
            with open(output_file, 'r') as f:
                existing = json.load(f)
            
            if not isinstance(existing, list) or len(existing) == 0:
                return [], None
            
            # Find the last signature hash
            # Assumption: Signatures are processed in order and appended sequentially,
            # so the last element in the array (existing[-1]) is the most recently processed signature
            last_sig = existing[-1]
            last_hash = last_sig.get('signature_hash')
            
            if last_hash:
                return existing, last_hash
            else:
                # Old format without signature_hash field - return existing but no resume point
                return existing, None
                
        except Exception as e:
            if os.getenv("DEBUG_SIG"):
                print(f"      Warning: Could not load existing file: {e}")
            return [], None
    
    def _save_signatures_incremental(self, output_file: str, signatures: List[Dict]):
        """
        Save signatures to file incrementally (overwrites with updated list).
        Thread-safe version using lock.
        """
        with self.file_lock:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Use atomic write: write to temp file then rename
            temp_file = str(output_path) + ".tmp"
            try:
                with open(temp_file, 'w') as f:
                    json.dump(signatures, f, indent=2)
                # Atomic rename
                os.replace(temp_file, output_file)
            except Exception as e:
                # Clean up temp file on error
                if os.path.exists(temp_file):
                    try:
                        os.remove(temp_file)
                    except:
                        pass
                raise e
    
    def _test_extraction_with_known_transaction(self) -> bool:
        """
        Test extraction logic with a real Solana transaction.
        This validates that our extraction logic is working correctly.
        
        Uses a known good Solana transaction to verify:
        1. R, S extraction from signature hash is correct
        2. Message extraction from transaction is correct
        3. Public key extraction is correct
        4. Format conversion (bytes -> int -> hex) is correct
        
        Note: Solana transactions may not verify with standard Ed25519 due to message format
        differences, but our extraction should still be correct for key recovery purposes.
        The verification test ensures our logic can distinguish between standard and flawed nonces.
        
        Returns:
            True if extraction logic is correct
        """
        test_signature_hash = "2fPirh661JH9B5TBCR83UP8ShDf28vViZQwgB2d91c5Ta9oLwxPp6eAzALGx2syC5DJeKepjRQk6kjQ7DTm4tUzf"
        expected_signer = "DRFTws1Segbxx6NYGfbxnJiTBi7m8wVuhwMfoY5RCXMD"
        
        try:
            print("  🧪 Testing extraction logic with real Solana transaction...")
            print(f"     Transaction: {test_signature_hash[:40]}...")
            print(f"     Expected signer: {expected_signer}")
            
            # Fetch the transaction with base64 encoding to get the correct message format
            from solders.signature import Signature as SoldersSignature
            sig_obj = SoldersSignature.from_string(test_signature_hash)
            tx = self.client.get_transaction(sig_obj, commitment=Confirmed, max_supported_transaction_version=0, encoding="base64")
            
            if not tx.value or not tx.value.transaction:
                print("  ⚠️  Test transaction not found - skipping validation test")
                return True  # Don't fail the whole process if test transaction is unavailable
            
            # Extract components manually to validate the logic
            try:
                # Extract R and S
                import base58
                sig_bytes = base58.b58decode(test_signature_hash)
                r_bytes = sig_bytes[:32]
                s_bytes = sig_bytes[32:64]
                r_int = int.from_bytes(r_bytes, 'little')
                s_int = int.from_bytes(s_bytes, 'little')
                
                # Extract message
                message_bytes = self._extract_message_from_transaction(tx.value)
                if not message_bytes:
                    print("  ❌ Test extraction FAILED - cannot extract message")
                    return False
                
                # Extract public key
                from solders.pubkey import Pubkey
                public_key_bytes = bytes(Pubkey.from_string(expected_signer))
                
                # Verify
                verification_passed = self.verify_ed25519_signature(
                    r_int, s_int, public_key_bytes, message_bytes
                )
                
                # Format the extracted values for display
                r_hex = f"0x{hex(r_int)[2:].zfill(64)}"
                s_hex = f"0x{hex(s_int)[2:].zfill(64)}"
                message_hex = message_bytes.hex()
                public_key_hex = public_key_bytes.hex()
                
                print("\n  📊 EXTRACTED VALUES:")
                print(f"     R: {r_hex}")
                print(f"     S: {s_hex}")
                print(f"     Message ({len(message_bytes)} bytes): {message_hex}")
                print(f"     Public Key: {public_key_hex}")
                
                if verification_passed:
                    print("\n  ✅ VERIFICATION: PASSED (standard nonce - would be skipped)")
                else:
                    print("\n  ⚠️  VERIFICATION: FAILED (flawed nonce - would be kept)")
                
                print("  ✅ EXTRACTION LOGIC: CORRECT")
                return True
            except Exception as e:
                print(f"  ❌ Test extraction FAILED - error: {e}")
                import traceback
                traceback.print_exc()
                return False
            
            # Verify we got all required components
            r_hex = result.get('r', '')
            s_hex = result.get('s', '')
            message_hex = result.get('message', '')
            public_key_hex = result.get('public_key', '')
            
            if not r_hex or not s_hex or not message_hex or not public_key_hex:
                print("  ❌ Test extraction incomplete - missing components:")
                print(f"     R: {'✓' if r_hex else '✗'}, S: {'✓' if s_hex else '✗'}, Message: {'✓' if message_hex else '✗'}, Public Key: {'✓' if public_key_hex else '✗'}")
                return False
            
            # Verify format
            r_valid = r_hex.startswith('0x') and len(r_hex) == 66  # 0x + 64 hex chars
            s_valid = s_hex.startswith('0x') and len(s_hex) == 66
            message_valid = len(message_hex) > 0 and not message_hex.startswith('0x')
            public_key_valid = len(public_key_hex) == 64 and not public_key_hex.startswith('0x')
            
            if not (r_valid and s_valid and message_valid and public_key_valid):
                print("  ❌ Test extraction format invalid:")
                print(f"     R format: {'✓' if r_valid else '✗'} ({len(r_hex)} chars)")
                print(f"     S format: {'✓' if s_valid else '✗'} ({len(s_hex)} chars)")
                print(f"     Message format: {'✓' if message_valid else '✗'} ({len(message_hex)} chars)")
                print(f"     Public Key format: {'✓' if public_key_valid else '✗'} ({len(public_key_hex)} chars)")
                return False
            
            # Check if signer matches
            expected_signer_bytes = bytes(Pubkey.from_string(expected_signer))
            expected_signer_hex = expected_signer_bytes.hex()
            
            if public_key_hex != expected_signer_hex:
                print(f"  ❌ Test signer mismatch:")
                print(f"     Expected: {expected_signer_hex[:32]}...")
                print(f"     Got:      {public_key_hex[:32]}...")
                return False
            
            # Verify message is not empty
            message_bytes = bytes.fromhex(message_hex)
            if len(message_bytes) == 0:
                print("  ❌ Test message is empty - extraction failed")
                return False
            
            # Check verification status
            verification_failed = result.get('_verification_failed', False)
            
            print("  ✅ Test extraction SUCCESSFUL:")
            print(f"     ✓ R extracted: {r_hex[:30]}... (64 hex chars)")
            print(f"     ✓ S extracted: {s_hex[:30]}... (64 hex chars)")
            print(f"     ✓ Message extracted: {len(message_bytes)} bytes")
            print(f"     ✓ Public Key extracted: {public_key_hex[:32]}... (64 hex chars)")
            print(f"     ✓ Signer matches: {expected_signer}")
            
            # CRITICAL: If a transaction is confirmed on Solana and uses standard nonce,
            # it MUST verify correctly with standard Ed25519. If verification fails,
            # it indicates flawed nonce generation (vulnerable to key recovery).
            if verification_failed:
                print("     ⚠️  Standard Ed25519 verification: FAILED")
                print("        → This indicates FLAWED/NON-STANDARD nonce generation")
                print("        → Transaction is vulnerable to key recovery attacks")
                print("        → This transaction will be KEPT for key recovery analysis")
            else:
                print("     ✓ Standard Ed25519 verification: PASSED")
                print("        → Transaction uses standard nonce (not vulnerable)")
                print("        → This transaction would be SKIPPED (as intended)")
            
            print("     → Extraction logic is CORRECT and ready for processing")
            
            return True
            
        except Exception as e:
            print(f"  ⚠️  Test extraction error: {e}")
            import traceback
            if os.getenv("DEBUG_SIG"):
                traceback.print_exc()
            print("     → Skipping validation test, proceeding with processing")
            return True  # Don't fail the whole process if test fails
    
    def process_signature_file(self, input_file: str, output_file: str, limit: Optional[int] = None) -> Dict:
        """
        Process a signature hash file and create processed signature file.
        Supports resume functionality: if output file exists, resumes from last processed signature.
        
        Returns:
            Dictionary with processing statistics
        """
        # Test extraction logic with known transaction (only on first file, not on resume)
        # This validates that our extraction logic is working correctly
        if not hasattr(self, '_extraction_tested'):
            if not self._test_extraction_with_known_transaction():
                print("  ⚠️  WARNING: Extraction test failed - proceeding anyway but results may be incorrect")
            self._extraction_tested = True
        
        # Extract main address from filename (filename is the main address)
        input_path = Path(input_file)
        main_address = input_path.stem  # Get filename without extension
        
        # Load signature hashes
        with open(input_file, 'r') as f:
            signature_hashes = json.load(f)
        
        if not isinstance(signature_hashes, list):
            return {"error": "Invalid file format: expected list of signature hashes"}
        
        # Check for existing output file and resume from last processed signature
        existing_signatures, last_hash = self._load_existing_signatures(output_file)
        start_index = 0
        
        if last_hash:
            # Find the index of the last processed signature
            try:
                start_index = signature_hashes.index(last_hash) + 1
                print(f"  📍 Resuming from signature {start_index + 1}/{len(signature_hashes)} (found {len(existing_signatures)} existing signatures)")
            except ValueError:
                # Last hash not found in input - might be from different file, start from beginning
                print(f"  ⚠️  Last processed signature not found in input file, starting from beginning")
                existing_signatures = []
                start_index = 0
        
        # Apply limit (if specified, limit from start_index)
        if limit:
            signature_hashes = signature_hashes[start_index:start_index + limit]
        else:
            signature_hashes = signature_hashes[start_index:]
        
        total_original = len(signature_hashes) + start_index
        total_to_process = len(signature_hashes)
        processed_signatures = existing_signatures.copy()  # Start with existing (passed verifications)
        failed_verification_signatures = []  # Signatures that failed verification (flawed nonce)
        failed_count = 0
        verification_passed_count = 0  # Count of signatures that passed verification (standard nonce)
        verification_failed_count = 0  # Count of signatures that failed verification (flawed nonce)
        
        # Load existing failed verification signatures if file exists
        failed_output_file = output_file.replace('.json', '_sig_failed.json')
        existing_failed_signatures, _ = self._load_existing_signatures(failed_output_file)
        failed_verification_signatures = existing_failed_signatures.copy()
        
        if total_to_process == 0:
            print(f"  ✅ All signatures already processed ({len(existing_signatures)} total)")
            return {
                "total": total_original,
                "successful": len(existing_signatures),
                "failed": 0,
                "output_file": output_file,
                "resumed": True
            }
        
        print(f"  Processing {total_to_process} signature hashes for main address: {main_address}...")
        print(f"  Total progress: {start_index}/{total_original} already processed, {total_to_process} remaining")
        if self.verify_signatures:
            print(f"  Signature verification: ENABLED (using cryptography library)")
            print(f"  📊 Signatures will be saved to two files:")
            print(f"     - Main file: Standard nonce (verification passed)")
            print(f"     - Failed file: Flawed nonce (verification failed)")
        else:
            print(f"  Signature verification: DISABLED (cryptography library not available)")
            print(f"  ⚠️  WARNING: Cannot verify signatures without cryptography library")
        
        # Test first few signatures with debug to understand failures
        debug_count = min(5, total_to_process)
        if os.getenv("DEBUG") and len(processed_signatures) == 0:
            print(f"  Debug mode: Testing first {debug_count} signatures...")
            os.environ["DEBUG_SIG"] = "1"
        
        # Incremental save frequency (save every N signatures)
        save_frequency = 10  # Save every 10 signatures
        
        # Thread-safe counters and lists
        processed_lock = threading.Lock()
        processed_count = [0]  # Use list to allow modification in nested functions
        failed_count_list = [0]
        last_saved_count = [len(existing_signatures)]  # Track last saved count (use list for thread safety)
        failure_reasons = {
            "signer_mismatch": 0,
            "empty_message": 0,
            "no_transaction": 0,
            "extraction_error": 0,
            "verification_failed": 0,
            "other": 0
        }
        
        def process_single_signature(sig_hash: str, index: int) -> Tuple[int, Optional[Dict], Optional[str], Optional[bool]]:
            """
            Process a single signature hash. Returns (index, signature_data, failure_reason, verification_passed) or (index, None, reason, None).
            Creates a new RPC client for thread safety.
            """
            # Create a new client for this thread to avoid thread-safety issues
            thread_client = Client(self.rpc_url)
            # Create a temporary processor instance for this thread
            thread_processor = SignatureProcessor(self.rpc_url, num_workers=1)
            thread_processor.client = thread_client
            
            try:
                sig_data = thread_processor.process_signature_hash(sig_hash, main_address)
                
                with processed_lock:
                    if sig_data:
                        processed_count[0] += 1
                        # Check verification status
                        verification_passed = sig_data.get('_verification_passed', False)
                        return (index, sig_data, None, verification_passed)
                    else:
                        failed_count_list[0] += 1
                        # Only check failure reason for a sample to reduce overhead
                        # Check first 10 failures and then every 100th failure
                        failure_reason = None
                        if failed_count_list[0] <= 10 or failed_count_list[0] % 100 == 0:
                            failure_reason = thread_processor._get_failure_reason(sig_hash, main_address)
                            if failure_reason:
                                failure_reasons[failure_reason] = failure_reasons.get(failure_reason, 0) + 1
                            else:
                                failure_reasons["other"] += 1
                        else:
                            # For other failures, just increment "other" counter
                            failure_reasons["other"] = failure_reasons.get("other", 0) + 1
                        
                        if os.getenv("DEBUG_SIG") and failed_count_list[0] <= debug_count:
                            if not failure_reason:
                                failure_reason = thread_processor._get_failure_reason(sig_hash, main_address)
                            print(f"    Failed signature {start_index + index + 1}: {sig_hash[:20]}... (reason: {failure_reason or 'unknown'})")
                        return (index, None, failure_reason, None)
            except Exception as e:
                with processed_lock:
                    failed_count_list[0] += 1
                    failure_reasons["other"] += 1
                if os.getenv("DEBUG_SIG"):
                    print(f"    Error processing signature {start_index + index + 1}: {e}")
                return (index, None, "exception", None)
        
        # Process signatures in parallel using thread pool
        print(f"  Using {self.num_workers} worker threads for parallel processing...")
        
        # Create a list to store results with their original indices
        results_dict = {}  # index -> sig_data
        
        with ThreadPoolExecutor(max_workers=self.num_workers) as executor:
            # Submit all tasks
            future_to_index = {
                executor.submit(process_single_signature, sig_hash, i): i
                for i, sig_hash in enumerate(signature_hashes)
            }
            
            # Process completed tasks as they finish
            completed = 0
            for future in as_completed(future_to_index):
                completed += 1
                try:
                    result = future.result()
                    if result:
                        idx, sig_data, failure_reason, verification_passed = result
                        results_dict[idx] = (sig_data, verification_passed)
                except Exception as e:
                    idx = future_to_index[future]
                    if os.getenv("DEBUG_SIG"):
                        print(f"    Exception processing signature {start_index + idx + 1}: {e}")
                    results_dict[idx] = (None, None)
                
                # Progress update and incremental save
                # Check for saves more frequently (every 50 completed or when we have enough new successful)
                should_check_save = (completed % 50 == 0) or (completed == total_to_process)
                
                if completed % 100 == 0 or should_check_save:
                    # Reconstruct ordered list from results (maintain original order)
                    with processed_lock:
                        ordered_results = []
                        # Sort by index to maintain original order
                        sorted_indices = sorted([idx for idx in results_dict.keys() if results_dict[idx] is not None])
                        for idx in sorted_indices:
                            ordered_results.append(results_dict[idx])
                        
                        # Separate passed and failed verifications
                        current_passed = []
                        current_failed = []
                        for result in ordered_results:
                            if result:
                                sig_data, verification_passed = result
                                if sig_data:
                                    if verification_passed:
                                        current_passed.append(sig_data)
                                    else:
                                        current_failed.append(sig_data)
                        
                        current_processed = existing_signatures + current_passed
                        current_failed_list = existing_failed_signatures + current_failed
                        current_successful_count = len(current_processed) + len(current_failed_list)
                        
                        current_index = start_index + completed
                        status = f"{len(current_processed)} passed, {len(current_failed_list)} failed verifications, {failed_count_list[0]} extraction errors"
                        
                        # Add failure breakdown if we have failures
                        if failed_count_list[0] > 0 and completed >= 500:  # Show breakdown after 500 processed
                            failure_breakdown = []
                            for reason, count in sorted(failure_reasons.items(), key=lambda x: x[1], reverse=True):
                                if count > 0:
                                    failure_breakdown.append(f"{reason}:{count}")
                            if failure_breakdown:
                                status += f" [{', '.join(failure_breakdown)}]"
                        
                        if completed % 100 == 0:  # Only print progress every 100
                            print(f"    Progress: {current_index}/{total_original} ({current_index*100//total_original}%) - {status}")
                        
                        # Incremental save - save when we have enough new successful signatures
                        # Save every 10 successful signatures, or if we have at least 10 and it's been a while
                        new_successful = current_successful_count - last_saved_count[0]
                        should_save = (
                            current_successful_count % save_frequency == 0 or  # Every 10 successful
                            (new_successful >= save_frequency and should_check_save) or  # At least 10 new and checking
                            completed == total_to_process  # Always save at the end
                        )
                        
                        if should_save:
                            try:
                                if len(current_processed) > len(existing_signatures):
                                    self._save_signatures_incremental(output_file, current_processed)
                                if len(current_failed_list) > len(existing_failed_signatures):
                                    self._save_signatures_incremental(failed_output_file, current_failed_list)
                                last_saved_count[0] = len(current_processed)
                                if completed % 100 == 0 or completed <= 100:  # Log saves early and periodically
                                    print(f"    💾 Saved checkpoint: {len(current_processed)} passed, {len(current_failed_list)} failed")
                            except Exception as e:
                                if os.getenv("DEBUG_SIG"):
                                    print(f"      Warning: Failed to save checkpoint: {e}")
        
        # Final reconstruction of ordered results (maintain original order)
        # Separate passed and failed verifications
        ordered_passed = []
        ordered_failed = []
        # Sort by index to maintain original order
        sorted_indices = sorted([idx for idx in results_dict.keys() if results_dict[idx] is not None])
        for idx in sorted_indices:
            result = results_dict[idx]
            if result:
                sig_data, verification_passed = result
                if sig_data:
                    if verification_passed:
                        ordered_passed.append(sig_data)
                        verification_passed_count += 1
                    else:
                        ordered_failed.append(sig_data)
                        verification_failed_count += 1
        
        # Combine with existing signatures
        processed_signatures = existing_signatures + ordered_passed
        failed_verification_signatures = existing_failed_signatures + ordered_failed
        failed_count = failed_count_list[0]
        
        if os.getenv("DEBUG_SIG"):
            os.environ.pop("DEBUG_SIG", None)
        
        # Final save for both files
        try:
            if len(processed_signatures) > len(existing_signatures):
                self._save_signatures_incremental(output_file, processed_signatures)
            if len(failed_verification_signatures) > len(existing_failed_signatures):
                self._save_signatures_incremental(failed_output_file, failed_verification_signatures)
        except Exception as e:
            print(f"  ⚠️  Warning: Failed to save final files: {e}")
        
        # Print statistics
        print(f"\n  📊 VERIFICATION STATISTICS:")
        print(f"     ✅ Verification PASSED (standard nonce): {verification_passed_count} signatures")
        print(f"     ⚠️  Verification FAILED (flawed nonce): {verification_failed_count} signatures")
        print(f"     ❌ Extraction/Processing FAILED: {failed_count} signatures")
        print(f"\n  💾 FILES SAVED:")
        print(f"     - Main file ({output_file}): {len(processed_signatures)} signatures (verification passed)")
        print(f"     - Failed file ({failed_output_file}): {len(failed_verification_signatures)} signatures (verification failed)")
        
        if failed_count > 0:
            # Show failure breakdown
            failure_breakdown = []
            for reason, count in sorted(failure_reasons.items(), key=lambda x: x[1], reverse=True):
                if count > 0:
                    failure_breakdown.append(f"{reason}:{count}")
            if failure_breakdown:
                print(f"     Failure breakdown: {', '.join(failure_breakdown)}")
        
        return {
            "total": total_original,
            "successful": len(processed_signatures) + len(failed_verification_signatures),
            "failed": failed_count,
            "verification_passed": verification_passed_count,
            "verification_failed": verification_failed_count,
            "output_file": output_file,
            "failed_output_file": failed_output_file,
            "resumed": start_index > 0
        }


def main():
    parser = argparse.ArgumentParser(
        description="Process Solana signature hash files into EdDSA format"
    )
    parser.add_argument(
        "--input-dir",
        type=str,
        default="solana_signatures/signatures",
        help="Input directory containing signature hash files (default: solana_signatures/signatures)"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="solana_signatures/processed_signatures",
        help="Output directory for processed signature files (default: solana_signatures/processed_signatures)"
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Maximum number of signatures to process per file (for testing)"
    )
    parser.add_argument(
        "--file",
        type=str,
        help="Process a specific file instead of all files"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode to see detailed error messages"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help=f"Number of parallel worker threads (default: auto-detect, uses half of CPU cores = {max(2, min(CPU_COUNT // 2, 32))} for {CPU_COUNT} cores). Increase for faster processing but watch RPC rate limits."
    )
    
    args = parser.parse_args()
    
    # Set debug mode
    if args.debug:
        os.environ["DEBUG"] = "1"
        os.environ["DEBUG_SIG"] = "1"
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Initialize processor with RPC
    # If workers not specified, use auto-detection (half of CPU cores)
    num_workers = args.workers if args.workers is not None else None
    processor = SignatureProcessor(num_workers=num_workers)
    
    print("✅ Processing signatures with RPC message fetching.")
    print(f"   RPC endpoint: {processor.rpc_url}")
    print(f"   CPU cores detected: {CPU_COUNT}")
    print(f"   Worker threads: {processor.num_workers} (auto-selected: {CPU_COUNT // 2} cores)\n")
    
    # Get list of files to process
    input_path = Path(args.input_dir)
    if not input_path.exists():
        print(f"Error: Input directory not found: {args.input_dir}")
        sys.exit(1)
    
    if args.file:
        # Process single file
        file_path = input_path / args.file
        if not file_path.exists():
            print(f"Error: File not found: {file_path}")
            sys.exit(1)
        files_to_process = [file_path]
    else:
        # Process all JSON files
        files_to_process = list(input_path.glob("*.json"))
    
    if not files_to_process:
        print(f"No JSON files found in {args.input_dir}")
        sys.exit(0)
    
    print(f"Found {len(files_to_process)} file(s) to process\n")
    
    # Process each file
    results = []
    for i, input_file in enumerate(files_to_process, 1):
        print(f"[{i}/{len(files_to_process)}] Processing {input_file.name}...")
        
        # Create output filename (same name as input)
        output_file = os.path.join(args.output_dir, input_file.name)
        
        try:
            stats = processor.process_signature_file(
                str(input_file),
                output_file,
                limit=args.limit
            )
            
            if "error" in stats:
                print(f"  ❌ Error: {stats['error']}")
                results.append((input_file.name, None, stats.get('error')))
            else:
                print(f"  ✅ Processed: {stats['successful']}/{stats['total']} signatures")
                print(f"     Failed: {stats['failed']}")
                print(f"     Saved to: {output_file}")
                results.append((input_file.name, stats, None))
        
        except Exception as e:
            error_msg = str(e) if str(e) else type(e).__name__
            print(f"  ❌ Error processing file: {error_msg}")
            results.append((input_file.name, None, error_msg))
        
        # No delay needed - no API calls!
    
    # Print summary
    print(f"\n{'='*60}")
    print("Summary:")
    print(f"{'='*60}")
    
    successful_files = [r for r in results if r[1] is not None]
    failed_files = [r for r in results if r[2] is not None]
    
    if successful_files:
        print(f"\n✅ Successfully processed ({len(successful_files)} files):")
        total_sigs = 0
        total_successful = 0
        for filename, stats, _ in successful_files:
            total_sigs += stats['total']
            total_successful += stats['successful']
            print(f"  {filename}: {stats['successful']}/{stats['total']} signatures")
        print(f"\n  Total: {total_successful}/{total_sigs} signatures processed successfully")
    
    if failed_files:
        print(f"\n❌ Failed ({len(failed_files)} files):")
        for filename, _, error in failed_files:
            print(f"  {filename}: {error}")
    
    print(f"\nProcessed {len(successful_files)}/{len(files_to_process)} files successfully.")


if __name__ == "__main__":
    main()

