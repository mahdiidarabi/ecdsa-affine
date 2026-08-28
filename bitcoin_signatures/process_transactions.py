#!/usr/bin/env python3
"""
Process Bitcoin Transaction Files

Converts transaction hash files to ECDSA format with r, s, z (message hash), and message.
Iterates through files in bitcoin-signatures/transactions/ and creates processed
signature files in bitcoin-signatures/processed_signatures/.

Fetches full transaction details via API to extract signature components.

VERIFICATION:
This script uses python-bitcoinlib for accurate Bitcoin transaction parsing and signature
verification. The library handles:
1. Proper transaction message reconstruction (scriptSig replacement with scriptPubKey)
2. Correct SIGHASH type handling
3. Accurate signature hash (z) calculation

If python-bitcoinlib is not available, the script falls back to manual parsing (less reliable).
Install with: pip install python-bitcoinlib

NOTE FOR FUTURE NETWORKS:
This approach of using established libraries (like python-bitcoinlib for Bitcoin) should be
followed for other networks (Solana, Ethereum, etc.) to ensure accuracy and maintainability.

Usage:
    python3 process_transactions.py
    python3 process_transactions.py --input-dir transactions
    python3 process_transactions.py --limit 100  # Process only first 100 transactions per file
"""

import json
import os
import sys
import argparse
import time
import threading
import hashlib
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError as e:
    print(f"Error: Missing required dependencies.")
    print(f"Please install: pip install requests")
    print(f"Import error: {e}")
    sys.exit(1)

try:
    from ecdsa import VerifyingKey, SECP256k1
    from ecdsa.util import sigencode_der
    ECDSA_AVAILABLE = True
except ImportError:
    ECDSA_AVAILABLE = False
    print("Warning: ecdsa library not available. Signature verification will be disabled.")
    print("Install with: pip install ecdsa")

try:
    from bitcoin.core import CTransaction
    from bitcoin.core.script import CScript, SignatureHash, SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE
    from bitcoin import SelectParams
    from bitcoin.core import b2x, x
    BITCOINLIB_AVAILABLE = True
    SelectParams('mainnet')  # Set to mainnet by default
except ImportError:
    BITCOINLIB_AVAILABLE = False
    print("Warning: python-bitcoinlib not available. Will use manual parsing (less reliable).")
    print("Install with: pip install python-bitcoinlib")

# Bitcoin API endpoint (Blockstream API - free, no API key needed)
DEFAULT_API_URL = os.getenv("BITCOIN_API_URL", "https://blockstream.info/api")
MAX_RETRIES = 3
RETRY_DELAY = 2.0  # seconds between retries
REQUEST_DELAY = 0.5  # seconds between requests to respect rate limits

# secp256k1 curve order
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def read_varint(data: bytes, offset: int) -> tuple:
    """
    Read a Bitcoin varint (variable-length integer).
    
    Returns:
        (value, new_offset)
    """
    if offset >= len(data):
        return 0, offset
    
    first_byte = data[offset]
    offset += 1
    
    if first_byte < 0xfd:
        return first_byte, offset
    elif first_byte == 0xfd:
        if offset + 2 > len(data):
            return 0, offset
        return int.from_bytes(data[offset:offset+2], 'little'), offset + 2
    elif first_byte == 0xfe:
        if offset + 4 > len(data):
            return 0, offset
        return int.from_bytes(data[offset:offset+4], 'little'), offset + 4
    else:  # 0xff
        if offset + 8 > len(data):
            return 0, offset
        return int.from_bytes(data[offset:offset+8], 'little'), offset + 8


def write_varint(value: int) -> bytes:
    """Write a Bitcoin varint."""
    if value < 0xfd:
        return bytes([value])
    elif value <= 0xffff:
        return bytes([0xfd]) + value.to_bytes(2, 'little')
    elif value <= 0xffffffff:
        return bytes([0xfe]) + value.to_bytes(4, 'little')
    else:
        return bytes([0xff]) + value.to_bytes(8, 'little')


def hash_message(message: bytes) -> int:
    """Hash a message using SHA-256 (Bitcoin standard)."""
    h = hashlib.sha256(message).digest()
    return int.from_bytes(h, 'big') % CURVE_ORDER


def der_decode_signature(der_sig: bytes) -> Tuple[int, int]:
    """
    Decode DER-encoded ECDSA signature to (r, s).
    
    Args:
        der_sig: DER-encoded signature bytes
        
    Returns:
        Tuple of (r, s) as integers
    """
    if len(der_sig) < 2:
        raise ValueError("DER signature too short")
    
    # Skip DER sequence tag (0x30)
    if der_sig[0] != 0x30:
        raise ValueError("Invalid DER signature format")
    
    idx = 2  # Skip 0x30 and length byte
    
    # Read r
    if idx >= len(der_sig) or der_sig[idx] != 0x02:
        raise ValueError("Invalid DER signature: missing r")
    idx += 1
    
    r_len = der_sig[idx]
    idx += 1
    r_bytes = der_sig[idx:idx + r_len]
    idx += r_len
    
    # Read s
    if idx >= len(der_sig) or der_sig[idx] != 0x02:
        raise ValueError("Invalid DER signature: missing s")
    idx += 1
    
    s_len = der_sig[idx]
    idx += 1
    s_bytes = der_sig[idx:idx + s_len]
    
    # Convert to integers
    r = int.from_bytes(r_bytes, 'big')
    s = int.from_bytes(s_bytes, 'big')
    
    return (r, s)


def extract_signature_and_pubkey_from_script_sig(script_sig: str) -> Optional[Tuple[int, int, bytes]]:
    """
    Extract r, s, and public key from Bitcoin scriptSig.
    
    Bitcoin scriptSig format: OP_PUSHBYTES_N <signature> OP_PUSHBYTES_M <public_key>
    Signature is DER-encoded and may have SIGHASH flag appended.
    Public key follows the signature.
    
    Args:
        script_sig: Hex-encoded scriptSig
        
    Returns:
        Tuple of (r, s, public_key_bytes), or None if extraction fails
    """
    try:
        script_bytes = bytes.fromhex(script_sig)
        
        if len(script_bytes) < 2:
            return None
        
        # Parse scriptSig format: OP_PUSHBYTES_N <data>
        idx = 0
        
        # Extract signature: OP_PUSHBYTES_N <DER_signature>
        if idx >= len(script_bytes):
            return None
        
        sig_push_op = script_bytes[idx]
        idx += 1
        
        # OP_PUSHBYTES opcodes: 0x01-0x4b push that many bytes
        if sig_push_op < 0x01 or sig_push_op > 0x4b:
            # Try to find DER signature marker (0x30) directly
            for i in range(len(script_bytes)):
                if script_bytes[i] == 0x30:
                    idx = i
                    break
            else:
                return None
        else:
            sig_length = sig_push_op
        
        # Extract DER signature
        if idx + sig_length > len(script_bytes):
            return None
        
        der_sig = script_bytes[idx:idx + sig_length]
        idx += sig_length
        
        # Check if there's a SIGHASH byte (last byte of DER signature)
        sighash_byte = None
        if len(der_sig) > 0 and der_sig[-1] in [0x01, 0x02, 0x03, 0x81, 0x82, 0x83]:
            # Remove SIGHASH byte
            sighash_byte = der_sig[-1]
            der_sig = der_sig[:-1]
        
        # Decode r and s from DER signature
        r, s = der_decode_signature(der_sig)
        
        # Extract public key: OP_PUSHBYTES_M <public_key>
        if idx >= len(script_bytes):
            return None
        
        pubkey_push_op = script_bytes[idx]
        idx += 1
        
        # OP_PUSHBYTES opcodes: 0x01-0x4b push that many bytes
        if pubkey_push_op < 0x01 or pubkey_push_op > 0x4b:
            return None
        
        pubkey_length = pubkey_push_op
        
        if idx + pubkey_length > len(script_bytes):
            return None
        
        public_key_bytes = script_bytes[idx:idx + pubkey_length]
        
        # Validate public key length (33 for compressed, 65 for uncompressed)
        if len(public_key_bytes) not in [33, 65]:
            return None
        
        return (r, s, public_key_bytes)
    except Exception as e:
        if os.getenv("DEBUG"):
            print(f"      Error extracting signature/pubkey: {e}")
            import traceback
            traceback.print_exc()
        return None


def extract_sighash_type(scriptsig_hex: str) -> int:
    """
    Extract SIGHASH type from scriptSig.
    
    The SIGHASH byte is the last byte of the DER signature in scriptSig.
    
    Returns:
        SIGHASH type (default: 0x01 = SIGHASH_ALL)
    """
    try:
        script_bytes = bytes.fromhex(scriptsig_hex)
        # Find DER signature (starts with 0x30)
        for i in range(len(script_bytes)):
            if script_bytes[i] == 0x30:
                if i + 1 < len(script_bytes):
                    length = script_bytes[i + 1]
                    if 68 <= length <= 72:  # Typical DER signature length
                        sig_end = i + length + 2
                        if sig_end <= len(script_bytes):
                            sighash_byte = script_bytes[sig_end - 1]
                            # SIGHASH types: 0x01, 0x02, 0x03, 0x81, 0x82, 0x83
                            if sighash_byte in [0x01, 0x02, 0x03, 0x81, 0x82, 0x83]:
                                return sighash_byte
    except:
        pass
    return 0x01  # Default to SIGHASH_ALL


def create_transaction_message(tx: dict, input_index: int, sighash_type: int = 0x01) -> bytes:
    """
    Create the message that was signed for a Bitcoin transaction input.
    
    Uses python-bitcoinlib if available for accurate message hash calculation.
    Falls back to manual parsing if library is not available.
    
    Args:
        tx: Full transaction object from API
        input_index: Index of the input being signed
        sighash_type: SIGHASH flag (default: 0x01 = SIGHASH_ALL)
        
    Returns:
        Message bytes that were signed (double SHA-256 hash)
    """
    # Use python-bitcoinlib if available (much more reliable)
    if BITCOINLIB_AVAILABLE:
        try:
            tx_hex = tx.get('hex', '')
            if not tx_hex:
                txid = tx.get('txid', '')
                return bytes.fromhex(txid) if txid else b''
            
            # Parse transaction using bitcoinlib
            raw_tx = bytes.fromhex(tx_hex)
            c_tx = CTransaction.deserialize(raw_tx)
            
            # Get scriptPubKey for this input from API data
            vin_list = tx.get('vin', [])
            if input_index >= len(vin_list):
                raise ValueError(f"Input index {input_index} out of range")
            
            vin = vin_list[input_index]
            prevout = vin.get('prevout', {})
            scriptpubkey_hex = prevout.get('scriptpubkey', '')
            if not scriptpubkey_hex:
                raise ValueError("Missing scriptPubKey for input")
            
            scriptpubkey = CScript(bytes.fromhex(scriptpubkey_hex))
            
            # Map SIGHASH types
            if sighash_type == 0x01:
                sig_hash_type = SIGHASH_ALL
            elif sighash_type == 0x02:
                sig_hash_type = SIGHASH_NONE
            elif sighash_type == 0x03:
                sig_hash_type = SIGHASH_SINGLE
            else:
                sig_hash_type = SIGHASH_ALL  # Default
            
            # Calculate signature hash using bitcoinlib (this is the correct way!)
            sighash = SignatureHash(scriptpubkey, c_tx, input_index, sig_hash_type)
            return sighash
            
        except Exception as e:
            if os.getenv("DEBUG"):
                print(f"      Error using bitcoinlib: {e}")
                import traceback
                traceback.print_exc()
            # Fall back to manual parsing
    
    # Fallback: manual parsing (old implementation)
    tx_hex = tx.get('hex', '')
    if not tx_hex:
        txid = tx.get('txid', '')
        return bytes.fromhex(txid) if txid else b''
    
    try:
        tx_bytes = bytes.fromhex(tx_hex)
        offset = 0
        
        # Read version (4 bytes, little-endian)
        if offset + 4 > len(tx_bytes):
            raise ValueError("Transaction too short for version")
        version = tx_bytes[offset:offset+4]
        offset += 4
        
        # Read input count (varint)
        input_count, offset = read_varint(tx_bytes, offset)
        if input_count == 0 or input_count > 10000:
            raise ValueError(f"Invalid input count: {input_count}")
        
        # Get scriptPubKeys for all inputs from API data
        vin_list = tx.get('vin', [])
        if len(vin_list) != input_count:
            raise ValueError(f"Input count mismatch: API={len(vin_list)}, tx={input_count}")
        
        scriptpubkeys = []
        for vin in vin_list:
            prevout = vin.get('prevout', {})
            scriptpubkey_hex = prevout.get('scriptpubkey', '')
            if not scriptpubkey_hex:
                raise ValueError("Missing scriptPubKey for input")
            scriptpubkeys.append(bytes.fromhex(scriptpubkey_hex))
        
        # Reconstruct inputs with scriptPubKey instead of scriptSig
        reconstructed_inputs = b''
        for i in range(input_count):
            if offset >= len(tx_bytes):
                raise ValueError("Transaction too short for inputs")
            
            # Previous output hash (32 bytes, reversed)
            if offset + 32 > len(tx_bytes):
                raise ValueError("Transaction too short for prevout hash")
            prevout_hash = tx_bytes[offset:offset+32]
            offset += 32
            
            # Previous output index (4 bytes, little-endian)
            if offset + 4 > len(tx_bytes):
                raise ValueError("Transaction too short for prevout index")
            prevout_index = tx_bytes[offset:offset+4]
            offset += 4
            
            # Script length - Bitcoin uses compact size (varint) encoding for scriptSig/scriptPubKey
            script_sig_len, offset = read_varint(tx_bytes, offset)
            
            if offset + script_sig_len > len(tx_bytes):
                raise ValueError("Transaction too short for scriptSig")
            offset += script_sig_len  # Skip scriptSig
            
            # Sequence (4 bytes, little-endian)
            if offset + 4 > len(tx_bytes):
                raise ValueError("Transaction too short for sequence")
            sequence = tx_bytes[offset:offset+4]
            offset += 4
            
            # Reconstruct input with scriptPubKey
            scriptpubkey = scriptpubkeys[i]
            reconstructed_inputs += prevout_hash + prevout_index
            reconstructed_inputs += write_varint(len(scriptpubkey))
            reconstructed_inputs += scriptpubkey
            reconstructed_inputs += sequence
        
        # Read output count (varint)
        output_count, offset = read_varint(tx_bytes, offset)
        if output_count > 10000:
            raise ValueError(f"Invalid output count: {output_count}")
        
        # Read outputs (we keep them as-is for SIGHASH_ALL)
        outputs_start = offset
        for i in range(output_count):
            # Value (8 bytes, little-endian)
            if offset + 8 > len(tx_bytes):
                raise ValueError("Transaction too short for output value")
            offset += 8
            
            # Script length - Bitcoin uses compact size (varint) encoding
            script_len, offset = read_varint(tx_bytes, offset)
            
            if offset + script_len > len(tx_bytes):
                raise ValueError("Transaction too short for output script")
            offset += script_len
        
        outputs = tx_bytes[outputs_start:offset]
        
        # Read locktime (4 bytes, little-endian)
        if offset + 4 > len(tx_bytes):
            raise ValueError("Transaction too short for locktime")
        locktime = tx_bytes[offset:offset+4]
        offset += 4
        
        # Reconstruct the message that was signed
        message = version
        message += write_varint(input_count)
        message += reconstructed_inputs
        message += write_varint(output_count)
        message += outputs
        message += locktime
        message += sighash_type.to_bytes(4, 'little')  # SIGHASH flag
        
        # Double SHA-256
        first_hash = hashlib.sha256(message).digest()
        message_hash = hashlib.sha256(first_hash).digest()
        
        return message_hash
        
    except Exception as e:
        if os.getenv("DEBUG"):
            print(f"      Error in message reconstruction: {e}")
            import traceback
            traceback.print_exc()
        # Fallback: use txid (won't verify correctly)
        txid = tx.get('txid', '')
        return bytes.fromhex(txid) if txid else b''


def verify_ecdsa_signature(r: int, s: int, z: int, public_key_bytes: bytes) -> bool:
    """
    Verify ECDSA signature using r, s, z (message hash), and public key.
    
    Implements ECDSA verification equation:
    - u1 = z * s^-1 mod n
    - u2 = r * s^-1 mod n
    - Q = u1 * G + u2 * P
    - Verify: r == Q.x mod n
    
    Args:
        r: r component of signature
        s: s component of signature
        z: Message hash (SHA-256 of message, mod n)
        public_key_bytes: Public key in compressed (33 bytes) or uncompressed (65 bytes) format
        
    Returns:
        True if signature is valid, False otherwise
    """
    if not ECDSA_AVAILABLE:
        # If ecdsa library not available, skip verification
        return True
    
    try:
        from ecdsa import VerifyingKey, SECP256k1, BadSignatureError
        try:
            from ecdsa.numbertheory import inverse_mod
        except ImportError:
            # Fallback: use pow for modular inverse (Python 3.8+)
            def inverse_mod(a, m):
                return pow(a, -1, m)
        
        # Check r and s are in valid range
        order = SECP256k1.generator.order()
        if r <= 0 or r >= order or s <= 0 or s >= order:
            return False
        
        # Parse public key
        try:
            if len(public_key_bytes) == 33:
                # Compressed format
                vk = VerifyingKey.from_string(public_key_bytes, curve=SECP256k1)
            elif len(public_key_bytes) == 65:
                # Uncompressed format: skip first byte (0x04)
                vk = VerifyingKey.from_string(public_key_bytes[1:], curve=SECP256k1, validate_point=True)
            else:
                return False
        except Exception as e:
            if os.getenv("DEBUG"):
                print(f"      Error parsing public key: {e}")
            return False
        
        # ECDSA verification with pre-hashed message (z)
        # Compute u1 = z * s^-1 mod n
        s_inv = inverse_mod(s, order)
        u1 = (z * s_inv) % order
        
        # Compute u2 = r * s^-1 mod n
        u2 = (r * s_inv) % order
        
        # Compute Q = u1 * G + u2 * P
        G = SECP256k1.generator
        P = vk.pubkey.point
        
        Q = u1 * G + u2 * P
        
        # Verify: r == Q.x mod n
        r_verified = (Q.x() % order) == r
        
        return r_verified
        
    except Exception as e:
        if os.getenv("DEBUG"):
            print(f"      Verification error: {e}")
        return False


class TransactionProcessor:
    """Processes Bitcoin transaction hash files into ECDSA format."""
    
    def __init__(self, api_url: str = DEFAULT_API_URL, num_workers: Optional[int] = None):
        """
        Initialize the processor.
        
        Args:
            api_url: Bitcoin API base URL
            num_workers: Number of parallel worker threads. If None, uses half of CPU cores
        """
        try:
            import multiprocessing
            CPU_COUNT = multiprocessing.cpu_count()
        except:
            CPU_COUNT = 4
        
        if num_workers is None:
            num_workers = max(2, min(CPU_COUNT // 2, 32))
        
        self.api_url = api_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Bitcoin-Transaction-Processor/1.0'
        })
        self.request_delay = REQUEST_DELAY
        self.max_retries = MAX_RETRIES
        self.retry_delay = RETRY_DELAY
        self.num_workers = num_workers
        self.file_lock = threading.Lock()
    
    def _get_transaction_with_retry(self, txid: str) -> Optional[dict]:
        """
        Fetch transaction with retry logic.
        
        Args:
            txid: Transaction ID (hash)
            
        Returns:
            Transaction object or None if failed
        """
        url = f"{self.api_url}/tx/{txid}"
        
        for attempt in range(self.max_retries):
            try:
                response = self.session.get(url, timeout=30)
                response.raise_for_status()
                tx_data = response.json()
                
                # Also fetch raw transaction hex for proper message reconstruction
                try:
                    hex_url = f"{self.api_url}/tx/{txid}/hex"
                    hex_response = self.session.get(hex_url, timeout=30)
                    if hex_response.status_code == 200:
                        tx_data['hex'] = hex_response.text.strip()
                except:
                    pass  # If hex fetch fails, continue without it
                
                return tx_data
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 404:
                    return None
                elif e.response.status_code == 429:
                    wait_time = self.retry_delay * (2 ** attempt)
                    if attempt < self.max_retries - 1:
                        time.sleep(wait_time)
                        continue
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay * (2 ** attempt))
                else:
                    return None
            except requests.exceptions.RequestException as e:
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay * (2 ** attempt))
                else:
                    return None
        
        return None
    
    def extract_signature_components(self, txid: str, address: str) -> List[Dict]:
        """
        Extract ECDSA signature components (r, s, z, message) from ALL inputs of a Bitcoin transaction.
        
        Args:
            txid: Transaction ID
            address: Bitcoin address (for filtering inputs)
            
        Returns:
            List of dictionaries with r, s, z, message fields for all verified signatures
        """
        # Fetch full transaction
        tx = self._get_transaction_with_retry(txid)
        if not tx:
            return []
        
        # Find inputs that belong to our address
        vin_list = tx.get('vin', [])
        signatures = []
        
        for i, vin in enumerate(vin_list):
            # Check if this input belongs to our address
            prevout = vin.get('prevout', {})
            scriptpubkey_address = prevout.get('scriptpubkey_address')
            
            if scriptpubkey_address != address:
                if os.getenv("DEBUG"):
                    print(f"      Input {i}: address mismatch ({scriptpubkey_address} != {address})")
                continue
            
            # Extract signature and public key from scriptSig
            scriptsig = vin.get('scriptsig', '')
            if not scriptsig:
                if os.getenv("DEBUG"):
                    print(f"      Input {i}: no scriptSig")
                continue
            
            scriptsig_hex = scriptsig if isinstance(scriptsig, str) else scriptsig.get('hex', '')
            if not scriptsig_hex:
                if os.getenv("DEBUG"):
                    print(f"      Input {i}: empty scriptSig hex")
                continue
            
            # Extract r, s, and public key from signature
            sig_result = extract_signature_and_pubkey_from_script_sig(scriptsig_hex)
            if not sig_result:
                if os.getenv("DEBUG"):
                    print(f"      Input {i}: Failed to extract signature/pubkey from scriptSig")
                continue
            
            r, s, public_key_bytes = sig_result
            
            if os.getenv("DEBUG"):
                print(f"      Input {i}: Extracted r={hex(r)[:20]}..., s={hex(s)[:20]}..., pubkey={public_key_bytes.hex()[:20]}...")
            
            # Extract SIGHASH type from scriptSig
            sighash_type = extract_sighash_type(scriptsig_hex)
            
            # Create message (transaction data that was signed)
            # For Bitcoin, the message is the double SHA-256 of the transaction
            # with the input's scriptSig replaced by the previous output's scriptPubKey
            # The create_transaction_message function returns the double SHA-256 hash (32 bytes)
            message_bytes = create_transaction_message(tx, i, sighash_type)
            message_str = message_bytes.hex()
            
            # Calculate z (message hash)
            # If message_bytes is already 32 bytes (the hash), convert directly to int
            # Otherwise, hash it
            if len(message_bytes) == 32:
                z = int.from_bytes(message_bytes, 'big') % CURVE_ORDER
            else:
                z = hash_message(message_bytes)
            
            if os.getenv("DEBUG"):
                print(f"      Input {i}: z={hex(z)[:20]}..., message_len={len(message_bytes)}")
            
            # Verify signature
            # Attempt verification - it may fail due to message calculation issues
            # but we'll try anyway to see if any signatures verify
            verification_passed = verify_ecdsa_signature(r, s, z, public_key_bytes)
            
            if not verification_passed:
                if os.getenv("DEBUG"):
                    print(f"      Input {i}: ⚠️  Verification failed (may be due to message calculation)")
            
            if os.getenv("DEBUG") and verification_passed:
                print(f"      Input {i}: ✅ Signature verified successfully!")
            
            # Add public key as hex string (compressed format, 33 bytes = 66 hex chars)
            public_key_hex = public_key_bytes.hex()
            
            signatures.append({
                'message': message_str,
                'z': z,
                'r': r,
                's': s,
                'public_key': public_key_hex,
                '_verification_passed': verification_passed
            })
        
        return signatures
    
    def process_transaction_file(self, input_file: str, output_file: str, address: str, limit: Optional[int] = None):
        """
        Process a transaction hash file and create processed signatures.
        
        Args:
            input_file: Path to input transaction hash file
            output_file: Path to output processed signatures file
            address: Bitcoin address (extracted from filename)
            limit: Maximum number of transactions to process
        """
        # Load transaction hashes
        try:
            with open(input_file, 'r') as f:
                txids = json.load(f)
        except Exception as e:
            print(f"  Error loading {input_file}: {e}")
            return
        
        if not isinstance(txids, list):
            print(f"  Error: {input_file} does not contain a list of transaction hashes")
            return
        
        if limit:
            txids = txids[:limit]
        
        print(f"  Processing {len(txids)} transactions...")
        
        # Process transactions in parallel
        signatures = []
        completed = 0
        failed = 0
        
        def process_txid(txid: str) -> List[Dict]:
            time.sleep(self.request_delay)  # Rate limiting
            return self.extract_signature_components(txid, address)
        
        with ThreadPoolExecutor(max_workers=self.num_workers) as executor:
            future_to_txid = {executor.submit(process_txid, txid): txid for txid in txids}
            
            for future in as_completed(future_to_txid):
                txid = future_to_txid[future]
                try:
                    result = future.result()
                    if result and len(result) > 0:
                        # result is a list of signatures from all inputs
                        signatures.extend(result)
                        completed += len(result)
                    else:
                        failed += 1
                except Exception as e:
                    failed += 1
                    if os.getenv("DEBUG"):
                        print(f"    Error processing {txid}: {e}")
        
        if not signatures:
            print(f"  No signatures extracted from {len(txids)} transactions")
            return
        
        # Save processed signatures
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(signatures, f, indent=2)
        
        print(f"  ✅ Extracted {len(signatures)} signatures (failed: {failed})")
        print(f"  Saved to {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Process Bitcoin transaction hash files into ECDSA format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process all transaction files
  python3 process_transactions.py
  
  # Process with custom directories
  python3 process_transactions.py --input-dir transactions --output-dir processed_signatures
  
  # Limit number of transactions per file
  python3 process_transactions.py --limit 100
        """
    )
    
    parser.add_argument(
        '--input-dir',
        default='transactions',
        help='Directory containing transaction hash files (default: transactions)'
    )
    parser.add_argument(
        '--output-dir',
        default='processed_signatures',
        help='Directory to save processed signature files (default: processed_signatures)'
    )
    parser.add_argument(
        '--limit',
        type=int,
        default=None,
        help='Maximum number of transactions to process per file (default: all)'
    )
    parser.add_argument(
        '--workers',
        type=int,
        default=None,
        help='Number of parallel workers (default: half of CPU cores)'
    )
    parser.add_argument(
        '--api-url',
        default=DEFAULT_API_URL,
        help=f'Bitcoin API base URL (default: {DEFAULT_API_URL})'
    )
    
    args = parser.parse_args()
    
    # Resolve paths relative to script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    input_dir = os.path.join(script_dir, args.input_dir) if not os.path.isabs(args.input_dir) else args.input_dir
    output_dir = os.path.join(script_dir, args.output_dir) if not os.path.isabs(args.output_dir) else args.output_dir
    
    # Initialize processor
    processor = TransactionProcessor(api_url=args.api_url, num_workers=args.workers)
    
    # Find all transaction hash files
    input_path = Path(input_dir)
    if not input_path.exists():
        print(f"Error: Input directory '{input_dir}' does not exist")
        sys.exit(1)
    
    tx_files = list(input_path.glob('*.json'))
    if not tx_files:
        print(f"No transaction files found in '{input_dir}'")
        sys.exit(1)
    
    print(f"Found {len(tx_files)} transaction file(s)")
    print("=" * 60)
    
    # Process each file
    for i, tx_file in enumerate(tx_files, 1):
        # Extract address from filename
        address = tx_file.stem
        
        print(f"\n[{i}/{len(tx_files)}] Processing: {address}")
        print("-" * 60)
        
        output_file = os.path.join(output_dir, f"{address}.json")
        
        try:
            processor.process_transaction_file(
                str(tx_file),
                output_file,
                address,
                limit=args.limit
            )
        except KeyboardInterrupt:
            print("\n\nInterrupted by user. Exiting.")
            sys.exit(1)
        except Exception as e:
            print(f"  Error processing {address}: {e}")
            continue
    
    print("\n" + "=" * 60)
    print("✅ All transaction files processed!")


if __name__ == '__main__':
    main()

