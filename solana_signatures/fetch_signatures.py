#!/usr/bin/env python3
"""
Solana Signature Fetcher

Fetches all transaction signature hashes (transaction hashes) for Solana addresses 
and stores them in JSON format. If an address is a sub-address (PDA), it finds 
the main signer address first.

Usage:
    python3 fetch_signatures.py <address>
    python3 fetch_signatures.py  # Process all addresses from addresses.json (default)
    python3 fetch_signatures.py --addresses addresses.json
"""

import json
import os
import sys
import argparse
import time
import shutil
from typing import List, Dict, Optional, Set
from pathlib import Path

try:
    from solders.pubkey import Pubkey
    from solana.rpc.api import Client
    from solana.rpc.commitment import Confirmed
    from solana.exceptions import SolanaRpcException
except ImportError as e:
    print(f"Error: Missing required dependencies.")
    print(f"Please install: pip install solders solana")
    print(f"Or: pip install -r ../scripts/requirements.txt")
    print(f"Import error: {e}")
    sys.exit(1)


# Solana RPC endpoint (can be overridden with environment variable)
HELIUS_API_KEY = "bbd34c18-7b97-414d-8d71-5a21a8c29835"
DEFAULT_RPC_URL = os.getenv("SOLANA_RPC_URL", f"https://mainnet.helius-rpc.com/?api-key={HELIUS_API_KEY}")
MAX_SIGNATURES_PER_REQUEST = 1000  # Solana RPC limit




class SolanaSignatureFetcher:
    """Fetches Solana transaction signatures for addresses."""
    
    def __init__(self, rpc_url: str = DEFAULT_RPC_URL):
        """Initialize the fetcher with an RPC endpoint."""
        self.client = Client(rpc_url)
        self.rpc_url = rpc_url
        
    def is_valid_address(self, address: str) -> bool:
        """Check if an address is a valid Solana address."""
        try:
            Pubkey.from_string(address)
            return True
        except:
            return False
    
    def find_main_signer_address(self, address: str) -> tuple[str, bool]:
        """
        Find the main signer address for a given address.
        
        Returns:
            (main_address, is_pda): The main signer address and whether it was a PDA
        """
        pubkey = Pubkey.from_string(address)
        
        # Try to get recent signatures to check if this address is a signer
        try:
            # Get recent signatures for this address
            response = self.client.get_signatures_for_address(
                pubkey,
                limit=10,
                commitment=Confirmed
            )
            
            if response.value and len(response.value) > 0:
                # Check if this address appears as a signer in transactions
                for sig_info in response.value[:5]:  # Check first 5 transactions
                    try:
                        tx = self.client.get_transaction(
                            sig_info.signature,
                            commitment=Confirmed,
                            max_supported_transaction_version=0
                        )
                        
                        if tx.value and tx.value.transaction:
                            # Get signers from transaction
                            signers = tx.value.transaction.transaction.message.account_keys
                            if signers and len(signers) > 0:
                                # First account key is typically the fee payer/signer
                                main_signer = str(signers[0])
                                
                                # If the address we're checking is in the signers, it's the main address
                                signer_addresses = [str(key) for key in signers]
                                if address in signer_addresses:
                                    return (address, False)
                                
                                # Otherwise, return the first signer as the main address
                                return (main_signer, True)
                    except Exception as e:
                        # Continue to next transaction if this one fails
                        continue
            
            # If we can't determine from transactions, assume it's the main address
            return (address, False)
            
        except Exception as e:
            print(f"Warning: Could not determine main signer for {address}: {e}")
            # Assume it's the main address if we can't determine
            return (address, False)
    
    def fetch_all_signatures(self, address: str, limit: Optional[int] = None) -> List[str]:
        """
        Fetch all transaction signature hashes for an address.
        
        Args:
            address: Solana address to fetch signatures for
            limit: Maximum number of signatures to fetch (None = all)
            
        Returns:
            List of signature hashes (transaction hashes), or None if RPC error occurred
        """
        pubkey = Pubkey.from_string(address)
        signatures = []
        before = None  # For pagination
        page_num = 0
        rpc_error_occurred = False
        
        print(f"Fetching transaction signatures for {address}...")
        
        while True:
            try:
                page_num += 1
                
                # Get signatures with pagination
                response = self.client.get_signatures_for_address(
                    pubkey,
                    limit=min(MAX_SIGNATURES_PER_REQUEST, limit or MAX_SIGNATURES_PER_REQUEST),
                    before=before,
                    commitment=Confirmed
                )
                
                # Check if response is valid
                if response is None:
                    print(f"  ⚠️  RPC Error: Received None response from RPC")
                    rpc_error_occurred = True
                    break
                
                if not response.value or len(response.value) == 0:
                    # No more signatures
                    if page_num == 1:
                        # First page returned empty - address has no signatures
                        print(f"  ℹ️  No signatures found for this address")
                    break
                
                print(f"  Page {page_num}: Found {len(response.value)} signatures (total: {len(signatures) + len(response.value)})...")
                
                # Extract signature hashes
                for sig_info in response.value:
                    # Convert Signature object to string (base58 encoded hash)
                    sig_str = str(sig_info.signature)
                    signatures.append(sig_str)
                
                # Check if we've reached the limit
                if limit and len(signatures) >= limit:
                    print(f"  Reached limit of {limit} signatures")
                    break
                
                # Set up pagination for next request
                if len(response.value) < MAX_SIGNATURES_PER_REQUEST:
                    # No more signatures available
                    break
                
                # Convert Signature object to string for pagination
                before = response.value[-1].signature
                
                # Rate limiting between requests (increased delay to avoid rate limits)
                time.sleep(1.0)  # Increased to 1 second to avoid rate limits
                
            except SolanaRpcException as e:
                # Extract error message more thoroughly
                error_str = str(e) if str(e) else ""
                error_repr = repr(e) if repr(e) else ""
                
                # Try to get error from exception attributes
                error_msg = error_str
                if not error_msg:
                    # Try to get from exception's message or args
                    if hasattr(e, 'message'):
                        error_msg = str(e.message)
                    elif hasattr(e, 'args') and e.args:
                        error_msg = str(e.args[0]) if e.args else ""
                    elif error_repr:
                        error_msg = error_repr
                    else:
                        error_msg = "Unknown RPC error"
                
                error_lower = (error_str + " " + error_repr + " " + error_msg).lower()
                
                # Check if it's a rate limit error (429)
                is_rate_limit = (
                    "429" in error_str or 
                    "429" in error_repr or
                    "429" in error_msg or
                    "too many requests" in error_lower or 
                    "rate limit" in error_lower or
                    "rate_limit" in error_lower
                )
                
                if is_rate_limit:
                    print(f"  ⚠️  RPC Rate Limit Error (429): {error_msg}")
                    print(f"  Waiting 10 seconds before retrying page {page_num}...")
                    time.sleep(10)
                    # Retry the same page (but limit retries to avoid infinite loop)
                    if page_num > 0:
                        page_num -= 1
                    continue
                else:
                    # Other RPC error - try to get more details
                    print(f"  ⚠️  RPC Error: {error_msg}")
                    # If we have some signatures, save them and continue
                    if len(signatures) > 0:
                        print(f"  ℹ️  Saving {len(signatures)} signatures collected so far...")
                        rpc_error_occurred = False  # Don't mark as error if we got some data
                        break
                    rpc_error_occurred = True
                    break
                    
            except Exception as e:
                # Get full error details
                error_msg = str(e) if str(e) else type(e).__name__
                error_type = type(e).__name__
                
                # Try to get more details from exception
                if hasattr(e, '__cause__') and e.__cause__:
                    error_msg += f" (caused by: {e.__cause__})"
                
                print(f"  ⚠️  Error fetching signatures ({error_type}): {error_msg}")
                # If we have some signatures, save them and continue
                if len(signatures) > 0:
                    print(f"  ℹ️  Saving {len(signatures)} signatures collected so far...")
                    rpc_error_occurred = False  # Don't mark as error if we got some data
                    break
                rpc_error_occurred = True
                break
        
        if rpc_error_occurred and len(signatures) == 0:
            print(f"  ❌ Failed to fetch signatures due to RPC error (no signatures collected)")
            return None
        elif rpc_error_occurred and len(signatures) > 0:
            print(f"  ⚠️  RPC error occurred, but saved {len(signatures)} signatures collected so far")
            return signatures
        
        if len(signatures) == 0:
            print(f"  ℹ️  No signatures found for this address")
        else:
            print(f"  ✅ Total signatures fetched: {len(signatures)}")
        
        return signatures
    
    
    def save_signatures(self, signatures: List[str], output_file: str):
        """Save signature hashes to a JSON file."""
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Save as a simple list of signature hashes
        with open(output_path, 'w') as f:
            json.dump(signatures, f, indent=2)
        
        print(f"Saved {len(signatures)} signature hashes to {output_path}")
    
    def process_address(self, address: str, output_dir: str = "solana_signatures", limit: Optional[int] = None, main_address_cache: Optional[Dict[str, str]] = None) -> tuple:
        """
        Process a single address: find main signer and fetch all signatures.
        
        Args:
            address: Address to process
            output_dir: Output directory for signature files
            limit: Maximum number of signatures to fetch
            main_address_cache: Dictionary mapping main addresses to their output files (for deduplication)
        
        Returns:
            Tuple of (output_file_path, status) where status is:
            - "success": Signatures found and saved
            - "no_signatures": Address has no signatures
            - "rpc_error": RPC error occurred
            - None if invalid address
        """
        if not self.is_valid_address(address):
            raise ValueError(f"Invalid Solana address: {address}")
        
        # Find main signer address
        main_address, is_pda = self.find_main_signer_address(address)
        
        if is_pda:
            print(f"Address {address} is a sub-address (PDA). Main signer: {main_address}")
        else:
            print(f"Address {address} is the main signer address.")
        
        # Create output filename using the MAIN address (not the original address)
        safe_main_address = main_address.replace("/", "_").replace("\\", "_")
        output_file = os.path.join(output_dir, f"{safe_main_address}.json")
        
        # Check if we've already processed this main address
        if main_address_cache is not None and main_address in main_address_cache:
            existing_file = main_address_cache[main_address]
            if os.path.exists(existing_file):
                print(f"  ℹ️  Main address {main_address} already processed. Skipping fetch (file exists: {existing_file})")
                return (output_file, "success")
            else:
                # File doesn't exist, remove from cache and continue
                del main_address_cache[main_address]
        
        # Fetch all signature hashes for the main address
        signatures = self.fetch_all_signatures(main_address, limit=limit)
        
        if signatures is None:
            # RPC error occurred
            print(f"  ❌ Failed to fetch signatures for {main_address} due to RPC error")
            return (None, "rpc_error")
        
        if not signatures or len(signatures) == 0:
            print(f"  ℹ️  No signatures found for {main_address}")
            return (None, "no_signatures")
        
        # Save signatures using main address as filename
        self.save_signatures(signatures, output_file)
        
        # Cache the main address -> output file mapping
        if main_address_cache is not None:
            main_address_cache[main_address] = output_file
        
        return (output_file, "success")


def load_addresses_from_file(file_path: str) -> List[str]:
    """Load addresses from a JSON file."""
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    addresses = []
    # Support different JSON structures
    if "solana_addresses" in data:
        addresses = data["solana_addresses"]
    elif "addresses" in data:
        addresses = data["addresses"]
    elif isinstance(data, list):
        addresses = data
    else:
        raise ValueError(f"Unknown JSON structure in {file_path}")
    
    # Filter out empty strings and None values
    addresses = [addr for addr in addresses if addr and isinstance(addr, str) and addr.strip()]
    
    return addresses


def main():
    parser = argparse.ArgumentParser(
        description="Fetch Solana transaction signatures for addresses"
    )
    parser.add_argument(
        "address",
        nargs="?",
        help="Solana address to fetch signatures for"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Process all addresses from addresses.json (default if no address provided)"
    )
    parser.add_argument(
        "--addresses",
        type=str,
        default="solana_signatures/addresses.json",
        help="Path to addresses JSON file (default: solana_signatures/addresses.json)"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="solana_signatures/signatures",
        help="Output directory for signature files (default: solana_signatures/signatures)"
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Maximum number of signatures to fetch per address"
    )
    parser.add_argument(
        "--rpc-url",
        type=str,
        default=DEFAULT_RPC_URL,
        help=f"Solana RPC endpoint (default: {DEFAULT_RPC_URL})"
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress warning messages (only show errors and summary)"
    )
    
    args = parser.parse_args()
    
    # Set quiet mode environment variable
    if args.quiet:
        os.environ["QUIET"] = "1"
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Initialize fetcher
    fetcher = SolanaSignatureFetcher(rpc_url=args.rpc_url)
    
    # Show RPC endpoint info
    if "helius-rpc.com" in args.rpc_url:
        print("✅ Using Helius RPC endpoint (higher rate limits).\n")
    elif "api.mainnet.solana.com" in args.rpc_url or "api.mainnet-beta.solana.com" in args.rpc_url:
        print("⚠️  Using public Solana RPC endpoint. Rate limits may apply.")
        print("   Consider using a custom RPC endpoint (--rpc-url) for better performance.\n")
    
    addresses_to_process = []
    
    # If address is provided, use it; otherwise process all addresses (default behavior)
    if args.address:
        addresses_to_process = [args.address]
    else:
        # Load addresses from file (default behavior)
        if not os.path.exists(args.addresses):
            print(f"Error: Addresses file not found: {args.addresses}")
            sys.exit(1)
        
        addresses_to_process = load_addresses_from_file(args.addresses)
        print(f"Loaded {len(addresses_to_process)} addresses from {args.addresses}")
        
        # Check if no addresses were found
        if not addresses_to_process or len(addresses_to_process) == 0:
            print("No addresses found in addresses.json. Nothing to process.")
            sys.exit(0)
    
    # Process each address with main address deduplication
    results = []
    failed_addresses = []
    no_signatures_addresses = []
    rpc_error_addresses = []
    main_address_cache = {}  # Maps main_address -> output_file_path
    address_to_main = {}  # Maps original address -> main address (for summary)
    
    for i, address in enumerate(addresses_to_process, 1):
        print(f"\n[{i}/{len(addresses_to_process)}] Processing {address}...")
        try:
            # Find main address first to track mapping
            main_address, _ = fetcher.find_main_signer_address(address)
            address_to_main[address] = main_address
            
            output_file, status = fetcher.process_address(
                address,
                output_dir=args.output_dir,
                limit=args.limit,
                main_address_cache=main_address_cache
            )
            
            if status == "success":
                # Store mapping: original address -> main address file
                results.append((address, main_address, output_file))
            elif status == "no_signatures":
                no_signatures_addresses.append((address, main_address))
            elif status == "rpc_error":
                rpc_error_addresses.append((address, main_address))
                
        except Exception as e:
            error_msg = str(e) if str(e) else type(e).__name__
            print(f"  ❌ Error processing {address}: {error_msg}")
            failed_addresses.append((address, error_msg))
            continue
        
        # Add delay between addresses to avoid rate limits
        if i < len(addresses_to_process):
            time.sleep(2.0)  # Increased to 2 seconds between addresses
    
    # Print summary
    print(f"\n{'='*60}")
    print("Summary:")
    print(f"{'='*60}")
    
    # Get unique main addresses that were successfully processed
    unique_main_addresses = set()
    address_mappings = {}
    
    if results:
        print(f"\n✅ Successfully processed ({len(results)} addresses -> {len(set(main for _, main, _ in results))} unique main addresses):")
        for address, main_address, output_file in results:
            unique_main_addresses.add(main_address)
            if main_address not in address_mappings:
                address_mappings[main_address] = []
            address_mappings[main_address].append(address)
            if address == main_address:
                print(f"  {address} -> {output_file}")
            else:
                print(f"  {address} (sub-address) -> {main_address} -> {output_file}")
        
        # Show unique main address files
        print(f"\n  Main address signature files created ({len(unique_main_addresses)} files):")
        for main_address in sorted(unique_main_addresses):
            safe_main = main_address.replace("/", "_").replace("\\", "_")
            output_file = os.path.join(args.output_dir, f"{safe_main}.json")
            sub_addresses = [addr for addr in address_mappings[main_address] if addr != main_address]
            if sub_addresses:
                print(f"    {main_address}.json (used by {len(sub_addresses)} sub-addresses)")
            else:
                print(f"    {main_address}.json")
    
    if no_signatures_addresses:
        print(f"\nℹ️  No signatures found ({len(no_signatures_addresses)} addresses):")
        for address, main_address in no_signatures_addresses:
            if address == main_address:
                print(f"  {address}")
            else:
                print(f"  {address} (sub-address of {main_address})")
    
    if rpc_error_addresses:
        print(f"\n⚠️  RPC errors occurred ({len(rpc_error_addresses)} addresses):")
        for address, main_address in rpc_error_addresses:
            if address == main_address:
                print(f"  {address} (rate limit or RPC error)")
            else:
                print(f"  {address} (sub-address of {main_address}) - rate limit or RPC error")
    
    if failed_addresses:
        print(f"\n❌ Failed due to errors ({len(failed_addresses)} addresses):")
        for address, error in failed_addresses:
            print(f"  {address}: {error}")
    
    total_processed = len(results) + len(no_signatures_addresses) + len(rpc_error_addresses) + len(failed_addresses)
    unique_mains = len(set(main for _, main, _ in results)) if results else 0
    print(f"\nTotal: {len(results)} addresses processed, {unique_mains} unique main addresses, {len(no_signatures_addresses)} no signatures, {len(rpc_error_addresses)} RPC errors, {len(failed_addresses)} failed")
    print(f"Processed {total_processed}/{len(addresses_to_process)} addresses.")
    print(f"\nNote: Only main address signature files are stored in {args.output_dir}/")


if __name__ == "__main__":
    main()

