#!/usr/bin/env python3
"""
Bitcoin Transaction Fetcher

Fetches all transaction hashes for Bitcoin addresses where the address is one of the signers
and stores them in JSON format.

Usage:
    python3 fetch_transactions.py  # Process all addresses from addresses.json (default)
    python3 fetch_transactions.py <address>
    python3 fetch_transactions.py --addresses addresses.json
"""

import json
import os
import sys
import argparse
import time
from typing import List, Dict, Optional, Set
from pathlib import Path

try:
    import requests
except ImportError as e:
    print(f"Error: Missing required dependencies.")
    print(f"Please install: pip install requests")
    print(f"Import error: {e}")
    sys.exit(1)


# Bitcoin API endpoint (Blockstream API - free, no API key needed)
DEFAULT_API_URL = os.getenv("BITCOIN_API_URL", "https://blockstream.info/api")
MAX_RETRIES = 3
RETRY_DELAY = 2.0  # seconds between retries
REQUEST_DELAY = 0.5  # seconds between requests to respect rate limits


class BitcoinTransactionFetcher:
    """
    Fetches Bitcoin transaction hashes for addresses.
    """
    
    def __init__(self, api_url: str = DEFAULT_API_URL):
        """
        Initialize the fetcher.
        
        Args:
            api_url: Base URL for Bitcoin API (default: Blockstream API)
        """
        self.api_url = api_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Bitcoin-Transaction-Fetcher/1.0'
        })
    
    def fetch_transaction_hashes(self, address: str, limit: Optional[int] = None) -> List[str]:
        """
        Fetch all transaction hashes for a Bitcoin address.
        
        Args:
            address: Bitcoin address to fetch transactions for
            limit: Maximum number of transactions to fetch (None = all)
            
        Returns:
            List of transaction hashes (txids)
        """
        transaction_hashes = []
        last_seen_txid = None
        page_num = 0
        
        print(f"Fetching transaction hashes for {address}...")
        
        while True:
            try:
                # Build API URL with pagination
                url = f"{self.api_url}/address/{address}/txs"
                params = {}
                if last_seen_txid:
                    params['after'] = last_seen_txid
                
                # Make request with retry logic
                response = None
                for attempt in range(MAX_RETRIES):
                    try:
                        response = self.session.get(url, params=params, timeout=30)
                        response.raise_for_status()
                        break
                    except requests.exceptions.RequestException as e:
                        if attempt < MAX_RETRIES - 1:
                            wait_time = RETRY_DELAY * (2 ** attempt)  # Exponential backoff
                            print(f"  Request failed (attempt {attempt + 1}/{MAX_RETRIES}), retrying in {wait_time:.1f}s...")
                            time.sleep(wait_time)
                        else:
                            raise
                
                data = response.json()
                
                # Handle empty response
                if not data or len(data) == 0:
                    print(f"  No more transactions found (page {page_num + 1})")
                    break
                
                # Extract transaction hashes (txids)
                # For each transaction, check if the address is a signer (in inputs)
                page_txids = []
                for tx in data:
                    txid = tx.get('txid')
                    if not txid:
                        continue
                    
                    # Check if address is a signer (appears in inputs)
                    is_signer = False
                    for vin in tx.get('vin', []):
                        # Check if this input's previous output belongs to our address
                        prevout = vin.get('prevout', {})
                        scriptpubkey_address = prevout.get('scriptpubkey_address')
                        if scriptpubkey_address == address:
                            is_signer = True
                            break
                    
                    # Only include transactions where address is a signer
                    if is_signer:
                        page_txids.append(txid)
                
                if not page_txids:
                    print(f"  No signer transactions found on page {page_num + 1}")
                    # Still continue to check next page in case there are more
                
                transaction_hashes.extend(page_txids)
                
                print(f"  Page {page_num + 1}: Found {len(page_txids)} signer transactions (total: {len(transaction_hashes)})")
                
                # Check if we've reached the limit
                if limit and len(transaction_hashes) >= limit:
                    transaction_hashes = transaction_hashes[:limit]
                    print(f"  Reached limit of {limit} transactions")
                    break
                
                # Check if we got fewer transactions than expected (last page)
                if len(data) < 25:  # Blockstream API returns up to 25 per page
                    print(f"  Reached last page (got {len(data)} transactions)")
                    break
                
                # Update last_seen_txid for pagination
                last_seen_txid = data[-1].get('txid')
                if not last_seen_txid:
                    break
                
                page_num += 1
                
                # Rate limiting
                time.sleep(REQUEST_DELAY)
                
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 404:
                    print(f"  Address not found or has no transactions")
                    break
                elif e.response.status_code == 429:
                    wait_time = RETRY_DELAY * (2 ** page_num)
                    print(f"  Rate limited, waiting {wait_time:.1f}s before retry...")
                    time.sleep(wait_time)
                    continue
                else:
                    print(f"  HTTP error: {e}")
                    print(f"  Response: {e.response.text[:200]}")
                    break
            except requests.exceptions.RequestException as e:
                print(f"  Request error: {e}")
                break
            except json.JSONDecodeError as e:
                print(f"  JSON decode error: {e}")
                print(f"  Response: {response.text[:200] if response else 'No response'}")
                break
            except Exception as e:
                print(f"  Unexpected error: {e}")
                break
        
        print(f"  Total signer transactions found: {len(transaction_hashes)}")
        return transaction_hashes
    
    def save_transactions(self, transaction_hashes: List[str], output_file: str):
        """
        Save transaction hashes to a JSON file.
        
        Args:
            transaction_hashes: List of transaction hashes
            output_file: Path to output JSON file
        """
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(transaction_hashes, f, indent=2)
        
        print(f"  Saved {len(transaction_hashes)} transaction hashes to {output_file}")
    
    def process_address(self, address: str, output_dir: str = "transactions", limit: Optional[int] = None):
        """
        Process a single address: fetch and save transaction hashes.
        
        Args:
            address: Bitcoin address to process
            output_dir: Directory to save output files
            limit: Maximum number of transactions to fetch
        """
        # Fetch transaction hashes
        transaction_hashes = self.fetch_transaction_hashes(address, limit=limit)
        
        if not transaction_hashes:
            print(f"  No signer transactions found for {address}")
            return
        
        # Save to file
        output_file = os.path.join(output_dir, f"{address}.json")
        self.save_transactions(transaction_hashes, output_file)


def load_addresses(addresses_file: str = "addresses.json") -> List[str]:
    """
    Load addresses from JSON file.
    
    Args:
        addresses_file: Path to addresses JSON file (relative or absolute)
        
    Returns:
        List of addresses
    """
    # If relative path, try to find it relative to script directory first
    if not os.path.isabs(addresses_file) and not os.path.exists(addresses_file):
        # Try in the same directory as the script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        script_path = os.path.join(script_dir, addresses_file)
        if os.path.exists(script_path):
            addresses_file = script_path
    
    try:
        with open(addresses_file, 'r') as f:
            data = json.load(f)
        
        # Handle different JSON structures
        if isinstance(data, dict):
            # Try common keys
            if 'bitcoin_addresses' in data:
                addresses = data['bitcoin_addresses']
            elif 'addresses' in data:
                addresses = data['addresses']
            elif 'address' in data:
                addresses = [data['address']]
            else:
                # Use first list value
                addresses = [v for v in data.values() if isinstance(v, list)]
                addresses = addresses[0] if addresses else []
        elif isinstance(data, list):
            addresses = data
        else:
            addresses = []
        
        # Filter out empty/invalid addresses
        addresses = [addr for addr in addresses if addr and isinstance(addr, str) and len(addr) > 0]
        
        return addresses
    except FileNotFoundError:
        print(f"Error: Addresses file '{addresses_file}' not found")
        return []
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in '{addresses_file}': {e}")
        return []
    except Exception as e:
        print(f"Error loading addresses: {e}")
        return []


def main():
    parser = argparse.ArgumentParser(
        description="Fetch Bitcoin transaction hashes for addresses",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process all addresses from addresses.json
  python3 fetch_transactions.py
  
  # Process a single address
  python3 fetch_transactions.py 1FaapwdwYVVBiV6Qvkis88c2KHPoxX1Jb1
  
  # Use custom addresses file
  python3 fetch_transactions.py --addresses custom_addresses.json
  
  # Use custom API endpoint
  BITCOIN_API_URL=https://your-api.com/api python3 fetch_transactions.py
        """
    )
    
    parser.add_argument(
        'address',
        nargs='?',
        help='Bitcoin address to fetch transactions for (if not provided, processes all from addresses.json)'
    )
    parser.add_argument(
        '--addresses',
        default='addresses.json',
        help='Path to addresses JSON file (default: addresses.json in script directory)'
    )
    parser.add_argument(
        '--output-dir',
        default='transactions',
        help='Directory to save transaction files (default: transactions in script directory)'
    )
    parser.add_argument(
        '--limit',
        type=int,
        default=None,
        help='Maximum number of transactions to fetch per address (default: all)'
    )
    parser.add_argument(
        '--api-url',
        default=DEFAULT_API_URL,
        help=f'Bitcoin API base URL (default: {DEFAULT_API_URL})'
    )
    
    args = parser.parse_args()
    
    # Initialize fetcher
    fetcher = BitcoinTransactionFetcher(api_url=args.api_url)
    
    # Determine addresses to process
    if args.address:
        # Single address provided
        addresses = [args.address]
    else:
        # Load from file
        addresses = load_addresses(args.addresses)
        if not addresses:
            print("No addresses found. Exiting.")
            sys.exit(1)
    
    # Resolve output directory relative to script directory if relative path
    if not os.path.isabs(args.output_dir):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        output_dir = os.path.join(script_dir, args.output_dir)
    else:
        output_dir = args.output_dir
    
    print(f"Processing {len(addresses)} address(es)...")
    print("=" * 60)
    
    # Process each address
    for i, address in enumerate(addresses, 1):
        print(f"\n[{i}/{len(addresses)}] Processing address: {address}")
        print("-" * 60)
        
        try:
            fetcher.process_address(address, output_dir=output_dir, limit=args.limit)
        except KeyboardInterrupt:
            print("\n\nInterrupted by user. Exiting.")
            sys.exit(1)
        except Exception as e:
            print(f"  Error processing {address}: {e}")
            continue
        
        # Delay between addresses to respect rate limits
        if i < len(addresses):
            time.sleep(REQUEST_DELAY * 2)
    
    print("\n" + "=" * 60)
    print("✅ All addresses processed!")


if __name__ == '__main__':
    main()

