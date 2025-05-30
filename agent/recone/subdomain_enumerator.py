# agent/recone/subdomain_enumerator.py
"""
Subdomain enumeration module that uses multiple sources to gather subdomains.
Currently supports: crt.sh, DNS resolution, and common subdomain patterns.
"""

from typing import List, Set, Dict, Any, Optional
import requests
import json
import time
import pathlib
import os
import random
import socket
import concurrent.futures
from urllib.parse import urlparse

# Define multiple user agents to avoid detection
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
    "VulneraX-Subdomain-Enum/1.0"
]

def get_random_user_agent() -> str:
    """Return a random user agent from the list."""
    return random.choice(USER_AGENTS)

def crtsh_enum(domain: str) -> List[str]:
    """
    Query crt.sh and return a sorted list of subdomains.
    
    Args:
        domain: The target domain to enumerate subdomains for
        
    Returns:
        A sorted list of unique subdomains
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {"User-Agent": get_random_user_agent()}
    
    try:
        print(f"[*] Querying crt.sh for {domain}")
        r = requests.get(url, timeout=15, headers=headers)
        r.raise_for_status()
        
        # Handle empty responses
        if not r.text or r.text.isspace():
            print(f"[!] crt.sh returned empty response for {domain}")
            return []
            
        try:
            data = json.loads(r.text)
        except json.JSONDecodeError:
            print(f"[!] Invalid JSON response from crt.sh for {domain}")
            return []
            
        # Extract and filter subdomains
        subs = {sub.strip().lower()
                for entry in data
                for sub in entry.get("name_value", "").split("\n")
                if sub.strip() and sub.endswith(domain)}
                
        print(f"[+] Found {len(subs)} subdomains from crt.sh")
        return sorted(subs)
    except requests.exceptions.RequestException as e:
        print(f"[!] crt.sh request error: {e}")
        return []
    except Exception as e:
        print(f"[!] crt.sh unexpected error: {e}")
        return []

def check_dns_resolution(domain: str) -> bool:
    """
    Check if a domain resolves to an IP address.
    
    Args:
        domain: The domain to check
        
    Returns:
        True if the domain resolves, False otherwise
    """
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

def bruteforce_subdomains(domain: str, wordlist: Optional[str] = None) -> List[str]:
    """
    Attempt to find subdomains using common subdomain prefixes.
    
    Args:
        domain: The target domain
        wordlist: Optional path to a wordlist file
        
    Returns:
        A list of discovered subdomains
    """
    # Common subdomain prefixes
    common_prefixes = [
        "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", 
        "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal", 
        "dns", "admin", "cdn", "api", "dev", "stage", "web", "auth", "beta", 
        "gateway", "intranet", "internal", "jenkins", "gitlab", "git", "wiki", 
        "support", "status", "docs", "login", "app", "apps", "staging", "prod"
    ]
    
    # Load custom wordlist if provided
    if wordlist and os.path.exists(wordlist):
        try:
            with open(wordlist, 'r') as f:
                custom_prefixes = [line.strip() for line in f if line.strip()]
                common_prefixes.extend(custom_prefixes)
                print(f"[+] Loaded {len(custom_prefixes)} additional subdomain prefixes from {wordlist}")
        except Exception as e:
            print(f"[!] Error loading wordlist: {e}")
    
    # Remove duplicates
    common_prefixes = list(set(common_prefixes))
    
    discovered = []
    total = len(common_prefixes)
    print(f"[*] Testing {total} common subdomain prefixes for {domain}")
    
    # Use thread pool for faster checking
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        subdomains = [f"{prefix}.{domain}" for prefix in common_prefixes]
        results = list(executor.map(check_dns_resolution, subdomains))
        
        for subdomain, resolves in zip(subdomains, results):
            if resolves:
                discovered.append(subdomain)
                print(f"[+] Discovered subdomain: {subdomain}")
    
    print(f"[+] Found {len(discovered)} subdomains through DNS resolution")
    return discovered

def enumerate_subdomains(domain: str, use_bruteforce: bool = True, wordlist: Optional[str] = None) -> List[str]:
    """
    Enumerate subdomains using multiple methods.
    
    Args:
        domain: The target domain
        use_bruteforce: Whether to use bruteforce method
        wordlist: Optional path to a wordlist file
        
    Returns:
        A list of all discovered subdomains
    """
    all_subdomains = set()
    
    # Method 1: crt.sh
    crtsh_results = crtsh_enum(domain)
    all_subdomains.update(crtsh_results)
    
    # Method 2: DNS bruteforce (if enabled)
    if use_bruteforce:
        bruteforce_results = bruteforce_subdomains(domain, wordlist)
        all_subdomains.update(bruteforce_results)
    
    # Always include the base domain
    all_subdomains.add(domain)
    
    # Filter out any invalid domains
    valid_subdomains = []
    for subdomain in all_subdomains:
        if subdomain and '.' in subdomain:
            valid_subdomains.append(subdomain)
    
    return sorted(valid_subdomains)

def save_subdomains(domain: str,
                    subs: List[str],
                    path: str = "data/subdomains.json") -> None:
    """
    Save the list of subdomains to a JSON file.
    
    Args:
        domain: The target domain
        subs: List of discovered subdomains
        path: Path to save the JSON file
    """
    try:
        pathlib.Path(os.path.dirname(path)).mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fp:
            json.dump(
                {
                    "domain": domain,
                    "count": len(subs),
                    "subdomains": subs,
                    "timestamp": time.time()
                },
                fp,
                indent=2,
            )
        print(f"[+] Saved {len(subs)} subdomains to {path}")
    except Exception as e:
        print(f"[!] Error saving subdomains: {e}")

# Command-line interface
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="VulneraX Subdomain Enumerator")
    parser.add_argument("domain", help="Target domain to enumerate subdomains for")
    parser.add_argument("--no-bruteforce", action="store_true", help="Disable bruteforce enumeration")
    parser.add_argument("--wordlist", help="Path to a custom wordlist for bruteforce")
    parser.add_argument("--output", default="data/subdomains.json", help="Output file path")
    
    args = parser.parse_args()
    
    print(f"[*] Starting subdomain enumeration for {args.domain}")
    subdomains = enumerate_subdomains(
        args.domain, 
        use_bruteforce=not args.no_bruteforce,
        wordlist=args.wordlist
    )
    
    print(f"\n[+] Found {len(subdomains)} total subdomains:")
    for s in subdomains:
        print(f" - {s}")
    
    save_subdomains(args.domain, subdomains, args.output)

