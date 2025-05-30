#!/usr/bin/env python3
"""
Scope Manager for VulneraX
Manages bug bounty scope domains and prepares them for reconnaissance and scanning.
"""

from __future__ import annotations
import json
import os
import pathlib
import re
import time
from typing import Dict, List, Set, Optional, Union

from .recon_agent import ReconAgent


class ScopeManager:
    """Manages bug bounty scope domains and coordinates reconnaissance."""
    
    def __init__(self, scope_file: Optional[str] = None):
        """Initialize the scope manager.
        
        Args:
            scope_file: Optional path to a file containing scope domains
        """
        self.domains: List[str] = []
        self.wildcard_domains: List[str] = []
        self.scope_file = scope_file or os.path.join("data", "scope.txt")
        self.results_file = os.path.join("data", "recon_full.json")
        self.results: Dict = {}
        
        # Create data directory if it doesn't exist
        pathlib.Path(os.path.dirname(self.scope_file)).mkdir(parents=True, exist_ok=True)
        
        # Load domains if scope file exists
        if os.path.exists(self.scope_file):
            self.load_scope()
    
    def load_scope(self) -> None:
        """Load domains from the scope file."""
        try:
            with open(self.scope_file, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
                
            self.domains = []
            self.wildcard_domains = []
            
            for domain in lines:
                if domain.startswith("*."):
                    # Handle wildcard domains
                    self.wildcard_domains.append(domain[2:])  # Remove the *. prefix
                else:
                    self.domains.append(domain)
                    
            print(f"[+] Loaded {len(self.domains)} regular domains and {len(self.wildcard_domains)} wildcard domains")
        except Exception as e:
            print(f"[!] Error loading scope: {e}")
    
    def save_scope(self, domains: List[str]) -> None:
        """Save domains to the scope file.
        
        Args:
            domains: List of domains to save
        """
        try:
            # Process domains to separate regular and wildcard domains
            regular_domains = []
            wildcard_domains = []
            
            for domain in domains:
                domain = domain.strip()
                if domain.startswith("*."):
                    wildcard_domains.append(domain)
                else:
                    regular_domains.append(domain)
            
            # Sort domains alphabetically
            regular_domains.sort()
            wildcard_domains.sort()
            
            # Combine and write to file
            all_domains = regular_domains + wildcard_domains
            with open(self.scope_file, "w", encoding="utf-8") as f:
                f.write("\n".join(all_domains))
            
            # Update instance variables
            self.domains = [d for d in regular_domains]
            self.wildcard_domains = [d[2:] for d in wildcard_domains]  # Remove *. prefix
            
            print(f"[+] Saved {len(regular_domains)} regular domains and {len(wildcard_domains)} wildcard domains to {self.scope_file}")
        except Exception as e:
            print(f"[!] Error saving scope: {e}")
    
    def expand_wildcards(self) -> List[str]:
        """Expand wildcard domains using reconnaissance.
        
        Returns:
            List of expanded subdomains
        """
        expanded_domains = []
        
        for wildcard in self.wildcard_domains:
            print(f"[*] Expanding wildcard domain: {wildcard}")
            recon = ReconAgent(wildcard)
            recon.enumerate_subs()
            expanded_domains.extend(recon.subs)
        
        return expanded_domains
    
    def run_recon(self, max_pages: int = 10, include_wildcards: bool = True) -> None:
        """Run reconnaissance on all domains in scope.
        
        Args:
            max_pages: Maximum number of pages to crawl per domain
            include_wildcards: Whether to expand and include wildcard domains
        """
        all_domains = self.domains.copy()
        
        # Expand wildcard domains if requested
        if include_wildcards and self.wildcard_domains:
            print(f"[*] Expanding {len(self.wildcard_domains)} wildcard domains...")
            expanded = self.expand_wildcards()
            all_domains.extend(expanded)
            print(f"[+] Added {len(expanded)} subdomains from wildcards")
        
        # Remove duplicates and sort
        all_domains = sorted(set(all_domains))
        
        if not all_domains:
            print("[!] No domains to scan. Please add domains to scope first.")
            return
        
        print(f"[*] Starting reconnaissance on {len(all_domains)} domains")
        
        # Initialize combined results
        combined_results = {
            "timestamp": time.time(),
            "domains": all_domains,
            "subdomains": {},
            "links": {},
            "params": {}
        }
        
        # Run recon on each domain
        for i, domain in enumerate(all_domains, 1):
            print(f"[*] Processing domain {i}/{len(all_domains)}: {domain}")
            
            try:
                recon = ReconAgent(domain, max_pages=max_pages)
                recon.enumerate_subs()
                recon.crawl_all()
                recon.extract_params()
                
                # Add results to combined data
                combined_results["subdomains"][domain] = recon.subs
                combined_results["links"][domain] = recon.links
                combined_results["params"][domain] = recon.params
                
                print(f"[+] Completed reconnaissance for {domain}")
            except Exception as e:
                print(f"[!] Error processing {domain}: {e}")
        
        # Save combined results
        self.results = combined_results
        self.save_results()
    
    def save_results(self) -> None:
        """Save reconnaissance results to file."""
        try:
            with open(self.results_file, "w", encoding="utf-8") as f:
                json.dump(self.results, f, indent=2)
            print(f"[+] Saved reconnaissance results to {self.results_file}")
        except Exception as e:
            print(f"[!] Error saving results: {e}")
    
    def load_results(self) -> Dict:
        """Load reconnaissance results from file.
        
        Returns:
            Dictionary containing reconnaissance results
        """
        try:
            if os.path.exists(self.results_file):
                with open(self.results_file, "r", encoding="utf-8") as f:
                    self.results = json.load(f)
                print(f"[+] Loaded reconnaissance results from {self.results_file}")
            else:
                print(f"[!] Results file {self.results_file} not found")
        except Exception as e:
            print(f"[!] Error loading results: {e}")
        
        return self.results
    
    def prepare_scan_targets(self) -> List[str]:
        """Prepare targets for scanning based on reconnaissance results.
        
        Returns:
            List of URLs with parameters for scanning
        """
        if not self.results:
            self.load_results()
        
        if not self.results:
            print("[!] No reconnaissance results available. Run recon first.")
            return []
        
        scan_targets = []
        
        # Extract all URLs with parameters
        for domain, domain_data in self.results.get("params", {}).items():
            for subdomain, subdomain_data in domain_data.items():
                for url, params in subdomain_data.items():
                    if params:  # Only include URLs with parameters
                        scan_targets.append(url)
        
        print(f"[+] Prepared {len(scan_targets)} targets for scanning")
        
        # Save scan targets to a file
        targets_file = os.path.join("data", "scan_targets.txt")
        try:
            with open(targets_file, "w", encoding="utf-8") as f:
                f.write("\n".join(scan_targets))
            print(f"[+] Saved scan targets to {targets_file}")
        except Exception as e:
            print(f"[!] Error saving scan targets: {e}")
        
        return scan_targets


def main():
    """Command-line interface for the scope manager."""
    import argparse
    
    parser = argparse.ArgumentParser(description="VulneraX Scope Manager")
    parser.add_argument("--add", help="Add domains from a file to scope", metavar="FILE")
    parser.add_argument("--list", action="store_true", help="List domains in scope")
    parser.add_argument("--recon", action="store_true", help="Run reconnaissance on domains in scope")
    parser.add_argument("--max-pages", type=int, default=10, help="Maximum pages to crawl per domain")
    parser.add_argument("--prepare-scan", action="store_true", help="Prepare targets for scanning")
    
    args = parser.parse_args()
    
    scope_manager = ScopeManager()
    
    if args.add:
        try:
            with open(args.add, "r", encoding="utf-8") as f:
                domains = [line.strip() for line in f if line.strip()]
            scope_manager.save_scope(domains)
        except Exception as e:
            print(f"[!] Error adding domains: {e}")
    
    if args.list:
        print("\nRegular domains:")
        for domain in scope_manager.domains:
            print(f"  - {domain}")
        
        print("\nWildcard domains:")
        for domain in scope_manager.wildcard_domains:
            print(f"  - *.{domain}")
    
    if args.recon:
        scope_manager.run_recon(max_pages=args.max_pages)
    
    if args.prepare_scan:
        scope_manager.prepare_scan_targets()


if __name__ == "__main__":
    main()
