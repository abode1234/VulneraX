# agent/recone/recon_agent.py
"""
ReconAgent:
1. Collects subdomains using multiple methods
2. Crawls each domain (GET links with parameters)
3. Extracts parameters from each URL
4. Saves everything to data/recon_full.json
"""

from __future__ import annotations
import threading
import json
import time
import requests
import pathlib
import os
import random
import concurrent.futures
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse
from typing import Dict, List, Set, Optional, Tuple, Any

from .subdomain_enumerator import enumerate_subdomains, get_random_user_agent

# Default request headers
DEFAULT_HEADERS = {
    "User-Agent": get_random_user_agent(),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1"
}

class ReconAgent:
    def __init__(self, domain: str, max_pages: int = 10, timeout: int = 10, 
                 use_bruteforce: bool = True, wordlist: Optional[str] = None,
                 threads: int = 10, verbose: bool = False):
        """
        Initialize the reconnaissance agent.
        
        Args:
            domain: Target domain
            max_pages: Maximum pages to crawl per subdomain
            timeout: Request timeout in seconds
            use_bruteforce: Whether to use bruteforce for subdomain enumeration
            wordlist: Optional path to a subdomain wordlist
            threads: Number of threads for crawling
            verbose: Whether to print verbose output
        """
        self.domain: str = domain
        self.max_pages: int = max_pages
        self.timeout: int = timeout
        self.use_bruteforce: bool = use_bruteforce
        self.wordlist: Optional[str] = wordlist
        self.threads: int = threads
        self.verbose: bool = verbose
        
        # Results storage
        self.subs: List[str] = []
        self.links: Dict[str, List[str]] = {}
        self.params: Dict[str, Dict[str, List[str]]] = {}
        
        # Rate limiting
        self.request_delay: float = 0.5  # seconds between requests to same domain
        self.last_request_time: Dict[str, float] = {}
        
        # Thread safety
        self.lock = threading.Lock()
        
        if self.verbose:
            print(f"[*] Initialized ReconAgent for {domain}")
            print(f"    - Max pages: {max_pages}")
            print(f"    - Timeout: {timeout}s")
            print(f"    - Threads: {threads}")
            print(f"    - Bruteforce: {'Enabled' if use_bruteforce else 'Disabled'}")

    # ---------- 1. Subdomain enumeration ----------
    def enumerate_subs(self) -> None:
        """
        Enumerate subdomains using multiple methods.
        """
        print(f"[*] Enumerating subdomains for {self.domain}...")
        self.subs = enumerate_subdomains(
            self.domain,
            use_bruteforce=self.use_bruteforce,
            wordlist=self.wordlist
        )
        print(f"[+] Found {len(self.subs)} subdomains for {self.domain}")

    # ---------- 2. Web crawling ----------
    def _normalize_url(self, url: str) -> str:
        """
        Normalize URL by removing fragments and default ports.
        
        Args:
            url: URL to normalize
            
        Returns:
            Normalized URL
        """
        parsed = urlparse(url)
        # Remove fragment
        normalized = urlunparse((parsed.scheme, parsed.netloc, parsed.path, 
                               parsed.params, parsed.query, ''))
        return normalized
        
    def _respect_rate_limit(self, domain: str) -> None:
        """
        Respect rate limiting for a domain.
        
        Args:
            domain: Domain to check rate limiting for
        """
        with self.lock:
            current_time = time.time()
            if domain in self.last_request_time:
                elapsed = current_time - self.last_request_time[domain]
                if elapsed < self.request_delay:
                    time.sleep(self.request_delay - elapsed)
            self.last_request_time[domain] = time.time()
    
    def _crawl_one(self, sub: str) -> List[str]:
        """
        Crawl a single subdomain and find links with parameters.
        
        Args:
            sub: Subdomain to crawl
            
        Returns:
            List of discovered URLs
        """
        # Try both http and https
        queue: List[str] = []
        for protocol in ["https", "http"]:
            queue.append(f"{protocol}://{sub}")
            
        visited: Set[str] = set()
        found: Set[str] = set()
        
        while queue and len(visited) < self.max_pages:
            url = queue.pop(0)  # Use FIFO for breadth-first search
            normalized_url = self._normalize_url(url)
            
            if normalized_url in visited:
                continue
                
            visited.add(normalized_url)
            parsed_url = urlparse(normalized_url)
            domain = parsed_url.netloc
            
            # Respect rate limiting
            self._respect_rate_limit(domain)
            
            try:
                # Use random user agent for each request
                headers = DEFAULT_HEADERS.copy()
                headers["User-Agent"] = get_random_user_agent()
                
                if self.verbose:
                    print(f"[*] Crawling: {normalized_url}")
                    
                r = requests.get(
                    normalized_url, 
                    timeout=self.timeout, 
                    headers=headers,
                    allow_redirects=True
                )
                
                # Skip non-HTML responses
                content_type = r.headers.get('Content-Type', '')
                if not content_type.startswith('text/html'):
                    if self.verbose:
                        print(f"[!] Skipping non-HTML content: {content_type} at {normalized_url}")
                    continue
                
                # Parse HTML
                soup = BeautifulSoup(r.text, "html.parser")
                
                # Extract links from <a> tags
                for tag in soup.find_all("a", href=True):
                    href = tag["href"]
                    if not href or href.startswith("javascript:") or href == "#":
                        continue
                        
                    next_url = urljoin(normalized_url, href)
                    next_parsed = urlparse(next_url)
                    
                    # Only follow links to the same domain or subdomains
                    if self.domain in next_parsed.netloc and next_url not in visited:
                        # Prioritize URLs with parameters
                        if next_parsed.query:
                            found.add(next_url)
                            
                        # Add to queue for further crawling
                        queue.append(next_url)
                
                # Also check forms for potential parameter discovery
                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    if action:
                        form_url = urljoin(normalized_url, action)
                        found.add(form_url)
                        
                        # Extract form fields as potential parameters
                        for input_field in form.find_all(["input", "select", "textarea"]):
                            field_name = input_field.get("name")
                            if field_name:
                                # Store as a URL with this parameter
                                param_url = f"{form_url}?{field_name}=test"
                                found.add(param_url)
                
            except requests.exceptions.RequestException as e:
                if self.verbose:
                    print(f"[!] Request error for {normalized_url}: {e}")
            except Exception as e:
                if self.verbose:
                    print(f"[!] Error crawling {normalized_url}: {e}")
        
        # Prioritize URLs with parameters
        result = [url for url in found if parse_qs(urlparse(url).query)]

        if not result:
            # If no parameters found, include some regular URLs
            regular_urls = list(found)[:10]  # Limit to 10 URLs
            if self.verbose and regular_urls:
                print(f"[*] No URLs with parameters found for {sub}, including {len(regular_urls)} regular URLs")
            return regular_urls
        
        if self.verbose:
            print(f"[+] Found {len(result)} URLs with parameters for {sub}")
        return result

    def crawl_all(self) -> None:
        """
        Crawl all subdomains using a thread pool.
        """
        print(f"[*] Crawling {len(self.subs)} subdomains with {self.threads} threads")
        
        # Use ThreadPoolExecutor for better thread management
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Create a dictionary mapping futures to subdomains
            future_to_sub = {executor.submit(self._crawl_one, sub): sub for sub in self.subs}
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_sub):
                sub = future_to_sub[future]
                try:
                    links = future.result()
                    with self.lock:
                        self.links[sub] = links
                    print(f"[+] {sub}: {len(links)} links with parameters")
                except Exception as e:
                    print(f"[!] Error crawling {sub}: {e}")
                    self.links[sub] = []

    # ---------- 3. Extract parameters ----------
    def extract_params(self) -> None:
        """
        Extract parameters from all discovered URLs.
        """
        print(f"[*] Extracting parameters from discovered URLs")
        
        total_params = 0
        for sub, urls in self.links.items():
            self.params[sub] = {}
            for url in urls:
                parsed = urlparse(url)
                query_params = parse_qs(parsed.query)
                
                # Store the parameter names for this URL
                param_names = list(query_params.keys())
                if param_names:
                    self.params[sub][url] = param_names
                    total_params += len(param_names)
                    
                    if self.verbose:
                        print(f"[*] URL: {url}")
                        print(f"    Parameters: {', '.join(param_names)}")
        
        print(f"[+] Extracted {total_params} parameters from {sum(len(urls) for urls in self.links.values())} URLs")

    # ---------- 4. Save results ----------
    def save(self, path: str = "data/recon_full.json") -> None:
        """
        Save reconnaissance results to a JSON file.
        
        Args:
            path: Path to save the JSON file
        """
        try:
            # Create directory if it doesn't exist
            pathlib.Path(os.path.dirname(path)).mkdir(parents=True, exist_ok=True)
            
            # Prepare data for saving
            data = {
                "domain": self.domain,
                "timestamp": time.time(),
                "scan_date": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                "subdomains": self.subs,
                "links": self.links,
                "params": self.params,
                "stats": {
                    "subdomain_count": len(self.subs),
                    "url_count": sum(len(urls) for urls in self.links.values()),
                    "parameter_count": sum(len(params) for sub_params in self.params.values() 
                                       for params in sub_params.values())
                }
            }
            
            # Save to file
            with open(path, "w", encoding="utf-8") as fp:
                json.dump(data, fp, indent=2)
                
            print(f"[+] Saved reconnaissance results to {path}")
            
            # Also save a list of URLs with parameters for scanning
            scan_targets = []
            for sub_params in self.params.values():
                scan_targets.extend(sub_params.keys())
                
            scan_path = os.path.join(os.path.dirname(path), "scan_targets.txt")
            with open(scan_path, "w", encoding="utf-8") as fp:
                fp.write("\n".join(scan_targets))
                
            print(f"[+] Saved {len(scan_targets)} scan targets to {scan_path}")
            
        except Exception as e:
            print(f"[!] Error saving results: {e}")

    # ---------- Orchestration ----------
    def run_all(self) -> None:
        """
        Run the complete reconnaissance process.
        """
        start_time = time.time()
        print(f"[*] Starting reconnaissance for {self.domain}")
        
        try:
            # Step 1: Enumerate subdomains
            self.enumerate_subs()
            
            # Step 2: Crawl all subdomains
            self.crawl_all()
            
            # Step 3: Extract parameters
            self.extract_params()
            
            # Step 4: Save results
            self.save()
            
            # Print summary
            duration = time.time() - start_time
            print(f"\n[+] Reconnaissance completed in {duration:.2f} seconds")
            print(f"[+] Summary:")
            print(f"    - {len(self.subs)} subdomains discovered")
            print(f"    - {sum(len(urls) for urls in self.links.values())} URLs with parameters found")
            print(f"    - Results saved to data/recon_full.json and data/scan_targets.txt")
            
        except Exception as e:
            print(f"[!] Error during reconnaissance: {e}")
            print(f"[!] Reconnaissance failed after {time.time() - start_time:.2f} seconds")

# ---------- CLI ----------
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="VulneraX Reconnaissance Agent")
    parser.add_argument("domain", help="Target domain to perform reconnaissance on")
    parser.add_argument("--max-pages", type=int, default=10, help="Maximum pages to crawl per subdomain")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads for crawling")
    parser.add_argument("--no-bruteforce", action="store_true", help="Disable bruteforce subdomain enumeration")
    parser.add_argument("--wordlist", help="Path to a custom subdomain wordlist")
    parser.add_argument("--output", default="data/recon_full.json", help="Output file path")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    print(f"\n{'='*50}")
    print(f"VulneraX Reconnaissance Agent - Bug Bounty Edition")
    print(f"{'='*50}\n")
    
    agent = ReconAgent(
        domain=args.domain,
        max_pages=args.max_pages,
        timeout=args.timeout,
        use_bruteforce=not args.no_bruteforce,
        wordlist=args.wordlist,
        threads=args.threads,
        verbose=args.verbose
    )
    
    try:
        agent.run_all()
        print("\n[+] Reconnaissance completed successfully")
        print("[*] You can now run the scanner on the discovered targets")
        print(f"[*] Command: python -m agent.scanner.scanner_agent --targets data/scan_targets.txt --threads 30 --timeout 10\n")
    except KeyboardInterrupt:
        print("\n[!] Reconnaissance interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Critical error: {e}")
        sys.exit(1)

