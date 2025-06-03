"""scanner_agent.py
Main entry‑point – consumes a list of URLs (with parameters) and orchestrates
sending payloads + logging the responses.  Designed for multithreaded use.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable, List, Optional

from .payload_loader import PayloadLoader
from .request_sender import RequestSender
from .response_logger import ResponseLogger

class ScannerAgent:
    """Scans each URL using all payloads for each attack type."""

    def __init__(
        self,
        targets: Iterable[str] | Path,
        threads: int = 10,
        timeout: int = 5,
        proxies: Optional[str] = None,
        log_level: str = "info",
        attack_types: list = None,
        use_base64: bool = True,
    ) -> None:
        # Set up logging level
        self.log_level = log_level.lower()
        self.verbose = self.log_level == "debug"
        
        # Normalize targets
        if isinstance(targets, (str, Path)):
            try:
                with open(targets, "r", encoding="utf-8") as fh:
                    self.targets: List[str] = json.load(fh)
                    if self.verbose:
                        print(f"[*] Loaded {len(self.targets)} targets from {targets}")
            except json.JSONDecodeError:
                # Try loading as plain text, one URL per line
                with open(targets, "r", encoding="utf-8") as fh:
                    self.targets = [line.strip() for line in fh if line.strip()]
                    if self.verbose:
                        print(f"[*] Loaded {len(self.targets)} targets from plain text file {targets}")
        else:
            self.targets = list(targets)
            if self.verbose:
                print(f"[*] Using {len(self.targets)} provided targets")

        self.threads = threads
        self.timeout = timeout
        self.proxies = proxies
        self.attack_types = attack_types
        self.use_base64 = use_base64
        
        if self.verbose:
            print(f"[*] Scanner configuration:")
            print(f"    - Threads: {self.threads}")
            print(f"    - Timeout: {self.timeout}s")
            print(f"    - Proxies: {self.proxies if self.proxies else 'None'}")
        
        # Initialize components
        self.logger = ResponseLogger("scan_results.jsonl")
        self.requester = RequestSender(timeout=self.timeout, proxies=self.proxies)
        self.loader = PayloadLoader(verbose=self.verbose, attack_types=self.attack_types, use_base64=self.use_base64)
        
        # Print payload statistics if in verbose mode
        if self.verbose:
            self.loader.print_payload_stats()

    # ------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------
    def _scan_single(self, url: str) -> None:
        """Scan a single URL with all attack payloads on all parameters."""
        if self.verbose:
            print(f"[*] Scanning target: {url}")
            
        attack_count = 0
        payload_count = 0
        
        for attack_type, payloads in self.loader.iter_attack_payloads():
            if self.verbose:
                print(f"    - Using {len(payloads)} {attack_type} payloads")
                
            attack_count += 1
            for payload_variant in payloads:  # already includes encodings
                try:
                    injected_list = self.requester.inject(url, payload_variant)
                    for injected_url, meta in injected_list:
                        resp = self.requester.send(injected_url, meta)
                        self.logger.handle_response(resp, attack_type, payload_variant)
                        payload_count += 1
                except Exception as e:
                    if self.verbose:
                        print(f"    [!] Error with {attack_type} payload: {e}")
        
        if self.verbose:
            print(f"[+] Completed scan of {url} with {attack_count} attack types and {payload_count} total payloads")

    # ------------------------------------------------------
    # Public API
    # ------------------------------------------------------
    def run(self) -> None:
        """Launch threads and perform the scan."""
        total_targets = len(self.targets)
        if not total_targets:
            print("[!] No targets to scan. Please provide valid targets.")
            return
            
        print(f"[*] Starting scan of {total_targets} targets with {self.threads} threads")
        print(f"[*] Using {len(self.loader.attack_types)} attack types: {', '.join(self.loader.attack_types)}")
        print(f"[*] Timeout set to {self.timeout} seconds per request")
        if self.proxies:
            print(f"[*] Routing traffic through proxy: {self.proxies}")
        
        start_time = time.time()
        completed = 0
        errors = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._scan_single, u): u for u in self.targets}
            
            for fut in as_completed(futures):
                target = futures[fut]
                if fut.exception():
                    errors += 1
                    print(f"[!] Error while scanning {target}: {fut.exception()}", file=sys.stderr)
                else:
                    completed += 1
                    if not self.verbose and completed % max(1, total_targets // 10) == 0:
                        print(f"[*] Progress: {completed}/{total_targets} targets completed ({completed/total_targets*100:.1f}%)")
        
        duration = time.time() - start_time
        print(f"\n[+] Scan Summary:")
        print(f"    - Targets scanned: {completed}/{total_targets}")
        print(f"    - Failed targets: {errors}")
        print(f"    - Total duration: {duration:.2f} seconds")
        print(f"    - Average time per target: {duration/total_targets:.2f} seconds")
        print(f"[+] Scan finished – results in scan_results.jsonl")
        
        # Suggest next steps
        print("\n[*] Next steps:")
        print("    - Run 'python3 report_generator.py' to analyze the scan results")
        print("    - Check 'agent/scan_results.jsonl' for detailed scan data")


# ------------------------------------------------------
# CLI wrapper
# ------------------------------------------------------

def _cli() -> None:  # noqa: D401 – short name OK
    parser = argparse.ArgumentParser(description="Run VulneraX parameter scanner")
    parser.add_argument("--targets", required=True, help="JSON/TXT file with parameterised URLs")
    parser.add_argument("--threads", type=int, default=10)
    parser.add_argument("--timeout", type=int, default=5)
    parser.add_argument("--proxies", help="Proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--log-level", default="info", choices=["info", "debug"])
    args = parser.parse_args()

    agent = ScannerAgent(
        targets=Path(args.targets),
        threads=args.threads,
        timeout=args.timeout,
        proxies=args.proxies,
        log_level=args.log_level,
    )
    agent.run()

if __name__ == "__main__":
    _cli()
