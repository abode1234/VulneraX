#!/usr/bin/env python3
"""
VulneraX Manager
A command-line interface to manage reconnaissance and scanning of bug bounty scope domains.
"""

import argparse
import os
import sys
import time
from typing import List

from agent.recone.scope_manager import ScopeManager
from agent.scanner.scanner_agent import ScannerAgent


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="VulneraX - Bug Bounty Reconnaissance and Vulnerability Scanner"
    )
    
    # Main command groups
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Scope management commands
    scope_parser = subparsers.add_parser("scope", help="Manage bug bounty scope")
    scope_parser.add_argument("--list", action="store_true", help="List domains in scope")
    scope_parser.add_argument("--add", help="Add domains from a file to scope", metavar="FILE")
    scope_parser.add_argument("--remove", help="Remove a domain from scope", metavar="DOMAIN")
    scope_parser.add_argument("--clear", action="store_true", help="Clear all domains from scope")
    
    # Recon commands
    recon_parser = subparsers.add_parser("recon", help="Run reconnaissance on domains in scope")
    recon_parser.add_argument("--max-pages", type=int, default=10, help="Maximum pages to crawl per domain")
    recon_parser.add_argument("--no-wildcards", action="store_true", help="Don't expand wildcard domains")
    recon_parser.add_argument("--domain", help="Run recon on a specific domain only")
    recon_parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    recon_parser.add_argument("--threads", type=int, default=10, help="Number of threads for crawling")
    recon_parser.add_argument("--wordlist", help="Path to a custom subdomain wordlist")
    recon_parser.add_argument("--no-bruteforce", action="store_true", help="Disable bruteforce subdomain enumeration")
    recon_parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    
    # Scan commands
    scan_parser = subparsers.add_parser("scan", help="Run vulnerability scanner")
    scan_parser.add_argument("--threads", type=int, default=30, help="Number of threads to use")
    scan_parser.add_argument("--timeout", type=int, default=8, help="Request timeout in seconds")
    scan_parser.add_argument("--proxies", help="Proxy to use (e.g., http://127.0.0.1:8080)")
    scan_parser.add_argument("--log-level", choices=["info", "debug"], default="info", help="Logging level")
    scan_parser.add_argument("--targets", help="Custom targets file (default: data/scan_targets.txt)")
    scan_parser.add_argument("--attack-types", help="Comma-separated list of attack types to use (e.g., sqli,xss,path)")
    scan_parser.add_argument("--user-agent", help="Custom User-Agent string for requests")
    scan_parser.add_argument("--cookies", help="Cookies to include with requests (format: name=value;name2=value2)")
    scan_parser.add_argument("--headers", help="Custom headers for requests (format: Header1:value1;Header2:value2)")
    
    # Report commands
    report_parser = subparsers.add_parser("report", help="Generate vulnerability report")
    report_parser.add_argument("--output", help="Output file for the report", default="vulnerability_report.txt")
    report_parser.add_argument("--format", choices=["txt", "html", "json"], default="txt", help="Report format")
    report_parser.add_argument("--include-payloads", action="store_true", help="Include payloads in the report")
    report_parser.add_argument("--severity", choices=["all", "high", "medium", "low"], default="all", 
                              help="Filter vulnerabilities by severity")
    
    # Full workflow command
    workflow_parser = subparsers.add_parser("workflow", help="Run the full workflow (recon + scan + report)")
    workflow_parser.add_argument("--threads", type=int, default=30, help="Number of threads to use for scanning")
    workflow_parser.add_argument("--timeout", type=int, default=8, help="Request timeout in seconds")
    workflow_parser.add_argument("--proxies", help="Proxy to use (e.g., http://127.0.0.1:8080)")
    workflow_parser.add_argument("--max-pages", type=int, default=10, help="Maximum pages to crawl per domain")
    workflow_parser.add_argument("--no-wildcards", action="store_true", help="Don't expand wildcard domains")
    workflow_parser.add_argument("--no-bruteforce", action="store_true", help="Disable bruteforce subdomain enumeration")
    workflow_parser.add_argument("--wordlist", help="Path to a custom subdomain wordlist")
    workflow_parser.add_argument("--attack-types", help="Comma-separated list of attack types to use")
    workflow_parser.add_argument("--user-agent", help="Custom User-Agent string for requests")
    workflow_parser.add_argument("--cookies", help="Cookies to include with requests (format: name=value;name2=value2)")
    workflow_parser.add_argument("--headers", help="Custom headers for requests (format: Header1:value1;Header2:value2)")
    workflow_parser.add_argument("--report-format", choices=["txt", "html", "json"], default="txt", help="Report format")
    workflow_parser.add_argument("--output", help="Output file for the report", default="vulnerability_report.txt")
    workflow_parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Check if no command was provided
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    return args


def run_scope_command(args):
    """Run scope management commands."""
    scope_manager = ScopeManager()
    
    if args.list:
        print("\n=== Domains in Scope ===")
        print("\nRegular domains:")
        for domain in scope_manager.domains:
            print(f"  - {domain}")
        
        print("\nWildcard domains:")
        for domain in scope_manager.wildcard_domains:
            print(f"  - *.{domain}")
        
        print(f"\nTotal: {len(scope_manager.domains) + len(scope_manager.wildcard_domains)} domains")
        
        if not scope_manager.domains and not scope_manager.wildcard_domains:
            print("\n[!] No domains in scope. Use --add to add domains.")
    
    if args.add:
        try:
            if not os.path.exists(args.add):
                print(f"[!] File not found: {args.add}")
                return
                
            with open(args.add, "r", encoding="utf-8") as f:
                domains = [line.strip() for line in f if line.strip()]
                
            if not domains:
                print(f"[!] No domains found in {args.add}")
                return
                
            print(f"[*] Adding {len(domains)} domains to scope from {args.add}")
            scope_manager.save_scope(domains)
            print(f"[+] Successfully added domains to scope")
        except Exception as e:
            print(f"[!] Error adding domains: {e}")
    
    if args.remove:
        try:
            domain_to_remove = args.remove.strip()
            
            # Get current domains
            current_domains = []
            for domain in scope_manager.domains:
                if domain != domain_to_remove:
                    current_domains.append(domain)
                else:
                    print(f"[+] Removing domain: {domain}")
            
            # Handle wildcard domains
            for domain in scope_manager.wildcard_domains:
                wildcard_domain = f"*.{domain}"
                if domain != domain_to_remove and wildcard_domain != domain_to_remove:
                    current_domains.append(wildcard_domain)
                else:
                    print(f"[+] Removing domain: {wildcard_domain if wildcard_domain == domain_to_remove else domain}")
            
            # Save updated scope
            scope_manager.save_scope(current_domains)
            print(f"[+] Domain '{domain_to_remove}' removed from scope")
        except Exception as e:
            print(f"[!] Error removing domain: {e}")
    
    if args.clear:
        try:
            confirm = input("[!] Are you sure you want to clear all domains from scope? (y/n): ")
            if confirm.lower() == 'y':
                scope_manager.save_scope([])
                print("[+] All domains cleared from scope")
            else:
                print("[*] Operation cancelled")
        except Exception as e:
            print(f"[!] Error clearing domains: {e}")


def run_recon_command(args):
    """Run reconnaissance commands."""
    scope_manager = ScopeManager()
    
    if not scope_manager.domains and not scope_manager.wildcard_domains and not args.domain:
        print("[!] No domains in scope. Please add domains first:")
        print("    python vulnerax_manager.py scope --add your_domains.txt")
        return
    
    if args.domain:
        # Run recon on a specific domain
        print(f"[*] Running reconnaissance on domain: {args.domain}")
        from agent.recone.recon_agent import ReconAgent
        
        recon = ReconAgent(
            domain=args.domain,
            max_pages=args.max_pages,
            timeout=args.timeout if hasattr(args, 'timeout') else 10,
            threads=args.threads if hasattr(args, 'threads') else 10,
            verbose=args.verbose if hasattr(args, 'verbose') else False
        )
        recon.run_all()
    else:
        # Run recon on all domains in scope
        include_wildcards = not args.no_wildcards
        scope_manager.run_recon(max_pages=args.max_pages, include_wildcards=include_wildcards)
    
    # Prepare targets for scanning
    targets = scope_manager.prepare_scan_targets()
    if targets:
        print(f"[+] Prepared {len(targets)} targets for scanning")
    else:
        print("[!] No targets with parameters found for scanning")
        print("[*] Try increasing --max-pages or adding more domains to scope")


def run_scan_command(args):
    """Run vulnerability scanning commands."""
    targets_file = args.targets or os.path.join("data", "scan_targets.txt")
    
    if not os.path.exists(targets_file):
        print(f"[!] Targets file not found: {targets_file}")
        print("[*] Run 'python vulnerax_manager.py recon' first to generate targets")
        return
    
    print(f"[*] Running vulnerability scan on targets in {targets_file}")
    scanner = ScannerAgent(
        targets=targets_file,
        threads=args.threads,
        timeout=args.timeout,
        proxies=args.proxies,
        log_level=args.log_level
    )
    scanner.run()


def run_report_command(args):
    """Generate vulnerability report."""
    results_file = os.path.join("agent", "scan_results.jsonl")
    
    if not os.path.exists(results_file):
        print(f"[!] Scan results file not found: {results_file}")
        print("[*] Run 'python vulnerax_manager.py scan' first to generate scan results")
        return
    
    print(f"[*] Generating vulnerability report from {results_file}")
    
    # Import here to avoid circular imports
    try:
        sys.path.append(os.path.dirname(os.path.abspath(__file__)))
        from report_generator import load_scan_results, generate_report
        
        results = load_scan_results(results_file)
        
        # Redirect stdout to capture the report
        original_stdout = sys.stdout
        with open(args.output, 'w') as f:
            sys.stdout = f
            generate_report(results)
            sys.stdout = original_stdout
        
        print(f"[+] Report generated: {args.output}")
    except Exception as e:
        print(f"[!] Error generating report: {e}")


def run_workflow(args):
    """Run the full workflow: recon + scan + report."""
    start_time = time.time()
    
    print("\n=== Starting VulneraX Workflow ===\n")
    
    # Step 1: Reconnaissance
    print("\n=== Step 1: Reconnaissance ===\n")
    scope_manager = ScopeManager()
    include_wildcards = not args.no_wildcards
    scope_manager.run_recon(max_pages=args.max_pages, include_wildcards=include_wildcards)
    targets = scope_manager.prepare_scan_targets()
    
    if not targets:
        print("[!] No targets found for scanning. Workflow aborted.")
        return
    
    # Step 2: Vulnerability Scanning
    print("\n=== Step 2: Vulnerability Scanning ===\n")
    targets_file = os.path.join("data", "scan_targets.txt")
    scanner = ScannerAgent(
        targets=targets_file,
        threads=args.threads,
        timeout=args.timeout,
        proxies=args.proxies,
        log_level="info"  # Use info level for workflow to avoid excessive output
    )
    scanner.run()
    
    # Step 3: Report Generation
    print("\n=== Step 3: Report Generation ===\n")
    report_file = "vulnerability_report.txt"
    
    try:
        from report_generator import load_scan_results, generate_report
        
        results = load_scan_results(os.path.join("agent", "scan_results.jsonl"))
        
        # Redirect stdout to capture the report
        original_stdout = sys.stdout
        with open(report_file, 'w') as f:
            sys.stdout = f
            generate_report(results)
            sys.stdout = original_stdout
        
        print(f"[+] Report generated: {report_file}")
    except Exception as e:
        print(f"[!] Error generating report: {e}")
    
    # Workflow summary
    duration = time.time() - start_time
    print(f"\n=== Workflow Completed in {duration:.2f} seconds ===")
    print(f"[+] Reconnaissance: {len(targets)} targets identified")
    print(f"[+] Vulnerability scan: Results saved to agent/scan_results.jsonl")
    print(f"[+] Report: {report_file}")


def main():
    """Main entry point."""
    args = parse_args()
    
    if args.command == "scope":
        run_scope_command(args)
    elif args.command == "recon":
        run_recon_command(args)
    elif args.command == "scan":
        run_scan_command(args)
    elif args.command == "report":
        run_report_command(args)
    elif args.command == "workflow":
        run_workflow(args)
    else:
        print("Please specify a command. Use --help for more information.")


if __name__ == "__main__":
    main()
