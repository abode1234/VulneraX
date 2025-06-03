#!/usr/bin/env python3
"""
Scan Results Report Generator
Parses the scan_results.jsonl file and generates a readable report
"""

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Any

def load_scan_results(file_path: str) -> List[Dict[str, Any]]:
    """Load scan results from a JSONL file."""
    results = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    results.append(json.loads(line))
        return results
    except Exception as e:
        print(f"Error loading scan results: {e}")
        sys.exit(1)

def generate_report(results: List[Dict[str, Any]]) -> None:
    """Generate a comprehensive report from scan results."""
    if not results:
        print("No scan results found.")
        return
    
    # Count statistics
    total_requests = len(results)
    attack_types = Counter()
    status_codes = Counter()
    errors = Counter()
    urls_tested = set()
    
    # Group by attack type for detailed analysis
    attack_details = defaultdict(list)
    
    for entry in results:
        attack_type = entry.get('attack_type', 'unknown')
        attack_types[attack_type] += 1
        
        status = entry.get('status_code', 0)
        status_codes[status] += 1
        
        if entry.get('error'):
            errors[entry.get('error')] += 1
        
        urls_tested.add(entry.get('url', ''))
        
        # Add to attack details
        attack_details[attack_type].append(entry)
    
    # Print summary report
    print("\n" + "="*80)
    print(" "*30 + "VULNERABILITY SCAN REPORT")
    print("="*80)
    
    print(f"\nScan Summary:")
    print(f"  Total Requests:     {total_requests}")
    print(f"  Unique URLs Tested: {len(urls_tested)}")
    print(f"  Attack Types Used:  {len(attack_types)}")
    
    print("\nStatus Code Distribution:")
    for status, count in sorted(status_codes.items()):
        status_desc = ""
        if 200 <= status < 300:
            status_desc = "(Success)"
        elif 300 <= status < 400:
            status_desc = "(Redirect)"
        elif 400 <= status < 500:
            status_desc = "(Client Error)"
        elif 500 <= status < 600:
            status_desc = "(Server Error)"
        
        print(f"  HTTP {status} {status_desc}: {count} responses ({count/total_requests*100:.1f}%)")
    
    print("\nAttack Type Distribution:")
    for attack, count in attack_types.most_common():
        print(f"  {attack}: {count} requests ({count/total_requests*100:.1f}%)")
    
    # Potential vulnerabilities section
    print("\nPotential Vulnerabilities:")
    vulnerability_found = False
    
    # Check for SQL injection indicators
    sql_entries = attack_details.get('sql', [])
    sql_vulns = [e for e in sql_entries if 
                 (e.get('status_code') in [500, 200]) and 
                 any(x in e.get('content_preview', '').lower() for x in 
                     ['sql', 'syntax', 'mysql', 'oracle', 'error', 'exception'])]
    
    if sql_vulns:
        vulnerability_found = True
        print(f"\n  SQL Injection: {len(sql_vulns)} potential vulnerabilities")
        for i, vuln in enumerate(sql_vulns[:3], 1):  # Show top 3
            print(f"    {i}. URL: {vuln.get('url')}")
            print(f"       Payload: {vuln.get('payload')}")
            print(f"       Response: HTTP {vuln.get('status_code')}")
    
    # Check for XSS indicators
    xss_entries = attack_details.get('xss', [])
    xss_vulns = [e for e in xss_entries if 
                e.get('status_code') == 200 and 
                e.get('payload', '') in e.get('content_preview', '')]
    
    if xss_vulns:
        vulnerability_found = True
        print(f"\n  Cross-Site Scripting (XSS): {len(xss_vulns)} potential vulnerabilities")
        for i, vuln in enumerate(xss_vulns[:3], 1):  # Show top 3
            print(f"    {i}. URL: {vuln.get('url')}")
            print(f"       Payload: {vuln.get('payload')}")
            print(f"       Response: Payload reflected in response")
    
    # Check for path traversal
    path_entries = attack_details.get('path', [])
    path_vulns = [e for e in path_entries if 
                 e.get('status_code') == 200 and 
                 any(x in e.get('content_preview', '').lower() for x in 
                     ['root:', 'etc', 'passwd', 'win.ini', 'system32'])]
    
    if path_vulns:
        vulnerability_found = True
        print(f"\n  Path Traversal: {len(path_vulns)} potential vulnerabilities")
        for i, vuln in enumerate(path_vulns[:3], 1):  # Show top 3
            print(f"    {i}. URL: {vuln.get('url')}")
            print(f"       Payload: {vuln.get('payload')}")
            print(f"       Response contains sensitive file content")
    
    # If no vulnerabilities were found
    if not vulnerability_found:
        print("  No clear vulnerabilities detected in the scan results.")
    
    # Error summary
    if errors:
        print("\nErrors Encountered:")
        for error, count in errors.most_common(5):  # Top 5 errors
            print(f"  {error}: {count} occurrences")
    
    # بعد ملخص الهجمات، أضف قسم جديد لكشف مؤشرات كل الثغرات بناءً على محتوى الرد
    print("\nVulnerability Indicators (based on response content):")
    INDICATORS = {
        "sql": [
            "sql syntax", "mysql", "error in your sql syntax", "unexpected token",
            "unterminated string", "warning:", "you have an error in your sql syntax", "syntax error", "sqlite", "psql", "pg_query", "oracle", "mssql", "native client", "unclosed quotation mark"
        ],
        "xss": [
            "<script", "<img", "<svg", "onerror", "alert(", "javascript:", "payload reflected", "<iframe", "ontoggle", "<math"
        ],
        "ssrf": [
            "127.0.0.1", "localhost", "internal server error", "connection refused", "cannot connect", "refused to connect", "aws metadata", "169.254.169.254"
        ],
        "path": [
            "root:", "/etc/passwd", "c:\\windows", "win.ini", "system32", "boot.ini", "[boot loader]"
        ],
        "command": [
            "uid=", "gid=", "root:x:", "command not found", "No such file or directory", "sh: ", "bash: ", "syntax error near unexpected token"
        ],
        "xxe": [
            "xml parser", "entity", "DOCTYPE", "SYSTEM", "external entity", "parser error"
        ],
        "ssti": [
            "jinja", "mustache", "template syntax error", "{{7*7}}", "500 internal server error", "unexpected 'end of file'"
        ],
    }
    # استخرج فقط الأنواع التي تم اختبارها فعليًا
    tested_types = set(entry.get('attack_type') for entry in results)
    for vuln_type, keywords in INDICATORS.items():
        if vuln_type not in tested_types:
            continue  # لا تطبع إلا الأنواع التي تم اختبارها
        print(f"\n{vuln_type.upper()} Indicators:")
        found = 0
        for entry in results:
            if entry.get('attack_type') != vuln_type:
                continue
            content = entry.get("content_preview", "").lower()
            if any(k in content for k in keywords):
                found += 1
                print(f"[!] Potential {vuln_type.upper()} at {entry['url']}")
                print(f"    Payload: {entry['payload']}")
                print(f"    Response: {content[:120]}")
        if found == 0:
            print(f"  No {vuln_type.upper()} indicators found in response content.")
    
    print("\n" + "="*80)
    print(" "*25 + "END OF VULNERABILITY SCAN REPORT")
    print("="*80 + "\n")

if __name__ == "__main__":
    # Default path or command line argument
    results_file = sys.argv[1] if len(sys.argv) > 1 else "./agent/scan_results.jsonl"
    
    print(f"Loading scan results from: {results_file}")
    results = load_scan_results(results_file)
    
    print(f"Loaded {len(results)} scan result entries.")
    generate_report(results)
