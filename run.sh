#!/bin/bash

# VulneraX - Bug Bounty Reconnaissance and Vulnerability Scanner
# This script runs the entire workflow: recon, scan, and report generation

# Set default values
THREADS=30
TIMEOUT=8
# PROXIES="http://127.0.0.1:8080"
MAX_PAGES=10
SCOPE_FILE="data/scope.txt"
MODE="workflow"
LOG_LEVEL="info"
OUTPUT_REPORT="vulnerability_report.txt"
SKIP_WILDCARDS=false

# Display banner
show_banner() {
    echo "=================================================="
    echo "  VulneraX - Bug Bounty Reconnaissance & Scanner  "
    echo "=================================================="
    echo ""
}

# Display help message
show_help() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --mode MODE          Set the operation mode (workflow, recon, scan, report)"
    echo "  --scope FILE         Path to a file containing scope domains"
    echo "  --threads NUM        Number of threads for scanning (default: $THREADS)"
    echo "  --timeout NUM        Request timeout in seconds (default: $TIMEOUT)"
    echo "  --proxies URL        Proxy URL (default: $PROXIES)"
    echo "  --max-pages NUM      Maximum pages to crawl per domain (default: $MAX_PAGES)"
    echo "  --log-level LEVEL    Log level (info, debug) (default: $LOG_LEVEL)"
    echo "  --output FILE        Output report file (default: $OUTPUT_REPORT)"
    echo "  --no-wildcards       Don't expand wildcard domains"
    echo "  --no-bruteforce      Disable bruteforce subdomain enumeration"
    echo "  --wordlist FILE      Path to a custom subdomain wordlist"
    echo "  --attack-types TYPES Comma-separated list of attack types to use"
    echo "  --user-agent STR     Custom User-Agent string for requests"
    echo "  --cookies STR        Cookies to include with requests (format: name=value;name2=value2)"
    echo "  --headers STR        Custom headers for requests (format: Header1:value1;Header2:value2)"
    echo "  --report-format FMT  Report format (txt, html, json)"
    echo "  --help               Show this help message"
    echo ""
    echo "Modes:"
    echo "  workflow  Run the entire workflow (recon + scan + report)"
    echo "  recon     Run only the reconnaissance phase"
    echo "  scan      Run only the vulnerability scanning phase"
    echo "  report    Generate a report from existing scan results"
    echo "  scope     List, add, or remove domains from scope"
    echo ""
    echo "Scope Options:"
    echo "  --list              List domains in scope"
    echo "  --add FILE          Add domains from file to scope"
    echo "  --remove DOMAIN     Remove a domain from scope"
    echo "  --clear             Clear all domains from scope"
    echo ""
    echo "Examples:"
    echo "  # Add domains to scope"
    echo "  $0 --mode scope --add domains.txt"
    echo "  "
    echo "  # Remove a domain from scope"
    echo "  $0 --mode scope --remove example.com"
    echo "  "
    echo "  # Run full workflow with custom settings"
    echo "  $0 --mode workflow --threads 50 --timeout 10 --proxies http://127.0.0.1:8080"
    echo "  "
    echo "  # Run recon with custom settings"
    echo "  $0 --mode recon --max-pages 20 --wordlist custom_wordlist.txt"
    echo "  "
    echo "  # Run scan with specific attack types"
    echo "  $0 --mode scan --attack-types sqli,xss --threads 30"
    echo "  "
    echo "  # Generate detailed report"
    echo "  $0 --mode report --output report.html --report-format html"
    echo ""
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --mode)
            MODE="$2"
            shift 2
            ;;
        --scope)
            SCOPE_FILE="$2"
            shift 2
            ;;
        --threads)
            THREADS="$2"
            shift 2
            ;;
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        --proxies)
            # PROXIES="$2"
            shift 2
            ;;
        --max-pages)
            MAX_PAGES="$2"
            shift 2
            ;;
        --log-level)
            LOG_LEVEL="$2"
            shift 2
            ;;
        --output)
            OUTPUT_REPORT="$2"
            shift 2
            ;;
        --no-wildcards)
            SKIP_WILDCARDS=true
            shift
            ;;
        --no-bruteforce)
            NO_BRUTEFORCE=true
            shift
            ;;
        --wordlist)
            WORDLIST="$2"
            shift 2
            ;;
        --attack-types)
            ATTACK_TYPES="$2"
            shift 2
            ;;
        --user-agent)
            USER_AGENT="$2"
            shift 2
            ;;
        --cookies)
            COOKIES="$2"
            shift 2
            ;;
        --headers)
            HEADERS="$2"
            shift 2
            ;;
        --no-base64)
            NO_BASE64=true
            shift
            ;;
        --report-format)
            REPORT_FORMAT="$2"
            shift 2
            ;;
        --list)
            SCOPE_ACTION="list"
            shift
            ;;
        --add)
            SCOPE_ACTION="add"
            SCOPE_FILE="$2"
            shift 2
            ;;
        --remove)
            SCOPE_ACTION="remove"
            SCOPE_DOMAIN="$2"
            shift 2
            ;;
        --clear)
            SCOPE_ACTION="clear"
            shift
            ;;
        --help)
            show_banner
            show_help
            exit 0
            ;;
        *)
            echo "[!] Unknown option: $key"
            show_help
            exit 1
            ;;
    esac
done

# Set up wildcard flag
WILDCARD_FLAG=""
if [ "$SKIP_WILDCARDS" = true ]; then
    WILDCARD_FLAG="--no-wildcards"
fi

# Set up bruteforce flag
BRUTEFORCE_FLAG=""
if [ "$NO_BRUTEFORCE" = true ]; then
    BRUTEFORCE_FLAG="--no-bruteforce"
fi

# Set up no-base64 flag
NO_BASE64_FLAG=""
if [ "$NO_BASE64" = true ]; then
    NO_BASE64_FLAG="--no-base64"
fi

# Run the selected mode
case "$MODE" in
    workflow)
        echo "[*] Starting VulneraX workflow with the following settings:"
        echo "    - Threads: $THREADS"
        echo "    - Timeout: $TIMEOUT seconds"
        echo "    - Max pages to crawl: $MAX_PAGES"
        echo "    - Log level: $LOG_LEVEL"
        echo "    - Report format: $REPORT_FORMAT"
        echo ""
        
        ./vulnerax_manager.py workflow --threads "$THREADS" --timeout "$TIMEOUT" \
            --max-pages "$MAX_PAGES" $WILDCARD_FLAG \
            $BRUTEFORCE_FLAG --wordlist "$WORDLIST" \
            --attack-types "$ATTACK_TYPES" --user-agent "$USER_AGENT" \
            --cookies "$COOKIES" --headers "$HEADERS" --report-format "$REPORT_FORMAT" \
            --output "$OUTPUT_REPORT" $NO_BASE64_FLAG
        
        echo ""
        echo "[+] Workflow completed"
        echo "[*] Results can be found in:"
        echo "    - Reconnaissance data: data/recon_full.json"
        echo "    - Scan targets: data/scan_targets.txt"
        echo "    - Scan results: agent/scan_results.jsonl"
        echo "    - Vulnerability report: $OUTPUT_REPORT"
        ;;
    
    recon)
        echo "[*] Starting reconnaissance with the following settings:"
        echo "    - Max pages to crawl: $MAX_PAGES"
        echo "    - Wordlist: ${WORDLIST:-'default'}"
        echo "    - Bruteforce: ${NO_BRUTEFORCE:-'enabled'}"
        echo ""
        
        ./vulnerax_manager.py recon --max-pages "$MAX_PAGES" $WILDCARD_FLAG \
            $BRUTEFORCE_FLAG --wordlist "$WORDLIST"
        
        echo ""
        echo "[+] Reconnaissance completed"
        echo "[*] Results can be found in:"
        echo "    - Reconnaissance data: data/recon_full.json"
        echo "    - Scan targets: data/scan_targets.txt"
        ;;
    
    scan)
        echo "[*] Starting vulnerability scan with the following settings:"
        echo "    - Threads: $THREADS"
        echo "    - Timeout: $TIMEOUT seconds"
        echo "    - Log level: $LOG_LEVEL"
        echo "    - Attack types: ${ATTACK_TYPES:-'all'}"
        echo "    - User-Agent: ${USER_AGENT:-'default'}"
        echo ""
        
        ./vulnerax_manager.py scan --threads "$THREADS" --timeout "$TIMEOUT" \
            --log-level "$LOG_LEVEL" \
            --attack-types "$ATTACK_TYPES" --user-agent "$USER_AGENT" \
            --cookies "$COOKIES" --headers "$HEADERS" $NO_BASE64_FLAG
        
        echo ""
        echo "[+] Scan completed"
        echo "[*] Results can be found in:"
        echo "    - Scan results: agent/scan_results.jsonl"
        ;;
    
    report)
        echo "[*] Generating vulnerability report"
        echo "    - Format: $REPORT_FORMAT"
        echo "    - Output file: $OUTPUT_REPORT"
        echo ""
        
        ./vulnerax_manager.py report --output "$OUTPUT_REPORT" \
            --format "$REPORT_FORMAT" --include-payloads
        
        echo ""
        echo "[+] Report generation completed"
        echo "[*] Report saved to: $OUTPUT_REPORT"
        ;;
    
    scope)
        echo "[*] Managing scope domains"
        
        case "$SCOPE_ACTION" in
            list)
                ./vulnerax_manager.py scope --list
                ;;
            add)
                if [ -z "$SCOPE_FILE" ]; then
                    echo "[!] Missing scope file. Use --add FILE"
                    exit 1
                fi
                ./vulnerax_manager.py scope --add "$SCOPE_FILE"
                ;;
            remove)
                if [ -z "$SCOPE_DOMAIN" ]; then
                    echo "[!] Missing domain. Use --remove DOMAIN"
                    exit 1
                fi
                ./vulnerax_manager.py scope --remove "$SCOPE_DOMAIN"
                ;;
            clear)
                ./vulnerax_manager.py scope --clear
                ;;
            *)
                echo "[!] Unknown scope action. Use --list, --add, --remove, or --clear"
                exit 1
                ;;
        esac
        ;;
    
    *)
        echo "[!] Unknown mode: $MODE"
        show_help
        exit 1
        ;;
esac

echo ""
echo "[+] VulneraX execution completed"
echo ""

# Display banner
show_banner

# Check if the vulnerax_manager.py script exists
if [ ! -f "./vulnerax_manager.py" ]; then
    echo "[!] Error: vulnerax_manager.py not found"
    exit 1
fi

# Make sure the script is executable
chmod +x ./vulnerax_manager.py

# Create data directory if it doesn't exist
mkdir -p data

# Handle custom scope file
if [ "$SCOPE_FILE" != "data/scope.txt" ] && [ -f "$SCOPE_FILE" ]; then
    echo "[*] Using custom scope file: $SCOPE_FILE"
    cp "$SCOPE_FILE" data/scope.txt
fi

# Set up wildcard flag
WILDCARD_FLAG=""
if [ "$SKIP_WILDCARDS" = true ]; then
    WILDCARD_FLAG="--no-wildcards"
fi

# Run the selected mode
case "$MODE" in
    workflow)
        echo "[*] Starting VulneraX workflow with the following settings:"
        echo "    - Threads: $THREADS"
        echo "    - Timeout: $TIMEOUT seconds"
        echo "    - Max pages to crawl: $MAX_PAGES"
        echo "    - Log level: $LOG_LEVEL"
        echo ""
        
        ./vulnerax_manager.py workflow --threads "$THREADS" --timeout "$TIMEOUT" \
            --max-pages "$MAX_PAGES" $WILDCARD_FLAG
        
        echo ""
        echo "[+] Workflow completed"
        echo "[*] Results can be found in:"
        echo "    - Reconnaissance data: data/recon_full.json"
        echo "    - Scan targets: data/scan_targets.txt"
        echo "    - Scan results: agent/scan_results.jsonl"
        echo "    - Vulnerability report: $OUTPUT_REPORT"
        ;;
    
    recon)
        echo "[*] Starting reconnaissance with the following settings:"
        echo "    - Max pages to crawl: $MAX_PAGES"
        echo ""
        
        ./vulnerax_manager.py recon --max-pages "$MAX_PAGES" $WILDCARD_FLAG
        
        echo ""
        echo "[+] Reconnaissance completed"
        echo "[*] Results can be found in:"
        echo "    - Reconnaissance data: data/recon_full.json"
        echo "    - Scan targets: data/scan_targets.txt"
        ;;
    
    scan)
        echo "[*] Starting vulnerability scan with the following settings:"
        echo "    - Threads: $THREADS"
        echo "    - Timeout: $TIMEOUT seconds"
        echo "    - Log level: $LOG_LEVEL"
        echo ""
        
        ./vulnerax_manager.py scan --threads "$THREADS" --timeout "$TIMEOUT" \
            --log-level "$LOG_LEVEL"
        
        echo ""
        echo "[+] Scan completed"
        echo "[*] Results can be found in:"
        echo "    - Scan results: agent/scan_results.jsonl"
        ;;
    
    report)
        echo "[*] Generating vulnerability report"
        echo "    - Output file: $OUTPUT_REPORT"
        echo ""
        
        ./vulnerax_manager.py report --output "$OUTPUT_REPORT"
        
        echo ""
        echo "[+] Report generation completed"
        echo "[*] Report saved to: $OUTPUT_REPORT"
        ;;
    
    scope)
        echo "[*] Managing scope domains"
        echo ""
        
        ./vulnerax_manager.py scope --list
        
        echo ""
        echo "[*] To add domains to scope, use: $0 --mode scope --add your_domains.txt"
        ;;
    
    *)
        echo "[!] Unknown mode: $MODE"
        show_help
        exit 1
        ;;
esac

echo ""
echo "[+] VulneraX execution completed"
echo ""
