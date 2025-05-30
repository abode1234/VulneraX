# VulneraX - Advanced Bug Bounty Reconnaissance Tool

VulneraX is a powerful reconnaissance tool designed specifically for bug bounty hunters and security researchers. It automates the process of discovering vulnerabilities in web applications by performing comprehensive reconnaissance and scanning operations.

## Features

- Subdomain enumeration with multiple user agents
- Web crawling with parameter discovery
- Scope management for bug bounty programs
- Custom attack type selection
- Flexible configuration options
- Detailed reporting capabilities

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Required Python packages (automatically installed via setup)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/abode1234/VulneraX.git
cd VulneraX
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Step 1: Configure Scope

Before running any scans, you need to configure your target scope. This can be done in two ways:

1. Using scope.txt:
   - Edit `data/scope.txt` to add your target domains
   - Each domain should be on a new line
   - Use wildcards (e.g., `*.example.com`) for subdomain scope

2. Using command-line options:
```bash
./run.sh --add-domain example.com
./run.sh --remove-domain example.com
./run.sh --clear-domains
```

### Step 2: Run Reconnaissance

Basic usage:
```bash
./run.sh --target example.com
```

Advanced options:

1. Subdomain Enumeration:
```bash
./run.sh --target example.com --no-wildcards --no-bruteforce --wordlist custom-wordlist.txt
```

2. Web Crawling:
```bash
./run.sh --target example.com --cookies "session=123" --headers "X-Forwarded-For:127.0.0.1"
```

3. Attack Type Selection:
```bash
./run.sh --target example.com --attack-types "sql,xss,ssrf"
```

4. Custom User Agent:
```bash
./run.sh --target example.com --user-agent "Custom User Agent"
```

### Step 3: Output and Reporting

By default, results are saved in the `output` directory. You can specify a custom output location:
```bash
./run.sh --target example.com --output custom-report.txt
```

## Command-Line Options

```bash
./run.sh [options]

Options:
  --help                    Show this help message
  --target <domain>        Target domain to scan
  --output <file>          Output report file
  --no-wildcards           Skip wildcard subdomain detection
  --no-bruteforce          Skip subdomain bruteforce
  --wordlist <file>        Custom wordlist for bruteforce
  --attack-types <types>   Comma-separated list of attack types
  --user-agent <ua>        Custom User-Agent string
  --cookies <cookies>      Custom cookies
  --headers <headers>      Custom headers
  --add-domain <domain>    Add domain to scope
  --remove-domain <domain> Remove domain from scope
  --clear-domains          Clear all domains from scope
```

## Scope Management

VulneraX maintains a scope file (`data/scope.txt`) that contains all allowed domains for scanning. You can:

1. Add domains:
```bash
./run.sh --add-domain example.com
```

2. Remove domains:
```bash
./run.sh --remove-domain example.com
```

3. Clear all domains:
```bash
./run.sh --clear-domains
```

## Output Format

The tool generates comprehensive reports that include:
- Discovered subdomains
- Web endpoints and parameters
- Potential vulnerabilities
- Recommendations for further testing

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
