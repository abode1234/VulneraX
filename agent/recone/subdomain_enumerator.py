# agents/recon/subdomain_enumerator.py

import requests
import json
import time
from typing import List

def crtsh_enum(domain: str) -> List[str]:
    """
    Uses crt.sh to enumerate subdomains.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        print(f"[*] Querying crt.sh for {domain}...")
        resp = requests.get(url, timeout=100)
        if resp.status_code != 200:
            print(f"[!] crt.sh returned status code {resp.status_code}")
            return []

        entries = json.loads(resp.text)
        subdomains = set()
        for entry in entries:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                if sub.endswith(domain):
                    subdomains.add(sub.strip())

        return sorted(subdomains)
    except Exception as e:
        print(f"[!] Error during crt.sh enumeration: {e}")
        return []


def save_subdomains(domain: str, subdomains: List[str], filepath: str = "data/subdomains.json"):
    """
    Saves the enumerated subdomains to a JSON file.
    """
    try:
        data = {"domain": domain, "subdomains": subdomains, "count": len(subdomains), "timestamp": time.time()}
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Saved {len(subdomains)} subdomains to {filepath}")
    except Exception as e:
        print(f"[!] Failed to save subdomains: {e}")


def main():
    target_domain = input("Enter the domain (e.g., example.com): ").strip()
    subs = crtsh_enum(target_domain)
    if subs:
        for s in subs:
            print(f" - {s}")
        save_subdomains(target_domain, subs)
    else:
        print("[!] No subdomains found.")


if __name__ == "__main__":
    main()

