"""Load payload lists for each attack type from payloads/ text files."""

from pathlib import Path
from typing import Dict, Iterator, List, Tuple

from .encode_utils import ENCODERS

PAYLOAD_DIR = Path(__file__).resolve().parent.parent / "payloads"

class UnknownAttackType(ValueError):
    pass

def list_attack_types() -> List[str]:
    """Return all .txt names (without extension) found under payloads/."""
    return [p.stem for p in PAYLOAD_DIR.glob("*.txt")]

def load_payloads(attack: str) -> List[str]:
    attack = attack.lower()
    file_path = PAYLOAD_DIR / f"{attack}.txt"
    if not file_path.exists():
        raise UnknownAttackType(f"No payload list for attack type '{attack}'.")
    with file_path.open(encoding="utf-8") as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")]

class PayloadLoader:
    """Loads payloads from files and applies encoding variants."""
    
    def __init__(self, verbose: bool = False):
        """Initialize the payload loader.
        
        Args:
            verbose: If True, print detailed information about loaded payloads
        """
        self.attack_types = list_attack_types()
        self.verbose = verbose
        self.payload_counts = {}
        
        if self.verbose:
            print(f"[*] Found {len(self.attack_types)} attack types: {', '.join(self.attack_types)}")
    
    def get_payload_stats(self) -> Dict[str, int]:
        """Get statistics about loaded payloads.
        
        Returns:
            Dictionary mapping attack types to payload counts
        """
        if not self.payload_counts:
            # Lazy load the counts if not already calculated
            for attack_type in self.attack_types:
                try:
                    self.payload_counts[attack_type] = len(load_payloads(attack_type))
                except UnknownAttackType:
                    self.payload_counts[attack_type] = 0
        
        return self.payload_counts
    
    def print_payload_stats(self) -> None:
        """Print statistics about available payloads."""
        stats = self.get_payload_stats()
        total = sum(stats.values())
        
        print("\n[*] Payload Statistics:")
        print(f"    Total unique payloads: {total}")
        print("    Breakdown by attack type:")
        
        for attack_type, count in sorted(stats.items(), key=lambda x: x[1], reverse=True):
            print(f"      - {attack_type}: {count} payloads")
    
    def iter_attack_payloads(self) -> Iterator[Tuple[str, List[str]]]:
        """Iterate through all attack types and their payloads with encodings.
        
        Yields:
            Tuples of (attack_type, encoded_payloads)
        """
        for attack_type in self.attack_types:
            try:
                payloads = load_payloads(attack_type)
                encoded_payloads = []
                
                # Apply each encoder to each payload
                for payload in payloads:
                    for encoder_name, encoder_func in ENCODERS.items():
                        encoded = encoder_func(payload)
                        encoded_payloads.append(encoded)
                
                if self.verbose:
                    print(f"[*] Loaded {len(payloads)} payloads for {attack_type} attack type")
                    print(f"    Total with encodings: {len(encoded_payloads)}")
                
                yield attack_type, encoded_payloads
            except UnknownAttackType as e:
                if self.verbose:
                    print(f"[!] Warning: {e}")
                continue
