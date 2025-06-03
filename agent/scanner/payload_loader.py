"""Load payload lists for each attack type from payloads/ text files."""

from pathlib import Path
from typing import Dict, Iterator, List, Tuple
import os
from dotenv import load_dotenv
import openai

from .encode_utils import ENCODERS

PAYLOAD_DIR = Path(__file__).resolve().parent.parent / "payloads"

# تحميل متغيرات البيئة من .env
load_dotenv()
if not os.getenv("OPENAI_API_KEY"):
    raise RuntimeError("OPENAI_API_KEY not found in environment. Please set it in your .env file.")

class UnknownAttackType(ValueError):
    pass

def list_attack_types() -> List[str]:
    """Return all .txt names (without extension) found under payloads/, except SSRF."""
    return [p.stem for p in PAYLOAD_DIR.glob("*.txt") if p.stem.lower() != "ssrf"]

def load_payloads(attack: str) -> List[str]:
    attack = attack.lower()
    file_path = PAYLOAD_DIR / f"{attack}.txt"
    if not file_path.exists():
        raise UnknownAttackType(f"No payload list for attack type '{attack}'.")
    with file_path.open(encoding="utf-8") as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")]

def generate_payloads_with_gpt(attack_type: str, n: int = 5) -> list[str]:
    """استخدم OpenAI GPT لتوليد قائمة من payloads حسب نوع الهجوم المطلوب."""
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not found in environment.")
    client = openai.OpenAI(api_key=api_key)
    prompt = f"Generate {n} unique and effective payloads for {attack_type} attacks. Only output the payloads as a plain list, no explanations."
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=256,
        n=1,
        temperature=0.7,
    )
    # استخرج الـ payloads كسطور نصية
    content = response.choices[0].message.content
    payloads = [line.strip('- ').strip() for line in content.split('\n') if line.strip()]
    return [p for p in payloads if p]

class PayloadLoader:
    """Loads payloads from files and applies encoding variants."""
    
    def __init__(self, verbose: bool = False, attack_types: list = None, use_base64: bool = True, use_gpt: bool = False, gpt_payloads_per_type: int = 5):
        """Initialize the payload loader.
        
        Args:
            verbose: If True, print detailed information about loaded payloads
            attack_types: Optional list of attack types to use (subset of available)
            use_base64: If False, do not use base64 encoding for payloads
            use_gpt: If True, use GPT to generate payloads
            gpt_payloads_per_type: Number of payloads to generate for each attack type using GPT
        """
        all_types = list_attack_types()
        if attack_types:
            # Normalize and filter
            self.attack_types = [t for t in all_types if t in [a.lower() for a in attack_types]]
        else:
            self.attack_types = all_types
        self.verbose = verbose
        self.payload_counts = {}
        self.use_base64 = use_base64
        self.use_gpt = use_gpt
        self.gpt_payloads_per_type = gpt_payloads_per_type
        
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
                if self.use_gpt:
                    payloads = generate_payloads_with_gpt(attack_type, self.gpt_payloads_per_type)
                else:
                    payloads = load_payloads(attack_type)
                encoded_payloads = set()
                if not self.use_base64:
                    encoders = {"direct": ENCODERS["direct"]}
                else:
                    encoders = ENCODERS.copy()
                for payload in payloads:
                    for encoder_name, encoder_func in encoders.items():
                        encoded = encoder_func(payload)
                        encoded_payloads.add(encoded)
                encoded_payloads = list(encoded_payloads)
                if self.verbose:
                    print(f"[*] Loaded {len(payloads)} payloads for {attack_type} attack type")
                    print(f"    Total with encodings (unique): {len(encoded_payloads)})")
                yield attack_type, encoded_payloads
            except UnknownAttackType as e:
                if self.verbose:
                    print(f"[!] Warning: {e}")
                continue 