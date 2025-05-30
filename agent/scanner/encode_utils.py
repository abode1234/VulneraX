"""Helpers for generating the three encoding variants requested."""

import urllib.parse as _url

def direct(payload: str) -> str:
    """Return payload as‑is (direct attack)."""
    return payload

def full_encode(payload: str) -> str:
    """Percent‑encode all characters (فول تشفير)."""
    return _url.quote(payload, safe="")

def partial_encode(payload: str, safe_chars: str = "/:&?=") -> str:
    """Encode only dangerous characters, keep safe_chars readable (تشفير جزئي)."""
    return _url.quote(payload, safe=safe_chars)

ENCODERS = {
    "direct": direct,
    "full": full_encode,
    "partial": partial_encode,
}
