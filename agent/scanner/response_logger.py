"""Centralised JSONL logger – one line per test case."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

LOG_FILE = Path(__file__).resolve().parent.parent / "scan_results.jsonl"
LOG_FILE.touch(exist_ok=True)

def log(entry: Dict[str, Any]) -> None:
    entry["ts"] = datetime.now(timezone.utc).isoformat()
    with LOG_FILE.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(entry, ensure_ascii=False) + "\n")


class ResponseLogger:
    """Logs scan responses to a JSONL file."""
    
    def __init__(self, log_file: str = "scan_results.jsonl"):
        """Initialize the response logger with a log file path."""
        self.log_file = Path(__file__).resolve().parent.parent / log_file
        self.log_file.touch(exist_ok=True)
    
    def handle_response(self, response: Dict[str, Any], attack_type: str, payload: str) -> None:
        """Process and log a response from a scan."""
        # Extract relevant data from the response
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attack_type": attack_type,
            "payload": payload,
            "url": response.get("url", ""),
            "status_code": response.get("status_code", 0),
            "headers": response.get("headers", {}),
            "content_preview": response.get("content", "")[:200],  # First 200 chars only
            "error": response.get("error")
        }
        
        # Write to log file
        with self.log_file.open("a", encoding="utf-8") as fp:
            fp.write(json.dumps(entry, ensure_ascii=False) + "\n")
