"""HTTP helpers: inject parameter → send → return requests.Response."""

from __future__ import annotations

import warnings
from typing import Dict, Any, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

def _inject_get(url: str, param: str, value: str) -> str:
    # If param is None, try to replace the value after the last '=' in the URL
    if param is None:
        if '=' in url:
            base, _ = url.rsplit('=', 1)
            return f"{base}={value}"
        else:
            # No '=' in URL, just append payload
            return url + value
    # Default: replace param value as before
    parts = urlparse(url)
    qs = parse_qs(parts.query)
    qs[param] = value  # overwrite or add
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parts._replace(query=new_query))

def send_request(
    url: str,
    param: str,
    payload: str,
    method: str = "GET",
    json_body: bool = False,
    headers: Dict[str, str] | None = None,
    timeout: int = 10,
) -> requests.Response:
    """Build & dispatch a request with the injected payload."""

    hdrs: Dict[str, str] = {
        "User-Agent": "VulneraX‑Scanner/1.0",
        "Accept": "*/*",
    }
    if headers:
        hdrs.update(headers)

    if method.upper() == "GET":
        target_url = _inject_get(url, param, payload)
        return requests.get(target_url, headers=hdrs, timeout=timeout, verify=False)

    # POST / JSON
    if json_body:
        return requests.post(url, json={param: payload}, headers=hdrs, timeout=timeout, verify=False)

    return requests.post(url, data={param: payload}, headers=hdrs, timeout=timeout, verify=False)


class RequestSender:
    """Handles sending HTTP requests with injected payloads."""
    
    def __init__(self, timeout: int = 10, proxies: str = None):
        """Initialize the request sender with timeout and optional proxy."""
        self.timeout = timeout
        self.proxies = None
        if proxies:
            self.proxies = {"http": proxies, "https": proxies}
    
    def inject(self, url: str, payload: str) -> list[tuple[str, dict]]:
        """Inject a payload into every parameter in the URL and return a list of (modified URL, metadata)."""
        parts = urlparse(url)
        qs = parse_qs(parts.query)
        if not qs:
            # If no parameters, try to inject after last '='
            if '=' in url:
                injected_url = url.rsplit('=', 1)[0] + '=' + payload
                meta = {"method": "GET", "param": None, "payload": payload}
                return [(injected_url, meta)]
            else:
                # No '=' in URL, just append payload
                injected_url = url + payload
                meta = {"method": "GET", "param": None, "payload": payload}
                return [(injected_url, meta)]
        # If multiple parameters, inject payload into all and use POST
        if len(qs) > 1:
            injected_url = urlunparse(parts._replace(query=""))
            data = {param: payload for param in qs.keys()}
            meta = {
                "method": "POST",
                "param": list(qs.keys()),
                "payload": payload,
                "original_url": url,
                "data": data
            }
            return [(injected_url, meta)]
        # If only one parameter, keep previous logic (GET)
        injected = []
        for param in qs.keys():
            new_qs = qs.copy()
            new_qs[param] = [payload]
            new_query = urlencode(new_qs, doseq=True)
            injected_url = urlunparse(parts._replace(query=new_query))
            meta = {
                "method": "GET",
                "param": param,
                "payload": payload,
                "original_url": url
            }
            injected.append((injected_url, meta))
        return injected
    
    def send(self, url: str, meta: Dict[str, Any]) -> Dict[str, Any]:
        """Send the request and return the response with metadata."""
        try:
            method = meta.get("method", "GET")
            data = meta.get("data")
            payload = meta.get("payload")
            # Debug print before sending
            print(f"[DEBUG] Sending request: url={url} method={method} data={data} payload={payload}")
            if method == "POST":
                response = requests.post(
                    url,
                    data=data,
                    headers={"User-Agent": "VulneraX-Scanner/1.0"},
                    timeout=self.timeout,
                    proxies=self.proxies,
                    verify=False
                )
            else:
                response = requests.get(
                    url,
                    headers={"User-Agent": "VulneraX-Scanner/1.0"},
                    timeout=self.timeout,
                    proxies=self.proxies,
                    verify=False
                )
            # Debug print after response
            print(f"[DEBUG] Got response: url={url} status={response.status_code}")
            # Prepare response data
            result = {
                "url": url,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "content": response.text[:1000],  # Limit content size
                "meta": meta,
                "error": None
            }
            return result
        except Exception as e:
            # Debug print on error
            print(f"[DEBUG] Request error: url={url} error={e}")
            # Handle errors
            return {
                "url": url,
                "status_code": 0,
                "headers": {},
                "content": "",
                "meta": meta,
                "error": str(e)
            }
