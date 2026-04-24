"""Parse saved HTTP requests from Burp Suite and OWASP ZAP."""
import re
from urllib.parse import urlparse


def parse_burp_request(filepath: str) -> dict:
    """Parse a raw HTTP request file (Burp/ZAP format)."""
    with open(filepath, "r", errors="ignore") as f:
        raw = f.read()

    lines = raw.strip().splitlines()
    if not lines:
        raise ValueError("Empty request file")

    # First line: METHOD PATH HTTP/1.x
    first = lines[0].strip()
    parts = first.split()
    if len(parts) < 2:
        raise ValueError(f"Invalid request line: {first}")

    method = parts[0].upper()
    path = parts[1]

    headers = {}
    body = ""
    i = 1
    while i < len(lines) and lines[i].strip():
        line = lines[i]
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
        i += 1

    # Body after blank line
    if i < len(lines):
        body = "\n".join(lines[i+1:]).strip()

    host = headers.get("Host", "")
    scheme = "https" if headers.get("X-Forwarded-Proto", "http") == "https" else "http"
    url = f"{scheme}://{host}{path}"

    # Parse body params
    params = {}
    if body and "=" in body:
        for pair in body.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[k] = v

    return {
        "method": method,
        "url": url,
        "headers": headers,
        "body": body,
        "params": params,
        "path": path,
        "host": host,
        "raw": raw,
    }


def parse_zap_request(filepath: str) -> dict:
    """Alias - ZAP raw requests are same format as Burp."""
    return parse_burp_request(filepath)
