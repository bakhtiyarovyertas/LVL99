"""CSRF Protection Scanner - OWASP A01:2021 Broken Access Control / A05:2021."""
import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from core.base_scanner import BaseScanner
from core.logger import vuln, debug, info

CSRF_TOKEN_NAMES = [
    "csrf", "csrf_token", "csrftoken", "_csrf", "csrfmiddlewaretoken",
    "_token", "authenticity_token", "xsrf_token", "_xsrf", "token",
    "form_token", "request_token", "security_token", "__RequestVerificationToken",
    "nonce", "state", "antiforgery",
]

SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}

SAMESITE_COOKIE_RE = re.compile(r"samesite\s*=\s*(strict|lax)", re.IGNORECASE)
HTTPONLY_RE = re.compile(r"httponly", re.IGNORECASE)
SECURE_RE = re.compile(r";\s*secure", re.IGNORECASE)

CSRF_HEADERS = [
    "X-CSRF-Token",
    "X-CSRFToken",
    "X-XSRF-TOKEN",
    "X-Requested-With",
    "Anti-CSRF-Token",
]


class CSRFScanner(BaseScanner):
    MODULE_NAME = "csrf"
    OWASP_CATEGORY = "A01:2021 - Broken Access Control"

    def scan(self, urls: list) -> list:
        findings = []
        tested_forms = set()
        tested_endpoints = set()

        for url in urls:
            if url in tested_endpoints:
                continue
            tested_endpoints.add(url)

            # Check response headers
            resp = self.session.get(url)
            if not resp:
                continue

            # 1. Check CSRF headers on response
            findings.extend(self._check_security_headers(url, resp))

            # 2. Check cookies
            findings.extend(self._check_cookies(url, resp))

            # 3. Check forms on this page
            forms = self._extract_forms_full(url, resp.text)
            for form in forms:
                form_key = f"{form['url']}:{form['method']}:{','.join(sorted(form['inputs'].keys()))}"
                if form_key in tested_forms:
                    continue
                tested_forms.add(form_key)
                findings.extend(self._check_form(url, form))

        # 4. Check CORS policy
        findings.extend(self._check_cors(self.session.url))

        return findings

    def _extract_forms_full(self, page_url: str, html: str):
        forms = []
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            return forms
        for form in soup.find_all("form"):
            action = form.get("action", page_url)
            method = form.get("method", "GET").upper()
            abs_action = urljoin(page_url, action)
            inputs = {}
            hidden_fields = {}
            has_csrf_token = False

            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name", "")
                if not name:
                    continue
                val = inp.get("value", "") or ""
                inputs[name] = val
                if inp.get("type", "").lower() == "hidden":
                    hidden_fields[name] = val
                    if any(t in name.lower() for t in CSRF_TOKEN_NAMES):
                        has_csrf_token = True
                        debug(f"  CSRF token found: {name}={val[:20]}")

            forms.append({
                "url": abs_action,
                "method": method,
                "inputs": inputs,
                "hidden": hidden_fields,
                "has_csrf_token": has_csrf_token,
                "page": page_url,
                "html": str(form),
            })
        return forms

    def _check_form(self, page_url: str, form: dict):
        findings = []
        method = form["method"]

        # Only state-changing methods are CSRF-relevant
        if method in SAFE_METHODS:
            return findings

        info(f"  [~] Checking form: {form['url']} [{method}]")

        # Check 1: No CSRF token at all
        if not form["has_csrf_token"]:
            f = self.make_finding(
                url=form["url"], param="form", payload="N/A",
                evidence=f"Form [{method}] has no CSRF token. Inputs: {list(form['inputs'].keys())}",
                severity="HIGH",
                description=(
                    f"CSRF vulnerability: {method} form at {form['url']} (discovered at {page_url}) "
                    f"has no anti-CSRF token. An attacker can forge cross-site requests."
                ),
                remediation=(
                    "Add a secret, unpredictable, per-session CSRF token to all state-changing forms. "
                    "Validate the token server-side. Use SameSite=Strict cookie attribute."
                ),
            )
            vuln(f"  [VULN] CSRF - No token in form @ {form['url']}")
            findings.append(f)

        else:
            # Check 2: Token present - try submitting without it
            findings.extend(self._try_bypass_csrf_token(form))

        # Check 3: Content-Type bypass check (JSON CSRF)
        findings.extend(self._check_json_csrf(form))

        return findings

    def _try_bypass_csrf_token(self, form: dict):
        """Try submitting form without the CSRF token."""
        findings = []
        inputs_no_csrf = {k: v for k, v in form["inputs"].items()
                          if not any(t in k.lower() for t in CSRF_TOKEN_NAMES)}
        # Try without token
        if form["method"] == "POST":
            resp = self.session.post(form["url"], data=inputs_no_csrf)
        else:
            resp = self.session.get(form["url"], params=inputs_no_csrf)

        if resp and resp.status_code in (200, 302, 301):
            # Check if we get a CSRF rejection message
            rejection_words = ["csrf", "token", "invalid", "forbidden", "403", "rejected", "mismatch"]
            body_lower = resp.text.lower()
            rejected = any(w in body_lower for w in rejection_words)
            if not rejected and resp.status_code != 403:
                f = self.make_finding(
                    url=form["url"], param="csrf_token", payload="(token omitted)",
                    evidence=f"Server returned HTTP {resp.status_code} without CSRF token in request",
                    severity="MEDIUM",
                    description="CSRF token may not be validated server-side. Request succeeded without token.",
                    remediation="Validate CSRF token server-side on every state-changing request.",
                )
                vuln(f"  [VULN] CSRF - Token bypass possible @ {form['url']}")
                findings.append(f)
            else:
                debug(f"  CSRF token validated correctly @ {form['url']}")
        return findings

    def _check_json_csrf(self, form: dict):
        """Check if endpoint accepts JSON without CSRF token (JSON CSRF)."""
        findings = []
        json_data = {k: "test" for k in form["inputs"] if not any(t in k.lower() for t in CSRF_TOKEN_NAMES)}
        resp = self.session.post(
            form["url"],
            json=json_data,
            headers={"Content-Type": "application/json"},
        )
        if resp and resp.status_code not in (400, 403, 415, 422):
            f = self.make_finding(
                url=form["url"], param="Content-Type", payload="application/json",
                evidence=f"Endpoint accepted JSON content-type without CSRF token (HTTP {resp.status_code})",
                severity="MEDIUM",
                description="JSON CSRF: The endpoint may accept JSON requests without CSRF token validation.",
                remediation="Reject requests with non-standard content types or validate CSRF for all state changes.",
                vulnerable=True,
            )
            findings.append(f)
        return findings

    def _check_security_headers(self, url: str, resp) -> list:
        findings = []
        headers = {k.lower(): v for k, v in resp.headers.items()}

        # Missing X-Frame-Options (clickjacking enabling CSRF)
        if "x-frame-options" not in headers and "content-security-policy" not in headers:
            f = self.make_finding(
                url=url, param="X-Frame-Options", payload="N/A",
                evidence="Neither X-Frame-Options nor CSP frame-ancestors header present",
                severity="MEDIUM",
                description="Missing X-Frame-Options allows UI Redressing / Clickjacking which can aid CSRF.",
                remediation="Add: X-Frame-Options: DENY or Content-Security-Policy: frame-ancestors 'none'",
            )
            findings.append(f)

        # Missing CSRF-related response headers
        if "x-content-type-options" not in headers:
            f = self.make_finding(
                url=url, param="X-Content-Type-Options", payload="N/A",
                evidence="X-Content-Type-Options header not set",
                severity="LOW",
                description="Missing X-Content-Type-Options: nosniff header.",
                remediation="Add: X-Content-Type-Options: nosniff",
            )
            findings.append(f)

        return findings

    def _check_cookies(self, url: str, resp) -> list:
        findings = []
        cookies = resp.headers.get("Set-Cookie", "")
        if not cookies:
            return findings

        if not SAMESITE_COOKIE_RE.search(cookies):
            f = self.make_finding(
                url=url, param="Set-Cookie", payload="N/A",
                evidence=f"Cookie set without SameSite attribute: {cookies[:100]}",
                severity="MEDIUM",
                description="Session cookie missing SameSite=Strict/Lax attribute. Makes CSRF easier.",
                remediation="Set SameSite=Strict or SameSite=Lax on all session cookies.",
            )
            findings.append(f)

        if not HTTPONLY_RE.search(cookies):
            f = self.make_finding(
                url=url, param="Set-Cookie", payload="N/A",
                evidence=f"Cookie set without HttpOnly flag",
                severity="MEDIUM",
                description="Session cookie missing HttpOnly flag. Accessible via JavaScript (XSS risk).",
                remediation="Add HttpOnly flag to all session cookies.",
            )
            findings.append(f)

        return findings

    def _check_cors(self, url: str) -> list:
        findings = []
        # Try with a spoofed Origin
        resp = self.session.get(url, headers={"Origin": "https://evil.com"})
        if not resp:
            return findings
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*" and acac.lower() == "true":
            f = self.make_finding(
                url=url, param="CORS", payload="Origin: https://evil.com",
                evidence=f"Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
                severity="CRITICAL",
                description="Misconfigured CORS: wildcard origin with credentials. Any origin can make credentialed requests.",
                remediation="Never use * with Allow-Credentials. Whitelist specific trusted origins.",
            )
            vuln(f"  [VULN] CORS misconfiguration @ {url}")
            findings.append(f)
        elif acao == "https://evil.com":
            f = self.make_finding(
                url=url, param="CORS", payload="Origin: https://evil.com",
                evidence=f"Access-Control-Allow-Origin reflects arbitrary origin: {acao}",
                severity="HIGH",
                description="CORS origin reflection: server reflects any Origin header value.",
                remediation="Validate Origin against a strict whitelist before reflecting.",
            )
            vuln(f"  [VULN] CORS origin reflection @ {url}")
            findings.append(f)
        return findings
