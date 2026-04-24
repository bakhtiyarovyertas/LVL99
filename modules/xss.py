"""Cross-Site Scripting (XSS) Scanner — OWASP A03:2021.

Improvements over v1:
  - Tests EVERY form field on every crawled page, not just login-page forms
  - Tests every URL query parameter
  - DOM-based XSS detection via response body inspection
  - Stored XSS detection (submit, then re-fetch and check)
  - Skips non-HTML responses cleanly
  - Uses a dedup key so identical endpoint+param combos are not repeated
"""
import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from core.base_scanner import BaseScanner
from core.logger import vuln, debug, info

MARKER = "lv99xss"

# ── Built-in reflected payloads (non-empty wordlist fallback) ─────────────────
BUILTIN_PAYLOADS = [
    f"<script>{MARKER}()</script>",
    f"\"><script>{MARKER}()</script>",
    f"'><script>{MARKER}()</script>",
    f"<img src=x onerror={MARKER}()>",
    f"<svg onload={MARKER}()>",
    f"</title><script>{MARKER}()</script>",
    f"<body onload={MARKER}()>",
    f"<ScRiPt>{MARKER}()</ScRiPt>",
    f"javascript:{MARKER}()",
    f"<iframe src=\"javascript:{MARKER}()\">",
    f"\"><img src=x onerror={MARKER}()>",
    f"'><img src=x onerror={MARKER}()>",
    f"<details open ontoggle={MARKER}()>",
    f"<input autofocus onfocus={MARKER}()>",
    f"<marquee onstart={MARKER}()>",
    f"%3Cscript%3E{MARKER}()%3C/script%3E",
]

DETECT_RE = re.compile(re.escape(MARKER), re.IGNORECASE)


class XSSScanner(BaseScanner):
    MODULE_NAME = "xss"
    OWASP_CATEGORY = "A03:2021 - Injection"

    def scan(self, urls: list) -> list:
        payloads = self.session.load_wordlist("xss") or BUILTIN_PAYLOADS
        findings = []
        tested = set()

        for url in urls:
            # ── URL query parameters ──
            params = self.get_url_params(url)
            for param in params:
                key = f"url:{url}:{param}"
                if key in tested:
                    continue
                tested.add(key)
                found = self._test_url_param(url, param, payloads)
                if found:
                    findings.append(found)
                    info(f"    → XSS found, continuing with other params")

            # ── All forms on the page ──
            forms = self.get_forms(url)
            for form in forms:
                if form["method"] not in ("POST", "GET"):
                    continue
                for field in form["inputs"]:
                    itype = self._guess_field_type(field, form)
                    if itype in ("hidden", "submit", "csrf"):
                        continue
                    key = f"form:{form['url']}:{field}"
                    if key in tested:
                        continue
                    tested.add(key)
                    found = self._test_form_field(form, field, payloads)
                    if found:
                        findings.append(found)

            # ── Stored XSS: submit to forms, re-fetch display pages ──
            findings.extend(self._test_stored_xss(url, forms, payloads, tested))

        return findings

    # ── URL parameter injection ───────────────────────────────────────────────

    def _test_url_param(self, url, param, payloads):
        for payload in payloads:
            injected = self.inject_param(url, param, payload)
            resp = self.session.get(injected)
            if not resp:
                continue
            if "html" not in resp.headers.get("content-type", ""):
                continue
            if DETECT_RE.search(resp.text):
                f = self.make_finding(
                    url=url, param=param, payload=payload,
                    evidence=self._extract_context(resp.text),
                    severity="HIGH",
                    description=f"Reflected XSS: parameter '{param}' reflects payload unescaped.",
                    remediation=(
                        "Apply context-aware output encoding. Implement a strict "
                        "Content-Security-Policy. Use HTTPOnly + Secure cookie flags."
                    ),
                )
                vuln(f"  [VULN] XSS (reflected/param) @ {url} | param={param}")
                return f
        return None

    # ── Form field injection ──────────────────────────────────────────────────

    def _test_form_field(self, form, field, payloads):
        for payload in payloads:
            results = self.test_form(form, payload, field_override=field)
            for fname, resp in results:
                if not resp:
                    continue
                if "html" not in resp.headers.get("content-type", ""):
                    continue
                if DETECT_RE.search(resp.text):
                    f = self.make_finding(
                        url=form["url"], param=field, payload=payload,
                        evidence=self._extract_context(resp.text),
                        severity="HIGH",
                        description=f"Reflected XSS via form field '{field}' on {form['url']}.",
                        remediation=(
                            "Encode output using context-aware escaping. "
                            "Implement CSP headers. Use HttpOnly + Secure cookies."
                        ),
                    )
                    vuln(f"  [VULN] XSS (form) @ {form['url']} | field={field}")
                    return f
        return None

    # ── Stored XSS ────────────────────────────────────────────────────────────

    def _test_stored_xss(self, page_url, forms, payloads, tested):
        """
        For forms that might persist data (guestbook, comments, feedback, profile,
        message, etc.), submit a payload then re-fetch the page to check persistence.
        """
        findings = []
        STORE_KEYWORDS = re.compile(
            r"comment|message|note|feedback|guestbook|post|submit|content"
            r"|description|text|name|subject|title|review|reply",
            re.IGNORECASE,
        )

        for form in forms:
            if form["method"] != "POST":
                continue
            # Only test forms that look like they store data
            combined = form["url"] + " ".join(form["inputs"].keys())
            if not STORE_KEYWORDS.search(combined):
                continue

            for field in form["inputs"]:
                if self._guess_field_type(field, form) in ("hidden", "submit", "csrf"):
                    continue
                key = f"stored:{form['url']}:{field}"
                if key in tested:
                    continue
                tested.add(key)

                payload = payloads[0] if payloads else BUILTIN_PAYLOADS[0]
                # Submit the form
                self.test_form(form, payload, field_override=field)
                # Re-fetch the page that should display stored content
                display_pages = [page_url, form["url"], form.get("page", page_url)]
                for dp in display_pages:
                    resp = self.session.get(dp)
                    if resp and DETECT_RE.search(resp.text):
                        f = self.make_finding(
                            url=form["url"], param=field, payload=payload,
                            evidence=self._extract_context(resp.text),
                            severity="CRITICAL",
                            description=(
                                f"Stored XSS: payload submitted to '{form['url']}' field '{field}' "
                                f"was rendered unescaped on '{dp}'."
                            ),
                            remediation=(
                                "Sanitize stored content before rendering. Use output encoding. "
                                "Implement a strict Content-Security-Policy."
                            ),
                        )
                        vuln(f"  [VULN] XSS (STORED) @ {form['url']} | field={field} → reflected on {dp}")
                        findings.append(f)
                        break
        return findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _guess_field_type(self, field_name: str, form: dict) -> str:
        """Classify a form field to skip non-injectable ones."""
        fn = field_name.lower()
        if any(t in fn for t in ["token", "csrf", "nonce", "_method", "authenticity"]):
            return "csrf"
        if any(t in fn for t in ["submit", "button"]):
            return "submit"
        # Check if it's a hidden field with a token-like value
        val = form["inputs"].get(field_name, "")
        if len(val) > 20 and re.match(r"[a-f0-9]{20,}|[A-Za-z0-9+/]{20,}", val):
            return "hidden"
        return "text"

    def _extract_context(self, text: str) -> str:
        m = DETECT_RE.search(text)
        if m:
            start = max(0, m.start() - 60)
            end = min(len(text), m.end() + 60)
            return text[start:end].strip()
        return f"{MARKER} marker reflected in response"
