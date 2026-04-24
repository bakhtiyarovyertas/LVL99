"""Server-Side Template Injection (SSTI) Scanner — OWASP A03:2021."""
import re
from core.base_scanner import BaseScanner
from core.logger import vuln

SSTI_PROBES = [
    ("{{7*7}}",          r"49"),
    ("${7*7}",           r"49"),
    ("#{7*7}",           r"49"),
    ("<%= 7*7 %>",       r"49"),
    ("{{7*'7'}}",        r"7777777|49"),
    ("@(7*7)",           r"49"),
    ("${7*7}",           r"49"),
    ("*{7*7}",           r"49"),
    ("{{config}}",       r"Config|SECRET|APP_|DEBUG"),
    ("{{self}}",         r"Environment|Template|Context"),
    ("{{'abc'|upper}}",  r"ABC"),
]
SKIP_FIELD_RE = re.compile(r"token|csrf|nonce|_method|authenticity", re.IGNORECASE)


class SSTIScanner(BaseScanner):
    MODULE_NAME = "ssti"
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
                for probe, expect in SSTI_PROBES:
                    resp = self.session.get(self.inject_param(url, param, probe))
                    if resp and re.search(expect, resp.text):
                        findings.append(self.make_finding(
                            url=url, param=param, payload=probe,
                            evidence=re.search(expect, resp.text).group(0),
                            severity="CRITICAL",
                            description=f"SSTI: template expression '{probe}' evaluated in param '{param}'.",
                            remediation="Never pass user input directly to template engines. Use sandboxed rendering.",
                        ))
                        vuln(f"  [VULN] SSTI @ {url} param={param}")
                        break

            for form in self.get_forms(url):
                for field in form["inputs"]:
                    if SKIP_FIELD_RE.search(field):
                        continue
                    key = f"form:{form['url']}:{field}"
                    if key in tested:
                        continue
                    tested.add(key)
                    for probe, expect in SSTI_PROBES:
                        results = self.test_form(form, probe, field_override=field)
                        for _, resp in results:
                            if resp and re.search(expect, resp.text):
                                findings.append(self.make_finding(
                                    url=form["url"], param=field, payload=probe,
                                    evidence=re.search(expect, resp.text).group(0),
                                    severity="CRITICAL",
                                    description=f"SSTI via form field '{field}'.",
                                    remediation="Never pass user input to template engines.",
                                ))
                                vuln(f"  [VULN] SSTI (form) @ {form['url']} field={field}")
                                break
        return findings
