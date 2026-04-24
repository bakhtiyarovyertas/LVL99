"""Code Injection Scanner - OWASP A03:2021."""
import re
from core.base_scanner import BaseScanner
from core.logger import vuln

CODE_PAYLOADS = [
    # PHP
    ("; echo lv188code;", r"lv188code"),
    ("'; echo lv188code; //", r"lv188code"),
    ("<?php echo 'lv188code'; ?>", r"lv188code"),
    ("${@print('lv188code')}", r"lv188code"),
    ("';print('lv188code');//", r"lv188code"),
    # Python
    ("__import__('os').popen('echo lv188code').read()", r"lv188code"),
    # Ruby
    ("%x{echo lv188code}", r"lv188code"),
    # Generic eval
    ("eval('lv188code')", r"lv188code"),
    # Node.js
    ("require('child_process').execSync('echo lv188code')", r"lv188code"),
    # Perl
    ("`echo lv188code`", r"lv188code"),
]


class CodeInjectionScanner(BaseScanner):
    MODULE_NAME = "code_inject"
    OWASP_CATEGORY = "A03:2021 - Injection"

    def scan(self, urls: list) -> list:
        findings = []
        tested = set()
        for url in urls:
            for param in self.get_url_params(url):
                key = f"{url}:{param}"
                if key in tested:
                    continue
                tested.add(key)
                for payload, sig in CODE_PAYLOADS:
                    resp = self.session.get(self.inject_param(url, param, payload))
                    if resp and re.search(sig, resp.text):
                        f = self.make_finding(
                            url=url, param=param, payload=payload,
                            evidence=re.search(sig, resp.text).group(0),
                            severity="CRITICAL",
                            description="Code Injection: injected code was executed server-side.",
                            remediation="Never eval() or exec() user input. Use safe parsing APIs.",
                        )
                        vuln(f"  [VULN] Code Injection @ {url} | param={param}")
                        findings.append(f)
                        break

            forms = self.get_forms(url)
            for form in forms:
                for field in form["inputs"]:
                    key = f"form:{form['url']}:{field}"
                    if key in tested:
                        continue
                    tested.add(key)
                    for payload, sig in CODE_PAYLOADS[:4]:
                        results = self.test_form(form, payload, field_override=field)
                        for fname, resp in results:
                            if resp and re.search(sig, resp.text):
                                f = self.make_finding(
                                    url=form["url"], param=field, payload=payload,
                                    evidence=re.search(sig, resp.text).group(0),
                                    severity="CRITICAL",
                                    description="Code Injection via form field.",
                                    remediation="Never eval() user input.",
                                )
                                findings.append(f)
                                break
        return findings
