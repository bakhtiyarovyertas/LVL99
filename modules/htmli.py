"""HTML Injection Scanner — OWASP A03:2021."""
import re
from core.base_scanner import BaseScanner
from core.logger import vuln

BUILTIN_PAYLOADS = [
    "<h1>LVL99HTMLi</h1>",
    "<b>LVL99HTMLi</b>",
    "<marquee>LVL99HTMLi</marquee>",
    "<u>LVL99HTMLi</u>",
    "<i>LVL99HTMLi</i>",
    "</p><h1>LVL99HTMLi</h1>",
    "<br><h1>LVL99HTMLi</h1>",
]
DETECT_RE = re.compile(r"LVL99HTMLi", re.IGNORECASE)
SKIP_FIELD_RE = re.compile(r"token|csrf|nonce|_method|authenticity", re.IGNORECASE)


class HTMLiScanner(BaseScanner):
    MODULE_NAME = "htmli"
    OWASP_CATEGORY = "A03:2021 - Injection"

    def scan(self, urls: list) -> list:
        payloads = self.session.load_wordlist("htmli") or BUILTIN_PAYLOADS
        findings = []
        tested = set()

        for url in urls:
            for param in self.get_url_params(url):
                key = f"url:{url}:{param}"
                if key in tested:
                    continue
                tested.add(key)
                for payload in payloads:
                    resp = self.session.get(self.inject_param(url, param, payload))
                    if resp and "html" in resp.headers.get("content-type", "") and DETECT_RE.search(resp.text):
                        findings.append(self.make_finding(
                            url=url, param=param, payload=payload,
                            evidence=self._ctx(resp.text),
                            severity="MEDIUM",
                            description=f"HTML Injection in URL param '{param}'.",
                            remediation="Encode all user output. Use a Content-Security-Policy.",
                        ))
                        vuln(f"  [VULN] HTMLi @ {url} param={param}")
                        break

            for form in self.get_forms(url):
                for field in form["inputs"]:
                    if SKIP_FIELD_RE.search(field):
                        continue
                    key = f"form:{form['url']}:{field}"
                    if key in tested:
                        continue
                    tested.add(key)
                    for payload in payloads:
                        results = self.test_form(form, payload, field_override=field)
                        for _, resp in results:
                            if resp and "html" in resp.headers.get("content-type","") and DETECT_RE.search(resp.text):
                                findings.append(self.make_finding(
                                    url=form["url"], param=field, payload=payload,
                                    evidence=self._ctx(resp.text),
                                    severity="MEDIUM",
                                    description=f"HTML Injection via form field '{field}'.",
                                    remediation="Encode all user output. Use CSP.",
                                ))
                                vuln(f"  [VULN] HTMLi (form) @ {form['url']} field={field}")
                                break
        return findings

    def _ctx(self, text):
        m = DETECT_RE.search(text)
        if m:
            return text[max(0, m.start()-40):m.end()+40].strip()
        return "Payload reflected"
