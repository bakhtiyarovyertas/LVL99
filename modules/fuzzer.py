"""Fuzzer - generic payload fuzzing for all parameters."""
import re
from core.base_scanner import BaseScanner
from core.logger import vuln, debug, info

ERROR_SIGNS = re.compile(
    r"exception|traceback|stack trace|fatal error|undefined|null pointer|"
    r"segfault|core dump|unhandled|syntax error|parse error|internal server error",
    re.IGNORECASE
)

INTERESTING_STATUS = [500, 502, 503, 400]


class Fuzzer(BaseScanner):
    MODULE_NAME = "fuzz"
    OWASP_CATEGORY = "A05:2021 - Security Misconfiguration"

    def scan(self, urls: list) -> list:
        payloads = self.session.load_wordlist("fuzz") or [
            # Boundary values
            "A" * 1000, "A" * 5000,
            "%00", "%0d%0a", "\x00", "\n", "\r\n",
            # Special chars
            "!@#$%^&*()", "<>'\"|;:,./`~",
            "../../../../",
            "${{}}", "{{7*7}}",
            # Numeric edge cases
            "-1", "0", "99999999", "2147483647", "-2147483648",
            "NaN", "Infinity", "null", "undefined", "true", "false",
            # Format strings
            "%s%s%s%s%s", "%d%d%d%d",
            "%x%x%x%x",
            # Unicode
            "\u0000", "\uffff", "\ud800",
            # SQL
            "'", '"', "\\", "--", "/*", "*/",
            # Path
            "/", "//", "\\", "..", "../",
        ]

        findings = []
        tested = set()
        info(f"  [~] Fuzzing {len(urls)} URLs with {len(payloads)} payloads")

        for url in urls:
            params = self.get_url_params(url)
            for param in params:
                key = f"{url}:{param}"
                if key in tested:
                    continue
                tested.add(key)

                baseline = self.session.get(url)
                baseline_status = baseline.status_code if baseline else 200
                baseline_len = len(baseline.text) if baseline else 0

                for payload in payloads:
                    injected = self.inject_param(url, param, payload)
                    resp = self.session.get(injected)
                    if not resp:
                        continue

                    # Detect anomalies
                    is_error_status = resp.status_code in INTERESTING_STATUS
                    is_error_body = ERROR_SIGNS.search(resp.text)
                    length_anomaly = abs(len(resp.text) - baseline_len) > baseline_len * 2

                    if is_error_status or is_error_body:
                        evidence = ""
                        if is_error_body:
                            m = ERROR_SIGNS.search(resp.text)
                            start = max(0, m.start() - 50)
                            evidence = resp.text[start:start+200]
                        else:
                            evidence = f"HTTP {resp.status_code}"

                        f = self.make_finding(
                            url=url, param=param, payload=repr(payload)[:80],
                            evidence=evidence[:300],
                            severity="MEDIUM" if is_error_status else "LOW",
                            description=(
                                f"Fuzzer: payload triggered error response "
                                f"(HTTP {resp.status_code}, len={len(resp.text)})"
                            ),
                            remediation="Implement input validation and sanitization. Handle errors gracefully without leaking details.",
                        )
                        vuln(f"  [FUZZ] Anomaly @ {url} | param={param} | status={resp.status_code}")
                        findings.append(f)
                        break  # Move to next param after first hit

        return findings
