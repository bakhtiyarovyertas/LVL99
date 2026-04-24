"""IDOR Scanner - OWASP A01:2021."""
import re
from core.base_scanner import BaseScanner
from core.logger import vuln, debug

NUMERIC_RE = re.compile(r"^(\d+)$")


class IDORScanner(BaseScanner):
    MODULE_NAME = "idor"
    OWASP_CATEGORY = "A01:2021 - Broken Access Control"

    def scan(self, urls: list) -> list:
        findings = []
        tested = set()
        for url in urls:
            params = self.get_url_params(url)
            for param, values in params.items():
                val = values[0] if values else ""
                if not NUMERIC_RE.match(val):
                    continue
                key = f"{url}:{param}:{val}"
                if key in tested:
                    continue
                tested.add(key)
                original_resp = self.session.get(url)
                if not original_resp:
                    continue
                original_len = len(original_resp.text)
                original_status = original_resp.status_code

                # Try adjacent IDs
                for delta in [1, 2, -1, 100, 999, 0]:
                    test_id = str(max(1, int(val) + delta)) if delta != 0 else "0"
                    if test_id == val:
                        continue
                    injected = self.inject_param(url, param, test_id)
                    resp = self.session.get(injected)
                    if not resp:
                        continue
                    # If we get similar content with a different ID, possible IDOR
                    if (resp.status_code == 200 and original_status == 200
                            and abs(len(resp.text) - original_len) < original_len * 0.3
                            and len(resp.text) > 200):
                        f = self.make_finding(
                            url=url, param=param, payload=test_id,
                            evidence=f"ID={val} returns similar content as ID={test_id} (lengths: {original_len} vs {len(resp.text)})",
                            severity="HIGH",
                            description=f"Potential IDOR: parameter '{param}' may allow access to other users' data.",
                            remediation="Implement object-level authorization. Verify ownership on every resource access.",
                        )
                        vuln(f"  [VULN] IDOR @ {url} | param={param} | {val}->{test_id}")
                        findings.append(f)
                        break
        return findings
