"""API Vulnerability Scanner - OWASP A01/A03/A09:2021."""
import re, json
from urllib.parse import urljoin
from core.base_scanner import BaseScanner
from core.logger import vuln, debug, info

API_PATHS = [
    "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
    "/rest/", "/graphql", "/swagger.json", "/swagger/",
    "/openapi.json", "/api-docs/", "/api-docs",
    "/v1/", "/v2/", "/.well-known/", "/api/users",
    "/api/user", "/api/admin", "/api/config",
    "/api/keys", "/api/token", "/api/auth",
    "/api/login", "/api/register", "/api/me",
    "/api/products", "/api/orders", "/api/payments",
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

SENSITIVE_DATA_RE = re.compile(
    r'"password"\s*:', r'"secret"\s*:', r'"api_key"\s*:',
    re.IGNORECASE
)
SENSITIVE_RE = re.compile(
    r'"(password|secret|api_key|token|private_key|credit_card|ssn|pin)"\s*:\s*"[^"]{3,}"',
    re.IGNORECASE
)

GRAPHQL_INTROSPECTION = """
{
  __schema {
    types { name }
    queryType { name }
    mutationType { name }
  }
}
"""


class APIScanner(BaseScanner):
    MODULE_NAME = "api"
    OWASP_CATEGORY = "A09:2021 - Security Logging Failures / API"

    def scan(self, urls: list) -> list:
        findings = []
        base = self.session.base_url

        # 1. Discover API endpoints
        discovered = self._discover_api(base)
        info(f"  [~] Discovered {len(discovered)} API endpoints")

        # 2. Test each discovered endpoint
        all_api_urls = list(set(discovered + [u for u in urls if "/api/" in u or "/rest/" in u or "/graphql" in u]))

        for api_url in all_api_urls:
            # Check for sensitive data exposure
            findings.extend(self._check_sensitive_data(api_url))
            # Check missing auth
            findings.extend(self._check_auth_required(api_url))
            # Check HTTP method enumeration
            findings.extend(self._check_methods(api_url))

        # 3. GraphQL introspection
        graphql_url = urljoin(base, "/graphql")
        findings.extend(self._check_graphql(graphql_url))

        # 4. Swagger/OpenAPI exposure
        findings.extend(self._check_swagger(base))

        return findings

    def _discover_api(self, base: str) -> list:
        found = []
        for path in API_PATHS:
            url = urljoin(base, path)
            resp = self.session.get(url)
            if resp and resp.status_code in (200, 201, 401, 403):
                found.append(url)
                debug(f"  API: {url} [{resp.status_code}]")
        return found

    def _check_sensitive_data(self, url: str) -> list:
        resp = self.session.get(url)
        if not resp:
            return []
        findings = []
        ct = resp.headers.get("content-type", "")
        if "json" in ct or "javascript" in ct:
            matches = SENSITIVE_RE.findall(resp.text)
            for m in matches:
                f = self.make_finding(
                    url=url, param="response_body", payload="GET",
                    evidence=str(m)[:150],
                    severity="HIGH",
                    description="API Sensitive Data Exposure: response contains sensitive fields.",
                    remediation="Mask/omit sensitive fields from API responses. Implement field-level access control.",
                )
                vuln(f"  [VULN] API Data Exposure @ {url} | {m}")
                findings.append(f)
        return findings

    def _check_auth_required(self, url: str) -> list:
        findings = []
        # Try without any auth
        session_backup = dict(self.session.session.cookies)
        self.session.session.cookies.clear()
        resp = self.session.get(url)
        # Restore cookies
        for k, v in session_backup.items():
            self.session.session.cookies.set(k, v)

        if resp and resp.status_code == 200:
            ct = resp.headers.get("content-type", "")
            body = resp.text
            if ("json" in ct or len(body) > 100) and resp.status_code != 401:
                f = self.make_finding(
                    url=url, param="Authorization", payload="(none)",
                    evidence=f"HTTP 200 returned without authentication (len={len(body)})",
                    severity="HIGH",
                    description="API endpoint accessible without authentication.",
                    remediation="Implement authentication on all sensitive API endpoints. Return 401 for unauthenticated requests.",
                )
                findings.append(f)
        return findings

    def _check_methods(self, url: str) -> list:
        findings = []
        allowed = []
        for method in HTTP_METHODS:
            resp = self.session.request(method, url)
            if resp and resp.status_code not in (404, 405, 501):
                allowed.append(method)
        if "DELETE" in allowed or "PUT" in allowed:
            f = self.make_finding(
                url=url, param="HTTP-Method", payload=str(allowed),
                evidence=f"Allowed methods: {', '.join(allowed)}",
                severity="MEDIUM",
                description=f"Dangerous HTTP methods allowed: {allowed}. Ensure DELETE/PUT are properly authorized.",
                remediation="Restrict HTTP methods per endpoint. Implement method-level authorization.",
                vulnerable=False,
            )
            findings.append(f)
        return findings

    def _check_graphql(self, url: str) -> list:
        findings = []
        resp = self.session.post(url, json={"query": GRAPHQL_INTROSPECTION},
                                  headers={"Content-Type": "application/json"})
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if "__schema" in str(data):
                    f = self.make_finding(
                        url=url, param="graphql", payload="introspection",
                        evidence="GraphQL introspection enabled - schema fully exposed",
                        severity="MEDIUM",
                        description="GraphQL introspection is enabled. Attackers can enumerate the entire schema.",
                        remediation="Disable introspection in production. Implement query depth limiting and complexity analysis.",
                    )
                    vuln(f"  [VULN] GraphQL Introspection @ {url}")
                    findings.append(f)
            except Exception:
                pass
        return findings

    def _check_swagger(self, base: str) -> list:
        findings = []
        swagger_paths = ["/swagger.json", "/openapi.json", "/api-docs", "/swagger/v1/swagger.json"]
        for path in swagger_paths:
            url = urljoin(base, path)
            resp = self.session.get(url)
            if resp and resp.status_code == 200 and ("swagger" in resp.text.lower() or "openapi" in resp.text.lower()):
                f = self.make_finding(
                    url=url, param="swagger", payload="GET",
                    evidence=f"Swagger/OpenAPI spec publicly accessible at {url}",
                    severity="MEDIUM",
                    description="API documentation (Swagger/OpenAPI) is publicly accessible. May expose internal endpoints.",
                    remediation="Restrict API documentation access to internal networks or authenticated users only.",
                    vulnerable=False,
                )
                findings.append(f)
        return findings
