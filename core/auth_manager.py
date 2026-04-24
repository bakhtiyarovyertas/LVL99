"""
Authentication Manager for LVL99.

Auto-detects and logs into known vulnerable apps:
  - DVWA          http://localhost:8001  admin/password
  - Juice Shop    http://localhost:8002  admin@juice-sh.op/admin123
  - WebGoat       http://localhost:8003  guest/guest

Also tries generic form-based login on unknown targets.
"""

import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from core.logger import get_logger, info, ok, warn, debug

logger = get_logger(__name__)


def _extract_token(html: str) -> str:
    """Extract a CSRF / hidden token from a login form."""
    token_names = [
        "user_token", "csrf_token", "csrfmiddlewaretoken", "_token",
        "authenticity_token", "token", "_csrf", "__RequestVerificationToken",
    ]
    soup = BeautifulSoup(html, "html.parser")
    for name in token_names:
        tag = soup.find("input", {"name": name})
        if tag and tag.get("value"):
            return tag["value"]
    # Fallback: any hidden input whose name contains 'token'/'csrf'/'nonce'
    for inp in soup.find_all("input", {"type": "hidden"}):
        n = inp.get("name", "").lower()
        if any(t in n for t in ["token", "csrf", "nonce", "state"]):
            return inp.get("value", "")
    return ""


def _dvwa_set_security_low(session, base_url: str):
    """Set DVWA security to LOW after login so all vulns are active."""
    sec_url = base_url.rstrip("/") + "/security.php"
    resp = session.get(sec_url)
    if not resp:
        return
    token = _extract_token(resp.text)
    data = {"security": "low", "seclev_submit": "Submit"}
    if token:
        data["user_token"] = token
    session.post(sec_url, data=data)
    ok("  [AUTH] DVWA security level set to LOW")


KNOWN_APPS = [
    {
        "name": "DVWA",
        "fingerprint": re.compile(r"dvwa|damn vulnerable web", re.IGNORECASE),
        "login_url": "/login.php",
        "user_field": "username",
        "pass_field": "password",
        "creds": [("admin", "password"), ("admin", "admin")],
        "success_re": re.compile(r"logout|dvwa security|welcome to dvwa|index\.php", re.IGNORECASE),
        "post_hook": _dvwa_set_security_low,
    },
    {
        "name": "JuiceShop",
        "fingerprint": re.compile(r"juice.?shop|OWASP Juice|Juice Shop", re.IGNORECASE),
        "login_url": "/rest/user/login",
        "is_json": True,
        "json_creds": [
            {"email": "admin@juice-sh.op", "password": "admin123"},
        ],
        "success_re": re.compile(r"authentication|token|bearer", re.IGNORECASE),
    },
    {
        "name": "WebGoat",
        "fingerprint": re.compile(r"webgoat|goat.*wolf|WebGoat", re.IGNORECASE),
        "login_url": "/WebGoat/login",
        "user_field": "username",
        "pass_field": "password",
        "creds": [("guest", "guest"), ("webgoat", "webgoat")],
        "success_re": re.compile(r"logout|webgoat|lesson|start\.mvc", re.IGNORECASE),
    },
]

GENERIC_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "1234"),
    ("guest", "guest"),
    ("test", "test"),
    ("user", "user"),
    ("admin@admin.com", "admin"),
]
GENERIC_LOGIN_PATHS = [
    "/login", "/login.php", "/login.html", "/signin", "/sign-in",
    "/auth/login", "/user/login", "/account/login", "/admin/login",
]


class AuthManager:
    def __init__(self, session):
        self.session = session
        self.http = session.session          # underlying requests.Session
        self.base_url = session.base_url
        self.authenticated = False
        self.app_name = "Unknown"

    # ── Public API ────────────────────────────────────────────────────────────

    def auto_login(self) -> bool:
        """
        Attempt authentication. Returns True when a valid session is obtained.
        Priority:
          1. Existing cookies/headers → verify them
          2. Known-app fingerprint    → dedicated login
          3. Generic form discovery   → try common paths + credentials
        """
        # 1. Pre-existing session
        if self.http.cookies or "Authorization" in self.http.headers:
            if self._verify_logged_in():
                ok("  [AUTH] Pre-existing session is valid ✓")
                self.authenticated = True
                return True

        # 2. Known app
        app = self._fingerprint()
        if app:
            self.app_name = app["name"]
            info(f"  [AUTH] Detected {app['name']} — attempting auto-login")
            success = (
                self._login_json(app) if app.get("is_json") else self._login_form(app)
            )
            if success:
                hook = app.get("post_hook")
                if callable(hook):
                    try:
                        hook(self.session, self.base_url)
                    except Exception as e:
                        debug(f"Post-login hook error: {e}")
                self.authenticated = True
                ok(f"  [AUTH] Logged into {app['name']} ✓")
                return True
            warn(f"  [AUTH] {app['name']} login failed — falling back to generic")

        # 3. Generic
        if self._generic_login():
            self.authenticated = True
            return True

        warn("  [AUTH] Authentication failed — scan will run unauthenticated (limited coverage)")
        return False

    def ensure_session(self) -> bool:
        """Re-authenticate if session has expired."""
        if self._verify_logged_in():
            return True
        warn("  [AUTH] Session expired — re-authenticating")
        self.authenticated = False
        return self.auto_login()

    # ── Fingerprinting ────────────────────────────────────────────────────────

    def _fingerprint(self):
        resp = self.session.get(self.base_url)
        if not resp:
            return None
        title_m = re.search(r"<title[^>]*>([^<]+)</title>", resp.text, re.IGNORECASE)
        combined = (resp.text[:5000] + (title_m.group(1) if title_m else ""))
        for app in KNOWN_APPS:
            if app["fingerprint"].search(combined):
                return app
        return None

    # ── Login methods ─────────────────────────────────────────────────────────

    def _login_form(self, app: dict) -> bool:
        login_url = urljoin(self.base_url, app["login_url"])
        for username, password in app.get("creds", []):
            resp = self.session.get(login_url)
            if not resp:
                continue
            token = _extract_token(resp.text)

            data = {}
            # Fill all form fields with defaults
            soup = BeautifulSoup(resp.text, "html.parser")
            form = soup.find("form")
            if form:
                for inp in form.find_all("input"):
                    n = inp.get("name", "")
                    v = inp.get("value", "") or ""
                    if n:
                        data[n] = v
            data[app["user_field"]] = username
            data[app["pass_field"]] = password
            if token:
                for tf in ["user_token", "csrf_token", "_token", "csrfmiddlewaretoken"]:
                    if tf in data:
                        data[tf] = token

            r2 = self.http.post(login_url, data=data, allow_redirects=True,
                                timeout=self.session.timeout)
            if not r2:
                continue
            if app["success_re"].search(r2.text) or app["success_re"].search(r2.url):
                debug(f"  Login OK: {username}:{password}")
                return True
            # Redirect away from login = success
            if r2.url and "login" not in r2.url.lower() and r2.status_code in (200,):
                if len(r2.text) > 500:
                    return True
        return False

    def _login_json(self, app: dict) -> bool:
        login_url = urljoin(self.base_url, app["login_url"])
        for creds in app.get("json_creds", []):
            r = self.http.post(
                login_url,
                json=creds,
                headers={"Content-Type": "application/json"},
                allow_redirects=True,
                timeout=self.session.timeout,
            )
            if not r:
                continue
            if r.status_code in (200, 201):
                try:
                    data = r.json()
                    token = (
                        data.get("authentication", {}).get("token")
                        or data.get("token")
                        or data.get("access_token")
                    )
                    if token:
                        self.http.headers["Authorization"] = f"Bearer {token}"
                        ok("  [AUTH] JWT stored for API requests")
                        return True
                except Exception:
                    pass
                if app.get("success_re") and app["success_re"].search(r.text):
                    return True
        return False

    def _generic_login(self) -> bool:
        for path in GENERIC_LOGIN_PATHS:
            url = urljoin(self.base_url, path)
            resp = self.session.get(url)
            if not resp or resp.status_code != 200:
                continue
            if "login" not in resp.text.lower() and "signin" not in resp.text.lower():
                continue

            soup = BeautifulSoup(resp.text, "html.parser")
            for form in soup.find_all("form"):
                fields = [i.get("name", "") for i in form.find_all(["input", "textarea"])]
                user_f = next((f for f in fields if any(
                    kw in f.lower() for kw in ["user", "email", "login", "name"])), None)
                pass_f = next((f for f in fields if any(
                    kw in f.lower() for kw in ["pass", "pwd", "secret"])), None)
                if not (user_f and pass_f):
                    continue

                action = form.get("action", url)
                post_url = urljoin(url, action)
                token = _extract_token(resp.text)

                for uname, passwd in GENERIC_CREDS:
                    data = {}
                    for inp in form.find_all("input"):
                        n = inp.get("name", "")
                        if n:
                            data[n] = inp.get("value", "") or ""
                    data[user_f] = uname
                    data[pass_f] = passwd
                    if token:
                        for tf in ["user_token", "csrf_token", "_token"]:
                            if tf in data:
                                data[tf] = token

                    r2 = self.http.post(post_url, data=data, allow_redirects=True,
                                        timeout=self.session.timeout)
                    if not r2:
                        continue
                    success_re = re.compile(
                        r"logout|sign.?out|welcome|dashboard|my account|profile", re.IGNORECASE
                    )
                    fail_re = re.compile(
                        r"invalid|incorrect|wrong|failed|denied|error|bad credentials", re.IGNORECASE
                    )
                    if success_re.search(r2.text) and not fail_re.search(r2.text):
                        ok(f"  [AUTH] Generic login: {post_url} [{uname}:{passwd}] ✓")
                        return True
        return False

    # ── Session check ─────────────────────────────────────────────────────────

    def _verify_logged_in(self) -> bool:
        resp = self.session.get(self.base_url)
        if not resp:
            return False
        auth_re = re.compile(r"logout|sign.?out|my account|dashboard|welcome|logged.?in", re.IGNORECASE)
        login_re = re.compile(r'<form[^>]*(?:login|signin)[^>]*>|action=["\'][^"\']*login', re.IGNORECASE)
        return bool(auth_re.search(resp.text)) and not bool(login_re.search(resp.text[:3000]))
