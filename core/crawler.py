"""Fast Web Crawler for LVL99 — authenticated, JS-aware, form-aware."""
import re
import time
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from core.logger import get_logger, info, debug, ok, warn

logger = get_logger(__name__)

SKIP_EXT_RE = re.compile(
    r"\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|map|pdf"
    r"|zip|tar|gz|mp3|mp4|avi|mov|webm|swf)(\?.*)?$",
    re.IGNORECASE,
)
JS_URL_RE = re.compile(
    r"""(?:url|href|src|action|location|redirect|goto|path)\s*[=:]\s*['"]([^'"?#]{3,100})['"]""",
    re.IGNORECASE,
)

DVWA_MODULES = [
    "/vulnerabilities/brute/",
    "/vulnerabilities/exec/",
    "/vulnerabilities/csrf/",
    "/vulnerabilities/fi/?page=include.php",
    "/vulnerabilities/upload/",
    "/vulnerabilities/xss_r/",
    "/vulnerabilities/xss_s/",
    "/vulnerabilities/xss_d/",
    "/vulnerabilities/sqli/",
    "/vulnerabilities/sqli_blind/",
    "/vulnerabilities/idor/",
    "/vulnerabilities/weak_id/",
    "/vulnerabilities/open_redirect/",
    "/vulnerabilities/javascript/",
    "/vulnerabilities/authbypass/",
    "/vulnerabilities/csp/",
    "/index.php",
]
WEBGOAT_PATHS = [
    "/WebGoat/start.mvc",
    "/WebGoat/service/lessonoverview.mvc",
]
JUICESHOP_PATHS = [
    "/api/Products",
    "/api/Users",
    "/api/Feedbacks",
    "/api/Complaints",
    "/rest/user/whoami",
    "/rest/products/search?q=",
    "/api/SecurityQuestions",
]
GENERIC_PROBE_PATHS = [
    "/search", "/search.php", "/query", "/index.php?id=1",
    "/page.php?page=home", "/view.php?file=index",
    "/admin", "/admin/", "/user", "/profile", "/settings",
    "/upload", "/file", "/download",
    "/api/v1/users", "/api/v1/products", "/api/users",
]


class Crawler:
    def __init__(self, session):
        self.session = session
        self.visited = set()
        self.found_urls = []
        self.found_forms = []
        self.max_depth = 4
        self.max_urls = 300
        self._base_host = urlparse(session.base_url).netloc

    def crawl(self, start_url: str) -> list:
        info(f"[~] Crawling {start_url} (depth={self.max_depth}, max={self.max_urls})")
        self._seed_known_paths(start_url)
        queue = [(start_url, 0)]
        self._add_url(start_url)

        while queue and len(self.found_urls) < self.max_urls:
            batch, queue = queue[:20], queue[20:]
            with ThreadPoolExecutor(max_workers=self.session.threads) as ex:
                futures = {
                    ex.submit(self._fetch_and_parse, url, depth): (url, depth)
                    for url, depth in batch
                }
                for fut in as_completed(futures):
                    url, depth = futures[fut]
                    try:
                        new_links, forms = fut.result()
                        self.found_forms.extend(forms)
                        for link in new_links:
                            if self._add_url(link) and depth + 1 < self.max_depth:
                                queue.append((link, depth + 1))
                    except Exception as e:
                        debug(f"Crawl error {url}: {e}")

        ok(f"[+] Crawled {len(self.found_urls)} unique URLs | {len(self.found_forms)} forms found")
        for u in self.found_urls[:25]:
            debug(f"  {u}")
        if len(self.found_urls) > 25:
            debug(f"  ... and {len(self.found_urls) - 25} more")
        return self.found_urls

    def get_forms(self):
        return self.found_forms

    def _seed_known_paths(self, start_url: str):
        base = self.session.base_url
        resp = self.session.get(start_url)
        if not resp:
            return
        body = resp.text.lower()

        if "dvwa" in body or "damn vulnerable" in body:
            info("  [CRAWL] DVWA detected — seeding all module URLs")
            for path in DVWA_MODULES:
                self._add_url(urljoin(base, path))
        elif "juice" in body or "owasp juice" in body or "juiceshop" in body:
            info("  [CRAWL] Juice Shop detected — seeding API + SPA routes")
            for path in JUICESHOP_PATHS:
                self._add_url(urljoin(base, path))
        elif "webgoat" in body or "goat" in body:
            info("  [CRAWL] WebGoat detected — seeding lesson URLs")
            for path in WEBGOAT_PATHS:
                self._add_url(urljoin(base, path))

        for path in GENERIC_PROBE_PATHS:
            self._add_url(urljoin(base, path))

    def _fetch_and_parse(self, url: str, depth: int):
        if SKIP_EXT_RE.search(url):
            return [], []
        resp = self.session.get(url, allow_redirects=True)
        if not resp:
            return [], []

        ct = resp.headers.get("content-type", "")
        if "application/json" in ct:
            return self._parse_json_links(resp.text), []
        if "text/html" not in ct and "application/xhtml" not in ct:
            return [], []

        try:
            soup = BeautifulSoup(resp.text, "html.parser")
        except Exception:
            return [], []

        links = []

        # Standard tags
        for tag in soup.find_all(["a", "link", "area"]):
            link = self._resolve(url, tag.get("href", ""))
            if link:
                links.append(link)

        # Forms
        for tag in soup.find_all("form"):
            link = self._resolve(url, tag.get("action", ""))
            if link:
                links.append(link)

        # Scripts
        for tag in soup.find_all("script"):
            link = self._resolve(url, tag.get("src", ""))
            if link:
                links.append(link)
            for m in JS_URL_RE.finditer(tag.string or ""):
                link = self._resolve(url, m.group(1))
                if link:
                    links.append(link)

        # data-* SPA attributes
        for tag in soup.find_all(True):
            for attr in ["data-url", "data-href", "data-src", "data-action", "data-api"]:
                val = tag.get(attr, "")
                if val:
                    link = self._resolve(url, val)
                    if link:
                        links.append(link)

        forms = self._parse_forms(url, soup)

        # Redirect header
        loc = resp.headers.get("Location", "")
        if loc:
            link = self._resolve(url, loc)
            if link:
                links.append(link)

        return links, forms

    def _parse_forms(self, page_url: str, soup) -> list:
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action", page_url)
            method = form.get("method", "GET").upper()
            abs_action = urljoin(page_url, action) if action else page_url
            inputs = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name", "")
                if not name:
                    continue
                val = inp.get("value", "")
                itype = inp.get("type", "text").lower()
                if itype in ("submit", "button", "image", "reset"):
                    continue
                elif itype == "hidden":
                    inputs[name] = val or ""
                elif itype == "checkbox":
                    inputs[name] = "on"
                elif itype == "radio":
                    if name not in inputs:
                        inputs[name] = val or "on"
                elif inp.name == "select":
                    opt = inp.find("option")
                    inputs[name] = (opt["value"] if opt and opt.get("value") else "") or val or "1"
                else:
                    inputs[name] = val or "test"
            enctype = form.get("enctype", "application/x-www-form-urlencoded")
            forms.append({
                "url": abs_action,
                "method": method,
                "inputs": inputs,
                "enctype": enctype,
                "page": page_url,
                "raw": str(form),
            })
        return forms

    def _parse_json_links(self, text: str) -> list:
        links = []
        url_re = re.compile(r'"((?:/|https?://)[^"]{3,200})"')
        for m in url_re.finditer(text):
            link = self._resolve(self.session.base_url, m.group(1))
            if link:
                links.append(link)
        return links[:50]

    def _resolve(self, base: str, href: str) -> str:
        if not href or href.startswith(("javascript:", "mailto:", "tel:", "#", "void", "data:")):
            return None
        try:
            abs_url = urljoin(base, href)
            p = urlparse(abs_url)
            if p.netloc != self._base_host:
                return None
            if p.scheme not in ("http", "https"):
                return None
            if SKIP_EXT_RE.search(p.path):
                return None
            return self._normalize(abs_url)
        except Exception:
            return None

    def _normalize(self, url: str) -> str:
        p = urlparse(url)
        return urlunparse((p.scheme, p.netloc, p.path, p.params, p.query, ""))

    def _add_url(self, url: str) -> bool:
        if not url:
            return False
        norm = self._normalize(url)
        if norm in self.visited:
            return False
        self.visited.add(norm)
        self.found_urls.append(norm)
        return True
