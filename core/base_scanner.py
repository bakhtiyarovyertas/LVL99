"""Base scanner class for all LV188 modules."""
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.logger import get_logger, debug, vuln, info

logger = get_logger(__name__)


class BaseScanner:
    """Base class all scanner modules inherit from."""

    MODULE_NAME = "base"
    OWASP_CATEGORY = "A00 - Uncategorized"

    def __init__(self, session):
        self.session = session
        self.findings = []

    def scan(self, urls: list) -> list:
        """Override in subclasses. Should return list of finding dicts."""
        raise NotImplementedError

    def make_finding(self, url, param, payload, evidence, severity="HIGH",
                     description="", remediation="", vulnerable=True):
        return {
            "module": self.MODULE_NAME,
            "owasp": self.OWASP_CATEGORY,
            "url": url,
            "param": param,
            "payload": payload,
            "evidence": evidence,
            "severity": severity,
            "description": description,
            "remediation": remediation,
            "vulnerable": vulnerable,
        }

    def get_url_params(self, url: str) -> dict:
        parsed = urlparse(url)
        return parse_qs(parsed.query, keep_blank_values=True)

    def inject_param(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def get_forms(self, url: str):
        """Fetch page and extract all HTML forms."""
        resp = self.session.get(url)
        if not resp:
            return []
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
        except Exception:
            return []
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action", url)
            method = form.get("method", "GET").upper()
            abs_action = urljoin(url, action)
            inputs = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name", "")
                if name:
                    inputs[name] = inp.get("value", "") or "test"
            forms.append({
                "url": abs_action,
                "method": method,
                "inputs": inputs,
                "page": url,
            })
        return forms

    def test_form(self, form: dict, payload: str, field_override=None):
        """Submit a form with a payload injected into all/specific fields."""
        inputs = dict(form["inputs"])
        targets = [field_override] if field_override else list(inputs.keys())
        results = []
        for field in targets:
            injected = dict(inputs)
            injected[field] = payload
            if form["method"] == "POST":
                resp = self.session.post(form["url"], data=injected)
            else:
                resp = self.session.get(form["url"], params=injected)
            results.append((field, resp))
        return results

    def run_threaded(self, func, items, max_workers=None):
        """Run func(item) across items using a thread pool."""
        results = []
        workers = max_workers or self.session.threads
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(func, item): item for item in items}
            for fut in as_completed(futures):
                try:
                    r = fut.result()
                    if r:
                        if isinstance(r, list):
                            results.extend(r)
                        else:
                            results.append(r)
                except Exception as e:
                    debug(f"Thread error: {e}")
        return results
