"""Scan session - holds config and shared HTTP session."""
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from core.logger import get_logger, debug

logger = get_logger(__name__)


class ScanSession:
    def __init__(self, config: dict):
        self.config = config
        self.url = config.get("url", "")
        self.base_url = self._get_base(self.url)
        self.timeout = config.get("timeout", 10)
        self.delay = config.get("delay", 0)
        self.threads = config.get("threads", 10)
        self.verbose = config.get("verbose", False)
        self.request_data = config.get("request_data")

        self.session = requests.Session()
        self.session.verify = False

        # Suppress SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Retry strategy
        retry = Retry(total=2, backoff_factor=0.3,
                      status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Headers
        ua = config.get("user_agent", "LV188-Scanner/1.0")
        self.session.headers.update({
            "User-Agent": ua,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
        })
        if config.get("headers"):
            self.session.headers.update(config["headers"])

        # Cookie
        if config.get("cookie"):
            for part in config["cookie"].split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    self.session.cookies.set(k.strip(), v.strip())

        # Proxy
        if config.get("proxy"):
            self.session.proxies = {
                "http": config["proxy"],
                "https": config["proxy"],
            }

    def _get_base(self, url):
        from urllib.parse import urlparse
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    def get(self, url, **kwargs):
        import time
        if self.delay:
            time.sleep(self.delay)
        try:
            kwargs.setdefault("timeout", self.timeout)
            kwargs.setdefault("allow_redirects", True)
            return self.session.get(url, **kwargs)
        except Exception as e:
            debug(f"GET {url} failed: {e}")
            return None

    def post(self, url, data=None, json=None, **kwargs):
        import time
        if self.delay:
            time.sleep(self.delay)
        try:
            kwargs.setdefault("timeout", self.timeout)
            return self.session.post(url, data=data, json=json, **kwargs)
        except Exception as e:
            debug(f"POST {url} failed: {e}")
            return None

    def request(self, method, url, **kwargs):
        import time
        if self.delay:
            time.sleep(self.delay)
        try:
            kwargs.setdefault("timeout", self.timeout)
            return self.session.request(method, url, **kwargs)
        except Exception as e:
            debug(f"{method} {url} failed: {e}")
            return None

    def get_wordlist(self, module=None):
        """Return wordlist path for a given module, falling back to defaults."""
        from pathlib import Path
        wl_dir = Path(__file__).parent.parent / "wordlists"
        custom = None
        if module == "sqli":
            custom = self.config.get("sqli_wordlist")
        elif module == "xss":
            custom = self.config.get("xss_wordlist")
        elif module == "fuzz":
            custom = self.config.get("fuzz_wordlist")
        if not custom:
            custom = self.config.get("wordlist")
        if custom and Path(custom).exists():
            return custom
        # Built-in defaults
        defaults = {
            "sqli": wl_dir / "sqli.txt",
            "xss": wl_dir / "xss.txt",
            "lfi": wl_dir / "lfi.txt",
            "rce": wl_dir / "rce.txt",
            "fuzz": wl_dir / "fuzz.txt",
            "ssti": wl_dir / "ssti.txt",
            "xxe": wl_dir / "xxe.txt",
            "nosqli": wl_dir / "nosqli.txt",
            "htmli": wl_dir / "htmli.txt",
        }
        if module and module in defaults:
            return str(defaults[module])
        return str(wl_dir / "common.txt")

    def load_wordlist(self, module=None):
        """Load and return list of payloads from wordlist."""
        path = self.get_wordlist(module)
        try:
            with open(path, "r", errors="ignore") as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            debug(f"Loaded {len(lines)} payloads from {path}")
            return lines
        except FileNotFoundError:
            debug(f"Wordlist not found: {path}")
            return []
