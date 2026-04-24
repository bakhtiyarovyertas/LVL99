#!/usr/bin/env python3
"""
LVL99 - Web Application Vulnerability Scanner
CLI Entry Point

Usage:
  lvl99.py -u <url> [options]
  lvl99.py -u http://localhost:8001 -A --output report.html
  lvl99.py -u http://localhost:8001 --xss --sqli --csrf --crawl
  lvl99.py -r request.txt --sqli --xss
"""
import argparse
import sys
import os
import time
import warnings

warnings.filterwarnings("ignore")
os.environ["PYTHONWARNINGS"] = "ignore"

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.logger import (
    banner, info, ok, warn, error, set_verbose,
    CYAN, RESET, BOLD, WHITE, GREY, RED, GREEN, YELLOW,
)
from core.session import ScanSession
from core.crawler import Crawler
from core.auth_manager import AuthManager
from core.request_parser import parse_burp_request
from core.report import ReportGenerator


MODULE_MAP = {
    "sqli":    ("modules.sqli",          "SQLiScanner"),
    "xss":     ("modules.xss",           "XSSScanner"),
    "csrf":    ("modules.csrf",          "CSRFScanner"),
    "rce":     ("modules.rce",           "RCEScanner"),
    "lfi":     ("modules.lfi",           "LFIScanner"),
    "ssti":    ("modules.ssti",          "SSTIScanner"),
    "idor":    ("modules.idor",          "IDORScanner"),
    "htmli":   ("modules.htmli",         "HTMLiScanner"),
    "nosqli":  ("modules.nosqli",        "NoSQLiScanner"),
    "auth":    ("modules.auth_bypass",   "AuthBypassScanner"),
    "code":    ("modules.code_injection","CodeInjectionScanner"),
    "api":     ("modules.api_scanner",   "APIScanner"),
    "fuzz":    ("modules.fuzzer",        "Fuzzer"),
    "xxe":     ("modules.xxe",           "XXEScanner"),
    "ssrf":    ("modules.ssrf",          "SSRFScanner"),
    "fileext": ("modules.file_ext",      "FileExtBypassScanner"),
}

MODULE_LABELS = {
    "sqli":    "SQL Injection",
    "xss":     "Cross-Site Scripting",
    "csrf":    "CSRF Protection",
    "rce":     "Remote Code Execution",
    "lfi":     "Local File Inclusion",
    "ssti":    "Server-Side Template Injection",
    "idor":    "Insecure Direct Object Reference",
    "htmli":   "HTML Injection",
    "nosqli":  "NoSQL Injection",
    "auth":    "Authentication Bypass",
    "code":    "Code Injection",
    "api":     "API Security",
    "fuzz":    "Fuzzer",
    "xxe":     "XML External Entity",
    "ssrf":    "Server-Side Request Forgery",
    "fileext": "File Extension Bypass",
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lvl99",
        description=f"{BOLD}LVL99{RESET} — Web Application Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full auto scan + HTML report  (auto-logs into DVWA/JuiceShop/WebGoat)
  python lvl99.py -u http://localhost:8001 -A --output report.html

  # Crawl then test XSS + SQLi
  python lvl99.py -u http://localhost:8001 --crawl --xss --sqli

  # Specific endpoint, CSRF + auth bypass
  python lvl99.py -u http://localhost:8001/login.php --csrf --auth

  # Load Burp/ZAP saved request
  python lvl99.py -r request.txt --sqli --xss

  # Multiple output formats
  python lvl99.py -u http://localhost:8001 -A --output report --format html,json,txt
        """,
    )

    tgt = p.add_argument_group("Target")
    tgt.add_argument("-u", "--url", metavar="URL", help="Target URL")
    tgt.add_argument("-r", "--request", metavar="FILE",
                     help="Saved HTTP request file (Burp Suite / ZAP format)")
    tgt.add_argument("--crawl", action="store_true",
                     help="Crawl target before scanning (auto-discovers URLs)")
    tgt.add_argument("--no-auth", action="store_true",
                     help="Skip auto-login (use if you supply --cookie manually)")

    mods = p.add_argument_group("Scan Modules (use -A for all)")
    mods.add_argument("-A", "--all", action="store_true", help="Run ALL scan modules")
    mods.add_argument("--sqli",    action="store_true", help="SQL Injection")
    mods.add_argument("--xss",     action="store_true", help="Cross-Site Scripting")
    mods.add_argument("--csrf",    action="store_true", help="CSRF Protection")
    mods.add_argument("--rce",     action="store_true", help="Remote Code Execution")
    mods.add_argument("--lfi",     action="store_true", help="Local File Inclusion")
    mods.add_argument("--ssti",    action="store_true", help="Server-Side Template Injection")
    mods.add_argument("--idor",    action="store_true", help="Insecure Direct Object Reference")
    mods.add_argument("--htmli",   action="store_true", help="HTML Injection")
    mods.add_argument("--nosqli",  action="store_true", help="NoSQL Injection")
    mods.add_argument("--auth",    action="store_true", help="Authentication Bypass")
    mods.add_argument("--code",    action="store_true", help="Code Injection")
    mods.add_argument("--api",     action="store_true", help="API Security")
    mods.add_argument("--fuzz",    action="store_true", help="Generic Fuzzer")
    mods.add_argument("--xxe",     action="store_true", help="XML External Entity")
    mods.add_argument("--ssrf",    action="store_true", help="Server-Side Request Forgery")
    mods.add_argument("--fileext", action="store_true", help="File Extension Bypass")

    wl = p.add_argument_group("Wordlists")
    wl.add_argument("-w",  "--wordlist",      metavar="FILE", help="Custom wordlist (all modules)")
    wl.add_argument("--sqli-wordlist",        metavar="FILE", help="Custom SQLi wordlist")
    wl.add_argument("--xss-wordlist",         metavar="FILE", help="Custom XSS wordlist")
    wl.add_argument("--fuzz-wordlist",        metavar="FILE", help="Custom fuzz wordlist")

    out = p.add_argument_group("Output")
    out.add_argument("--output", "-o", metavar="PATH",
                     help="Output path (e.g. report or report.html)")
    out.add_argument("--format", "-f", metavar="FMT", default="html",
                     help="Output format(s): html,json,txt,markdown (default: html)")
    out.add_argument("--no-color", action="store_true", help="Disable ANSI color output")

    sess = p.add_argument_group("Session / HTTP")
    sess.add_argument("--cookie",   metavar="COOKIE",  help="Session cookie")
    sess.add_argument("--header",   metavar="HDR",     action="append", default=[],
                      help="Extra header (repeatable): 'X-Auth: token'")
    sess.add_argument("--proxy",    metavar="URL",     help="HTTP proxy")
    sess.add_argument("--timeout",  type=int, default=10, metavar="N", help="Request timeout")
    sess.add_argument("--delay",    type=float, default=0, metavar="SEC",
                      help="Delay between requests in seconds")
    sess.add_argument("--threads",  type=int, default=10, metavar="N",
                      help="Concurrent threads (default: 10)")
    sess.add_argument("--user-agent", metavar="UA", help="Custom User-Agent")

    misc = p.add_argument_group("Misc")
    misc.add_argument("-v", "--verbose", action="store_true", help="Verbose debug output")
    misc.add_argument("--no-banner", action="store_true", help="Suppress ASCII banner")

    return p


def load_module(key: str):
    mod_path, cls_name = MODULE_MAP[key]
    import importlib
    mod = importlib.import_module(mod_path)
    return getattr(mod, cls_name)


def print_scan_summary(findings: list, elapsed: float, crawled: int):
    from collections import Counter
    sevs = Counter(f.get("severity", "INFO") for f in findings if f.get("vulnerable", True))
    total = sum(sevs.values())
    print(f"\n\n{'─'*60}")
    print(f"{BOLD}{WHITE}  SCAN COMPLETE{RESET}  ({elapsed:.1f}s · {crawled} URLs)")
    print(f"{'─'*60}")
    print(f"  {RED}{BOLD}CRITICAL{RESET}  {sevs.get('CRITICAL',0):>4}")
    print(f"  {YELLOW}HIGH    {RESET}  {sevs.get('HIGH',0):>4}")
    print(f"  {YELLOW}MEDIUM  {RESET}  {sevs.get('MEDIUM',0):>4}")
    print(f"  {GREEN}LOW     {RESET}  {sevs.get('LOW',0):>4}")
    print(f"  {'─'*16}")
    print(f"  TOTAL     {total:>4}")
    print(f"{'─'*60}\n")


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.url and not args.request:
        parser.print_help()
        print(f"\n{RED}[!] Error: provide -u URL or -r REQUEST_FILE{RESET}")
        sys.exit(1)

    if not args.no_banner:
        banner()

    set_verbose(args.verbose)

    # ── Active modules ────────────────────────────────────────────────────────
    if args.all:
        active_modules = list(MODULE_MAP.keys())
    else:
        active_modules = [k for k in MODULE_MAP if getattr(args, k, False)]

    if not active_modules:
        warn("No scan modules selected. Use -A or specify flags (--xss, --sqli, ...)")
        sys.exit(1)

    # ── Build session ─────────────────────────────────────────────────────────
    headers = {}
    for hdr in args.header:
        if ":" in hdr:
            k, v = hdr.split(":", 1)
            headers[k.strip()] = v.strip()

    config = {
        "url":           args.url or "",
        "timeout":       args.timeout,
        "delay":         args.delay,
        "threads":       args.threads,
        "verbose":       args.verbose,
        "cookie":        args.cookie,
        "headers":       headers,
        "proxy":         args.proxy,
        "user_agent":    args.user_agent or "LVL99-Scanner/1.0",
        "wordlist":      args.wordlist,
        "sqli_wordlist": args.sqli_wordlist,
        "xss_wordlist":  args.xss_wordlist,
        "fuzz_wordlist": args.fuzz_wordlist,
    }

    # ── Load saved request ────────────────────────────────────────────────────
    if args.request:
        try:
            req = parse_burp_request(args.request)
            config["url"] = req["url"]
            config["headers"].update(req["headers"])
            if req.get("params"):
                config["request_data"] = req
            info(f"Loaded request: {req['method']} {req['url']}")
        except Exception as e:
            error(f"Failed to parse request file: {e}")
            sys.exit(1)

    session = ScanSession(config)

    # ── Auto-login (unless --no-auth or --cookie provided with intent to skip) ─
    if not args.no_auth:
        auth = AuthManager(session)
        auth.auto_login()
    else:
        info("[AUTH] Skipping auto-login (--no-auth specified)")

    # ── Crawl ─────────────────────────────────────────────────────────────────
    crawled_urls = [session.url]
    if args.crawl or args.all:
        info(f"Starting crawler on {session.url}")
        crawler = Crawler(session)
        crawled_urls = crawler.crawl(session.url)
        ok(f"Crawler finished: {len(crawled_urls)} URLs discovered")
    else:
        info(f"Target: {session.url}  (tip: add --crawl to auto-discover more attack surface)")

    # De-duplicate and remove obviously un-scannable URLs
    seen = set()
    clean_urls = []
    for u in crawled_urls:
        if u not in seen:
            seen.add(u)
            clean_urls.append(u)
    crawled_urls = clean_urls

    # ── Run modules ───────────────────────────────────────────────────────────
    all_findings = []
    start_time = time.time()
    print(f"\n{BOLD}  Running {len(active_modules)} module(s) against {len(crawled_urls)} URL(s){RESET}\n")

    for i, key in enumerate(active_modules):
        label = MODULE_LABELS.get(key, key.upper())
        print(f"  {CYAN}[{i+1}/{len(active_modules)}]{RESET} {BOLD}{label}{RESET}")

        try:
            ScannerClass = load_module(key)
            scanner = ScannerClass(session)
            findings = scanner.scan(crawled_urls)
            all_findings.extend(findings)

            vuln_count = sum(1 for f in findings if f.get("vulnerable", True))
            if vuln_count:
                print(f"        {RED}↳ {vuln_count} finding(s){RESET}")
            else:
                print(f"        {GREEN}↳ Clean{RESET}")
        except ImportError as e:
            warn(f"Module '{key}' could not be loaded: {e}")
        except Exception as e:
            error(f"Module '{key}' crashed: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()

    elapsed = time.time() - start_time
    print_scan_summary(all_findings, elapsed, len(crawled_urls))

    # ── Report ────────────────────────────────────────────────────────────────
    if args.output:
        formats = [f.strip().lower() for f in args.format.split(",")]
        report_gen = ReportGenerator(session, all_findings, crawled_urls, elapsed)
        ext_map = {"html": ".html", "json": ".json", "txt": ".txt", "markdown": ".md"}
        base = args.output
        for ext in ext_map.values():
            if base.endswith(ext):
                base = base[:-len(ext)]
                break

        generated = []
        for fmt in formats:
            if fmt not in ext_map:
                warn(f"Unknown format '{fmt}', skipping")
                continue
            path = base + ext_map[fmt]
            report_gen.generate(fmt, path)
            generated.append(path)
            ok(f"Report saved: {path}")

        if generated:
            print(f"\n{BOLD}  Reports generated:{RESET}")
            for p in generated:
                print(f"    {GREEN}→{RESET} {os.path.abspath(p)}")
    else:
        # Inline summary table
        vuln_findings = [f for f in all_findings if f.get("vulnerable", True)]
        if vuln_findings:
            print(f"{'─'*110}")
            print(f"  {'SEV':<10} {'MODULE':<12} {'URL':<45} {'PARAM':<15} {'DESCRIPTION'}")
            print(f"{'─'*110}")
            from core.report import SEVERITY_ORDER
            for f in sorted(vuln_findings,
                            key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 4)):
                sev = f.get("severity", "INFO")
                col = RED if sev == "CRITICAL" else YELLOW if sev in ("HIGH", "MEDIUM") else GREEN
                print(
                    f"  {col}{sev:<10}{RESET}"
                    f" {f.get('module',''):<12}"
                    f" {f.get('url','')[:45]:<45}"
                    f" {f.get('param',''):<15}"
                    f" {f.get('description','')[:55]}"
                )
            print(f"{'─'*110}")
            print(f"\n  Use --output report --format html,json,txt to save a full report\n")
        else:
            print(f"  {GREEN}No vulnerabilities found.{RESET}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
