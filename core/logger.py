"""Colored CLI logger for LVL99 Scanner."""
import logging
import sys
from datetime import datetime

# ANSI color codes
RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[91m"
ORANGE  = "\033[38;5;208m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
WHITE   = "\033[97m"
GREY    = "\033[90m"
DIM     = "\033[2m"

SEVERITY_COLORS = {
    "CRITICAL": RED + BOLD,
    "HIGH":     ORANGE,
    "MEDIUM":   YELLOW,
    "LOW":      GREEN,
    "INFO":     BLUE,
}

_verbose = False


def set_verbose(v: bool):
    global _verbose
    _verbose = v


def _ts():
    return GREY + datetime.now().strftime("%H:%M:%S") + RESET


def info(msg: str):
    print(f"{_ts()} {CYAN}[*]{RESET} {msg}")


def ok(msg: str):
    print(f"{_ts()} {GREEN}[+]{RESET} {msg}")


def warn(msg: str):
    print(f"{_ts()} {YELLOW}[!]{RESET} {msg}")


def error(msg: str):
    print(f"{_ts()} {RED}[✗]{RESET} {msg}", file=sys.stderr)


def debug(msg: str):
    if _verbose:
        print(f"{_ts()} {GREY}[~]{RESET} {DIM}{msg}{RESET}")


def vuln(msg: str):
    print(f"{_ts()} {RED}{BOLD}[VULN]{RESET} {RED}{msg}{RESET}")


def banner():
    art = f"""
{RED}{BOLD}
 ██╗    ██╗   ██╗██╗      █████╗  █████╗
 ██║    ██║   ██║██║     ██╔══██╗██╔══██╗
 ██║    ██║   ██║██║     ╚██████║╚██████║
 ██║    ╚██╗ ██╔╝██║      ╚═══██║ ╚═══██║
 ███████╗╚████╔╝ ███████╗ █████╔╝ █████╔╝
 ╚══════╝ ╚═══╝  ╚══════╝ ╚════╝  ╚════╝{RESET}
{GREY} ─────────────────────────────────────────────────────{RESET}
{WHITE}  Web Application Vulnerability Scanner{RESET}
{DIM}  OWASP Top 10 | SQLi | XSS | CSRF | RCE | SSTI | LFI{RESET}
{DIM}  IDOR | NoSQLi | XXE | SSRF | AuthBypass | API | Fuzz{RESET}
{GREY} ─────────────────────────────────────────────────────{RESET}
{GREY}  For authorized testing on local environments only{RESET}
{GREY}  (DVWA · Juice Shop · WebGoat){RESET}
{GREY} ─────────────────────────────────────────────────────{RESET}
"""
    print(art)


def get_logger(name: str):
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    return logger
