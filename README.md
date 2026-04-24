# LVL99 — Web Application Vulnerability Scanner

```
 ██╗    ██╗   ██╗██╗      █████╗  █████╗
 ██║    ██║   ██║██║     ██╔══██╗██╔══██╗
 ██║    ██║   ██║██║     ╚██████║╚██████║
 ██║    ╚██╗ ██╔╝██║      ╚═══██║ ╚═══██║
 ███████╗╚████╔╝ ███████╗ █████╔╝ █████╔╝
 ╚══════╝ ╚═══╝  ╚══════╝ ╚════╝  ╚════╝
```

> **Authorized testing only** — designed for local Docker environments: DVWA, OWASP Juice Shop, WebGoat.

---

## Features

| Module | Flag | OWASP Category |
|---|---|---|
| SQL Injection | `--sqli` | A03:2021 |
| Cross-Site Scripting | `--xss` | A03:2021 |
| CSRF Protection | `--csrf` | A01:2021 |
| Remote Code Execution | `--rce` | A03:2021 |
| Local File Inclusion | `--lfi` | A01:2021 |
| Server-Side Template Injection | `--ssti` | A03:2021 |
| IDOR | `--idor` | A01:2021 |
| HTML Injection | `--htmli` | A03:2021 |
| NoSQL Injection | `--nosqli` | A03:2021 |
| Auth Bypass | `--auth` | A07:2021 |
| Code Injection | `--code` | A03:2021 |
| API Security | `--api` | A09:2021 |
| Fuzzer | `--fuzz` | A05:2021 |
| XXE | `--xxe` | A05:2021 |
| SSRF | `--ssrf` | A10:2021 |
| File Extension Bypass | `--fileext` | A03:2021 |

---

## Setup

### 1. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 2. Start vulnerable targets via Docker

```bash
cd docker
docker compose up -d
```

| App | URL | Default Credentials |
|---|---|---|
| DVWA | http://localhost:8001 | admin / password |
| Juice Shop | http://localhost:8002 | admin@juice-sh.op / admin123 |
| WebGoat | http://localhost:8003/WebGoat | guest / guest |

> **DVWA setup:** After starting, visit `http://localhost:8001/setup.php` and click **Create / Reset Database**.

---

## Usage

### Full auto-scan with HTML report

```bash
python lvl99.py -u http://localhost:8001 -A --output report.html
```

### Crawl + specific modules

```bash
python lvl99.py -u http://localhost:8001 --crawl --xss --sqli --csrf
```

### Target a specific endpoint

```bash
python lvl99.py -u "http://localhost:8001/vulnerabilities/sqli/?id=1&Submit=Submit" --sqli
```

### Load a saved Burp Suite / ZAP request

```bash
python lvl99.py -r request.txt --sqli --xss --output report
```

### Use a custom wordlist

```bash
python lvl99.py -u http://localhost:8001 --sqli -w my_sqli_payloads.txt
```

### Multiple output formats

```bash
python lvl99.py -u http://localhost:8001 -A --output report --format html,json,txt,markdown
```

### Authenticated scan (with session cookie)

```bash
python lvl99.py -u http://localhost:8001 -A \
  --cookie "PHPSESSID=abc123; security=low" \
  --output report.html
```

### With proxy (Burp Suite / ZAP intercepting)

```bash
python lvl99.py -u http://localhost:8001 --sqli --xss \
  --proxy http://127.0.0.1:8080
```

---

## All CLI Flags

```
Target:
  -u, --url URL          Target URL
  -r, --request FILE     Saved Burp/ZAP HTTP request file
  --crawl                Crawl target before scanning

Modules:
  -A, --all              Run ALL modules
  --sqli                 SQL Injection
  --xss                  Cross-Site Scripting
  --csrf                 CSRF Protection
  --rce                  Remote Code Execution
  --lfi                  Local File Inclusion
  --ssti                 SSTI
  --idor                 IDOR
  --htmli                HTML Injection
  --nosqli               NoSQL Injection
  --auth                 Authentication Bypass
  --code                 Code Injection
  --api                  API Security
  --fuzz                 Generic Fuzzer
  --xxe                  XXE
  --ssrf                 SSRF
  --fileext              File Extension Bypass

Wordlists:
  -w, --wordlist FILE    Custom wordlist (all modules)
  --sqli-wordlist FILE
  --xss-wordlist FILE
  --fuzz-wordlist FILE

Output:
  -o, --output PATH      Output path (without extension)
  -f, --format FMT       html,json,txt,markdown (default: html)

Session / HTTP:
  --cookie COOKIE        Session cookie
  --header HDR           Extra header (repeatable)
  --proxy URL            HTTP proxy
  --timeout N            Request timeout (default: 10)
  --delay SEC            Delay between requests
  --threads N            Threads (default: 10)
  --user-agent UA        Custom User-Agent

Misc:
  -v, --verbose          Verbose debug output
  --no-banner            Suppress banner
```

---

## Wordlists

Wordlists are in `wordlists/`. They are empty by default — add your own payloads, one per line. Lines starting with `#` are ignored.

```
wordlists/
  sqli.txt
  xss.txt
  lfi.txt
  rce.txt
  fuzz.txt
  ssti.txt
  xxe.txt
  nosqli.txt
  htmli.txt
  common.txt
```

---

## Report Formats

- **HTML** — dark-theme interactive report with OWASP classification, risk score, collapsible payloads/evidence
- **JSON** — machine-readable, suitable for CI/CD pipelines
- **TXT** — plain text for terminal logging
- **Markdown** — for GitHub issues / documentation

---

## Project Structure

```
lvl99/
├── lvl99.py              # Main CLI entry point
├── requirements.txt
├── core/
│   ├── logger.py         # Colored CLI output
│   ├── session.py        # HTTP session + config
│   ├── crawler.py        # Web crawler (BFS, threaded)
│   ├── base_scanner.py   # Base class for all modules
│   ├── request_parser.py # Burp/ZAP request file parser
│   └── report.py         # HTML/JSON/TXT/MD report generator
├── modules/
│   ├── sqli.py           # SQL Injection
│   ├── xss.py            # XSS
│   ├── csrf.py           # CSRF
│   ├── rce.py            # RCE
│   ├── lfi.py            # LFI
│   ├── ssti.py           # SSTI
│   ├── idor.py           # IDOR
│   ├── htmli.py          # HTML Injection
│   ├── nosqli.py         # NoSQL Injection
│   ├── auth_bypass.py    # Auth Bypass
│   ├── code_injection.py # Code Injection
│   ├── api_scanner.py    # API Security
│   ├── fuzzer.py         # Fuzzer
│   ├── xxe.py            # XXE
│   ├── ssrf.py           # SSRF
│   └── file_ext.py       # File Extension Bypass
├── wordlists/            # Payload wordlists (fill yourself)
├── reports/              # Default report output directory
└── docker/
    └── docker-compose.yml # DVWA + Juice Shop + WebGoat
```

---

## Disclaimer

LVL99 is intended **exclusively** for authorized security testing on systems you own or have explicit written permission to test. Running this against systems without authorization is illegal. The authors are not responsible for misuse.
