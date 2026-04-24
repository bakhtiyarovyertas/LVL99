"""Report Generator - HTML, JSON, TXT, Markdown output."""
import json
import re
from datetime import datetime
from pathlib import Path
from collections import defaultdict

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLOR = {
    "CRITICAL": "#c0392b",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f39c12",
    "LOW":      "#27ae60",
    "INFO":     "#2980b9",
}
SEVERITY_BADGE = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ff8800",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#00cc44",
    "INFO":     "#4488ff",
}

OWASP_DESCRIPTIONS = {
    "A01:2021 - Broken Access Control":                    "Access control enforces policy such that users cannot act outside of their intended permissions.",
    "A02:2021 - Cryptographic Failures":                   "Failures related to cryptography which often lead to sensitive data exposure.",
    "A03:2021 - Injection":                                "Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query.",
    "A04:2021 - Insecure Design":                          "Risks related to design and architectural flaws.",
    "A05:2021 - Security Misconfiguration":                "Insecure default configurations, incomplete configurations, or misconfigured HTTP headers.",
    "A06:2021 - Vulnerable and Outdated Components":       "Using components with known vulnerabilities.",
    "A07:2021 - Identification and Authentication Failures":"Weaknesses in authentication and session management.",
    "A08:2021 - Software and Data Integrity Failures":     "Failures related to code and infrastructure that does not protect against integrity violations.",
    "A09:2021 - Security Logging Failures":                "Without logging and monitoring, breaches cannot be detected.",
    "A10:2021 - Server-Side Request Forgery":              "SSRF flaws occur when a web application fetches a remote resource without validating the URL.",
}


class ReportGenerator:
    def __init__(self, session, findings: list, crawled_urls: list, elapsed: float):
        self.session = session
        self.findings = findings
        self.crawled_urls = crawled_urls
        self.elapsed = elapsed
        self.target = session.url
        self.scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.vulns = [f for f in findings if f.get("vulnerable", True)]
        self.infos = [f for f in findings if not f.get("vulnerable", True)]

    def generate(self, fmt: str, output_path: str):
        if fmt == "html":
            self._write(output_path, self._html())
        elif fmt == "json":
            self._write(output_path, self._json())
        elif fmt == "txt":
            self._write(output_path, self._txt())
        elif fmt == "markdown":
            self._write(output_path, self._markdown())

    def _write(self, path: str, content: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

    def _severity_counts(self):
        counts = defaultdict(int)
        for f in self.vulns:
            counts[f.get("severity", "INFO")] += 1
        return counts

    def _by_owasp(self):
        grouped = defaultdict(list)
        for f in self.vulns:
            grouped[f.get("owasp", "Uncategorized")].append(f)
        return grouped

    # ─── HTML ────────────────────────────────────────────────────────────────
    def _html(self) -> str:
        counts = self._severity_counts()
        by_owasp = self._by_owasp()
        total_vulns = len(self.vulns)

        # Findings rows
        rows = ""
        for i, f in enumerate(sorted(self.vulns, key=lambda x: SEVERITY_ORDER.get(x.get("severity","INFO"), 4))):
            sev = f.get("severity", "INFO")
            color = SEVERITY_COLOR.get(sev, "#888")
            badge = SEVERITY_BADGE.get(sev, "#888")
            rows += f"""
            <tr>
                <td><span class="badge" style="background:{badge}">{sev}</span></td>
                <td>{self._esc(f.get('module','').upper())}</td>
                <td class="owasp-cell">{self._esc(f.get('owasp',''))}</td>
                <td><a href="{self._esc(f.get('url',''))}" target="_blank" class="url-link">{self._esc(f.get('url','')[:60])}</a></td>
                <td><code>{self._esc(f.get('param',''))}</code></td>
                <td><details><summary>View</summary><pre>{self._esc(str(f.get('payload',''))[:200])}</pre></details></td>
                <td><details><summary>View</summary><pre class="evidence">{self._esc(str(f.get('evidence',''))[:500])}</pre></details></td>
                <td>{self._esc(f.get('description',''))}</td>
                <td class="remediation">{self._esc(f.get('remediation',''))}</td>
            </tr>"""

        # OWASP summary cards
        owasp_cards = ""
        for cat, items in by_owasp.items():
            critical = sum(1 for i in items if i.get("severity") == "CRITICAL")
            high     = sum(1 for i in items if i.get("severity") == "HIGH")
            owasp_cards += f"""
            <div class="owasp-card">
                <div class="owasp-title">{self._esc(cat)}</div>
                <div class="owasp-desc">{self._esc(OWASP_DESCRIPTIONS.get(cat,''))}</div>
                <div class="owasp-stats">
                    <span class="stat-badge critical">{critical} Critical</span>
                    <span class="stat-badge high">{high} High</span>
                    <span class="stat-badge total">{len(items)} Total</span>
                </div>
            </div>"""

        risk_score = min(100, counts.get("CRITICAL",0)*25 + counts.get("HIGH",0)*10 +
                         counts.get("MEDIUM",0)*3 + counts.get("LOW",0))
        risk_label = "CRITICAL" if risk_score >= 75 else "HIGH" if risk_score >= 40 else "MEDIUM" if risk_score >= 15 else "LOW"
        risk_color = SEVERITY_COLOR.get(risk_label, "#888")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LV188 Vulnerability Report — {self._esc(self.target)}</title>
<style>
  :root {{
    --bg: #0d0d0f;
    --panel: #141417;
    --border: #222228;
    --text: #e0e0e8;
    --muted: #888;
    --accent: #e74c3c;
    --accent2: #3498db;
    --mono: 'Courier New', monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; line-height: 1.6; }}
  a {{ color: var(--accent2); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}

  /* Header */
  .header {{ background: linear-gradient(135deg, #0d0d0f 0%, #1a1020 100%); border-bottom: 1px solid #c0392b44; padding: 40px; }}
  .header-inner {{ max-width: 1400px; margin: 0 auto; }}
  .logo {{ font-family: var(--mono); color: #e74c3c; font-size: 11px; line-height: 1.2; white-space: pre; margin-bottom: 20px; opacity: 0.9; }}
  .header h1 {{ font-size: 22px; font-weight: 700; color: #fff; margin-bottom: 8px; }}
  .header-meta {{ color: var(--muted); font-size: 13px; display: flex; gap: 24px; flex-wrap: wrap; margin-top: 12px; }}
  .header-meta span {{ display: flex; align-items: center; gap: 6px; }}

  /* Layout */
  .main {{ max-width: 1400px; margin: 0 auto; padding: 32px 40px; }}

  /* Summary cards */
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 32px; }}
  .summary-card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 20px; text-align: center; }}
  .summary-card .num {{ font-size: 36px; font-weight: 800; font-family: var(--mono); }}
  .summary-card .label {{ font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}
  .c-critical {{ color: #ff4444; border-color: #ff444433; }}
  .c-high     {{ color: #ff8800; border-color: #ff880033; }}
  .c-medium   {{ color: #ffcc00; border-color: #ffcc0033; }}
  .c-low      {{ color: #00cc44; border-color: #00cc4433; }}
  .c-info     {{ color: #4488ff; border-color: #4488ff33; }}
  .c-total    {{ color: #e0e0e8; }}

  /* Risk meter */
  .risk-panel {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 24px; margin-bottom: 32px; display: flex; align-items: center; gap: 24px; }}
  .risk-label {{ font-size: 13px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; }}
  .risk-score {{ font-size: 42px; font-weight: 900; font-family: var(--mono); color: {risk_color}; }}
  .risk-bar {{ flex: 1; height: 12px; background: #222; border-radius: 6px; overflow: hidden; }}
  .risk-bar-fill {{ height: 100%; background: linear-gradient(90deg, #27ae60, #f39c12, #e74c3c); width: {risk_score}%; border-radius: 6px; transition: width 1s; }}
  .risk-desc {{ font-size: 14px; color: var(--muted); }}

  /* Section */
  .section {{ margin-bottom: 40px; }}
  .section-title {{ font-size: 16px; font-weight: 700; color: #fff; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 10px; }}
  .section-title::before {{ content: '▶'; color: var(--accent); font-size: 10px; }}

  /* OWASP cards */
  .owasp-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 16px; }}
  .owasp-card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 18px; }}
  .owasp-title {{ font-size: 13px; font-weight: 700; color: var(--accent); margin-bottom: 8px; }}
  .owasp-desc {{ font-size: 12px; color: var(--muted); margin-bottom: 12px; }}
  .owasp-stats {{ display: flex; gap: 8px; flex-wrap: wrap; }}
  .stat-badge {{ font-size: 11px; padding: 3px 8px; border-radius: 12px; font-weight: 600; }}
  .stat-badge.critical {{ background: #c0392b22; color: #ff4444; border: 1px solid #c0392b44; }}
  .stat-badge.high {{ background: #e67e2222; color: #ff8800; border: 1px solid #e67e2244; }}
  .stat-badge.total {{ background: #ffffff11; color: #aaa; border: 1px solid #ffffff22; }}

  /* Table */
  .table-wrap {{ overflow-x: auto; border-radius: 10px; border: 1px solid var(--border); }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  thead {{ background: #0a0a0c; }}
  th {{ padding: 12px 14px; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--muted); border-bottom: 1px solid var(--border); white-space: nowrap; }}
  td {{ padding: 12px 14px; border-bottom: 1px solid #1a1a1f; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #ffffff04; }}
  .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; color: #fff; letter-spacing: 0.5px; font-family: var(--mono); }}
  code {{ font-family: var(--mono); font-size: 12px; background: #ffffff0f; padding: 2px 6px; border-radius: 3px; }}
  pre {{ font-family: var(--mono); font-size: 12px; background: #0a0a0c; padding: 10px; border-radius: 6px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; color: #a8d8a8; border: 1px solid var(--border); margin-top: 8px; max-height: 200px; overflow-y: auto; }}
  pre.evidence {{ color: #f0c674; }}
  details summary {{ cursor: pointer; color: var(--accent2); font-size: 12px; }}
  details summary:hover {{ text-decoration: underline; }}
  .url-link {{ font-family: var(--mono); font-size: 11px; word-break: break-all; }}
  .owasp-cell {{ font-size: 11px; color: var(--muted); }}
  .remediation {{ font-size: 12px; color: #8bc34a; max-width: 280px; }}

  /* Crawled URLs */
  .url-list {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px; max-height: 300px; overflow-y: auto; }}
  .url-list .url-item {{ font-family: var(--mono); font-size: 12px; color: var(--muted); padding: 3px 0; border-bottom: 1px solid #1a1a1f; }}
  .url-list .url-item:last-child {{ border-bottom: none; }}

  /* Footer */
  .footer {{ border-top: 1px solid var(--border); padding: 24px 40px; text-align: center; color: var(--muted); font-size: 12px; }}

  /* No vulns */
  .no-vulns {{ background: #0a1a0a; border: 1px solid #00cc4433; border-radius: 10px; padding: 32px; text-align: center; color: #00cc44; }}
</style>
</head>
<body>

<div class="header">
<div class="header-inner">
<pre class="logo">██╗     ██╗   ██╗ ██╗ █████╗  █████╗
██║     ██║   ██║ ██║██╔══██╗██╔══██╗
██║     ██║   ██║ ██║╚██████║╚██████║
██║     ╚██╗ ██╔╝ ██║ ╚═══██║ ╚═══██║
███████╗ ╚████╔╝  ██║ █████╔╝ █████╔╝
╚══════╝  ╚═══╝   ╚═╝ ╚════╝  ╚════╝</pre>
<h1>Web Application Vulnerability Report</h1>
<div class="header-meta">
  <span>🎯 Target: <strong>{self._esc(self.target)}</strong></span>
  <span>📅 {self._esc(self.scan_time)}</span>
  <span>⏱ Scan Duration: {self.elapsed:.1f}s</span>
  <span>🔗 URLs Crawled: {len(self.crawled_urls)}</span>
  <span>⚠️ Vulnerabilities: {total_vulns}</span>
</div>
</div>
</div>

<div class="main">

  <!-- Risk Score -->
  <div class="risk-panel">
    <div>
      <div class="risk-label">Overall Risk Score</div>
      <div class="risk-score">{risk_score}/100</div>
      <div class="risk-label" style="color:{risk_color}; font-weight:700">{risk_label} RISK</div>
    </div>
    <div style="flex:1">
      <div class="risk-bar"><div class="risk-bar-fill"></div></div>
      <div class="risk-desc" style="margin-top:8px">Based on {total_vulns} findings across {len(by_owasp)} OWASP categories</div>
    </div>
  </div>

  <!-- Severity Summary -->
  <div class="section">
    <div class="section-title">Vulnerability Summary</div>
    <div class="summary-grid">
      <div class="summary-card c-critical"><div class="num">{counts.get('CRITICAL',0)}</div><div class="label">Critical</div></div>
      <div class="summary-card c-high"><div class="num">{counts.get('HIGH',0)}</div><div class="label">High</div></div>
      <div class="summary-card c-medium"><div class="num">{counts.get('MEDIUM',0)}</div><div class="label">Medium</div></div>
      <div class="summary-card c-low"><div class="num">{counts.get('LOW',0)}</div><div class="label">Low</div></div>
      <div class="summary-card c-info"><div class="num">{counts.get('INFO',0)}</div><div class="label">Info</div></div>
      <div class="summary-card c-total"><div class="num">{total_vulns}</div><div class="label">Total</div></div>
    </div>
  </div>

  <!-- OWASP Top 10 Breakdown -->
  <div class="section">
    <div class="section-title">OWASP Top 10 Classification</div>
    {"<div class='owasp-grid'>" + owasp_cards + "</div>" if owasp_cards else "<div class='no-vulns'>✓ No OWASP classifications triggered</div>"}
  </div>

  <!-- Findings Table -->
  <div class="section">
    <div class="section-title">Detailed Findings ({total_vulns})</div>
    {"<div class='no-vulns'><h2>✓ No vulnerabilities detected</h2><p style='margin-top:8px;color:#888'>The target appears to be secure against tested attack vectors.</p></div>" if not self.vulns else f"""
    <div class="table-wrap">
    <table>
      <thead><tr>
        <th>Severity</th><th>Module</th><th>OWASP</th><th>URL</th>
        <th>Parameter</th><th>Payload</th><th>Evidence</th>
        <th>Description</th><th>Remediation</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table>
    </div>"""}
  </div>

  <!-- Crawled URLs -->
  <div class="section">
    <div class="section-title">Crawled URLs ({len(self.crawled_urls)})</div>
    <div class="url-list">
      {"".join(f'<div class="url-item"><a href="{self._esc(u)}" target="_blank">{self._esc(u)}</a></div>' for u in self.crawled_urls)}
    </div>
  </div>

</div>

<div class="footer">
  Generated by LV188 Scanner — For authorized testing on local environments only (DVWA, Juice Shop, WebGoat)
  — {self._esc(self.scan_time)}
</div>

</body>
</html>"""

    def _esc(self, s: str) -> str:
        return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

    # ─── JSON ─────────────────────────────────────────────────────────────────
    def _json(self) -> str:
        counts = self._severity_counts()
        data = {
            "scanner": "LV188",
            "target": self.target,
            "scan_time": self.scan_time,
            "duration_seconds": round(self.elapsed, 2),
            "summary": {
                "total_vulnerabilities": len(self.vulns),
                "critical": counts.get("CRITICAL", 0),
                "high": counts.get("HIGH", 0),
                "medium": counts.get("MEDIUM", 0),
                "low": counts.get("LOW", 0),
                "info": counts.get("INFO", 0),
                "urls_crawled": len(self.crawled_urls),
            },
            "findings": self.vulns,
            "crawled_urls": self.crawled_urls,
        }
        return json.dumps(data, indent=2, default=str)

    # ─── TXT ──────────────────────────────────────────────────────────────────
    def _txt(self) -> str:
        counts = self._severity_counts()
        lines = []
        lines.append("=" * 80)
        lines.append("  LV188 WEB APPLICATION VULNERABILITY SCANNER")
        lines.append("=" * 80)
        lines.append(f"  Target  : {self.target}")
        lines.append(f"  Scanned : {self.scan_time}")
        lines.append(f"  Duration: {self.elapsed:.1f}s")
        lines.append(f"  URLs    : {len(self.crawled_urls)} crawled")
        lines.append("=" * 80)
        lines.append("")
        lines.append("  SUMMARY")
        lines.append("-" * 40)
        lines.append(f"  CRITICAL : {counts.get('CRITICAL',0)}")
        lines.append(f"  HIGH     : {counts.get('HIGH',0)}")
        lines.append(f"  MEDIUM   : {counts.get('MEDIUM',0)}")
        lines.append(f"  LOW      : {counts.get('LOW',0)}")
        lines.append(f"  INFO     : {counts.get('INFO',0)}")
        lines.append(f"  TOTAL    : {len(self.vulns)}")
        lines.append("")

        by_owasp = self._by_owasp()
        lines.append("  OWASP TOP 10 CLASSIFICATION")
        lines.append("-" * 40)
        for cat, items in by_owasp.items():
            lines.append(f"  [{len(items)}] {cat}")
        lines.append("")

        lines.append("  DETAILED FINDINGS")
        lines.append("=" * 80)
        for i, f in enumerate(sorted(self.vulns, key=lambda x: SEVERITY_ORDER.get(x.get("severity","INFO"), 4)), 1):
            lines.append(f"\n[{i}] {f.get('severity','INFO')} — {f.get('module','').upper()}")
            lines.append(f"    OWASP    : {f.get('owasp','')}")
            lines.append(f"    URL      : {f.get('url','')}")
            lines.append(f"    Param    : {f.get('param','')}")
            lines.append(f"    Payload  : {str(f.get('payload',''))[:120]}")
            lines.append(f"    Evidence : {str(f.get('evidence',''))[:200]}")
            lines.append(f"    Desc     : {f.get('description','')}")
            lines.append(f"    Fix      : {f.get('remediation','')}")
            lines.append("-" * 80)

        lines.append("\n  CRAWLED URLS")
        lines.append("-" * 40)
        for u in self.crawled_urls:
            lines.append(f"  {u}")

        lines.append("\n" + "=" * 80)
        lines.append("  Generated by LV188 Scanner — Authorized testing only")
        lines.append("=" * 80)
        return "\n".join(lines)

    # ─── MARKDOWN ─────────────────────────────────────────────────────────────
    def _markdown(self) -> str:
        counts = self._severity_counts()
        by_owasp = self._by_owasp()
        lines = []
        lines.append("# LV188 Vulnerability Report")
        lines.append(f"\n**Target:** `{self.target}`  ")
        lines.append(f"**Scanned:** {self.scan_time}  ")
        lines.append(f"**Duration:** {self.elapsed:.1f}s  ")
        lines.append(f"**URLs Crawled:** {len(self.crawled_urls)}  ")
        lines.append("\n---\n")

        lines.append("## Summary\n")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            lines.append(f"| {sev} | {counts.get(sev,0)} |")
        lines.append(f"| **TOTAL** | **{len(self.vulns)}** |")

        lines.append("\n## OWASP Top 10 Classification\n")
        for cat, items in by_owasp.items():
            lines.append(f"### {cat}")
            lines.append(f"*{OWASP_DESCRIPTIONS.get(cat,'')}*")
            lines.append(f"\n**{len(items)} finding(s)**\n")

        lines.append("\n## Findings\n")
        for i, f in enumerate(sorted(self.vulns, key=lambda x: SEVERITY_ORDER.get(x.get("severity","INFO"),4)), 1):
            lines.append(f"### [{i}] {f.get('severity','INFO')} — {f.get('module','').upper()}")
            lines.append(f"\n| Field | Value |")
            lines.append(f"|-------|-------|")
            lines.append(f"| OWASP | {f.get('owasp','')} |")
            lines.append(f"| URL | `{f.get('url','')}` |")
            lines.append(f"| Parameter | `{f.get('param','')}` |")
            lines.append(f"| Payload | `{str(f.get('payload',''))[:100]}` |")
            lines.append(f"\n**Evidence:**\n```\n{str(f.get('evidence',''))[:300]}\n```")
            lines.append(f"\n**Description:** {f.get('description','')}")
            lines.append(f"\n**Remediation:** {f.get('remediation','')}\n")
            lines.append("---\n")

        lines.append("## Crawled URLs\n")
        for u in self.crawled_urls:
            lines.append(f"- {u}")

        lines.append("\n---\n*Generated by LV188 Scanner — For authorized testing only*")
        return "\n".join(lines)
