"""
reports/html_reporter.py
Generates professional HTML security reports for FiveM scan results.
"""

import os
import json
from datetime import datetime
from typing import List, Dict, Optional

from core.risk_scorer import ResourceScanResult, get_severity_color, get_risk_level_color


def _get_reports_dir() -> str:
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cfg_path = os.path.join(base, "config.json")
    r_dir = "scan_reports"
    if os.path.exists(cfg_path):
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            r_dir = cfg.get("reports", {}).get("directory", r_dir)
        except Exception:
            pass
    path = os.path.join(base, r_dir)
    os.makedirs(path, exist_ok=True)
    return path


def _severity_badge(severity: str) -> str:
    colors = {
        "CRITICAL": "#FF4444",
        "HIGH": "#FF8C00",
        "MEDIUM": "#FFD700",
        "LOW": "#4CAF50",
    }
    text_colors = {"MEDIUM": "#333"}
    bg = colors.get(severity.upper(), "#999")
    fg = text_colors.get(severity.upper(), "#fff")
    return f'<span class="badge" style="background:{bg};color:{fg}">{severity}</span>'


def _risk_badge(level: str, score: int) -> str:
    color = get_risk_level_color(level)
    fg = "#333" if level == "MEDIUM" or level == "SAFE" else "#fff"
    return f'<span class="badge risk-badge" style="background:{color};color:{fg}">{level} ({score}/100)</span>'


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FiveM Anti-Backdoor Scan Report</title>
<style>
  :root {{
    --bg: #0f0f17;
    --card: #1a1a2e;
    --border: #2d2d4e;
    --accent: #6c63ff;
    --text: #e2e2f0;
    --text2: #9090b0;
    --critical: #FF4444;
    --high: #FF8C00;
    --medium: #FFD700;
    --low: #4CAF50;
    --safe: #2196F3;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'Segoe UI', system-ui, sans-serif;
    font-size: 14px;
    line-height: 1.6;
  }}
  .header {{
    background: linear-gradient(135deg, #1a0533 0%, #0d1b4b 100%);
    padding: 40px;
    border-bottom: 2px solid var(--accent);
  }}
  .header h1 {{ font-size: 2rem; color: #fff; margin-bottom: 8px; }}
  .header .subtitle {{ color: var(--text2); font-size: 0.95rem; }}
  .header .meta {{ margin-top: 16px; display: flex; gap: 24px; flex-wrap: wrap; }}
  .header .meta-item {{ color: var(--text2); font-size: 0.85rem; }}
  .header .meta-item strong {{ color: var(--text); }}
  .container {{ max-width: 1400px; margin: 0 auto; padding: 32px 24px; }}
  .summary-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
  }}
  .stat-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    text-align: center;
  }}
  .stat-card .value {{ font-size: 2rem; font-weight: 700; }}
  .stat-card .label {{ color: var(--text2); font-size: 0.8rem; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.05em; }}
  .stat-card.critical .value {{ color: var(--critical); }}
  .stat-card.high .value {{ color: var(--high); }}
  .stat-card.medium .value {{ color: var(--medium); }}
  .stat-card.low .value {{ color: var(--low); }}
  .stat-card.safe .value {{ color: var(--safe); }}
  .section {{ margin-bottom: 40px; }}
  .section h2 {{
    font-size: 1.2rem;
    color: var(--accent);
    border-bottom: 1px solid var(--border);
    padding-bottom: 12px;
    margin-bottom: 20px;
  }}
  .resource-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 10px;
    margin-bottom: 20px;
    overflow: hidden;
  }}
  .resource-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 16px 20px;
    background: rgba(255,255,255,0.03);
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
    gap: 8px;
  }}
  .resource-name {{ font-size: 1.1rem; font-weight: 600; }}
  .resource-meta {{ color: var(--text2); font-size: 0.85rem; }}
  .badge {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
  }}
  .risk-badge {{ font-size: 0.8rem; padding: 4px 12px; }}
  .detection-list {{ padding: 0; list-style: none; }}
  .detection-item {{
    padding: 16px 20px;
    border-bottom: 1px solid var(--border);
  }}
  .detection-item:last-child {{ border-bottom: none; }}
  .detection-header {{
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 10px;
    flex-wrap: wrap;
    gap: 8px;
  }}
  .detection-title {{ font-weight: 600; font-size: 0.95rem; }}
  .detection-badges {{ display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }}
  .detection-meta {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 8px;
    margin-bottom: 10px;
    font-size: 0.82rem;
    color: var(--text2);
  }}
  .detection-meta span strong {{ color: var(--text); }}
  .detection-desc {{ font-size: 0.88rem; color: var(--text2); margin-bottom: 8px; }}
  .detection-rec {{
    font-size: 0.82rem;
    color: #7bb3ff;
    margin-bottom: 8px;
  }}
  .code-block {{
    background: #0a0a14;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px;
    font-family: 'Cascadia Code', 'Consolas', monospace;
    font-size: 0.78rem;
    color: #c8c8e8;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 200px;
    overflow-y: auto;
    margin-top: 8px;
  }}
  .confidence-bar {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 0.8rem;
  }}
  .confidence-fill {{
    height: 6px;
    border-radius: 3px;
    background: var(--accent);
    display: inline-block;
  }}
  .safe-resource {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px 16px;
    color: var(--low);
    font-size: 0.88rem;
    margin-bottom: 8px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }}
  .footer {{
    text-align: center;
    padding: 32px;
    color: var(--text2);
    font-size: 0.8rem;
    border-top: 1px solid var(--border);
    margin-top: 40px;
  }}
  .toc {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 20px; margin-bottom: 32px; }}
  .toc h3 {{ font-size: 1rem; margin-bottom: 12px; color: var(--accent); }}
  .toc ul {{ list-style: none; }}
  .toc li {{ padding: 4px 0; }}
  .toc a {{ color: var(--text2); text-decoration: none; font-size: 0.88rem; }}
  .toc a:hover {{ color: var(--accent); }}
  @media print {{ body {{ background: #fff; color: #000; }} }}
</style>
</head>
<body>
<div class="header">
  <h1>🛡️ FiveM Anti-Backdoor — Security Report</h1>
  <div class="subtitle">FiveM Resource Static Analysis Report</div>
  <div class="meta">
    <div class="meta-item"><strong>Scan Date:</strong> {scan_date}</div>
    <div class="meta-item"><strong>Scan Type:</strong> {scan_type}</div>
    <div class="meta-item"><strong>Target:</strong> {target_path}</div>
    <div class="meta-item"><strong>Duration:</strong> {duration}</div>
  </div>
</div>

<div class="container">
  <div class="summary-grid">
    <div class="stat-card"><div class="value">{total_resources}</div><div class="label">Resources</div></div>
    <div class="stat-card"><div class="value">{total_files}</div><div class="label">Files Scanned</div></div>
    <div class="stat-card"><div class="value">{total_detections}</div><div class="label">Total Threats</div></div>
    <div class="stat-card critical"><div class="value">{critical_count}</div><div class="label">Critical</div></div>
    <div class="stat-card high"><div class="value">{high_count}</div><div class="label">High</div></div>
    <div class="stat-card medium"><div class="value">{medium_count}</div><div class="label">Medium</div></div>
    <div class="stat-card low"><div class="value">{low_count}</div><div class="label">Low</div></div>
  </div>

  {toc_html}

  {threats_html}

  {safe_html}
</div>

<div class="footer">
  Generated by FiveM Anti-Backdoor v1.0.0 &nbsp;|&nbsp; {scan_date} &nbsp;|&nbsp;
  Static analysis only — no code was executed during this scan.
</div>
</body>
</html>
"""


def generate_html_report(results: List[ResourceScanResult],
                          scan_type: str = "full",
                          target_path: str = "",
                          duration_str: str = "",
                          output_path: Optional[str] = None) -> str:
    """
    Generate an HTML security report from scan results.
    Returns the path to the generated HTML file.
    """
    reports_dir = _get_reports_dir()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if output_path is None:
        output_path = os.path.join(reports_dir, f"scan_report_{timestamp}.html")

    # Compute summary stats
    total_resources = len(results)
    total_files = sum(r.total_files_scanned for r in results)
    total_detections = sum(len(r.detections) for r in results)
    critical_count = sum(r.critical_count for r in results)
    high_count = sum(r.high_count for r in results)
    medium_count = sum(r.medium_count for r in results)
    low_count = sum(r.low_count for r in results)

    # Sort: highest risk first
    sorted_results = sorted(results, key=lambda r: r.risk_score, reverse=True)
    threat_results = [r for r in sorted_results if r.detections]
    safe_results = [r for r in sorted_results if not r.detections]

    # Build TOC
    toc_items = []
    for r in threat_results:
        anchor = r.resource_name.replace(" ", "_")
        toc_items.append(
            f'<li><a href="#{anchor}">{r.resource_name}</a> — '
            f'{_risk_badge(r.risk_level, r.risk_score)} '
            f'({len(r.detections)} detection{"s" if len(r.detections) != 1 else ""})</li>'
        )
    toc_html = ""
    if toc_items:
        toc_html = f"""
        <div class="toc">
          <h3>📋 Table of Contents — {len(threat_results)} resource(s) with detections</h3>
          <ul>{''.join(toc_items)}</ul>
        </div>"""

    # Build threat sections
    threats_parts = []
    if threat_results:
        threats_parts.append('<div class="section"><h2>⚠️ Resources With Detections</h2>')
        for r in threat_results:
            anchor = r.resource_name.replace(" ", "_")
            detection_items = []
            for det in r.detections:
                file_rel = os.path.basename(det.file_path)
                line_str = f"Line {det.line_number}" if det.line_number else "N/A"
                conf_w = int(det.confidence * 0.8)
                conf_bar = (
                    f'<span class="confidence-bar">'
                    f'<span class="confidence-fill" style="width:{conf_w}px;"></span>'
                    f'{det.confidence}%</span>'
                )
                code_block = ""
                if det.code_context:
                    safe_ctx = (det.code_context
                                .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
                    code_block = f'<div class="code-block">{safe_ctx}</div>'

                detection_items.append(f"""
                  <li class="detection-item">
                    <div class="detection-header">
                      <div class="detection-title">{det.rule_name}</div>
                      <div class="detection-badges">
                        {_severity_badge(det.severity)}
                        {conf_bar}
                      </div>
                    </div>
                    <div class="detection-meta">
                      <span><strong>File:</strong> {file_rel}</span>
                      <span><strong>Line:</strong> {line_str}</span>
                      <span><strong>Rule ID:</strong> {det.rule_id}</span>
                      <span><strong>Pattern:</strong> {det.matched_pattern[:60] if det.matched_pattern else 'N/A'}</span>
                    </div>
                    <div class="detection-desc">{det.description}</div>
                    <div class="detection-rec">💡 {det.recommendation}</div>
                    {code_block}
                  </li>""")

            threats_parts.append(f"""
              <div class="resource-card" id="{anchor}">
                <div class="resource-header">
                  <div>
                    <div class="resource-name">{r.resource_name}</div>
                    <div class="resource-meta">
                      Framework: {r.framework} &nbsp;|&nbsp;
                      {len(r.detections)} detection{"s" if len(r.detections) != 1 else ""} &nbsp;|&nbsp;
                      {r.total_files_scanned} file{"s" if r.total_files_scanned != 1 else ""} scanned
                    </div>
                  </div>
                  {_risk_badge(r.risk_level, r.risk_score)}
                </div>
                <ul class="detection-list">
                  {''.join(detection_items)}
                </ul>
              </div>""")
        threats_parts.append("</div>")

    threats_html = "\n".join(threats_parts)

    # Build safe resources section
    safe_html = ""
    if safe_results:
        safe_items = []
        for r in safe_results:
            safe_items.append(
                f'<div class="safe-resource">'
                f'<span>✅ {r.resource_name} <small style="color:#666">({r.framework})</small></span>'
                f'{_risk_badge("SAFE", 0)}'
                f'</div>'
            )
        safe_html = f"""
        <div class="section">
          <h2>✅ Clean Resources ({len(safe_results)})</h2>
          {''.join(safe_items)}
        </div>"""

    html = HTML_TEMPLATE.format(
        scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        scan_type=scan_type.upper(),
        target_path=target_path or "N/A",
        duration=duration_str or "N/A",
        total_resources=total_resources,
        total_files=total_files,
        total_detections=total_detections,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        toc_html=toc_html,
        threats_html=threats_html,
        safe_html=safe_html,
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path
