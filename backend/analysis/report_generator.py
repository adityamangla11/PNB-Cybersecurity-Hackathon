"""
PDF Report Generator

Generates a professional PDF report of scan results using only
the standard library (no external PDF lib needed — outputs HTML
that can be rendered to PDF, or uses a simple text-based PDF approach).

For hackathon simplicity, we generate a styled HTML report that browsers
can print to PDF natively.
"""

import datetime
import html


def _label_color(label: str) -> str:
    return {
        "PQC Ready": "#10b981",
        "Quantum-Safe": "#3b82f6",
        "At Risk": "#f59e0b",
        "Critical": "#dc2626",
    }.get(label, "#6b7280")


def generate_html_report(scan_data: dict, assets: list[dict], recommendations: list[dict]) -> str:
    """Generate a styled HTML report suitable for printing to PDF."""
    scan_date = scan_data.get("created_at", datetime.datetime.utcnow().isoformat())
    total = len(assets)
    pqc_count = sum(1 for a in assets if a.get("label") == "PQC Ready")
    safe_count = sum(1 for a in assets if a.get("label") == "Quantum-Safe")
    risk_count = sum(1 for a in assets if a.get("label") == "At Risk")
    crit_count = sum(1 for a in assets if a.get("label") == "Critical")
    avg_score = sum(a.get("score", 0) for a in assets) / total if total else 0

    # Build asset rows
    asset_rows = ""
    for a in assets:
        lcolor = _label_color(a.get("label", ""))
        asset_rows += f"""
        <tr>
            <td>{html.escape(a.get('host', ''))}</td>
            <td>{a.get('port', 443)}</td>
            <td>{html.escape(a.get('highest_tls_version', 'N/A'))}</td>
            <td>{html.escape(a.get('cert_key_type', 'N/A'))}-{a.get('cert_key_size', 'N/A')}</td>
            <td>{html.escape(a.get('cert_signature_algorithm', 'N/A'))}</td>
            <td style="font-weight:bold;">{a.get('score', 0)}</td>
            <td><span style="background:{lcolor}; color:white; padding:2px 10px; border-radius:12px; font-size:11px; font-weight:600;">{html.escape(a.get('label', 'Unknown'))}</span></td>
        </tr>"""

    # Build recommendation rows
    rec_rows = ""
    priority_colors = {"Critical": "#dc2626", "High": "#f59e0b", "Medium": "#3b82f6", "Low": "#6b7280"}
    for r in recommendations:
        pcolor = priority_colors.get(r.get("priority", ""), "#6b7280")
        rec_rows += f"""
        <tr>
            <td><span style="background:{pcolor}; color:white; padding:2px 8px; border-radius:8px; font-size:10px; font-weight:600;">{html.escape(r.get('priority', ''))}</span></td>
            <td>{html.escape(r.get('asset_host', ''))}:{r.get('asset_port', 443)}</td>
            <td>{html.escape(r.get('current', ''))}</td>
            <td style="color:#10b981; font-weight:600;">{html.escape(r.get('recommended', ''))}</td>
            <td style="font-size:11px;">{html.escape(r.get('standard', ''))}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>PNB QuantumShield — Scan Report</title>
<style>
    @page {{ margin: 1cm; }}
    body {{ font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; color: #1e293b; margin: 0; padding: 20px; background: white; font-size: 13px; line-height: 1.5; }}
    .header {{ background: linear-gradient(135deg, #0f172a, #1e3a5f); color: white; padding: 30px; border-radius: 12px; margin-bottom: 24px; }}
    .header h1 {{ margin: 0; font-size: 28px; }}
    .header p {{ margin: 4px 0 0; opacity: 0.8; font-size: 14px; }}
    .header .subtitle {{ font-size: 12px; opacity: 0.6; margin-top: 8px; }}
    .stats {{ display: flex; gap: 12px; margin-bottom: 24px; }}
    .stat-card {{ flex: 1; padding: 16px; border-radius: 10px; text-align: center; }}
    .stat-card .number {{ font-size: 32px; font-weight: 700; }}
    .stat-card .label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 1px; opacity: 0.8; margin-top: 4px; }}
    h2 {{ color: #0f172a; border-bottom: 2px solid #e2e8f0; padding-bottom: 8px; margin-top: 32px; font-size: 18px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 12px; }}
    th {{ background: #f1f5f9; color: #475569; text-align: left; padding: 10px 12px; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }}
    td {{ padding: 8px 12px; border-bottom: 1px solid #e2e8f0; }}
    tr:hover {{ background: #f8fafc; }}
    .section {{ page-break-inside: avoid; }}
    .footer {{ margin-top: 40px; text-align: center; color: #94a3b8; font-size: 11px; border-top: 1px solid #e2e8f0; padding-top: 16px; }}
    .risk-banner {{ background: #fef3c7; border: 1px solid #f59e0b; border-radius: 10px; padding: 16px; margin-bottom: 20px; }}
    .risk-banner.critical {{ background: #fef2f2; border-color: #dc2626; }}
</style>
</head>
<body>
    <div class="header">
        <h1>PNB QuantumShield — Crypto Scan Report</h1>
        <p>Quantum Readiness Assessment for Public-Facing Applications</p>
        <p class="subtitle">Scan #{scan_data.get('id', 'N/A')} | Generated: {datetime.datetime.utcnow().strftime('%d %B %Y, %H:%M UTC')} | Scan Date: {scan_date}</p>
    </div>

    <div class="stats">
        <div class="stat-card" style="background:#f0fdf4; color:#166534;">
            <div class="number">{total}</div>
            <div class="label">Total Assets</div>
        </div>
        <div class="stat-card" style="background:#f0fdf4; color:#166534;">
            <div class="number">{pqc_count}</div>
            <div class="label">PQC Ready</div>
        </div>
        <div class="stat-card" style="background:#eff6ff; color:#1e40af;">
            <div class="number">{safe_count}</div>
            <div class="label">Quantum-Safe</div>
        </div>
        <div class="stat-card" style="background:#fffbeb; color:#92400e;">
            <div class="number">{risk_count}</div>
            <div class="label">At Risk</div>
        </div>
        <div class="stat-card" style="background:#fef2f2; color:#991b1b;">
            <div class="number">{crit_count}</div>
            <div class="label">Critical</div>
        </div>
        <div class="stat-card" style="background:#f1f5f9; color:#334155;">
            <div class="number">{avg_score:.0f}</div>
            <div class="label">Avg Score</div>
        </div>
    </div>

    {'<div class="risk-banner critical"><strong>⚠ CRITICAL FINDING:</strong> ' + str(crit_count) + ' asset(s) have critical quantum vulnerabilities requiring immediate attention.</div>' if crit_count > 0 else ''}
    {'<div class="risk-banner"><strong>⚠ ATTENTION:</strong> ' + str(risk_count) + ' asset(s) are at risk and require a PQC migration plan.</div>' if risk_count > 0 else ''}

    <div class="section">
        <h2>Cryptographic Asset Inventory</h2>
        <table>
            <thead>
                <tr><th>Host</th><th>Port</th><th>TLS</th><th>Key</th><th>Signature</th><th>Score</th><th>Label</th></tr>
            </thead>
            <tbody>{asset_rows}</tbody>
        </table>
    </div>

    <div class="section">
        <h2>PQC Migration Recommendations</h2>
        <table>
            <thead>
                <tr><th>Priority</th><th>Asset</th><th>Current</th><th>Recommended</th><th>Standard</th></tr>
            </thead>
            <tbody>{rec_rows if rec_rows else '<tr><td colspan="5" style="text-align:center; color:#94a3b8;">All assets are quantum-safe. No recommendations.</td></tr>'}</tbody>
        </table>
    </div>

    <div class="section">
        <h2>About This Report</h2>
        <p>This report was generated by <strong>PNB QuantumShield</strong>, a cryptographic scanner that assesses quantum readiness of public-facing banking infrastructure. The scanner evaluates TLS configurations, certificate algorithms, cipher suites, and key exchange mechanisms against NIST Post-Quantum Cryptography standards (FIPS 203, 204, 205, 206).</p>
        <p><strong>Scoring Methodology:</strong> Each asset is scored 0-100 based on TLS version (25%), key exchange algorithm (35%), symmetric cipher strength (15%), and signature algorithm (25%). Assets using NIST-standardized PQC algorithms receive the "PQC Ready" label.</p>
        <p><strong>HNDL Threat:</strong> Harvest Now, Decrypt Later attacks mean that encrypted data intercepted today could be decrypted once cryptanalytically relevant quantum computers (CRQCs) become available. Banking data with long shelf life (customer PII, regulatory records) is especially vulnerable.</p>
    </div>

    <div class="footer">
        <p>Punjab National Bank — Cybersecurity Division | PNB QuantumShield v1.0.0 | Confidential</p>
        <p>This report is auto-generated and should be reviewed by qualified cybersecurity personnel.</p>
    </div>
</body>
</html>"""
