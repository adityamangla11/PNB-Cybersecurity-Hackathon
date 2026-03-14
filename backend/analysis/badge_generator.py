"""
Certificate Badge Generator

Generates SVG certificate badges for assets:
- "PQC Ready" — fully quantum-safe
- "Quantum-Safe" — mostly safe with minor issues
- "At Risk" / "Critical" — needs attention

The SVG can be downloaded and embedded in reports.
"""

import datetime
import html as html_mod


def _gradient_colors(label: str) -> tuple:
    """Return (color1, color2, text_color) for badge gradient."""
    return {
        "PQC Ready": ("#059669", "#10b981", "#ffffff"),
        "Quantum-Safe": ("#2563eb", "#3b82f6", "#ffffff"),
        "At Risk": ("#d97706", "#f59e0b", "#ffffff"),
        "Critical": ("#dc2626", "#ef4444", "#ffffff"),
    }.get(label, ("#6b7280", "#9ca3af", "#ffffff"))


def generate_badge_svg(host: str, port: int, score: float, label: str, scan_date: str = None) -> str:
    """Generate an SVG certificate badge."""
    c1, c2, tc = _gradient_colors(label)
    date_str = scan_date or datetime.datetime.utcnow().strftime("%Y-%m-%d")
    safe_host = html_mod.escape(host)
    score_int = int(score)
    badge_id = f"badge-{host.replace('.', '-')}"

    checkmark_icon = ""
    if label in ("PQC Ready", "Quantum-Safe"):
        checkmark_icon = f"""
        <circle cx="200" cy="115" r="32" fill="white" fill-opacity="0.15"/>
        <path d="M185 115 L195 125 L215 105" stroke="white" stroke-width="3.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/>"""
    else:
        checkmark_icon = f"""
        <circle cx="200" cy="115" r="32" fill="white" fill-opacity="0.15"/>
        <path d="M190 105 L210 125 M210 105 L190 125" stroke="white" stroke-width="3.5" fill="none" stroke-linecap="round"/>"""

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 280" width="400" height="280" id="{badge_id}">
  <defs>
    <linearGradient id="bg-{badge_id}" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="{c1}"/>
      <stop offset="100%" stop-color="{c2}"/>
    </linearGradient>
    <filter id="shadow-{badge_id}">
      <feDropShadow dx="0" dy="4" stdDeviation="6" flood-opacity="0.15"/>
    </filter>
  </defs>

  <!-- Background -->
  <rect width="400" height="280" rx="16" fill="url(#bg-{badge_id})" filter="url(#shadow-{badge_id})"/>

  <!-- Decorative border -->
  <rect x="8" y="8" width="384" height="264" rx="12" fill="none" stroke="white" stroke-opacity="0.25" stroke-width="1.5" stroke-dasharray="6,4"/>

  <!-- PNB Logo Area -->
  <text x="200" y="48" text-anchor="middle" font-family="system-ui, sans-serif" font-size="11" fill="white" fill-opacity="0.7" letter-spacing="3" font-weight="600">PUNJAB NATIONAL BANK</text>

  <!-- Main Label -->
  <text x="200" y="82" text-anchor="middle" font-family="system-ui, sans-serif" font-size="22" fill="{tc}" font-weight="800" letter-spacing="1">{html_mod.escape(label.upper())}</text>

  <!-- Icon -->
  {checkmark_icon}

  <!-- Score -->
  <text x="200" y="170" text-anchor="middle" font-family="system-ui, sans-serif" font-size="38" fill="{tc}" font-weight="800">{score_int}/100</text>
  <text x="200" y="190" text-anchor="middle" font-family="system-ui, sans-serif" font-size="11" fill="white" fill-opacity="0.7" letter-spacing="1">QUANTUM READINESS SCORE</text>

  <!-- Host -->
  <rect x="60" y="203" width="280" height="28" rx="14" fill="white" fill-opacity="0.15"/>
  <text x="200" y="222" text-anchor="middle" font-family="monospace" font-size="13" fill="{tc}" font-weight="600">{safe_host}:{port}</text>

  <!-- Footer -->
  <text x="200" y="256" text-anchor="middle" font-family="system-ui, sans-serif" font-size="10" fill="white" fill-opacity="0.5">QuantumShield Assessment — {date_str}</text>
</svg>"""
