"""LogSentinel | core/reporter.py — HTML report generator."""
import datetime
from pathlib import Path
from collections import Counter

SEV_COLOR = {"CRITICAL":"#7c3aed","HIGH":"#dc2626","MEDIUM":"#ea580c","LOW":"#ca8a04","INFO":"#2563eb"}
SEV_BG    = {"CRITICAL":"#f5f3ff","HIGH":"#fef2f2","MEDIUM":"#fff7ed","LOW":"#fefce8","INFO":"#eff6ff"}

def _badge(sev):
    c = SEV_COLOR.get(sev,"#6b7280")
    return f'<span style="background:{c};color:#fff;padding:2px 9px;border-radius:4px;font-size:11px;font-weight:700;">{sev}</span>'

def generate_report(incidents, parse_stats, log_filepath, output_path, top_ips):
    ts   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    counts = Counter(i.severity for i in incidents)
    sev_chips = "".join(
        f'<div style="background:#fff;border:1px solid #e5e7eb;border-left:4px solid {SEV_COLOR.get(s,"#6b7280")};border-radius:8px;padding:10px 16px;text-align:center;min-width:90px;">'
        f'<div style="font-size:22px;font-weight:800;color:{SEV_COLOR.get(s,"#6b7280")}">{counts.get(s,0)}</div>'
        f'<div style="font-size:10px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-top:3px">{s}</div></div>'
        for s in ["CRITICAL","HIGH","MEDIUM","LOW"]
    )

    # Incident cards
    cards = ""
    for i, inc in enumerate(incidents, 1):
        ev_rows = "".join(f'<div style="background:#0f172a;color:#67e8f9;font-family:monospace;font-size:11px;padding:4px 8px;border-radius:4px;margin:2px 0;word-break:break-all;">{e[:130]}</div>' for e in inc.evidence[:4])
        cards += f"""
        <div style="border:1px solid #e5e7eb;border-left:4px solid {SEV_COLOR.get(inc.severity,'#6b7280')};border-radius:10px;padding:1.25rem 1.5rem;margin-bottom:1rem;background:#fff;">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:8px;margin-bottom:10px;">
            <div>
              <span style="font-size:12px;color:#6b7280;">#{i} &nbsp;·&nbsp; {inc.threat_type.replace('_',' ').upper()}</span>
              <div style="font-size:14px;font-weight:600;color:#111827;margin-top:3px;">{inc.description}</div>
            </div>
            <div style="text-align:right;flex-shrink:0">{_badge(inc.severity)}<div style="font-size:11px;color:#6b7280;margin-top:4px;">Count: {inc.count}</div></div>
          </div>
          <div style="margin-bottom:8px;">{ev_rows}</div>
          <div style="background:#eff6ff;border-radius:6px;padding:8px 12px;font-size:12px;color:#1d4ed8;">
            <strong>→ Recommendation:</strong> {inc.recommendation}
          </div>
          {'<div style="font-size:11px;color:#6b7280;margin-top:6px;">Source IP: <code>' + (inc.source_ip or 'N/A') + '</code></div>' if inc.source_ip else ''}
        </div>"""

    # Top IPs table
    ip_rows = "".join(
        f'<tr><td style="padding:7px 12px;font-family:monospace;">{ip}</td><td style="padding:7px 12px;text-align:center;">{cnt}</td></tr>'
        for ip, cnt in top_ips[:10]
    )

    risk_level = "CRITICAL" if counts.get("CRITICAL",0) > 0 else \
                 "HIGH"     if counts.get("HIGH",0) > 0 else \
                 "MEDIUM"   if counts.get("MEDIUM",0) > 0 else \
                 "LOW"      if counts.get("LOW",0) > 0 else "SAFE"
    risk_color = SEV_COLOR.get(risk_level, "#16a34a")

    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/>
<title>LogSentinel Report</title>
<style>
  body{{font-family:'Segoe UI',system-ui,sans-serif;background:#f3f4f6;margin:0;padding:2rem;color:#111827}}
  .wrap{{max-width:1000px;margin:0 auto;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)}}
  .hd{{background:linear-gradient(135deg,#0f172a,#1a2b4a);color:#fff;padding:2rem 2.5rem}}
  .meta{{background:#f8fafc;padding:1.25rem 2.5rem;display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:1rem;border-bottom:1px solid #e5e7eb}}
  .mc{{text-align:center}}.ml{{font-size:10px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-bottom:3px}}.mv{{font-size:1.05rem;font-weight:700}}
  .sec{{padding:1.5rem 2.5rem}}.sec+.sec{{border-top:1px solid #f1f5f9}}
  h2{{font-size:14px;font-weight:700;color:#1e293b;text-transform:uppercase;letter-spacing:.5px;padding-bottom:6px;border-bottom:2px solid #e5e7eb;margin-bottom:1rem}}
  table{{width:100%;border-collapse:collapse;font-size:13px}}
  th{{background:#f1f5f9;padding:8px 12px;text-align:left;font-size:11px;text-transform:uppercase;color:#475569;font-weight:600}}
  tr:nth-child(even){{background:#f8fafc}}
  footer{{text-align:center;padding:1rem;font-size:12px;color:#9ca3af;border-top:1px solid #f1f5f9}}
</style></head><body>
<div class="wrap">
  <div class="hd">
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:1rem">
      <div style="width:42px;height:42px;background:#3b82f6;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:22px">🔍</div>
      <div><div style="font-size:1.4rem;font-weight:800">LogSentinel</div>
           <div style="font-size:11px;color:#94a3b8;letter-spacing:2px;text-transform:uppercase">Security Log Analyzer</div></div>
    </div>
    <div style="background:rgba(255,255,255,.08);border-radius:10px;padding:1rem 1.5rem;display:flex;align-items:center;gap:1.5rem;flex-wrap:wrap">
      <div>
        <div style="font-size:2.5rem;font-weight:900;color:{risk_color};line-height:1">{len(incidents)}</div>
        <div style="font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px">Incidents</div>
      </div>
      <div style="flex:1">
        <div style="font-size:12px;color:#94a3b8">LOG FILE</div>
        <div style="font-size:13px;color:#fff;font-family:monospace;margin-top:3px">{log_filepath}</div>
        <div style="margin-top:10px"><span style="background:{risk_color};color:#fff;padding:3px 12px;border-radius:5px;font-size:12px;font-weight:700;">OVERALL RISK: {risk_level}</span></div>
      </div>
    </div>
  </div>

  <div class="meta">
    <div class="mc"><div class="ml">Lines Parsed</div><div class="mv">{parse_stats.get("total_lines",0):,}</div></div>
    <div class="mc"><div class="ml">Web Entries</div><div class="mv">{parse_stats.get("web_count",0):,}</div></div>
    <div class="mc"><div class="ml">SSH Entries</div><div class="mv">{parse_stats.get("ssh_count",0):,}</div></div>
    <div class="mc"><div class="ml">Incidents</div><div class="mv" style="color:{risk_color}">{len(incidents)}</div></div>
    <div class="mc"><div class="ml">Unique IPs</div><div class="mv">{len(top_ips)}</div></div>
    <div class="mc"><div class="ml">Scanned At</div><div class="mv" style="font-size:.8rem">{ts}</div></div>
  </div>

  <div class="sec">
    <h2>Severity Summary</h2>
    <div style="display:flex;gap:10px;flex-wrap:wrap">{sev_chips}</div>
  </div>

  <div class="sec">
    <h2>Detected Incidents ({len(incidents)})</h2>
    {''.join([cards]) if incidents else '<p style="color:#6b7280;font-size:13px;">No incidents detected. Log appears clean.</p>'}
  </div>

  {'<div class="sec"><h2>Top Source IPs</h2><table><thead><tr><th>IP Address</th><th>Total Requests</th></tr></thead><tbody>' + ip_rows + '</tbody></table></div>' if top_ips else ''}

  <footer>LogSentinel v1.0 &nbsp;|&nbsp; Built by <strong>Daksh Shah</strong> &nbsp;|&nbsp; github.com/daksh-shah9135/logsentinel</footer>
</div></body></html>"""

    Path(output_path).write_text(html, encoding="utf-8")
    return output_path
