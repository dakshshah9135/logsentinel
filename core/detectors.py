"""
LogSentinel | core/detectors.py
All threat detection engines. Each detector takes a list of LogEntry
objects and returns a list of Incident objects.
"""
import json, re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Optional
from pathlib import Path
from core.parser import LogEntry

_DB = json.loads((Path(__file__).parent.parent / "config" / "rules.json").read_text())

@dataclass
class Incident:
    threat_type:    str
    severity:       str
    source_ip:      Optional[str]
    description:    str
    evidence:       List[str]
    line_numbers:   List[int]
    count:          int = 1
    recommendation: str = ""

def _sev(key: str) -> str:
    return _DB["threat_scores"].get(key, "MEDIUM")

# ── 1. Brute Force SSH ────────────────────────────────────────────────────────
def detect_brute_force_ssh(entries: List[LogEntry]) -> List[Incident]:
    threshold = _DB["brute_force"]["ssh_fail_threshold"]
    fails_by_ip = defaultdict(list)
    success_by_ip = defaultdict(list)
    for e in entries:
        if e.log_type != "ssh" or not e.ip or not e.message:
            continue
        msg = e.message.lower()
        if "failed password" in msg or "invalid user" in msg or "authentication failure" in msg:
            fails_by_ip[e.ip].append(e)
        if "accepted password" in msg or "accepted publickey" in msg:
            success_by_ip[e.ip].append(e)

    incidents = []
    for ip, fail_list in fails_by_ip.items():
        if len(fail_list) >= threshold:
            sev = "CRITICAL" if ip in success_by_ip else "HIGH"
            threat = "successful_brute_force" if ip in success_by_ip else "brute_force_ssh"
            desc = (f"IP {ip} made {len(fail_list)} failed SSH login attempts"
                    + (f" — then SUCCESSFULLY authenticated ({len(success_by_ip[ip])} time(s)). Possible account compromise." if ip in success_by_ip else "."))
            evidence = [e.raw[:120] for e in fail_list[:5]]
            if ip in success_by_ip:
                evidence += [f"[SUCCESS] {e.raw[:120]}" for e in success_by_ip[ip][:2]]
            rec = ("Immediately revoke session, rotate credentials, audit what was accessed." if ip in success_by_ip
                   else f"Block IP {ip} at the firewall. Enable fail2ban. Disable password-based SSH — use key auth only.")
            incidents.append(Incident(
                threat_type=threat, severity=sev, source_ip=ip,
                description=desc, evidence=evidence,
                line_numbers=[e.line_number for e in fail_list[:5]],
                count=len(fail_list), recommendation=rec))
    return incidents

# ── 2. Brute Force Web (Login Endpoint) ──────────────────────────────────────
def detect_brute_force_web(entries: List[LogEntry]) -> List[Incident]:
    threshold = _DB["brute_force"]["web_fail_threshold"]
    login_paths = ["/login", "/signin", "/auth", "/wp-login", "/admin/login", "/user/login"]
    fail_codes  = {401, 403}
    fails_by_ip = defaultdict(list)
    for e in entries:
        if e.log_type != "web" or not e.ip or not e.path:
            continue
        if any(p in e.path.lower() for p in login_paths) and e.status_code in fail_codes:
            fails_by_ip[e.ip].append(e)
    incidents = []
    for ip, fl in fails_by_ip.items():
        if len(fl) >= threshold:
            incidents.append(Incident(
                threat_type="brute_force_web", severity=_sev("brute_force_web"), source_ip=ip,
                description=f"IP {ip} made {len(fl)} failed web login attempts against {fl[0].path}.",
                evidence=[e.raw[:120] for e in fl[:5]],
                line_numbers=[e.line_number for e in fl[:5]],
                count=len(fl),
                recommendation=f"Rate-limit login endpoint. Add CAPTCHA. Block {ip} at WAF/firewall. Enable account lockout policy."))
    return incidents

# ── 3. SQL Injection ──────────────────────────────────────────────────────────
def detect_sql_injection(entries: List[LogEntry]) -> List[Incident]:
    patterns = _DB["sql_injection_patterns"]
    hits_by_ip = defaultdict(list)
    for e in entries:
        if e.log_type != "web" or not e.path:
            continue
        path_lower = e.path.lower()
        matched = [p for p in patterns if p in path_lower]
        if matched:
            hits_by_ip[e.ip or "unknown"].append((e, matched))
    incidents = []
    for ip, hits in hits_by_ip.items():
        entries_hit, patterns_hit = zip(*hits)
        all_patterns = list({p for pl in patterns_hit for p in pl})
        incidents.append(Incident(
            threat_type="sql_injection", severity=_sev("sql_injection"), source_ip=ip,
            description=f"IP {ip} sent {len(hits)} request(s) containing SQL injection payloads: {', '.join(all_patterns[:4])}.",
            evidence=[e.raw[:120] for e, _ in list(hits)[:5]],
            line_numbers=[e.line_number for e, _ in list(hits)[:5]],
            count=len(hits),
            recommendation="Use parameterized queries / prepared statements. Deploy a WAF. Block IP immediately. Audit database access logs."))
    return incidents

# ── 4. XSS Attempts ───────────────────────────────────────────────────────────
def detect_xss(entries: List[LogEntry]) -> List[Incident]:
    patterns = _DB["xss_patterns"]
    hits_by_ip = defaultdict(list)
    for e in entries:
        if e.log_type != "web" or not e.path:
            continue
        path_lower = e.path.lower()
        matched = [p for p in patterns if p in path_lower]
        if matched:
            hits_by_ip[e.ip or "unknown"].append((e, matched))
    incidents = []
    for ip, hits in hits_by_ip.items():
        entries_hit, patterns_hit = zip(*hits)
        all_p = list({p for pl in patterns_hit for p in pl})
        incidents.append(Incident(
            threat_type="xss_attempt", severity=_sev("xss_attempt"), source_ip=ip,
            description=f"IP {ip} injected XSS payloads ({len(hits)} request(s)). Patterns: {', '.join(all_p[:3])}.",
            evidence=[e.raw[:120] for e, _ in list(hits)[:5]],
            line_numbers=[e.line_number for e, _ in list(hits)[:5]],
            count=len(hits),
            recommendation="Implement output encoding. Use Content-Security-Policy (CSP) headers. Sanitize all user inputs. Deploy WAF."))
    return incidents

# ── 5. Path Traversal ─────────────────────────────────────────────────────────
def detect_path_traversal(entries: List[LogEntry]) -> List[Incident]:
    patterns = _DB["path_traversal_patterns"]
    hits_by_ip = defaultdict(list)
    for e in entries:
        if e.log_type != "web" or not e.path:
            continue
        path_lower = e.path.lower()
        matched = [p for p in patterns if p in path_lower]
        if matched:
            hits_by_ip[e.ip or "unknown"].append((e, matched))
    incidents = []
    for ip, hits in hits_by_ip.items():
        all_p = list({p for _, pl in hits for p in pl})
        incidents.append(Incident(
            threat_type="path_traversal", severity=_sev("path_traversal"), source_ip=ip,
            description=f"IP {ip} attempted directory traversal ({len(hits)} requests). Targeted: {', '.join(all_p[:3])}.",
            evidence=[e.raw[:120] for e, _ in list(hits)[:5]],
            line_numbers=[e.line_number for e, _ in list(hits)[:5]],
            count=len(hits),
            recommendation="Validate and sanitize all file path inputs. Use chroot jails. Ensure web root is isolated. Audit file access logs."))
    return incidents

# ── 6. Command Injection ──────────────────────────────────────────────────────
def detect_command_injection(entries: List[LogEntry]) -> List[Incident]:
    patterns = _DB["command_injection_patterns"]
    hits_by_ip = defaultdict(list)
    for e in entries:
        if e.log_type != "web" or not e.path:
            continue
        path_lower = e.path.lower()
        matched = [p for p in patterns if p in path_lower]
        if matched:
            hits_by_ip[e.ip or "unknown"].append((e, matched))
    incidents = []
    for ip, hits in hits_by_ip.items():
        all_p = list({p for _, pl in hits for p in pl})
        incidents.append(Incident(
            threat_type="command_injection", severity="CRITICAL", source_ip=ip,
            description=f"CRITICAL: IP {ip} attempted OS command injection ({len(hits)} requests). Payloads: {', '.join(all_p[:3])}.",
            evidence=[e.raw[:120] for e, _ in list(hits)[:5]],
            line_numbers=[e.line_number for e, _ in list(hits)[:5]],
            count=len(hits),
            recommendation="URGENT: Audit server for compromise. Never pass user input to OS commands. Use subprocess with shell=False. Block IP immediately."))
    return incidents

# ── 7. Malicious Scanners ─────────────────────────────────────────────────────
def detect_malicious_scanners(entries: List[LogEntry]) -> List[Incident]:
    bad_agents = _DB["malicious_user_agents"]
    hits_by_ip = defaultdict(list)
    for e in entries:
        if e.log_type != "web" or not e.user_agent:
            continue
        ua_lower = e.user_agent.lower()
        matched  = [a for a in bad_agents if a in ua_lower]
        if matched:
            hits_by_ip[e.ip or "unknown"].append((e, matched))
    incidents = []
    for ip, hits in hits_by_ip.items():
        tools = list({p for _, pl in hits for p in pl})
        incidents.append(Incident(
            threat_type="malicious_scanner", severity=_sev("malicious_scanner"), source_ip=ip,
            description=f"IP {ip} used known attack tool(s): {', '.join(tools)} ({len(hits)} requests). Active reconnaissance detected.",
            evidence=[e.raw[:120] for e, _ in list(hits)[:5]],
            line_numbers=[e.line_number for e, _ in list(hits)[:5]],
            count=len(hits),
            recommendation=f"Block IP {ip} at firewall immediately. Review all requests from this IP. Check if any exploits succeeded (2xx responses)."))
    return incidents

# ── 8. 404 Flood (Reconnaissance) ────────────────────────────────────────────
def detect_404_flood(entries: List[LogEntry]) -> List[Incident]:
    threshold = 20
    not_found_by_ip = defaultdict(list)
    for e in entries:
        if e.log_type == "web" and e.status_code == 404:
            not_found_by_ip[e.ip or "unknown"].append(e)
    incidents = []
    for ip, fl in not_found_by_ip.items():
        if len(fl) >= threshold:
            paths = list({e.path for e in fl if e.path})[:8]
            incidents.append(Incident(
                threat_type="404_flood", severity=_sev("404_flood"), source_ip=ip,
                description=f"IP {ip} triggered {len(fl)} HTTP 404 errors — directory/file enumeration detected.",
                evidence=[f"404 {e.path}" for e in fl[:5]],
                line_numbers=[e.line_number for e in fl[:5]],
                count=len(fl),
                recommendation=f"Block {ip} at WAF. Paths probed: {', '.join(paths)}. Harden directory listing settings."))
    return incidents

# ── 9. Suspicious Path Probes ─────────────────────────────────────────────────
def detect_suspicious_paths(entries: List[LogEntry]) -> List[Incident]:
    sus_paths = _DB["suspicious_paths"]
    hits_by_ip = defaultdict(list)
    for e in entries:
        if e.log_type != "web" or not e.path:
            continue
        path_lower = e.path.lower()
        matched = [sp for sp in sus_paths if path_lower.startswith(sp) or path_lower == sp]
        if matched:
            hits_by_ip[e.ip or "unknown"].append((e, matched))
    incidents = []
    for ip, hits in hits_by_ip.items():
        if len(hits) >= 3:
            paths = list({e.path for e, _ in hits})[:6]
            incidents.append(Incident(
                threat_type="suspicious_path_probe", severity=_sev("suspicious_path_probe"), source_ip=ip,
                description=f"IP {ip} probed {len(hits)} sensitive paths: {', '.join(paths[:4])}.",
                evidence=[e.raw[:120] for e, _ in list(hits)[:5]],
                line_numbers=[e.line_number for e, _ in list(hits)[:5]],
                count=len(hits),
                recommendation="Remove or protect admin/config paths. Return 404 for hidden paths (not 403 — 403 confirms existence). Enable authentication on admin panels."))
    return incidents

# ── 10. DDoS Pattern ──────────────────────────────────────────────────────────
def detect_ddos(entries: List[LogEntry]) -> List[Incident]:
    threshold = 500
    req_by_ip = defaultdict(list)
    for e in entries:
        if e.log_type == "web" and e.ip:
            req_by_ip[e.ip].append(e)
    incidents = []
    for ip, reqs in req_by_ip.items():
        if len(reqs) >= threshold:
            incidents.append(Incident(
                threat_type="ddos_pattern", severity="CRITICAL", source_ip=ip,
                description=f"IP {ip} sent {len(reqs):,} requests — potential DDoS / volumetric attack.",
                evidence=[reqs[0].raw[:100], f"... ({len(reqs)} total requests)"],
                line_numbers=[reqs[0].line_number],
                count=len(reqs),
                recommendation=f"Rate-limit at CDN/firewall level. Block {ip}. Enable DDoS protection (Cloudflare, AWS Shield). Analyze traffic pattern for botnet signatures."))
    return incidents

# ── Master runner ─────────────────────────────────────────────────────────────
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

def run_all_detectors(entries: List[LogEntry]) -> List[Incident]:
    all_incidents = []
    for detector in [
        detect_brute_force_ssh,
        detect_brute_force_web,
        detect_sql_injection,
        detect_xss,
        detect_path_traversal,
        detect_command_injection,
        detect_malicious_scanners,
        detect_404_flood,
        detect_suspicious_paths,
        detect_ddos,
    ]:
        all_incidents.extend(detector(entries))
    all_incidents.sort(key=lambda i: SEVERITY_ORDER.index(i.severity) if i.severity in SEVERITY_ORDER else 99)
    return all_incidents
