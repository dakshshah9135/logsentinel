"""
LogSentinel | core/detector.py
Attack detection engine.
"""
import json
from pathlib import Path
from dataclasses import dataclass
from typing import Optional
from datetime import datetime
from collections import defaultdict
from core.parser import LogEntry, LogFormat

_DB_PATH = Path(__file__).parent.parent / "config" / "patterns.json"
with open(_DB_PATH) as f:
    DB = json.load(f)

@dataclass
class Incident:
    incident_type:  str
    severity:       str
    source_ip:      Optional[str]
    timestamp:      Optional[datetime]
    description:    str
    evidence:       str
    line_number:    int
    recommendation: str
    count:          int = 1

def _check_sql(entry):
    target = (entry.path or "") + (entry.user_agent or "")
    for p in DB["sql_injection_patterns"]:
        if p.lower() in target.lower():
            return Incident("SQL_INJECTION","CRITICAL",entry.ip_address,entry.timestamp,
                f"SQL Injection attempt — pattern: '{p}'",entry.path or entry.raw[:120],entry.line_number,
                "Use parameterised queries. Enable WAF SQL rules. Block source IP.")
    return None

def _check_xss(entry):
    target = (entry.path or "") + (entry.user_agent or "")
    for p in DB["xss_patterns"]:
        if p.lower() in target.lower():
            return Incident("XSS","HIGH",entry.ip_address,entry.timestamp,
                f"XSS attempt — pattern: '{p}'",entry.path or entry.raw[:120],entry.line_number,
                "Sanitize all user input. Add Content-Security-Policy headers.")
    return None

def _check_traversal(entry):
    path = entry.path or ""
    for p in DB["directory_traversal_patterns"]:
        if p.lower() in path.lower():
            return Incident("DIRECTORY_TRAVERSAL","HIGH",entry.ip_address,entry.timestamp,
                f"Directory Traversal attempt — pattern: '{p}'",path[:120],entry.line_number,
                "Validate file paths. Restrict web root. Block ../ at WAF level.")
    return None

def _check_cmdi(entry):
    path = entry.path or ""
    for p in DB["command_injection_patterns"]:
        if p.lower() in path.lower():
            return Incident("COMMAND_INJECTION","CRITICAL",entry.ip_address,entry.timestamp,
                f"Command Injection attempt — pattern: '{p}'",path[:120],entry.line_number,
                "Never pass user input to shell. Use subprocess with arg lists.")
    return None

def _check_scanner(entry):
    ua = (entry.user_agent or "").lower()
    for s in DB["scanner_user_agents"]:
        if s.lower() in ua:
            return Incident("SCANNER_DETECTED","MEDIUM",entry.ip_address,entry.timestamp,
                f"Security scanner detected — UA contains: '{s}'",entry.user_agent or "",entry.line_number,
                "Block known scanner UAs at WAF. Implement rate limiting.")
    return None

def _check_sensitive(entry):
    path = (entry.path or "").lower().split("?")[0]
    for sp in DB["sensitive_paths"]:
        if sp.lower() in path:
            return Incident("SENSITIVE_PATH","MEDIUM",entry.ip_address,entry.timestamp,
                f"Sensitive path access: '{entry.path}'",entry.path or "",entry.line_number,
                "Restrict admin paths by IP. Remove exposed debug endpoints.")
    return None

def detect_brute_force_ssh(entries):
    fail_map = defaultdict(list)
    for e in entries:
        if e.log_format == LogFormat.SSH_AUTH and e.auth_result in ("failed","invalid"):
            fail_map[e.ip_address].append(e)
    incidents = []
    for ip, evts in fail_map.items():
        if len(evts) >= DB["brute_force"]["ssh_failed_threshold"]:
            usernames = list(set(e.username for e in evts if e.username))[:5]
            incidents.append(Incident("BRUTE_FORCE","HIGH",ip,evts[0].timestamp,
                f"SSH Brute Force — {len(evts)} failed logins from {ip}. Targets: {', '.join(usernames)}",
                f"{len(evts)} failed SSH auth attempts",evts[0].line_number,
                "Block IP via fail2ban/firewall. Use SSH key auth. Change port from 22.",len(evts)))
    return incidents

def detect_brute_force_http(entries):
    login_paths = ["/login","/signin","/auth","/wp-login.php","/admin/login","/api/login","/api/auth"]
    req_map = defaultdict(list)
    for e in entries:
        if e.path and any(lp in (e.path or "").lower() for lp in login_paths):
            req_map[e.ip_address].append(e)
    incidents = []
    for ip, evts in req_map.items():
        if len(evts) >= DB["brute_force"]["login_endpoint_threshold"]:
            incidents.append(Incident("BRUTE_FORCE","HIGH",ip,evts[0].timestamp,
                f"HTTP Login Brute Force — {len(evts)} requests to login endpoints from {ip}",
                f"{len(evts)} requests to login paths",evts[0].line_number,
                "Add CAPTCHA and account lockout. Rate-limit login endpoints.",len(evts)))
    return incidents

def detect_404_sweep(entries):
    map_404 = defaultdict(list)
    for e in entries:
        if e.status_code == 404:
            map_404[e.ip_address].append(e)
    incidents = []
    for ip, evts in map_404.items():
        if len(evts) >= DB["http_error_thresholds"]["404_spike_threshold"]:
            sample = list(set(e.path for e in evts if e.path))[:5]
            incidents.append(Incident("MASS_REQUEST","MEDIUM",ip,evts[0].timestamp,
                f"Path scanning detected — {len(evts)} 404 errors from {ip}. Paths: {', '.join(sample)}",
                f"{len(evts)} HTTP 404 responses",evts[0].line_number,
                "Block scanning IP. Investigate what paths were targeted.",len(evts)))
    return incidents

def run_detection(entries):
    incidents = []
    seen = set()
    detectors = [_check_sql, _check_xss, _check_traversal, _check_cmdi, _check_scanner, _check_sensitive]
    for entry in entries:
        for det in detectors:
            result = det(entry)
            if result:
                sig = (result.incident_type, result.source_ip, result.evidence[:40])
                if sig not in seen:
                    incidents.append(result)
                    seen.add(sig)
    incidents.extend(detect_brute_force_ssh(entries))
    incidents.extend(detect_brute_force_http(entries))
    incidents.extend(detect_404_sweep(entries))
    order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
    incidents.sort(key=lambda i: order.get(i.severity,4))
    return incidents
