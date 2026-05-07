"""
LogSentinel | core/audit.py
Builds the full audit report object from parsed entries and threat events.
"""

import datetime
from collections import defaultdict, Counter
from dataclasses  import dataclass, field
from typing       import Optional

from core.parser   import LogEntry
from core.detector import ThreatEvent


@dataclass
class IPProfile:
    ip:               str
    total_requests:   int
    threat_count:     int
    severities:       list[str]
    top_paths:        list[str]
    status_codes:     dict
    highest_severity: str

    @property
    def risk_color(self) -> str:
        return {"CRITICAL":"#dc2626","HIGH":"#ea580c",
                "MEDIUM":"#d97706","LOW":"#16a34a","INFO":"#2563eb"}.get(self.highest_severity,"#6b7280")


@dataclass
class AuditReport:
    filename:          str
    generated_at:      str
    total_lines:       int
    parsed_entries:    int
    log_types:         dict          # {"apache": N, "ssh": M, ...}
    threat_events:     list[ThreatEvent]
    ip_profiles:       list[IPProfile]
    top_ips:           list[tuple]   # (ip, count) top 10
    status_code_dist:  dict          # {200: N, 404: M, ...}
    severity_counts:   dict          # {CRITICAL: N, HIGH: M, ...}
    risk_score:        int           # 0-100 overall log risk
    risk_level:        str
    time_range:        str
    total_threats:     int
    unique_attacker_ips: int
    summary_line:      str


def build_report(
    filename:     str,
    entries:      list[LogEntry],
    events:       list[ThreatEvent],
    total_lines:  int
) -> AuditReport:

    generated_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Log type breakdown
    log_types = Counter(e.log_type for e in entries)

    # Top IPs by request volume
    ip_req_count = Counter(e.ip for e in entries if e.ip)
    top_ips      = ip_req_count.most_common(10)

    # Status code distribution
    status_dist = Counter(
        e.status_code for e in entries
        if e.status_code and e.log_type == "apache"
    )

    # Severity counts
    severity_counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
    for ev in events:
        severity_counts[ev.severity] = severity_counts.get(ev.severity, 0) + 1

    # Risk score
    score = 0
    score += severity_counts.get("CRITICAL", 0) * 30
    score += severity_counts.get("HIGH",     0) * 15
    score += severity_counts.get("MEDIUM",   0) * 7
    score  = min(score, 100)

    if score >= 80:   risk_level = "CRITICAL"
    elif score >= 60: risk_level = "HIGH"
    elif score >= 40: risk_level = "MEDIUM"
    elif score >= 20: risk_level = "LOW"
    else:             risk_level = "CLEAN"

    # Time range
    timestamps = [e.timestamp for e in entries if e.timestamp]
    if timestamps:
        lo  = min(timestamps)
        hi  = max(timestamps)
        time_range = f"{lo.strftime('%Y-%m-%d %H:%M')} → {hi.strftime('%Y-%m-%d %H:%M')}"
    else:
        time_range = "Unknown"

    # IP profiles
    ip_events = defaultdict(list)
    for ev in events:
        if ev.source_ip:
            ip_events[ev.source_ip].append(ev)

    ip_profiles = []
    for ip, ip_evs in ip_events.items():
        sev_list = [e.severity for e in ip_evs]
        top_paths_raw = [e.path for e in entries if e.ip == ip and e.path]
        top_paths = [p for p, _ in Counter(top_paths_raw).most_common(5)]
        sc_dist   = dict(Counter(
            e.status_code for e in entries if e.ip == ip and e.status_code
        ).most_common(5))
        high_sev  = min(sev_list, key=lambda s: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}.get(s,5))
        ip_profiles.append(IPProfile(
            ip=ip,
            total_requests=ip_req_count.get(ip, 0),
            threat_count=len(ip_evs),
            severities=sev_list,
            top_paths=top_paths,
            status_codes=sc_dist,
            highest_severity=high_sev
        ))
    ip_profiles.sort(key=lambda p: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}.get(p.highest_severity,5))

    # Unique attacker IPs
    unique_ips = len(set(ev.source_ip for ev in events if ev.source_ip))

    # Summary line
    if not events:
        summary_line = "No threats detected. Log file appears clean for the analyzed patterns."
    elif severity_counts.get("CRITICAL", 0) > 0:
        summary_line = (f"{severity_counts['CRITICAL']} CRITICAL threat(s) detected — immediate response required. "
                        f"{unique_ips} attacker IP(s) identified across {len(events)} total security events.")
    else:
        summary_line = (f"{len(events)} threat event(s) detected from {unique_ips} IP(s). "
                        f"Highest severity: {risk_level}. Review recommendations below.")

    return AuditReport(
        filename=filename,
        generated_at=generated_at,
        total_lines=total_lines,
        parsed_entries=len(entries),
        log_types=dict(log_types),
        threat_events=events,
        ip_profiles=ip_profiles,
        top_ips=top_ips,
        status_code_dist=dict(status_dist),
        severity_counts=severity_counts,
        risk_score=score,
        risk_level=risk_level,
        time_range=time_range,
        total_threats=len(events),
        unique_attacker_ips=unique_ips,
        summary_line=summary_line
    )
