"""
LogSentinel | core/parser.py
Parses Apache/Nginx access logs and Linux SSH auth logs
into a unified LogEntry dataclass.
"""
import re
from dataclasses import dataclass
from typing import Optional

@dataclass
class LogEntry:
    raw:         str
    line_number: int
    log_type:    str
    timestamp:   Optional[str] = None
    ip:          Optional[str] = None
    method:      Optional[str] = None
    path:        Optional[str] = None
    status_code: Optional[int] = None
    bytes_sent:  Optional[int] = None
    user_agent:  Optional[str] = None
    service:     Optional[str] = None
    message:     Optional[str] = None
    username:    Optional[str] = None

_WEB_RE = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<path>\S+)[^"]*"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)\s*'
    r'(?:"[^"]*"\s+)?'
    r'"(?P<ua>[^"]*)"'
)
_AUTH_RE = re.compile(
    r'(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+'
    r'(?P<service>\w+)\[\d+\]:\s+(?P<message>.+)'
)
_IP_RE   = re.compile(r'from\s+(\d{1,3}(?:\.\d{1,3}){3})')
_USER_RE = re.compile(r'for\s+(?:invalid user\s+)?(\S+)\s+from')

def parse_line(raw: str, ln: int) -> LogEntry:
    raw = raw.rstrip("\n")
    m = _WEB_RE.match(raw)
    if m:
        return LogEntry(raw=raw, line_number=ln, log_type="web",
            ip=m.group("ip"), timestamp=m.group("ts"),
            method=m.group("method"), path=m.group("path"),
            status_code=int(m.group("status")),
            bytes_sent=int(m.group("bytes")) if m.group("bytes").isdigit() else 0,
            user_agent=m.group("ua"))
    m = _AUTH_RE.match(raw)
    if m:
        msg = m.group("message")
        ip_m   = _IP_RE.search(msg)
        user_m = _USER_RE.search(msg)
        return LogEntry(raw=raw, line_number=ln, log_type="ssh",
            timestamp=m.group("ts"), service=m.group("service"),
            message=msg,
            ip=ip_m.group(1) if ip_m else None,
            username=user_m.group(1) if user_m else None)
    return LogEntry(raw=raw, line_number=ln, log_type="unknown", message=raw)

def parse_log_file(filepath: str) -> tuple:
    entries, stats = [], {"total_lines":0,"web_count":0,"ssh_count":0,"unknown_count":0}
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for ln, raw in enumerate(f, 1):
            stats["total_lines"] += 1
            if not raw.strip():
                continue
            e = parse_line(raw, ln)
            entries.append(e)
            key = f"{e.log_type}_count"
            stats[key] = stats.get(key, 0) + 1
    return entries, stats
