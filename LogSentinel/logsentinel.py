#!/usr/bin/env python3
"""
LogSentinel v1.0 — Security Log Analyzer & Threat Detector
Author : Daksh Shah | github.com/daksh-shah9135/logsentinel

Usage:
  python logsentinel.py <logfile>
  python logsentinel.py sample_logs/access.log
  python logsentinel.py sample_logs/auth.log --output my_report.html
  python logsentinel.py sample_logs/access.log --no-report
"""
import argparse, sys, os, datetime, time
from collections import Counter

from core.parser    import parse_log_file
from core.detectors import run_all_detectors
from core.reporter  import generate_report
from core.utils     import print_banner, print_section, print_incident, C, sev_str

def build_parser():
    p = argparse.ArgumentParser(prog="logsentinel",
        description="LogSentinel — Security Log Analyzer & Threat Detector")
    p.add_argument("logfile", help="Path to log file (Apache, Nginx, or SSH auth log)")
    p.add_argument("--output", default=None, help="Custom HTML report filename")
    p.add_argument("--no-report", action="store_true", help="Terminal output only")
    p.add_argument("--min-severity", default="LOW",
        choices=["CRITICAL","HIGH","MEDIUM","LOW"], help="Minimum severity to display")
    return p

def main():
    parser = build_parser()
    args   = parser.parse_args()

    print_banner()

    if not os.path.exists(args.logfile):
        print(f"{C.RED}Error: '{args.logfile}' not found.{C.RESET}"); sys.exit(1)

    # ── Parse ─────────────────────────────────────────────────────────────────
    print_section(f"Parsing Log File: {args.logfile}")
    t0 = time.perf_counter()
    entries, stats = parse_log_file(args.logfile)
    parse_time = time.perf_counter() - t0

    print(f"  Lines parsed : {stats['total_lines']:,}")
    print(f"  Web entries  : {stats.get('web_count',0):,}")
    print(f"  SSH entries  : {stats.get('ssh_count',0):,}")
    print(f"  Parse time   : {parse_time:.2f}s")

    # ── Detect ────────────────────────────────────────────────────────────────
    print_section("Running Threat Detectors")
    detectors = [
        "Brute Force SSH","Brute Force Web","SQL Injection","XSS Attempts",
        "Path Traversal","Command Injection","Malicious Scanners","404 Flood",
        "Suspicious Paths","DDoS Pattern"
    ]
    for d in detectors:
        print(f"  {C.GREEN}✓{C.RESET} {d}")

    t1 = time.perf_counter()
    incidents = run_all_detectors(entries)
    detect_time = time.perf_counter() - t1

    # ── Top IPs ───────────────────────────────────────────────────────────────
    ip_counter = Counter(e.ip for e in entries if e.ip)
    top_ips    = ip_counter.most_common(15)

    # ── Print Results ─────────────────────────────────────────────────────────
    sev_order = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
    min_idx   = sev_order.index(args.min_severity)
    shown     = [i for i in incidents if sev_order.index(i.severity) <= min_idx]

    print_section(f"Results — {len(incidents)} Incident(s) Found")

    if not incidents:
        print(f"\n  {C.GREEN}No threats detected. Log appears clean.{C.RESET}")
    else:
        for n, inc in enumerate(shown, 1):
            print_incident(inc, n)

    # ── Summary ───────────────────────────────────────────────────────────────
    print_section("Summary")
    counts = Counter(i.severity for i in incidents)
    for s in sev_order:
        if counts[s]:
            print(f"  {sev_str(s)} : {counts[s]} incident(s)")

    print(f"\n  {C.BOLD}Top Source IPs:{C.RESET}")
    for ip, cnt in top_ips[:5]:
        bar = "█" * min(cnt // 5, 30)
        print(f"    {C.CYAN}{ip:<18}{C.RESET} {cnt:>5} requests  {C.GRAY}{bar}{C.RESET}")

    print(f"\n  Detection time : {detect_time:.2f}s")

    # ── Report ────────────────────────────────────────────────────────────────
    if not args.no_report:
        os.makedirs("reports", exist_ok=True)
        ts  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        out = args.output or f"reports/logsentinel_{os.path.basename(args.logfile)}_{ts}.html"
        generate_report(incidents, stats, args.logfile, out, top_ips)
        print(f"\n  {C.GREEN}✓ HTML report:{C.RESET} {C.BOLD}{out}{C.RESET}")

    print(f"\n{C.GRAY}  LogSentinel complete. For authorized security analysis only.{C.RESET}\n")

if __name__ == "__main__":
    main()
