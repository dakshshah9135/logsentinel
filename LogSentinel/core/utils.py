"""LogSentinel | core/utils.py — Terminal helpers."""
import sys, os
USE_COLOR = sys.stdout.isatty() or os.environ.get("FORCE_COLOR")
class C:
    RESET="\033[0m" if USE_COLOR else ""; BOLD="\033[1m" if USE_COLOR else ""
    RED="\033[91m" if USE_COLOR else ""; ORANGE="\033[33m" if USE_COLOR else ""
    YELLOW="\033[93m" if USE_COLOR else ""; GREEN="\033[92m" if USE_COLOR else ""
    BLUE="\033[94m" if USE_COLOR else ""; CYAN="\033[96m" if USE_COLOR else ""
    GRAY="\033[90m" if USE_COLOR else ""; PURPLE="\033[95m" if USE_COLOR else ""
    WHITE="\033[97m" if USE_COLOR else ""
SEV_C={"CRITICAL":"\033[95m","HIGH":"\033[91m","MEDIUM":"\033[33m","LOW":"\033[93m","INFO":"\033[94m"}

def sev_str(s):
    return f"{SEV_C.get(s,'')}{C.BOLD}{s:8}{C.RESET}"

def print_banner():
    print(f"""
{C.BLUE}{C.BOLD}
  ██╗      ██████╗  ██████╗ ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
  ██║     ██╔═══██╗██╔════╝ ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
  ██║     ██║   ██║██║  ███╗███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
  ██║     ██║   ██║██║   ██║╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
  ███████╗╚██████╔╝╚██████╔╝███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
  ╚══════╝ ╚═════╝  ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
{C.RESET}{C.GRAY}  Security Log Analyzer & Threat Detector  |  v1.0  |  by Daksh Shah{C.RESET}
""")

def print_section(t):
    print(f"\n{C.BOLD}{C.WHITE}{'─'*65}{C.RESET}\n{C.BOLD}{C.CYAN}  {t}{C.RESET}\n{C.BOLD}{C.WHITE}{'─'*65}{C.RESET}")

def print_incident(i, n):
    sc=SEV_C.get(i.severity,C.WHITE)
    print(f"\n  {sc}{C.BOLD}[{n}] {i.severity:8}{C.RESET} {C.WHITE}{C.BOLD}{i.threat_type.replace('_',' ').upper()}{C.RESET}")
    print(f"  {C.GRAY}{i.description}{C.RESET}")
    if i.source_ip: print(f"  Source IP : {C.CYAN}{i.source_ip}{C.RESET}  |  Count: {i.count}")
    for e in i.evidence[:2]: print(f"  {C.GRAY}  ↳ {e[:100]}{C.RESET}")
    print(f"  {C.BLUE}→ {i.recommendation[:120]}{C.RESET}")
