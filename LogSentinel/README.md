# 🔍 LogSentinel — Security Log Analyzer & Threat Detector

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Detectors](https://img.shields.io/badge/Detectors-10-red)

Analyzes Apache/Nginx access logs and Linux SSH auth logs to automatically detect cyber attacks. Generates a professional HTML incident report.

## Features
- 10 threat detectors: Brute Force SSH/Web, SQL Injection, XSS, Path Traversal, Command Injection, Malicious Scanners, 404 Flood, Suspicious Paths, DDoS
- Severity scoring: CRITICAL / HIGH / MEDIUM / LOW
- HTML incident report with evidence and remediation per finding
- Works on real server logs — zero dependencies

## Usage
```bash
python logsentinel.py sample_logs/access.log
python logsentinel.py sample_logs/auth.log
python logsentinel.py /var/log/apache2/access.log --output report.html
python logsentinel.py access.log --no-report --min-severity HIGH
```

## Project Structure
```
LogSentinel/
├── logsentinel.py          # Main CLI
├── core/
│   ├── parser.py           # Apache/Nginx/SSH log parser
│   ├── detectors.py        # 10 threat detection engines
│   ├── reporter.py         # HTML report generator
│   └── utils.py            # Terminal colors & display
├── config/rules.json       # Detection rules & thresholds
└── sample_logs/            # Test logs (access + auth)
```

## Author
**Daksh Shah** — B.Tech Cybersecurity, SAKEC Mumbai  
[![LinkedIn](https://img.shields.io/badge/LinkedIn-daksh--shah9135-blue?logo=linkedin)](https://linkedin.com/in/daksh-shah9135)

MIT License — For authorized security analysis only.
