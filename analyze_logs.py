import re
import json
import argparse
from collections import defaultdict, Counter
from datetime import datetime

# ---------------------------------------------------------------------------
# Detection signatures
# ---------------------------------------------------------------------------

SQLI_PATTERNS = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
    r"union\s+select",
    r"drop\s+table",
    r"or\s+1\s*=\s*1",
    r"'\s*or\s*'1'\s*=\s*'1",
]

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"etc/passwd",
    r"win\.ini",
    r"%00",
]

SUSPICIOUS_USER_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "acunetix", "havij", "dirbuster",
]

BRUTE_FORCE_THRESHOLD = 5      # failed logins from same IP to trip alert
SQLI_HIT_THRESHOLD = 1         # any single SQLi pattern match is worth flagging

ACCESS_LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>.*?) HTTP/\S+" (?P<status>\d+) \S+ '
    r'"[^"]*" "(?P<ua>[^"]*)"'
)

AUTH_LOG_RE = re.compile(
    r'^(?P<time>\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+'
    r'(?P<result>Accepted|Failed)\s+(?P<method>\S+)\s+for\s+'
    r'(?P<user>\S+)\s+from\s+(?P<ip>\S+)'
)


# ---------------------------------------------------------------------------
# Access log analysis (SQLi, path traversal, malicious tools)
# ---------------------------------------------------------------------------

def analyze_access_log(path):
    findings = []
    ip_request_counts = Counter()

    with open(path, "r", errors="ignore") as f:
        for lineno, line in enumerate(f, 1):
            m = ACCESS_LOG_RE.search(line)
            if not m:
                continue
            ip = m.group("ip")
            request_path = m.group("path")
            ua = m.group("ua")
            ip_request_counts[ip] += 1

            for pattern in SQLI_PATTERNS:
                if re.search(pattern, request_path, re.IGNORECASE):
                    findings.append({
                        "type": "SQL Injection Attempt",
                        "severity": "High",
                        "source_ip": ip,
                        "line": lineno,
                        "evidence": request_path,
                    })
                    break

            for pattern in PATH_TRAVERSAL_PATTERNS:
                if re.search(pattern, request_path, re.IGNORECASE):
                    findings.append({
                        "type": "Path Traversal / LFI Attempt",
                        "severity": "High",
                        "source_ip": ip,
                        "line": lineno,
                        "evidence": request_path,
                    })
                    break

            for tool in SUSPICIOUS_USER_AGENTS:
                if tool.lower() in ua.lower():
                    findings.append({
                        "type": "Known Attack Tool User-Agent",
                        "severity": "Medium",
                        "source_ip": ip,
                        "line": lineno,
                        "evidence": ua,
                    })
                    break

    # Flag IPs with unusually high request volume (possible scanning)
    for ip, count in ip_request_counts.items():
        if count >= 5:
            findings.append({
                "type": "High Request Volume (possible scan)",
                "severity": "Low",
                "source_ip": ip,
                "line": None,
                "evidence": f"{count} requests from this IP in log window",
            })

    return findings


# ---------------------------------------------------------------------------
# Auth log analysis (brute force)
# ---------------------------------------------------------------------------

def analyze_auth_log(path):
    findings = []
    failed_by_ip = defaultdict(int)
    users_tried_by_ip = defaultdict(set)
    success_after_failures = []

    events = []
    with open(path, "r", errors="ignore") as f:
        for lineno, line in enumerate(f, 1):
            m = AUTH_LOG_RE.search(line)
            if not m:
                continue
            events.append((lineno, m.group("result"), m.group("ip"), m.group("user")))
            if m.group("result") == "Failed":
                failed_by_ip[m.group("ip")] += 1
                users_tried_by_ip[m.group("ip")].add(m.group("user"))

    for ip, count in failed_by_ip.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            findings.append({
                "type": "SSH Brute Force Attempt",
                "severity": "High",
                "source_ip": ip,
                "line": None,
                "evidence": f"{count} failed logins, usernames tried: "
                            f"{', '.join(sorted(users_tried_by_ip[ip]))}",
            })

    # Successful login immediately following a run of failures from same IP
    for i, (lineno, result, ip, user) in enumerate(events):
        if result == "Accepted" and failed_by_ip.get(ip, 0) >= BRUTE_FORCE_THRESHOLD:
            findings.append({
                "type": "Possible Compromised Credential (login after brute force)",
                "severity": "Critical",
                "source_ip": ip,
                "line": lineno,
                "evidence": f"Successful login for '{user}' from {ip} "
                            f"after {failed_by_ip[ip]} prior failures",
            })

    return findings


# ---------------------------------------------------------------------------
# Report output
# ---------------------------------------------------------------------------

def print_report(access_findings, auth_findings):
    all_findings = access_findings + auth_findings
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    all_findings.sort(key=lambda x: sev_order.get(x["severity"], 4))

    print("=" * 70)
    print("BLUE TEAM LOG ANALYSIS - FINDINGS REPORT")
    print(f"Generated: {datetime.now().isoformat()}")
    print("=" * 70)

    if not all_findings:
        print("No suspicious activity detected.")
        return all_findings

    for f in all_findings:
        print(f"\n[{f['severity'].upper()}] {f['type']}")
        print(f"  Source IP : {f['source_ip']}")
        if f['line']:
            print(f"  Log line  : {f['line']}")
        print(f"  Evidence  : {f['evidence']}")

    print("\n" + "-" * 70)
    print("SUMMARY BY SEVERITY:")
    counts = Counter(f["severity"] for f in all_findings)
    for sev in ["Critical", "High", "Medium", "Low"]:
        if counts[sev]:
            print(f"  {sev}: {counts[sev]}")

    unique_ips = sorted(set(f["source_ip"] for f in all_findings))
    print(f"\nFLAGGED IPs FOR OSINT ENRICHMENT (WHOIS / crt.sh / Shodan):")
    for ip in unique_ips:
        print(f"  - {ip}")

    return all_findings


def main():
    parser = argparse.ArgumentParser(description="Blue Team log analyzer")
    parser.add_argument("--access", help="Path to web access log", default=None)
    parser.add_argument("--auth", help="Path to SSH/auth log", default=None)
    parser.add_argument("--json-out", help="Write findings to JSON file", default=None)
    args = parser.parse_args()

    access_findings = analyze_access_log(args.access) if args.access else []
    auth_findings = analyze_auth_log(args.auth) if args.auth else []

    all_findings = print_report(access_findings, auth_findings)

    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump(all_findings, f, indent=2)
        print(f"\n[+] Findings written to {args.json_out}")


if __name__ == "__main__":
    main()
