# Log Analysis Exercise — Week 2 Module (Group 33)

## What this is
A defensive log-analysis module for SafeX Solutions' Blue Team exercise.
It parses web server access logs and SSH auth logs, automatically flags
common attack patterns, and outputs a severity-ranked findings report used
as the basis for `report_template.md`.

## What it detects
- **SQL injection attempts** (query-string payload matching)
- **Path traversal / LFI attempts** (`../`, `/etc/passwd`, null-byte injection, etc.)
- **Known attack-tool user agents** (sqlmap, nikto, nmap, acunetix, etc.)
- **High request volume from a single IP** (possible scanning)
- **SSH brute-force attempts** (≥5 failed logins from one IP)
- **Post-brute-force successful login** (likely compromised credential)

## How to run it
Requires Python 3.8+, no external dependencies.

```bash
python3 analyze_logs.py --access sample_access.log --auth sample_auth.log --json-out findings.json
```

This prints a console report and writes structured findings to `findings.json`.
Swap in real log files by pointing `--access` / `--auth` at them — same format
expected (Apache/Nginx combined log format; standard `sshd` syslog format).

## Files in this module
| File | Purpose |
|------|---------|
| `analyze_logs.py` | Core detection engine / source code deliverable |
| `sample_access.log` | Sample web log with seeded SQLi, path traversal, tool-signature attacks |
| `sample_auth.log` | Sample SSH log with seeded brute-force + compromise |
| `findings.json` | Example output from running the script |
| `report_template.md` | Professional findings report, pre-filled with this run's results as an example |

## OSINT enrichment (manual step)
After running the script, take each IP listed under "FLAGGED IPs FOR OSINT
ENRICHMENT" in the console output and passively look it up:
- **WHOIS**: `whois <ip>` — ownership/ASN
- **crt.sh**: `https://crt.sh/?q=<ip-or-domain>` — certificate transparency history
- **Shodan**: `https://www.shodan.io/host/<ip>` — exposed services/ports

Record results in Section 4 of the report.

