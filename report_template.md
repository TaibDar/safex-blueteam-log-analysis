# Log Analysis Exercise — Findings Report

**Project:** SafeX Solutions — Blue Team Defensive Exercise
**Group:** 33 | **Module Owner:** Taibah Dar
**Week:** 2 | **Date:** July 14, 2026

---

## 1. Executive Summary
I ran my log analysis tool (`analyze_logs.py`) on the sample web server logs and SSH logs. It found 4 types of attacks: SQL injection attempts, a path traversal / LFI probing attempt, a sqlmap scan on the login page, and a successful SSH brute-force attack where the attacker got into the root account. In total, 10 findings came out, and 1 of them is **Critical** — the attacker at `45.153.160.2` logged in as root right after 10 failed tries, which means the account was likely compromised. All the IPs in these logs are fake/reserved test IPs (RFC 5737 ranges), not real attackers, since this is a practice exercise.

## 2. Scope & Methodology
- **Logs used:** `sample_access.log` (web server log) and `sample_auth.log` (SSH login log)
- **Time window:** 10 Jul 2026, 09:12 AM to 09:55 AM — the full time range covered by the sample logs
- **Tools used:** My own Python script (`analyze_logs.py`) to scan the logs, plus WHOIS, crt.sh, and Shodan for OSINT lookups
- **How it works:** The script looks for known attack patterns — SQL injection text, path traversal (`../` style) requests, known hacking-tool user agents, 5+ failed SSH logins from the same IP, and IPs sending too many requests. Then I manually checked each flagged IP using OSINT tools.

## 3. Findings

| # | Severity | Type | Source IP | Log Line | Evidence |
|---|----------|------|-----------|----------|----------|
| 1 | Critical | Possible Compromised Credential (login after brute force) | 45.153.160.2 | 12 | Successful login for 'root' after 10 prior failures |
| 2 | High | SQL Injection Attempt | 198.51.100.22 | 4 | `GET /products?id=1' OR '1'='1` |
| 3 | High | SQL Injection Attempt | 198.51.100.22 | 5 | `GET /products?id=1' UNION SELECT username,password FROM users--` |
| 4 | High | SQL Injection Attempt | 198.51.100.22 | 6 | `GET /products?id=1;DROP TABLE users--` |
| 5 | High | SSH Brute Force Attempt | 45.153.160.2 | auth log | 10 failed logins, 5 usernames (admin, oracle, root, test, ubuntu) in ~10s |
| 6 | High | Path Traversal / LFI Attempt | 192.0.2.77 | 7 | `GET /../../../../etc/passwd` |
| 7 | High | Path Traversal / LFI Attempt | 192.0.2.77 | 8 | `GET /../../../../windows/win.ini` |
| 8 | High | Path Traversal / LFI Attempt | 192.0.2.77 | 9 | `GET /admin/config.php%00` |
| 9 | Medium | Known Attack Tool User-Agent (sqlmap) | 203.0.113.200 | 10–16 | `User-Agent: sqlmap/1.6.12` across 7 requests to `/wp-login.php` |
| 10 | Low | High Request Volume (possible scan) | 203.0.113.200 | — | 7 requests from this IP within the log window |

*(Source: `findings_v2.json`, produced by `analyze_logs.py`.)*

## 4. OSINT Enrichment
All 4 IPs that my tool flagged (`192.0.2.77`, `198.51.100.22`, `203.0.113.200`, `45.153.160.2`) are fake/reserved test IPs — they belong to special ranges (RFC 5737) that are set aside just for examples and documentation, and are never used by real websites or attackers. Because of this, a WHOIS lookup on any one of them gives the exact same result: they belong to IANA, not to a real company. So I only ran WHOIS on one of them (`192.0.2.77`) since running it on the other 3 would just repeat the same answer.

crt.sh and Shodan don't work on these flagged IPs at all: crt.sh only searches by domain name (not IP), and Shodan has no data for these reserved test ranges since nothing real is hosted there. Since I still needed to show I know how to use these tools, I used a real, well-known example instead — `google.com` for crt.sh, and `8.8.8.8` (Google's DNS server) for Shodan. This was just to demonstrate I can read and understand the tool's output — it has nothing to do with the actual sample incident, and I didn't need to repeat it for every flagged IP.

| IP | WHOIS / ASN | crt.sh | Shodan | Assessment |
|----|-------------|--------|--------|------------|
| 192.0.2.77 / 198.51.100.22 / 203.0.113.200 / 45.153.160.2 | TEST-NET ranges (RFC 5737), registered to IANA, reserved for documentation | N/A — crt.sh only searches by domain, not IP | N/A — no host record for reserved ranges | Fake IPs used for the exercise; confirmed non-routable, no real registration |
| *(demo)* google.com | — | Certificate history, issuers, SAN entries visible via crt.sh search | — | Shows how crt.sh is used |
| *(demo)* 8.8.8.8 | — | — | Google LLC, Mountain View US, ports 53/443 open, TLS cert detail visible | Shows how Shodan is used |

> Note: Only passive/OSINT lookups were done — no active scanning of any third-party infrastructure.

## 5. Timeline of Events
```
09:12:01 - Baseline legitimate traffic (203.0.113.45)
09:14:11 - SQL injection attempts detected against /products?id= (198.51.100.22)
09:20:01 - Path traversal / LFI probing begins (192.0.2.77)
09:25:00 - sqlmap-driven scan begins against /wp-login.php (203.0.113.200)
09:41:10 - SSH brute force begins (45.153.160.2)
09:41:20 - SSH brute force succeeds — root account compromised (45.153.160.2)
09:55:00 - Legitimate key-based SSH login (203.0.113.45, unrelated baseline)
```

## 6. Risk Assessment
| Finding | Likelihood | Impact | Overall Risk |
|---------|-----------|--------|---------------|
| SSH credential compromise (root) | High (already occurred) | Critical | **Critical** |
| SQL injection (confirmed, 198.51.100.22) | Medium | High | **High** |
| SSH brute-force activity | High | High | **High** |
| Path traversal / LFI probing | Medium | Medium | **High** |
| sqlmap-driven scan on /wp-login.php | Medium | Medium | **Medium** |
| Volumetric scanning (recon) | Medium | Low | **Low** |

## 7. Recommendations
- Change the passwords for every account that got brute-forced, especially root, and turn off direct root login over SSH.
- Only allow SSH login with keys (not passwords), and set up fail2ban or something similar to block IPs after too many failed tries.
- Add a firewall rule (WAF) or fix the code to use parameterized queries so SQL injection on `/products` stops working; always validate user input.
- Block path traversal attempts by properly checking file paths, and don't give the web server more file access than it needs.
- Set up alerts for: too many failed logins from one IP in a short time, known hacking tool user-agents (sqlmap, nikto, nmap, etc.), and suspicious URL patterns.

## 8. Responsible Disclosure / Escalation Note
This was just a practice exercise using fake sample logs and made-up test IPs — no real system or company was affected, so there's nothing to report to any outside party. I'm sharing these findings with my Group 33 lead and my internship supervisor as my Week 2 deliverable.

## 9. Appendix
- Full findings output: `findings_v2.json`
- The log files I analyzed: `sample_access.log`, `sample_auth.log`
- My analysis script: `analyze_logs.py`
- How-to guide for this module: `README.md`
