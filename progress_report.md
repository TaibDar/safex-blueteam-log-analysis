# Week 2 Progress Report

**Intern:** Taibah Dar
**Project:** SafeX Solutions — Blue Team Defensive Exercise
**Group:** 33 | **Module:** Log Analysis Exercise
**Week:** 2 | **Date:** July 14, 2026

---

## What I worked on this week
My task was to build the Log Analysis Exercise module for our group's Blue Team project — a tool that reads server logs, finds attack patterns automatically, and produces a findings report using passive OSINT tools.

## What I did
- Built `analyze_logs.py`, a Python script that reads a web server access log and an SSH auth log, and flags 6 types of activity: SQL injection attempts, path traversal / LFI attempts, known attack-tool user agents (sqlmap, nikto, etc.), SSH brute-force attempts, high request volume from one IP, and logins that happen right after a brute-force attack (likely compromise).
- Ran it against the sample logs — it found 16 individual matches (1 Critical, 7 High, 7 Medium, 1 Low), covering a confirmed SQL injection sequence, a path traversal probe, an sqlmap scan, and a successful SSH brute-force compromise of the root account.
- Looked up all flagged IPs using WHOIS, crt.sh, and Shodan, and documented what each tool returned.
- Wrote up the full findings in a professional report (`report_template.md` / Word doc), following the required template — executive summary, methodology, findings table, OSINT enrichment, timeline, risk assessment, and recommendations.
- Wrote `README.md` documenting how the tool works and how to run it.
- Took screenshots of the tool running and of each OSINT lookup.

## Time spent
Roughly 5-6 days, spread across: building and testing the detection script, running and re-checking the sample logs, doing the OSINT lookups, and writing the report and documentation.

## Blockers / challenges
Getting the log-parsing regex to reliably catch attack payloads without false positives took some trial and error, since the SQL injection payloads had unusual spacing and characters compared to normal clean URLs.


## Deliverables status
| Item | Status |
|---|---|
| Source code (`analyze_logs.py`) | Done |
| Documentation (`README.md`, findings report) | Done |
| Screenshots | Done |
| GitHub repository |Done |
| Explanation video | Done |
| Progress report | Done |
