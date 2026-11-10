# Runbook: ransomware-precursor (critical)

**Fires when:** a host enumerates network shares, archives data, then runs a cloud-sync tool (rclone, b2.exe), in that order within 4 hours.
**Why it matters:** this is the SafePay sequence before encryption (CISA AA26-293A). Detection here usually gives hours before impact (T1135, T1560.001, T1567.002).

## First 15 minutes
1. **Isolate the host** with EDR network containment (keep it powered on for memory).
2. **Block the destination:** rclone remote (Mega, Backblaze, S3) domains and IPs at proxy and firewall.
3. **Disable the account** that ran the processes; check for the same account on other hosts.
4. **Protect backups:** confirm immutable backups are intact; restrict access to backup consoles and NAS management.

## Scope
- What was archived (command line paths) and how much left (proxy bytes out)?
- Other hosts with share enumeration or rclone in the last 72 hours.
- Remote access tools (AnyDesk, ScreenConnect) and new admin accounts.

## Close
- Engage IR and legal for possible data exfiltration notification decisions.
- Feed hashes and domains into blocklists; add the host's indicators to the CTI brief.

## Tuning history
v1 used a 24-hour window and treated `net share` as enumeration. The backup server's daily `net share` (06:00), nightly 7-Zip (01:00) and rclone sync (01:30) chained into 13 false positives. A 4-hour window and dropping `net share` fixed it; the backup server stays monitored by the same rule.
