# Runbook: token-to-cloud-theft (critical)

**Fires when:** one identity creates a personal access token, clones at least 20 different repositories, then assumes an AWS role from an IP never seen for that identity, all within 60 minutes.
**Why it matters:** source code plus cloud credentials is a supply-chain and data-breach path (ATT&CK T1528, T1213.003, T1078.004).

## First 15 minutes
1. **Confirm the actor:** contact the user out of band (phone, not email or chat). Did they create the token and clone those repos?
2. **If not confirmed, contain immediately:** revoke the PAT and all of the user's GitHub sessions; revoke the AWS role session (attach a deny policy with an `aws:TokenIssueTime` condition, or deactivate the SSO user); reset the IdP password and require MFA re-registration.
3. **Preserve:** export GitHub audit log and CloudTrail for the actor for the last 24 hours.

## Scope (next hour)
- Which repos were cloned? Search them for secrets (keys, tokens) and rotate any found.
- What did the assumed role do? CloudTrail by `accessKeyId` from the AssumeRole response: data access (S3 GetObject), IAM changes, new keys.
- Where else did the source IP appear (IdP, VPN, other identities)?

## Close
- Benign (migration or travel): document the reason, and consider an allow-list entry for the specific migration window rather than a permanent exception.
- Malicious: hand to incident response with the evidence bundle; check whether the session was stolen through a phishing proxy (token theft) and block that domain.

## Tuning history
v1 (5 clones, any role assumption) raised 8 false positives in two weeks from repository migrations and travelling engineers. Requiring 20 clones of 15 distinct repos and a role from a new IP removed them without losing detections.
