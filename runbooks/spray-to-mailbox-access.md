# Runbook: spray-to-mailbox-access (high)

**Fires when:** one IP fails sign-in for at least 10 distinct accounts, then one sign-in from that IP succeeds, then mailbox items are read from the same IP, within 60 minutes.
**Why it matters:** separates the spray that worked from thousands that fail (T1110.003, T1078.004, T1114.002), the AA26-281A pattern.

## First 15 minutes
1. **Revoke sessions** for the account that succeeded; reset password; require MFA re-registration.
2. **Block the source IP** at the IdP (named location / network zone) and check for other successes from it.
3. **Check legacy protocols:** if the success used EWS, IMAP or ActiveSync, disable legacy auth for the tenant.

## Scope
- MailItemsAccessed for that mailbox: which items and folders were read?
- New inbox rules, forwarding, OAuth consents or app registrations by the account.
- Other accounts from the same spray list with later successes from different IPs.

## Close
- Notify the user and the data owner; assess whether sensitive mail requires reporting.

## Tuning history
v1 fired at 3 failures across 3 accounts, which caught a shared office NAT where a few users mistyped passwords before one signed in: 3 false positives. Raising to 10 failures across 10 distinct accounts removed them; real sprays hit 15 to 40 accounts.
