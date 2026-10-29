# Defender Query Playbook

A static site that maps Microsoft Defender XDR / Sentinel alerts to step-by-step KQL investigation queries. Analysts pick an alert, type the alert's entities (user, IP, device, hash) into fill-in fields, and copy ready-to-run queries.

## Layout

- `index.html`: the whole UI (styles, rendering, fill-in logic). No build step and no dependencies. Opens directly from disk.
- `data/alerts.js`: **the alert library.** Plain JSON wrapped in `window.PLAYBOOK_ALERTS = [ ... ];` so the page can load it over `file://`. Almost all edits happen here.
- `scripts/validate.mjs`: checks the library. Run `node scripts/validate.mjs` after every change to `data/alerts.js`.

## Alert entry shape

```json
{
  "id": "kebab-case-unique-id",
  "name": "Alert title as it appears in Defender",
  "cat": "Endpoint | Identity | Email | Cloud apps | Network | SIEM health",
  "src": "Product that raises it, e.g. Defender for Endpoint",
  "sev": "high | medium | low | info",
  "mitre": ["T1110", "T1110.003"],
  "playbook": true,
  "summary": "One or two sentences: what the alert means and what we need to decide.",
  "steps": [
    {
      "ctx": "The question this query answers (shown as the Context line)",
      "kql": "Table\n| where Timestamp > ago({{LOOKBACK}})\n| where DeviceName startswith \"{{DEVICE}}\"",
      "read": "How to interpret the result. May contain <b>bold</b> HTML."
    }
  ],
  "fp": "Common false positives."
}
```

`playbook: true` marks entries that came from the SOC team's own investigation notes (shown as "From your playbook").

## Fill-in tokens

Queries never contain real tenant data. Use these tokens; the page swaps in what the analyst types:

`{{LOOKBACK}}` (default 7d) · `{{BASELINE}}` (default 30d) · `{{ALERTID}}` · `{{DEVICE}}` · `{{UPN}}` · `{{UPNS}}` · `{{ACCOUNT}}` · `{{IP}}` · `{{IPS}}` · `{{SHA1}}` · `{{SHA256}}` · `{{FILENAME}}` · `{{SENDER}}` · `{{DOMAIN}}` · `{{MSGID}}` · `{{GUEST}}` · `{{OBJECTID}}` · `{{ACTOR}}` · `{{APPID}}` · `{{COUNTRIES}}` · `{{XCOUNTRIES}}` · `{{INTIP}}` (internal / VPN-assigned IP) · `{{SESSIONID}}` · `{{TABLE}}` (Usage DataType) · `{{RESOURCE}}` (Azure resource name fragment) · `{{ALERTNAME}}` (exact alert title, single value only)

- Single-value tokens go inside quotes: `where IPAddress == "{{IP}}"`.
- List tokens (`{{UPNS}}`, `{{IPS}}`) go **without** quotes and expand to `"a", "b"`: `where IPAddress in ({{IPS}})`.
- Window tokens go bare: `ago({{LOOKBACK}})`.
- Every entity field except `{{ALERTID}}` and the windows also accepts several comma-separated values. When it holds two or more, `expandMulti` in `index.html` rewrites `<col> <op> "{{TOK}}"`: `==` becomes `in`, `=~` becomes `in~`, `has` becomes `has_any`, and any other operator (e.g. `startswith`) becomes `(col op "a" or col op "b")`. A quoted token inside a list such as `has_any ("{{GUEST}}", ...)` expands in place. So write single-value tokens as `<column> <operator> "{{TOK}}"`; don't build them into strings with `strcat` or `let x = "{{TOK}}"`, or the multi-value rewrite won't apply.
- A new token needs an entry in `PARAMS` in `index.html` **and** in `TOKENS` in `scripts/validate.mjs`, and, if it can be picked out of pasted alert text, a rule in `extractEntities` in `index.html` (the **Paste alert details** auto-fill box).

## Rules for writing queries

1. **Never commit real identifiers.** No real user emails, IPs, object IDs, device names or company domains. Replace them with tokens. The validator warns on IPs, emails and GUIDs.
2. **Check table and column names against Microsoft Learn** (https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables) before adding a table that isn't already used. Don't guess column names.
3. **Defender XDR tables use `Timestamp`; Sentinel tables (SigninLogs, AuditLogs, AADNonInteractiveUserSignInLogs) use `TimeGenerated`.** Don't mix them in one table's query.
4. Use **`EntraIdSignInEvents`**, not `AADSignInEventsBeta` (Microsoft replaces it on 19 Oct 2026). Its error column is `ErrorCode` (int) and user column is `AccountUpn`; the Sentinel equivalents are `ResultType` (string) and `UserPrincipalName`.
5. Match device names with `startswith` (DeviceName is an FQDN) and UPNs with `=~` (case-insensitive).
6. Entra sign-in error codes used here: 50126 bad password, 50053 locked or malicious IP, 50055 expired password, 50057 disabled, 53003 blocked by Conditional Access, 500121 MFA failed. 50074/50076 are routine MFA prompts and should not be counted as brute-force failures.
7. Every step needs a `ctx` that states the question, in the team's style: "Are the alert IPs normal for the tenant? (30 days)".

## Converting the team's raw notes

Analysts paste notes like:

```
Alert Name: <title>
Context: <question>
<KQL with real values>
```

To turn them into an entry: one entry per alert name, one step per Context/query pair, replace literal values with tokens (and time windows with `{{LOOKBACK}}`/`{{BASELINE}}` where it makes sense), pick the category and MITRE IDs, write a short `read` and `fp`, then run the validator.

## Published copy

A copy of this site is published as a claude.ai artifact, where the "+ Add alert" button saves team entries to a shared store. That store only exists on the published page. When the page is opened from disk, the button offers **Copy as JSON** instead, and the result is pasted into `data/alerts.js`.

## Non-KQL entries

`ngfw-malicious-ip-auth` holds CrowdStrike Falcon Next-Gen SIEM (LogScale CQL) queries, not KQL. Fill-in tokens work the same, but CQL comparisons like `user.name="{{ACCOUNT}}"` take a single value only.
