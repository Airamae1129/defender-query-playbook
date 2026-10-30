# Defender Query Playbook

Alert → Context → KQL. Pick a Defender alert, type in its entities, copy ready-to-run hunting queries.

Owner: Aira Mae Bugay

## Open it

Double-click `index.html`. It runs in any browser with no install and no server.

To fill the fields automatically, open an alert and paste the alert details (from the Defender alert page, incident evidence or email headers) into **Paste alert details**. The page picks out users, IPs, devices, hashes, file names, URLs/domains, senders and the Alert ID, and fills every field. Check the values before running; you can still edit any field. Extraction runs in the page and nothing is sent anywhere. Pasted text and field values are never saved: they clear when you reload or close the page.

To preview with a local server instead of double-clicking, run `node scripts/serve.mjs` and open http://localhost:3130. It turns browser caching off so edits to `data/alerts.js` show on a normal reload.

To search several users, IPs, devices, hashes or file names at once, type them into the field separated by commas (e.g. `a@contoso.com, b@contoso.com`). The queries switch to `in~ (...)`, `has_any (...)` or `... or ...` automatically.

## Add or change alerts

All alerts live in `data/alerts.js`. Either:

- **Ask Claude Code**: open this folder in Claude Code and paste your notes, e.g. *"Add this alert to the playbook"* followed by your Alert Name / Context / query. `CLAUDE.md` tells it the format and rules.
- **Use the page**: click **+ Add alert**, fill in the form, click **Copy as JSON**, and paste the result into the list in `data/alerts.js`.
- **Edit by hand**: follow the entry shape in `CLAUDE.md`.

Then check your work:

```
node scripts/validate.mjs
```

This needs Node.js 18 or newer. It flags broken JSON, unknown fill-in tokens, duplicate IDs, and real IPs, emails or GUIDs left in queries.

## Sources

Table and column names were checked against Microsoft Learn on 9 Oct 2026:
https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables

Test each query in your own tenant before relying on it.

## OSINT tab

The **OSINT** switch in the header opens the same OSINT checker as SOC Triage Desk: add IPs, domains, URLs or hashes (several at once), run lookups, set verdicts, and copy the results in the team format (IP(s) Reputation / URL/Domain Reputation / File Hash Reputation / Screenshotbase), with an optional Defang toggle.

- Lookups run on the playbook server (`server.mjs`) with the API keys from `.env` (local) or Render's Environment settings. Keys are never sent to the browser.
- IPs: AbuseIPDB + VirusTotal. URLs and domains: VirusTotal + urlscan.io search. Hashes: VirusTotal. Shodan and OTX turn on when their keys are set. Private and internal addresses are refused.
- The tab asks for the team **access code** (`PLAYBOOK_ACCESS_CODE`). Ten wrong codes from one address lock it out for 15 minutes.
- Screenshotbase screenshots and new urlscan.io scans run only after you confirm.
- Indicators, results and screenshot links stay in the page's memory and clear on reload.

Run locally with OSINT: copy `.env.example` to `.env`, fill in the keys and an access code, then `node server.mjs` and open http://localhost:3130.

## Deploy on Render

The repo includes `render.yaml` (a Render Blueprint) for a free Node web service.

1. In Render: **New → Blueprint**, pick this repository, and apply. Render asks for the access code and API keys (paste them there; they never go in the repo).
2. Render runs `node scripts/validate.mjs` and starts `node server.mjs`.
3. Every push to the main branch redeploys automatically (the repository must be connected through Render's GitHub app). A broken `data/alerts.js` fails the build, so the live site keeps the last good version.

The query pages are public to anyone with the link; the OSINT tab needs the access code. Free services sleep when idle, so the first visit after a while takes about a minute. On Render the **+ Add alert** form offers **Copy as JSON**; paste the result into `data/alerts.js` and push.

To host only the queries as a static site instead (no OSINT), run `node scripts/build.mjs` and publish `dist/`.
