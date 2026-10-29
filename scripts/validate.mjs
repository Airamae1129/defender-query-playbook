// Checks data/alerts.js before you open or share the playbook.
// Usage: node scripts/validate.mjs
// Exits with code 1 if any error is found; warnings do not fail the run.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const src = readFileSync(join(root, "data", "alerts.js"), "utf8");

const PREFIX = "window.PLAYBOOK_ALERTS = ";
const start = src.indexOf(PREFIX);
if (start < 0) fail(`data/alerts.js must contain "${PREFIX}[...]"`);
let body = src.slice(start + PREFIX.length).trim();
if (body.endsWith(";")) body = body.slice(0, -1);

let alerts;
try { alerts = JSON.parse(body); }
catch (e) { fail("data/alerts.js is not valid JSON after the assignment: " + e.message + "\nCommon causes: a trailing comma after the last entry, or an unescaped \" or \\ inside a query."); }

// Keep in sync with PARAMS in index.html.
const TOKENS = new Set(["LOOKBACK","BASELINE","ALERTID","DEVICE","UPN","UPNS","ACCOUNT","IP","IPS","SHA1","SHA256","FILENAME","SENDER","DOMAIN","MSGID","GUEST","OBJECTID","ACTOR","APPID","COUNTRIES","XCOUNTRIES","INTIP","SESSIONID","TABLE","RESOURCE","ALERTNAME"]);
const LIST_TOKENS = new Set(["UPNS","IPS","COUNTRIES","XCOUNTRIES"]);
const CATS = new Set(["Endpoint","Identity","Email","Cloud apps","Network","SIEM health"]);
const SEVS = new Set(["high","medium","low","info"]);

// Columns verified on Microsoft Learn, 9 Oct 2026. Extend when you add tables.
const SCHEMA = {
  EntraIdSignInEvents: ["Timestamp","Application","ApplicationId","LogonType","ErrorCode","AccountUpn","AccountObjectId","AccountDisplayName","IPAddress","Country","State","City","DeviceName","OSPlatform","IsManaged","IsCompliant","AuthenticationRequirement","RiskLevelDuringSignIn","RiskState","UserAgent","ClientAppUsed","ConditionalAccessStatus","CorrelationId","SessionId","ReportId"],
  UrlClickEvents: ["Timestamp","Url","ActionType","AccountUpn","Workload","NetworkMessageId","ThreatTypes","DetectionMethods","IPAddress","IsClickedThrough","UrlChain","ReportId"],
  IdentityQueryEvents: ["Timestamp","ActionType","Application","QueryType","QueryTarget","Query","Protocol","AccountName","AccountDomain","AccountUpn","DeviceName","IPAddress","DestinationDeviceName","TargetAccountUpn","ReportId","AdditionalFields"],
};

const errors = [], warnings = [];
const ids = new Set();
const REAL_ID = [
  [/\b(?:\d{1,3}\.){3}\d{1,3}\b/, "an IP address"],
  [/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/, "an email address"],
  [/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i, "a GUID"],
];

if (!Array.isArray(alerts)) fail("PLAYBOOK_ALERTS must be a list ([ ... ]).");

alerts.forEach((a, i) => {
  const where = `#${i + 1} "${a?.name ?? "?"}"`;
  for (const k of ["id","name","cat","steps"]) if (!a?.[k]) errors.push(`${where}: missing "${k}"`);
  if (a?.id) { if (ids.has(a.id)) errors.push(`${where}: duplicate id "${a.id}"`); ids.add(a.id); }
  if (a?.id && !/^[a-z0-9-]+$/.test(a.id)) errors.push(`${where}: id should be lowercase letters, digits and dashes`);
  if (a?.cat && !CATS.has(a.cat)) errors.push(`${where}: category "${a.cat}" must be one of ${[...CATS].join(", ")}`);
  if (a?.sev && !SEVS.has(a.sev)) errors.push(`${where}: severity "${a.sev}" must be one of ${[...SEVS].join(", ")}`);
  (a?.mitre || []).forEach(m => { if (!/^T\d{4}(\.\d{3})?$/.test(m)) warnings.push(`${where}: MITRE ID "${m}" looks malformed`); });
  if (!Array.isArray(a?.steps) || !a.steps.length) return;
  a.steps.forEach((s, j) => {
    const sw = `${where} step ${j + 1}`;
    if (!s.ctx) errors.push(`${sw}: missing "ctx" (the Context line)`);
    if (!s.kql) { errors.push(`${sw}: missing "kql"`); return; }
    for (const m of s.kql.matchAll(/\{\{([A-Za-z0-9_]+)\}\}/g)) {
      const t = m[1];
      if (!TOKENS.has(t)) errors.push(`${sw}: unknown token {{${t}}}. Add it to PARAMS in index.html and TOKENS here, or use an existing one.`);
      const before = s.kql.slice(0, m.index), after = s.kql.slice(m.index + m[0].length);
      const quoted = /"$/.test(before) && /^"/.test(after);
      if (LIST_TOKENS.has(t) && quoted) errors.push(`${sw}: {{${t}}} is a list token and must not be wrapped in quotes`);
    }
    if (/\{\{[^}]*$/.test(s.kql)) errors.push(`${sw}: unclosed {{ token`);
    const text = s.kql.replace(/\{\{[A-Z0-9_]+\}\}/g, "");
    for (const [re, label] of REAL_ID) if (re.test(text)) warnings.push(`${sw}: contains ${label}. Use a fill-in token instead of real tenant data.`);
    for (const [table, cols] of Object.entries(SCHEMA)) {
      if (!new RegExp(`\\b${table}\\b`).test(s.kql)) continue;
      if (/\bunion\b|\bjoin\b/.test(s.kql)) continue; // multi-table: skip column check
      for (const c of ["UserPrincipalName","ResultType","TimeGenerated"]) {
        if (new RegExp(`\\b${c}\\b`).test(s.kql) && !cols.includes(c)) warnings.push(`${sw}: ${c} is a Sentinel column; ${table} doesn't have it`);
      }
    }
    const tableMixed = /\bTimestamp\b/.test(s.kql) && /\bTimeGenerated\b/.test(s.kql) && !/\bunion\b|\bjoin\b/.test(s.kql);
    if (tableMixed) warnings.push(`${sw}: uses both Timestamp (Defender) and TimeGenerated (Sentinel); check the table`);
  });
});

console.log(`${alerts.length} alerts, ${alerts.reduce((n, a) => n + (a.steps?.length || 0), 0)} queries checked.`);
warnings.forEach(w => console.log("warning  " + w));
errors.forEach(e => console.log("ERROR    " + e));
if (errors.length) { console.log(`\n${errors.length} error(s). Fix them before opening the page.`); process.exit(1); }
console.log(warnings.length ? "\nNo errors. Review the warnings above." : "\nAll good.");

function fail(msg) { console.error("ERROR    " + msg); process.exit(1); }
