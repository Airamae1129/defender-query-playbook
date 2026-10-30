// OSINT lookups for the playbook's OSINT tab. Same rules as SOC Triage Desk (src/osint):
// IPs → AbuseIPDB + VirusTotal (+ Shodan, OTX when keyed); domains/URLs → VirusTotal + urlscan.io search (+ OTX);
// hashes → VirusTotal (+ OTX). API keys come from the environment and never leave the server.

const env = (k) => (process.env[k] || "").trim();
const num = (k, d) => { const n = Number(process.env[k]); return Number.isFinite(n) && n > 0 ? n : d; };
const TIMEOUT_MS = () => num("OSINT_TIMEOUT_MS", 10000);
const CACHE_MS = () => num("OSINT_CACHE_HOURS", 24) * 3600e3;

// ---------- indicator validation ----------
export const isIp = (s) => /^(\d{1,3}\.){3}\d{1,3}$/.test(s) && s.split(".").every((o) => +o <= 255);
export const isPrivateIp = (ip) =>
  /^(10\.|127\.|0\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(ip) ||
  /^(22[4-9]|2[3-5]\d)\./.test(ip);
const looksIpv6 = (s) => /^[0-9a-f:]+$/i.test(s) && s.includes(":") && s.split(":").length <= 8;
const privateIpv6 = (v) => { v = v.toLowerCase(); return v === "::1" || v === "::" || /^f[cd]/.test(v) || /^fe[89ab]/.test(v) || /^ff/.test(v) || v.startsWith("::ffff:"); };
const INTERNAL_SUFFIX = /\.(local|lan|internal|intranet|corp|home|localdomain|localhost|private|domain|test|invalid)$/i;
const DOMAIN = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

export class BadInput extends Error {}

function checkHost(host, what) {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "");
  if (isIp(h)) { if (isPrivateIp(h)) throw new BadInput(`${what} uses a private or reserved IP. Internal addresses are not sent to OSINT providers.`); return; }
  if (looksIpv6(h)) { if (privateIpv6(h)) throw new BadInput(`${what} uses a private or reserved IPv6 address.`); return; }
  if (h === "localhost" || !h.includes(".") || INTERNAL_SUFFIX.test(h)) throw new BadInput(`${what} looks like an internal hostname (${h}). Internal names are not sent to OSINT providers.`);
}

export function detectType(v) {
  if (isIp(v) || looksIpv6(v)) return "ip";
  if (/^https?:\/\//i.test(v)) return "url";
  if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(v)) return "hash";
  if (DOMAIN.test(v) || !v.includes("/")) return "domain";
  return null;
}

/** Cleans an indicator (accepts defanged input) and refuses private / internal ones. */
export function validateIndicator(raw, type) {
  let v = String(raw ?? "").trim().replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".").replace(/^hxxp/i, "http").replace(/\[@\]/g, "@");
  if (!v || v.length > 2048) throw new BadInput("Enter an IP, domain, URL or hash.");
  const t = type || detectType(v);
  if (!t) throw new BadInput("Not a recognised IP, domain, URL or hash.");
  if (t === "ip") {
    if (isIp(v)) { if (isPrivateIp(v)) throw new BadInput("Private or reserved IPs (RFC1918, loopback, link-local, CGNAT, multicast) are not looked up."); }
    else if (looksIpv6(v)) { if (privateIpv6(v)) throw new BadInput("Private or reserved IPv6 addresses are not looked up."); }
    else throw new BadInput("Not a valid IP address.");
    return { indicator: v.toLowerCase(), type: t };
  }
  if (t === "hash") {
    if (!/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(v)) throw new BadInput("Hash must be MD5, SHA-1 or SHA-256 (hex).");
    return { indicator: v.toLowerCase(), type: t };
  }
  if (t === "url") {
    let u;
    try { u = new URL(v); } catch { throw new BadInput("Not a valid URL."); }
    if (!/^https?:$/.test(u.protocol)) throw new BadInput("Only http and https URLs can be looked up.");
    if (u.username || u.password) throw new BadInput("URLs with embedded credentials are not looked up.");
    checkHost(u.hostname, "This URL");
    return { indicator: v, type: t };
  }
  const d = v.toLowerCase().replace(/\.$/, "");
  checkHost(d, "This domain");
  if (!DOMAIN.test(d)) throw new BadInput("Not a valid domain name.");
  return { indicator: d, type: "domain" };
}

// ---------- HTTP with timeout ----------
class HttpError extends Error { constructor(status, retryAfter, msg) { super(msg); this.status = status; this.retryAfter = retryAfter; } }
class TimeoutError extends Error {}
class RateLimited extends Error { constructor(sec) { super(`Rate limit reached, try again in about ${sec}s`); this.sec = sec; } }

let httpFetch = (...a) => globalThis.fetch(...a);
export function setFetch(f) { httpFetch = f || ((...a) => globalThis.fetch(...a)); }

function retryAfter(res) {
  const v = res.headers.get("retry-after") || res.headers.get("x-rate-limit-reset-after");
  if (!v) return null;
  const n = Number(v);
  if (Number.isFinite(n)) return Math.max(1, Math.ceil(n));
  const d = Date.parse(v);
  return Number.isNaN(d) ? null : Math.max(1, Math.ceil((d - Date.now()) / 1000));
}

async function fetchJson(url, init, timeoutMs = TIMEOUT_MS()) {
  let res;
  try { res = await httpFetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) }); }
  catch (e) {
    if (e?.name === "TimeoutError" || e?.name === "AbortError") throw new TimeoutError(`No answer within ${Math.round(timeoutMs / 1000)}s`);
    throw new Error("Network error reaching the provider");
  }
  if (res.status === 404) return null;
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const b = await res.json();
      const d = b?.errors?.[0]?.detail ?? (typeof b?.error === "string" ? b.error : b?.error?.message) ?? b?.message ?? b?.description;
      if (d) msg += `: ${String(d).slice(0, 160)}`;
    } catch { /* not JSON */ }
    throw new HttpError(res.status, retryAfter(res), msg);
  }
  return res.json();
}

// ---------- per-provider request spacing + 429 backoff ----------
class Limiter {
  constructor(perMinute, maxWaitMs = 45000) { this.perMinute = perMinute; this.maxWaitMs = maxWaitMs; this.next = 0; this.cool = 0; this.strikes = 0; }
  async run(fn) {
    const now = Date.now();
    const interval = Math.ceil(60000 / Math.max(1, this.perMinute()));
    const start = Math.max(now, this.next, this.cool);
    const wait = start - now;
    if (wait > this.maxWaitMs) throw new RateLimited(Math.ceil(wait / 1000));
    this.next = start + interval;
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    return fn();
  }
  backoff(sec) {
    this.strikes = Math.min(this.strikes + 1, 6);
    const ms = sec != null ? sec * 1000 : 5000 * 2 ** (this.strikes - 1);
    this.cool = Date.now() + ms;
    return Math.ceil(ms / 1000);
  }
  ok() { this.strikes = 0; }
}

// ---------- providers ----------
const iso = (unix) => (unix ? new Date(unix * 1000).toISOString() : null);
const PROVIDERS = [
  {
    name: "abuseipdb", label: "AbuseIPDB", key: "ABUSEIPDB_API_KEY", rate: () => num("ABUSEIPDB_RATE_PER_MIN", 30),
    supports: (t) => t === "ip",
    async query(ip, _t, key) {
      const j = await fetchJson(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, { headers: { Key: key, Accept: "application/json" } });
      const d = j?.data ?? {};
      return { score: d.abuseConfidenceScore ?? 0, reports: d.totalReports ?? 0, country: d.countryCode ?? null, isp: d.isp ?? null, usageType: d.usageType ?? null, isTor: !!d.isTor, domain: d.domain ?? null, lastReportedAt: d.lastReportedAt ?? null };
    },
  },
  {
    name: "virustotal", label: "VirusTotal", key: "VIRUSTOTAL_API_KEY", rate: () => num("VIRUSTOTAL_RATE_PER_MIN", 4),
    supports: () => true,
    async query(v, t, key) {
      const path = t === "ip" ? `ip_addresses/${encodeURIComponent(v)}` : t === "domain" ? `domains/${encodeURIComponent(v)}` : t === "url" ? `urls/${Buffer.from(v).toString("base64url")}` : `files/${encodeURIComponent(v)}`;
      const j = await fetchJson(`https://www.virustotal.com/api/v3/${path}`, { headers: { "x-apikey": key, Accept: "application/json" } });
      const a = j?.data?.attributes;
      if (!a) return { found: false, malicious: 0, suspicious: 0, harmless: 0, undetected: 0, total: 0, reputation: null, asn: null, asOwner: null, country: null, lastAnalysisDate: null, creationDate: null };
      const s = a.last_analysis_stats ?? {};
      return {
        found: true, malicious: s.malicious ?? 0, suspicious: s.suspicious ?? 0, harmless: s.harmless ?? 0, undetected: s.undetected ?? 0,
        total: Object.values(s).reduce((x, y) => x + (typeof y === "number" ? y : 0), 0),
        reputation: a.reputation ?? null, asn: a.asn ?? null, asOwner: a.as_owner ?? null, country: a.country ?? null,
        lastAnalysisDate: iso(a.last_analysis_date), creationDate: iso(a.creation_date),
      };
    },
  },
  {
    name: "urlscan", label: "urlscan.io", key: "URLSCAN_API_KEY", rate: () => num("URLSCAN_RATE_PER_MIN", 60),
    supports: (t) => t === "domain" || t === "url",
    async query(v, t, key) {
      const q = t === "domain" ? `domain:${v}` : `page.url:"${v.replace(/"/g, "")}"`;
      const j = await fetchJson(`https://urlscan.io/api/v1/search/?q=${encodeURIComponent(q)}&size=10`, { headers: { "API-Key": key, Accept: "application/json" } });
      const res = j?.results ?? [];
      const l = res[0];
      return {
        hits: j?.total ?? res.length,
        malicious: res.filter((r) => r.verdicts?.malicious || r.verdicts?.overall?.malicious).length,
        latest: l ? { time: l.task?.time ?? null, url: l.page?.url ?? null, result: l.result?.replace("/api/v1/result/", "/result/") ?? null } : null,
      };
    },
  },
  {
    name: "shodan", label: "Shodan", key: "SHODAN_API_KEY", rate: () => num("SHODAN_RATE_PER_MIN", 60),
    supports: (t) => t === "ip",
    async query(ip, _t, key) {
      const j = await fetchJson(`https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(key)}&minify=true`, { headers: { Accept: "application/json" } });
      if (!j) return { found: false, ports: [], org: null, asn: null, isp: null, country: null, hostnames: [], vulns: 0 };
      return { found: true, ports: (j.ports ?? []).slice().sort((a, b) => a - b), org: j.org ?? null, asn: j.asn ?? null, isp: j.isp ?? null, country: j.country_name ?? null, hostnames: (j.hostnames ?? []).slice(0, 10), vulns: Array.isArray(j.vulns) ? j.vulns.length : j.vulns ? Object.keys(j.vulns).length : 0 };
    },
  },
  {
    name: "otx", label: "AlienVault OTX", key: "OTX_API_KEY", rate: () => num("OTX_RATE_PER_MIN", 60),
    supports: () => true,
    async query(v, t, key) {
      const section = t === "ip" ? (v.includes(":") ? "IPv6" : "IPv4") : t === "domain" ? "domain" : t === "url" ? "url" : "file";
      const j = await fetchJson(`https://otx.alienvault.com/api/v1/indicators/${section}/${encodeURIComponent(v)}/general`, { headers: { "X-OTX-API-KEY": key, Accept: "application/json" } });
      const p = j?.pulse_info;
      return { pulses: p?.count ?? 0, tags: [...new Set((p?.pulses ?? []).flatMap((x) => x.tags ?? []))].slice(0, 15) };
    },
  },
];
const limiters = new Map(PROVIDERS.map((p) => [p.name, new Limiter(p.rate)]));
export function resetLimiters() { for (const p of PROVIDERS) limiters.set(p.name, new Limiter(p.rate)); cache.clear(); }

export const providerStatus = () => PROVIDERS.map((p) => ({ name: p.name, label: p.label, configured: !!env(p.key), types: ["ip", "domain", "url", "hash"].filter(p.supports) }));

// ---------- in-memory cache (successful answers only) ----------
const cache = new Map(); // `${provider}|${type}:${indicator}` -> { data, at }
function cacheGet(k) { const c = cache.get(k); if (!c) return null; if (Date.now() - c.at > CACHE_MS()) { cache.delete(k); return null; } return c; }
function cacheSet(k, data) { if (cache.size > 5000) cache.delete(cache.keys().next().value); const c = { data, at: Date.now() }; cache.set(k, c); return c; }

async function runProvider(p, indicator, type, force) {
  const base = { provider: p.name, label: p.label };
  const key = env(p.key);
  if (!key) return { ...base, status: "not_configured" };
  const ck = `${p.name}|${type}:${indicator.toLowerCase()}`;
  if (!force) { const hit = cacheGet(ck); if (hit) return { ...base, status: "ok", data: hit.data, cached: true, fetchedAt: new Date(hit.at).toISOString() }; }
  const lim = limiters.get(p.name);
  try {
    const data = await lim.run(() => p.query(indicator, type, key));
    lim.ok();
    const c = cacheSet(ck, data);
    return { ...base, status: "ok", data, cached: false, fetchedAt: new Date(c.at).toISOString() };
  } catch (e) {
    if (e instanceof RateLimited) return { ...base, status: "rate_limited", error: e.message };
    if (e instanceof HttpError && e.status === 429) return { ...base, status: "rate_limited", error: `Provider rate limit, paused for ${lim.backoff(e.retryAfter)}s` };
    if (e instanceof HttpError && (e.status === 401 || e.status === 403)) console.warn(`[osint] ${p.name} rejected the API key (HTTP ${e.status})`);
    return { ...base, status: "error", error: e instanceof HttpError || e instanceof TimeoutError ? e.message : "Lookup failed" };
  }
}

// ---------- verdict + summary ----------
const okData = (results, name) => results.find((r) => r.provider === name && r.status === "ok")?.data;
/** Malicious: VT ≥3 or AbuseIPDB ≥75 · Low risk: anything lower that flagged it · Clean: all configured answered, none flagged. */
export function suggestVerdict(results, now = Date.now()) {
  const abuse = okData(results, "abuseipdb"), vt = okData(results, "virustotal"), us = okData(results, "urlscan"), otx = okData(results, "otx");
  const vtMal = vt?.found ? vt.malicious : 0, score = abuse?.score ?? 0;
  if (vtMal >= 3 || score >= 75) return "Malicious";
  const young = !!vt?.creationDate && now - Date.parse(vt.creationDate) < 30 * 86400e3;
  const vtSus = vt?.found ? vt.suspicious : 0;
  if (vtMal >= 1 || vtSus > 0 || score >= 1 || young || (us?.malicious ?? 0) > 0 || (otx?.pulses ?? 0) > 0) return "Low risk";
  const configured = results.filter((r) => r.status !== "not_configured");
  if (configured.length && configured.every((r) => r.status === "ok")) return "Clean";
  return "Not checked";
}

export function summaryLine(results) {
  const parts = [];
  for (const r of results) {
    if (r.status !== "ok" || !r.data) continue;
    const d = r.data;
    if (r.provider === "abuseipdb") parts.push(`AbuseIPDB – ${d.reports} report${d.reports === 1 ? "" : "s"}, ${d.score}% confidence score${d.isTor ? ", Tor exit node" : ""}`);
    if (r.provider === "virustotal") parts.push(d.found ? `VirusTotal – ${d.malicious}/${d.total} malicious${d.suspicious ? `, ${d.suspicious} suspicious` : ""}` : "VirusTotal – not found");
    if (r.provider === "urlscan") parts.push(`urlscan.io – ${d.hits} scan${d.hits === 1 ? "" : "s"}${d.malicious ? `, ${d.malicious} flagged malicious` : ", none flagged"}`);
    if (r.provider === "shodan") parts.push(d.found ? `Shodan – ${d.ports.length ? `ports ${d.ports.slice(0, 8).join(", ")}` : "no open ports"}${d.vulns ? `, ${d.vulns} CVEs` : ""}` : "Shodan – not found");
    if (r.provider === "otx") parts.push(`OTX – ${d.pulses} pulse${d.pulses === 1 ? "" : "s"}${d.tags.length ? ` (${d.tags.slice(0, 4).join(", ")})` : ""}`);
  }
  return parts.join(" · ");
}

/** Runs the applicable providers in parallel; one failing provider never fails the lookup. */
export async function lookup(rawIndicator, rawType, force = false) {
  const { indicator, type } = validateIndicator(rawIndicator, rawType);
  const chosen = PROVIDERS.filter((p) => p.supports(type));
  const results = await Promise.all(chosen.map((p) => runProvider(p, indicator, type, force)));
  return { indicator, type, results, verdict: suggestVerdict(results), summary: summaryLine(results), checkedAt: new Date().toISOString() };
}

// ---------- confirmed actions ----------
let shots = { day: "", count: 0 };
export const screenshotsToday = () => (shots.day === new Date().toISOString().slice(0, 10) ? shots.count : 0);

/** Screenshotbase URL → hosted PNG link (response_type=json). Only after the analyst confirms. */
export async function takeScreenshot(rawUrl) {
  const key = env("SCREENSHOTBASE_API_KEY");
  if (!key) throw new BadInput("Screenshot API key not configured.");
  const { indicator: url } = validateIndicator(/^https?:\/\//i.test(rawUrl) ? rawUrl : `https://${rawUrl}`, "url");
  const qs = new URLSearchParams({ url, format: "png", viewport_width: "1280", viewport_height: "800", response_type: "json" });
  let j;
  try { j = await fetchJson(`https://api.screenshotbase.com/v1/take?${qs}`, { headers: { apikey: key, Accept: "application/json" } }, 90000); }
  catch (e) { throw new Error(`Screenshot failed (${e.message})`); }
  if (!j?.url) throw new Error("Screenshot service returned no image link");
  const day = new Date().toISOString().slice(0, 10);
  shots = { day, count: (shots.day === day ? shots.count : 0) + 1 };
  return { url: j.url, page: url, taken_at: new Date().toISOString(), count_today: shots.count };
}

/** New urlscan.io scan, always private (unlisted if the plan doesn't allow private). Only after confirmation. */
export async function submitScan(rawUrl) {
  const key = env("URLSCAN_API_KEY");
  if (!key) throw new BadInput("urlscan.io is not configured.");
  const { indicator: url } = validateIndicator(/^https?:\/\//i.test(rawUrl) ? rawUrl : `https://${rawUrl}`, "url");
  const send = (visibility) => fetchJson("https://urlscan.io/api/v1/scan/", { method: "POST", headers: { "API-Key": key, "Content-Type": "application/json", Accept: "application/json" }, body: JSON.stringify({ url, visibility }) });
  let visibility = env("URLSCAN_VISIBILITY") === "unlisted" ? "unlisted" : "private";
  let r;
  try { r = await send(visibility); }
  catch (e) {
    if (visibility === "private" && e instanceof HttpError && (e.status === 400 || e.status === 403)) { visibility = "unlisted"; r = await send(visibility); }
    else throw new Error(e instanceof HttpError ? `urlscan.io: ${e.message}` : "urlscan.io scan failed");
  }
  if (!r?.uuid) throw new Error("urlscan.io did not accept the scan");
  return { uuid: r.uuid, result: `https://urlscan.io/result/${r.uuid}/`, visibility };
}
