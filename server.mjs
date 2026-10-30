// Defender Query Playbook server: serves the page and runs OSINT lookups with server-held API keys.
// Usage: node server.mjs [port]      (Node 18+, no dependencies)
// Settings come from .env locally and from the host's environment settings on Render. See .env.example.
import { createServer } from "node:http";
import { readFileSync, existsSync } from "node:fs";
import { timingSafeEqual, createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));

// Minimal .env loader (real environment variables win).
const envFile = join(root, ".env");
if (existsSync(envFile)) {
  for (const line of readFileSync(envFile, "utf8").split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (!m || line.trim().startsWith("#")) continue;
    const v = m[2].replace(/^"(.*)"$/, "$1").replace(/\s+#.*$/, "");
    if (!(m[1] in process.env)) process.env[m[1]] = v;
  }
}

const osint = await import("./server/osint.mjs");
const PORT = Number(process.argv[2] || process.env.PORT || 3130);
const ACCESS_CODE = (process.env.PLAYBOOK_ACCESS_CODE || "").trim();

// Only these files are ever served (never .env, scripts or server code).
const FILES = {
  "/": ["index.html", "text/html; charset=utf-8"],
  "/index.html": ["index.html", "text/html; charset=utf-8"],
  "/data/alerts.js": ["data/alerts.js", "text/javascript; charset=utf-8"],
};

const SECURITY_HEADERS = {
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  // img-src https: lets Screenshotbase image links show; scripts and connections stay same-origin.
  "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
};

// ---- small fixed-window rate limiter per client IP ----
const buckets = new Map();
function limited(key, max, windowMs) {
  const now = Date.now();
  const b = buckets.get(key);
  if (!b || now - b.start > windowMs) { buckets.set(key, { start: now, n: 1 }); return false; }
  b.n += 1;
  return b.n > max;
}
setInterval(() => { const now = Date.now(); for (const [k, b] of buckets) if (now - b.start > 3600e3) buckets.delete(k); }, 600e3).unref();

// Behind one proxy (Render), the last X-Forwarded-For entry is the one the proxy added, so a client can't fake it.
const clientIp = (req) => (process.env.TRUST_PROXY === "1" ? String(req.headers["x-forwarded-for"] || "").split(",").pop().trim() : "") || req.socket.remoteAddress || "?";
const digest = (s) => createHash("sha256").update(s).digest();
const codeOk = (given) => !!ACCESS_CODE && typeof given === "string" && timingSafeEqual(digest(given), digest(ACCESS_CODE));

function send(res, status, body, headers = {}) {
  const json = typeof body === "string" ? body : JSON.stringify(body);
  res.writeHead(status, { ...SECURITY_HEADERS, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers });
  res.end(json);
}
const fail = (res, status, code, message) => send(res, status, { error: { code, message } });

async function readJson(req) {
  let size = 0;
  const chunks = [];
  for await (const c of req) { size += c.length; if (size > 64 * 1024) throw Object.assign(new Error("too large"), { code: 413 }); chunks.push(c); }
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"); } catch { throw Object.assign(new Error("bad json"), { code: 400 }); }
}

async function api(req, res, path) {
  const ip = clientIp(req);
  if (limited(`api:${ip}`, 120, 60e3)) return fail(res, 429, "rate_limited", "Too many requests. Wait a minute.");
  if (req.method !== "GET" && req.headers["x-requested-with"] !== "XMLHttpRequest") return fail(res, 403, "csrf", "Missing X-Requested-With header.");

  if (path === "/api/osint/status" && req.method === "GET") {
    return send(res, 200, { enabled: !!ACCESS_CODE });
  }

  // Everything below needs the team access code.
  if (!ACCESS_CODE) return fail(res, 503, "not_configured", "OSINT is not set up on this server (PLAYBOOK_ACCESS_CODE is empty).");
  // 10 wrong codes from one address within 15 minutes locks that address out until the window ends.
  const badKey = `badcode:${ip}`;
  let bad = buckets.get(badKey);
  if (bad && Date.now() - bad.start > 15 * 60e3) { buckets.delete(badKey); bad = undefined; }
  if (bad && bad.n >= 10) return fail(res, 429, "locked", "Too many wrong access codes. Wait 15 minutes.");
  if (!codeOk(req.headers["x-access-code"])) {
    if (bad) bad.n += 1; else buckets.set(badKey, { start: Date.now(), n: 1 });
    return fail(res, 401, "bad_code", "Wrong or missing access code.");
  }
  if (limited(`osint:${ip}`, 60, 60e3)) return fail(res, 429, "rate_limited", "Too many OSINT requests. Wait a minute.");

  try {
    if (path === "/api/osint/check" && req.method === "POST") {
      return send(res, 200, { ok: true, providers: osint.providerStatus(), screenshot: !!(process.env.SCREENSHOTBASE_API_KEY || "").trim(), screenshotsToday: osint.screenshotsToday(), cacheHours: Number(process.env.OSINT_CACHE_HOURS) || 24 });
    }
    if (path === "/api/osint/lookup" && req.method === "POST") {
      const b = await readJson(req);
      const type = ["ip", "domain", "url", "hash"].includes(b.type) ? b.type : undefined;
      return send(res, 200, await osint.lookup(b.indicator, type, b.force === true));
    }
    if (path === "/api/osint/validate" && req.method === "POST") {
      const b = await readJson(req);
      const list = Array.isArray(b.indicators) ? b.indicators.slice(0, 100) : [];
      const ok = [], rejected = [];
      for (const raw of list) { try { ok.push(osint.validateIndicator(raw)); } catch (e) { rejected.push({ value: String(raw).slice(0, 200), reason: e.message }); } }
      return send(res, 200, { ok, rejected });
    }
    if (path === "/api/osint/screenshot" && req.method === "POST") {
      const b = await readJson(req);
      if (b.confirmed !== true) return fail(res, 400, "bad_request", "Screenshot needs explicit confirmation.");
      return send(res, 200, await osint.takeScreenshot(String(b.url || "")));
    }
    if (path === "/api/osint/urlscan-scan" && req.method === "POST") {
      const b = await readJson(req);
      if (b.confirmed !== true) return fail(res, 400, "bad_request", "Scans need explicit confirmation.");
      return send(res, 200, await osint.submitScan(String(b.url || "")));
    }
  } catch (e) {
    if (e instanceof osint.BadInput) return fail(res, 400, "bad_request", e.message);
    if (e.code === 413) return fail(res, 413, "too_large", "Request too large.");
    if (e.code === 400) return fail(res, 400, "bad_json", "Request body is not valid JSON.");
    console.error("[osint]", e.message);
    return fail(res, 502, "provider_error", e.message || "Lookup failed.");
  }
  return fail(res, 404, "not_found", "Unknown API route.");
}

const server = createServer(async (req, res) => {
  const path = new URL(req.url, "http://x").pathname;
  if (path.startsWith("/api/")) return api(req, res, path);
  if (path === "/healthz") return send(res, 200, { ok: true });
  const f = FILES[path];
  if (!f || (req.method !== "GET" && req.method !== "HEAD")) {
    res.writeHead(404, { ...SECURITY_HEADERS, "Content-Type": "text/plain" });
    return res.end("Not found");
  }
  try {
    const body = readFileSync(join(root, f[0]));
    res.writeHead(200, { ...SECURITY_HEADERS, "Content-Type": f[1], "Cache-Control": "no-cache" });
    res.end(req.method === "HEAD" ? undefined : body);
  } catch {
    res.writeHead(500, { "Content-Type": "text/plain" }); res.end("Server error");
  }
});

server.listen(PORT, () => {
  console.log(`Defender Query Playbook on http://localhost:${PORT}  (OSINT ${ACCESS_CODE ? "on" : "off: set PLAYBOOK_ACCESS_CODE"})`);
});
