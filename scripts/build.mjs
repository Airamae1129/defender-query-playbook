// Builds the static site for hosting (Render): copies only the page and its data into dist/.
// Usage: node scripts/build.mjs   (run node scripts/validate.mjs first)
import { cpSync, mkdirSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "dist");
rmSync(out, { recursive: true, force: true });
mkdirSync(join(out, "data"), { recursive: true });
cpSync(join(root, "index.html"), join(out, "index.html"));
cpSync(join(root, "data", "alerts.js"), join(out, "data", "alerts.js"));
console.log("Built dist/ (index.html, data/alerts.js)");
