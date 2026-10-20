// CyberShield Guard: drop-in rate limiting for Express (Node 18+, no dependencies).
// Stays OFF until the owner clicks "Add security / rate limiting" in CyberShield.
// Real visitor IP.
// Platforms like Render, Railway and Heroku put their own proxies in front of your site, so the
// direct connection comes from a private address (10.x, 172.16.x, 192.168.x, 127.x). Only in that
// case we read the visitor IP from the proxy headers. If the connection comes from a public IP,
// we use it as is, so nobody can fake their IP with a header.
const PRIV = /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|::1$|f[cd][0-9a-f]{2}:|fe80:)/i;
const isPriv = (ip) => PRIV.test(String(ip || "").replace(/^::ffff:/i, ""));
function clientIp(req) {
  const peer = String((req.socket && req.socket.remoteAddress) || req.ip || "").replace(/^::ffff:/i, "");
  if (!isPriv(peer)) return (req.app && req.app.get && req.app.get("trust proxy") && req.ip) || peer;
  const h = req.headers || {};
  const direct = h["cf-connecting-ip"] || h["true-client-ip"];
  if (direct) return String(direct).trim();
  const x = h["x-forwarded-for"];
  if (x) {
    const parts = String(x).split(",").map((s) => s.trim()).filter(Boolean);
    for (let i = parts.length - 1; i >= 0; i--) if (!isPriv(parts[i])) return parts[i];
  }
  return peer;
}
module.exports = function cybershieldGuard({ siteId, guardKey, api }) {
  let cfg = { enabled: false, max: 60, windowSec: 60 };
  let allowed = 0, blocked = 0;
  const hits = new Map();
  let events = []; // recent requests, sent to CyberShield so the Log Analyzer can show them live

  let lastLog = "";
  function note(msg) { if (msg !== lastLog) { lastLog = msg; console.log("[CyberShield Guard] " + msg); } }
  if (!siteId) console.log("[CyberShield Guard] PROBLEM: CYBERSHIELD_SITE_ID is empty or missing in Render Environment");
  if (!guardKey) console.log("[CyberShield Guard] PROBLEM: CYBERSHIELD_KEY is empty or missing in Render Environment");

  async function sync() {
    const a = allowed, b = blocked, ev = events.splice(0, 100);
    try {
      const r = await fetch(api + "/api/guard/" + siteId + "/sync", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-guard-key": guardKey },
        body: JSON.stringify({ allowed: a, blocked: b, events: ev })
      });
      if (r.ok) { cfg = await r.json(); allowed -= a; blocked -= b; note("Connected to CyberShield (status " + r.status + ")"); }
      else {
        events = ev.concat(events).slice(-300);
        let body = ""; try { body = (await r.text()).slice(0, 200); } catch (e) {}
        note("CyberShield answered with status " + r.status + " " + body);
      }
    } catch (e) { events = ev.concat(events).slice(-300); note("Could not reach CyberShield: " + (e && e.message)); /* keep last settings; retry next cycle */ }
  }
  sync();
  setInterval(sync, 4000).unref();
  setInterval(() => { const n = Date.now(); for (const [k, v] of hits) if (v.reset < n) hits.delete(k); }, 60000).unref();

  return function (req, res, next) {
    // record every request (no bodies, no headers, no query string) for live monitoring
    const t0 = Date.now(), ip0 = clientIp(req), m0 = req.method, p0 = String(req.originalUrl || req.url || "/").split("?")[0].slice(0, 200);
    res.on("finish", () => {
      if (events.length < 300) events.push({ t: t0, ip: ip0, m: m0, p: p0, s: res.statusCode });
    });
    if (!cfg.enabled) { allowed++; return next(); }
    const ip = clientIp(req), now = Date.now();
    let h = hits.get(ip);
    if (!h || h.reset < now) { h = { count: 0, reset: now + cfg.windowSec * 1000 }; hits.set(ip, h); }
    if (++h.count > cfg.max) {
      blocked++;
      res.set("Retry-After", String(Math.ceil((h.reset - now) / 1000)));
      return res.status(429).json({ error: "Too many requests", protectedBy: "CyberShield" });
    }
    allowed++; next();
  };
};
