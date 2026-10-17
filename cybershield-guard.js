// CyberShield Guard: drop-in rate limiting for Express (Node 18+, no dependencies).
// Stays OFF until the owner clicks "Add security / rate limiting" in CyberShield.
// Real visitor IP. If the site already uses app.set('trust proxy', ...), Express handles it.
// If not, behind a proxy like Render every visitor would look like the proxy, so read the
// last X-Forwarded-For entry (the one added by the nearest proxy, which visitors cannot fake).
function clientIp(req) {
  if (req.app && req.app.get && req.app.get("trust proxy")) return req.ip;
  const x = req.headers["x-forwarded-for"];
  if (x) { const p = String(x).split(",").map((s) => s.trim()).filter(Boolean); if (p.length) return p[p.length - 1]; }
  return req.ip;
}
module.exports = function cybershieldGuard({ siteId, guardKey, api }) {
  let cfg = { enabled: false, max: 60, windowSec: 60 };
  let allowed = 0, blocked = 0;
  const hits = new Map();
  let events = []; // recent requests, sent to CyberShield so the Log Analyzer can show them live

  async function sync() {
    const a = allowed, b = blocked, ev = events.splice(0, 100);
    try {
      const r = await fetch(api + "/api/guard/" + siteId + "/sync", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-guard-key": guardKey },
        body: JSON.stringify({ allowed: a, blocked: b, events: ev })
      });
      if (r.ok) { cfg = await r.json(); allowed -= a; blocked -= b; }
      else events = ev.concat(events).slice(-300);
    } catch (e) { events = ev.concat(events).slice(-300); /* keep last settings; retry next cycle */ }
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
