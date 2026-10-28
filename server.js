// ===== CyberShield guard: paste as the very first line of your main file =====
(function(){
const module = {};
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
const mw = module.exports({ siteId: '13b61e0438a9', guardKey: process.env.CYBERSHIELD_KEY || '866207ab1dbbb1cd864db45ef041f67f', api: 'https://cybershield-api.musharafnizamuddin.workers.dev' });
const http = typeof require === 'function' ? require('http') : process.getBuiltinModule('http');
const orig = http.Server.prototype.emit;
http.Server.prototype.emit = function (ev, req, res) {
  if (ev !== 'request') return orig.apply(this, arguments);
  let ok = false;
  const r = { on: (e, f) => res.on(e, f), get statusCode() { return res.statusCode; },
    set(k, v) { res.setHeader(k, v); return r; }, status(c) { res.statusCode = c; return r; },
    json(o) { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(o)); } };
  try { mw(req, r, () => { ok = true; }); } catch (e) { ok = true; }
  return ok ? orig.apply(this, arguments) : true;
};
})();
// ===== end CyberShield guard =====
const express = require("express");

const app = express();
app.set("trust proxy", 1);

app.get("/ping", (req, res) => res.send("pong"));
app.get("/", (req, res) => res.type("html").send(
  '<button onclick="go()" style="padding:14px;font-size:16px">Send 80 requests</button><pre id="o"></pre>' +
  '<script>async function go(){let ok=0,bad=0;for(let i=0;i<80;i++){const r=await fetch("/ping");r.status===429?bad++:ok++}document.getElementById("o").textContent="allowed "+ok+", blocked "+bad}</script>'
));

app.listen(process.env.PORT || 3000);
