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
const express = require("express");
const guard = require("./cybershield-guard");

const app = express();
app.set("trust proxy", 1);
app.use(guard({
  siteId: process.env.CYBERSHIELD_SITE_ID,
  guardKey: process.env.CYBERSHIELD_KEY,
  api: "https://cybershield-api.musharafnizamuddin.workers.dev"
}));

app.get("/ping", (req, res) => res.send("pong"));
app.get("/", (req, res) => res.type("html").send(
  '<button onclick="go()" style="padding:14px;font-size:16px">Send 80 requests</button><pre id="o"></pre>' +
  '<script>async function go(){let ok=0,bad=0;for(let i=0;i<80;i++){const r=await fetch("/ping");r.status===429?bad++:ok++}document.getElementById("o").textContent="allowed "+ok+", blocked "+bad}</script>'
));

app.listen(process.env.PORT || 3000);
