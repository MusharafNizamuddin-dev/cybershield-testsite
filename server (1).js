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
