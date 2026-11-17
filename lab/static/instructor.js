"use strict";
const $ = id => document.getElementById(id);
const esc = s => String(s).replace(/[&<>]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
let token = null, timer = null;

// theme (shared with the student UI)
function applyTheme(th) {
  document.documentElement.setAttribute("data-theme", th);
  try { localStorage.setItem("pwnsat_theme", th); } catch (e) {}
  $("themetoggle").textContent = th === "light" ? "☀" : "◐";
}
$("themetoggle").onclick = () =>
  applyTheme(document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light");
applyTheme((() => { try { return localStorage.getItem("pwnsat_theme") || "dark"; } catch (e) { return "dark"; } })());

async function api(path, method, body) {
  const opt = { method: method || "GET", headers: { "Content-Type": "application/json" } };
  if (body) opt.body = JSON.stringify(body);
  const r = await fetch(path, opt);
  return { status: r.status, data: await r.json().catch(() => ({})) };
}

async function login() {
  $("loginerr").textContent = "";
  const { status, data } = await api("/api/instructor/login", "POST", { password: $("pw").value });
  if (status === 200 && data.token) {
    token = data.token;
    try { sessionStorage.setItem("pwnsat_itoken", token); } catch (e) {}
    showDash();
  } else {
    $("loginerr").textContent = data.error || "login failed";
    $("pw").value = "";
  }
}
$("loginbtn").onclick = login;
$("pw").addEventListener("keydown", e => { if (e.key === "Enter") login(); });

function showLogin() {
  token = null;
  try { sessionStorage.removeItem("pwnsat_itoken"); } catch (e) {}
  if (timer) clearInterval(timer);
  $("login").style.display = ""; $("inst").style.display = "none"; $("logout").style.display = "none";
}
function showDash() {
  $("login").style.display = "none"; $("inst").style.display = ""; $("logout").style.display = "";
  refresh();
  if (timer) clearInterval(timer);
  timer = setInterval(refresh, 3000);
}
$("logout").onclick = showLogin;

const fmtDur = s => s >= 3600 ? `${(s / 3600).toFixed(1)}h` : s >= 60 ? `${Math.floor(s / 60)}m${s % 60}s` : `${s}s`;

async function refresh() {
  const { status, data } = await api(`/api/instructor/sessions?token=${encodeURIComponent(token)}`);
  if (status === 403) { showLogin(); return; }
  const sv = data.server || {};
  $("cards").innerHTML = [
    ["Active sessions", sv.sessions],
    ["Server RSS", (sv.rss_mb || 0) + " MB"],
    ["Uptime", fmtDur(sv.uptime_s || 0)],
  ].map(([k, v]) => `<div class="card"><div class="k">${k}</div><div class="v">${esc(v)}</div></div>`).join("");
  $("autostat").textContent = "auto-refresh 3s · " + new Date().toLocaleTimeString();
  const rows = (data.sessions || []).map(s => {
    const health = s.errors > 0 ? `<span class="badge fault">fault</span>`
      : s.connections > 0 ? `<span class="badge live">live</span>`
        : `<span class="badge idle">idle</span>`;
    const flags = [s.secure ? "AES" : null, s.debug ? "DEBUG" : null, s.gs ? "GS" : null]
      .filter(Boolean).join(" ") || "—";
    return `<tr>
      <td class="sid">${esc(s.sid)}</td><td>${health}</td><td>${esc(s.mode)}</td>
      <td>${esc(flags)}</td><td>${s.commands}</td><td>${s.tm}</td><td>${s.relays}</td>
      <td>${s.errors}</td><td>${fmtDur(s.age_s)}</td><td>${fmtDur(s.idle_s)}</td>
      <td><button class="sbtn" data-reset="${esc(s.sid)}">Reset</button>
          <button class="sbtn" data-del="${esc(s.sid)}">Delete</button></td></tr>`;
  }).join("");
  $("rows").innerHTML = rows || `<tr><td colspan="11" style="color:var(--dim);padding:16px">No active sessions.</td></tr>`;
  $("rows").querySelectorAll("button[data-reset]").forEach(b => b.onclick =
    () => act("/api/instructor/reset", { sid: b.dataset.reset }));
  $("rows").querySelectorAll("button[data-del]").forEach(b => b.onclick =
    () => { if (confirm(`Delete session ${b.dataset.del}? The student loses their state.`)) act("/api/instructor/delete", { sid: b.dataset.del }); });
}

async function act(path, body) {
  await api(path, "POST", { ...body, token });
  refresh();
}
$("refresh").onclick = refresh;
$("resetall").onclick = async () => {
  if (!confirm("Reset ALL student satellites to defaults?")) return;
  await act("/api/instructor/reset-all", {});
};

// resume a session if the tab was reloaded
token = (() => { try { return sessionStorage.getItem("pwnsat_itoken"); } catch (e) { return null; } })();
if (token) showDash(); else showLogin();
