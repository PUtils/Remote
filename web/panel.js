"use strict";

const $ = (s) => document.querySelector(s);
let timer = null;

async function api(path, params) {
  const opt = { method: params ? "POST" : "GET", headers: { "X-RT": "1" }, credentials: "same-origin", cache: "no-store" };
  if (params) opt.body = new URLSearchParams(params);
  let res;
  try {
    res = await fetch(path, opt);
  } catch {
    return { status: 0, error: "Cannot reach the Mac." };
  }
  let data = {};
  try { data = await res.json(); } catch {}
  return { status: res.status, ...data };
}

function setError(el, msg) {
  el.querySelector(".error").textContent = msg || "";
}

function age(s) {
  if (s < 60) return s + " s";
  if (s < 3600) return Math.floor(s / 60) + " min";
  return Math.floor(s / 3600) + " h " + Math.floor((s % 3600) / 60) + " min";
}

function showLogin(msg) {
  clearInterval(timer);
  timer = null;
  $("#panel").hidden = true;
  $("#status").hidden = true;
  $("#login").hidden = false;
  setError($("#login"), msg);
}

function render(s) {
  $("#login").hidden = true;
  $("#panel").hidden = false;

  const status = $("#status");
  status.hidden = false;
  status.textContent = s.hibernating ? "Hibernating" : "Active";
  status.className = "pill " + (s.hibernating ? "off" : "on");

  $("#state-text").textContent = s.hibernating
    ? "Remote access is off. New connections are refused."
    : "Remote access is on.";
  const toggle = $("#toggle");
  toggle.textContent = s.hibernating ? "Wake up" : "Hibernate";
  toggle.classList.toggle("wake", s.hibernating);
  toggle.dataset.action = s.hibernating ? "wake" : "hibernate";
  $("#open-term").hidden = s.hibernating;

  const routes = [
    [s.join, "Works with plain ssh."],
    [s.join_cf, "Needs cloudflared on that computer; use it if port 22 is blocked."],
  ].filter(([cmd]) => cmd);
  $("#join").hidden = routes.length === 0;
  const joinList = $("#join-list");
  const shown = [...joinList.querySelectorAll(".join-cmd")].map((c) => c.textContent).join("\n");
  if (shown !== routes.map(([cmd]) => cmd).join("\n")) {
    joinList.replaceChildren(...routes.map(([cmd, note]) => joinItem(cmd, note)));
  }

  const dir = $("#dir");
  if (document.activeElement !== dir) dir.value = s.dir;
  $("#dir-note").textContent = s.sandbox
    ? "New sessions are sandboxed to this directory."
    : "New sessions start here with full access.";

  const list = $("#sessions");
  list.replaceChildren();
  for (const c of s.sessions) {
    const li = document.createElement("li");
    const what = document.createElement("div");
    what.className = "what";
    const info = document.createElement("div");
    info.className = "info";
    info.textContent = c.info;
    const meta = document.createElement("div");
    meta.className = "age";
    meta.textContent = (c.closing ? "closing… " : "") + age(c.age);
    what.append(info, meta);
    const kill = document.createElement("button");
    kill.type = "button";
    kill.textContent = "Close";
    kill.disabled = c.closing;
    kill.addEventListener("click", async () => {
      kill.disabled = true;
      handle(await api("/api/kill", { id: c.id }), $("#panel section"));
    });
    li.append(what, kill);
    list.append(li);
  }
  $("#no-sessions").hidden = s.sessions.length > 0;

  if (!timer) timer = setInterval(refresh, 4000);
}

function handle(r, errEl) {
  if (r.status === 401) return showLogin(r.error === "Log in first." ? "" : r.error);
  if (r.status !== 200) {
    if (errEl) setError(errEl, r.error || "Something went wrong.");
    return false;
  }
  if (errEl) setError(errEl, "");
  render(r);
  return true;
}

async function refresh() {
  if (document.hidden) return;
  handle(await api("/api/state"), null);
}

$("#login").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.currentTarget;
  const btn = form.querySelector("button");
  const pw = $("#password");
  btn.disabled = true;
  const r = await api("/api/login", { password: pw.value });
  btn.disabled = false;
  pw.value = "";
  if (r.status === 200) render(r);
  else setError(form, r.error || "Could not log in.");
});

$("#toggle").addEventListener("click", async (e) => {
  const btn = e.currentTarget;
  const action = btn.dataset.action;
  if (action === "hibernate" && !confirm("Hibernate? All open sessions will be closed.")) return;
  btn.disabled = true;
  handle(await api("/api/" + action, {}), btn.closest(".card"));
  btn.disabled = false;
});

$("#cd").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.currentTarget;
  const btn = form.querySelector("button");
  btn.disabled = true;
  const ok = handle(await api("/api/cd", { dir: $("#dir").value.trim() }), form);
  btn.disabled = false;
  if (ok) $("#dir").blur();
});

function joinItem(cmd, note) {
  const item = document.createElement("div");
  item.className = "join-item";
  const code = document.createElement("code");
  code.className = "join-cmd";
  code.textContent = cmd;
  const p = document.createElement("p");
  p.className = "note";
  p.textContent = note;
  const btn = document.createElement("button");
  btn.type = "button";
  btn.textContent = "Copy command";
  btn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(cmd);
      btn.textContent = "Copied";
    } catch {
      getSelection().selectAllChildren(code);
      btn.textContent = "Selected; copy it from the menu";
    }
    setTimeout(() => { btn.textContent = "Copy command"; }, 2500);
  });
  item.append(code, p, btn);
  return item;
}

$("#logout").addEventListener("click", async () => {
  await api("/api/logout", {});
  showLogin("");
});

document.addEventListener("visibilitychange", refresh);

(async () => {
  const r = await api("/api/state");
  if (r.status === 200) render(r);
  else showLogin(r.status === 401 ? "" : r.error);
})();
