"use strict";

const $ = (s) => document.querySelector(s);
const statusEl = $("#status");
const touch = matchMedia("(pointer: coarse)").matches;

const term = new Terminal({
  fontFamily: "ui-monospace, Menlo, monospace",
  fontSize: touch ? 12 : 14,
  cursorBlink: true,
  scrollback: 5000,
  macOptionIsMeta: true,
  theme: { background: "#141413", foreground: "#ececea", cursor: "#ececea" },
});
const fit = new FitAddon.FitAddon();
term.loadAddon(fit);
term.open($("#term"));

let ws = null;
let sid = null;
let ctrl = false;
let failures = 0;
let ended = false;
let retryTimer = null;
try { sid = sessionStorage.getItem("rt-sid"); } catch {}

function setStatus(text, kind) {
  statusEl.textContent = text;
  statusEl.className = kind || "";
}

function send(data) {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send("0" + data);
}

function sendSize() {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send("1" + term.cols + "," + term.rows);
}

let layoutQueued = false;
function layout() {
  if (layoutQueued) return;
  layoutQueued = true;
  requestAnimationFrame(() => {
    layoutQueued = false;
    const vv = window.visualViewport;
    $("#app").style.height = (vv ? vv.height : window.innerHeight) + "px";
    window.scrollTo(0, 0);
    fit.fit();
    sendSize();
  });
}

async function newSession() {
  let r;
  try {
    r = await fetch("/api/term", { method: "POST", headers: { "X-RT": "1" }, credentials: "same-origin" });
  } catch {
    return false;
  }
  if (r.status === 401) {
    location.href = "/";
    return false;
  }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) {
    setStatus(j.error || "Could not start a terminal.", "off");
    return false;
  }
  sid = j.sid;
  try { sessionStorage.setItem("rt-sid", sid); } catch {}
  return true;
}

function forgetSession() {
  sid = null;
  try { sessionStorage.removeItem("rt-sid"); } catch {}
}

function scheduleRetry() {
  clearTimeout(retryTimer);
  const delay = Math.min(1000 * 2 ** Math.max(failures - 1, 0), 10000);
  retryTimer = setTimeout(connect, delay);
}

async function connect() {
  clearTimeout(retryTimer);
  if (ended || (ws && ws.readyState <= WebSocket.OPEN)) return;
  if (!sid && !(await newSession())) {
    failures++;
    scheduleRetry();
    return;
  }
  setStatus(failures ? "Reconnecting…" : "Connecting…");
  let opened = false;
  const sock = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/term/ws?s=" + sid);
  sock.binaryType = "arraybuffer";
  ws = sock;
  sock.onopen = () => {
    opened = true;
    failures = 0;
    term.reset();
    setStatus("Connected", "on");
    layout();
  };
  sock.onmessage = (e) => term.write(new Uint8Array(e.data));
  sock.onclose = async (e) => {
    if (ws === sock) ws = null;
    if (opened && e.code === 1000) {
      ended = true;
      forgetSession();
      setStatus("Session ended", "off");
      $("#new").hidden = false;
      return;
    }
    failures++;
    if (!opened && failures >= 2) {
      // The handshake keeps failing: logged out, hibernating, or the session is gone.
      const r = await fetch("/api/state", { headers: { "X-RT": "1" }, credentials: "same-origin" }).catch(() => null);
      if (r && r.status === 401) {
        location.href = "/";
        return;
      }
      const s = r && r.ok ? await r.json().catch(() => null) : null;
      if (s && s.hibernating) {
        setStatus("Hibernating", "off");
      } else {
        forgetSession();
      }
    }
    if (!(statusEl.textContent === "Hibernating")) setStatus("Disconnected, retrying…", "off");
    scheduleRetry();
  };
}

term.onData((data) => {
  if (ctrl && data.length === 1) {
    const c = data.toUpperCase().charCodeAt(0);
    if (c >= 64 && c <= 95) data = String.fromCharCode(c - 64);
    else if (data === " ") data = "\x00";
    setCtrl(false);
  }
  send(data);
});
term.onResize(sendSize);

function setCtrl(on) {
  ctrl = on;
  $('[data-mod="ctrl"]').setAttribute("aria-pressed", String(on));
}

function arrow(dir) {
  const app = term.modes.applicationCursorKeysMode;
  return (app ? "\x1bO" : "\x1b[") + { up: "A", down: "B", right: "C", left: "D" }[dir];
}

async function pressKey(btn) {
  if (btn.dataset.mod === "ctrl") {
    setCtrl(!ctrl);
  } else if (btn.dataset.key) {
    const k = btn.dataset.key;
    send(k === "esc" ? "\x1b" : k === "tab" ? "\t" : arrow(k));
  } else if (btn.dataset.text) {
    term.input(btn.dataset.text);
  } else if ("paste" in btn.dataset) {
    try {
      const text = await navigator.clipboard.readText();
      if (text) term.paste(text);
    } catch {
      setStatus("Paste blocked; long-press the terminal instead", "off");
    }
  }
  term.focus();
}

// Acting on touchstart/mousedown and cancelling it keeps the iOS keyboard open.
for (const btn of document.querySelectorAll("#keys button")) {
  const handler = (e) => {
    e.preventDefault();
    pressKey(btn);
  };
  btn.addEventListener("touchstart", handler, { passive: false });
  btn.addEventListener("mousedown", handler);
}

$("#new").addEventListener("click", () => {
  ended = false;
  failures = 0;
  $("#new").hidden = true;
  term.reset();
  connect();
});

if (window.visualViewport) window.visualViewport.addEventListener("resize", layout);
window.addEventListener("resize", layout);
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) {
    failures = 0;
    connect();
  }
});

layout();
connect();
if (!touch) term.focus();
