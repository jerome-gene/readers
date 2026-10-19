// 닉네임으로 내 기록 파일을 찾아 복호화하고 보여 주는 스크립트
var RBCrypto = (function () {
  var SALT_PREFIX = "dokseo-bbang-v1|"; // private/build.py 와 같아야 해요
  var ITER = 250000;                    // private/build.py 와 같아야 해요
  var subtle = (typeof crypto !== "undefined" ? crypto : require("crypto").webcrypto).subtle;
  var enc = new TextEncoder(), dec = new TextDecoder();
  function norm(s) { return s.normalize("NFC").replace(/\s+/g, "").toLowerCase(); }
  function hex(u8) { return Array.prototype.map.call(u8, function (b) { return ("0" + b.toString(16)).slice(-2); }).join(""); }
  function b64(s) { var bin = atob(s), u = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; }
  async function derive(nick, cid) {
    var base = await subtle.importKey("raw", enc.encode(norm(nick)), "PBKDF2", false, ["deriveBits"]);
    var bits = new Uint8Array(await subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt: enc.encode(SALT_PREFIX + cid), iterations: ITER }, base, 512));
    return { id: hex(bits.slice(0, 16)), key: bits.slice(32, 64) };
  }
  async function open(nick, cid, getJson) {
    var d = await derive(nick, cid);
    var j = await getJson("data/" + cid + "/" + d.id + ".json");
    if (!j || !j.iv || !j.ct) return null;
    try {
      var k = await subtle.importKey("raw", d.key, "AES-GCM", false, ["decrypt"]);
      var pt = await subtle.decrypt({ name: "AES-GCM", iv: b64(j.iv) }, k, b64(j.ct));
      return JSON.parse(dec.decode(pt));
    } catch (e) { return null; }
  }
  return { norm: norm, derive: derive, open: open };
})();
if (typeof module !== "undefined" && module.exports) module.exports = RBCrypto;

if (typeof document !== "undefined") (function () {
  var $ = function (id) { return document.getElementById(id); };
  function el(t, c, x) { var e = document.createElement(t); if (c) e.className = c; if (x !== undefined) e.textContent = x; return e; }
  function getJson(url) {
    return fetch(url, { cache: "no-store" }).then(function (r) {
      if (!r.ok) return null;
      return r.json().catch(function () { return null; });
    }).catch(function () { return null; });
  }
  var cohorts = [], results = {}, uid = 0;
  var tabs = $("mtabs"), panel = $("rec-panel"), nick = $("nick"), msg = $("msg");

  function say(t) { msg.hidden = !t; msg.textContent = t || ""; }

  function entry(en) {
    var f = en.kind === "완독";
    var d = el("div", "entry" + (f ? " fin" : ""));
    var head = [en.kind];
    if (en.week) head.push(en.week);
    if (en.date) head.push(en.date);
    if (en.pages) head.push(en.pages);
    if (f && en.stars) head.push("별점 " + en.stars);
    d.appendChild(el("p", "h", head.join(" · ")));
    if (!f && en.note) d.appendChild(el("p", "", en.note));
    if (f) {
      var s = en.reason || en.comment;
      if (s) d.appendChild(el("p", "", s));
      if (en.review) d.appendChild(el("p", "rv", en.review));
    }
    return d;
  }
  function bookRow(b) {
    var w = el("div", "book"), id = "log" + (uid++);
    var btn = el("button", "bk");
    btn.setAttribute("aria-expanded", "false"); btn.setAttribute("aria-controls", id);
    var left = el("span");
    left.appendChild(el("span", "t", b.title));
    left.appendChild(el("span", "m", b.period + (b.author ? " · " + b.author : "") + " · 인증 " + b.entries.length + "건"));
    btn.appendChild(left);
    btn.appendChild(el("span", "st" + (b.done ? " done" : ""), b.done ? "완독" : "읽는 중"));
    var log = el("div", "log"); log.id = id; log.hidden = true;
    b.entries.forEach(function (en) { log.appendChild(entry(en)); });
    btn.addEventListener("click", function () {
      var open = btn.getAttribute("aria-expanded") === "true";
      btn.setAttribute("aria-expanded", open ? "false" : "true"); log.hidden = open;
    });
    w.appendChild(btn); w.appendChild(log); return w;
  }
  function select(cid) {
    Array.prototype.forEach.call(tabs.children, function (b) {
      b.setAttribute("aria-selected", b.dataset.k === cid ? "true" : "false");
    });
    var c = cohorts.filter(function (x) { return x.id === cid; })[0];
    var p = results[cid];
    panel.textContent = "";
    if (!p) {
      panel.appendChild(el("div", "empty", c.status === "ongoing"
        ? c.label + "는 진행 중이에요. 기수가 끝나면 이곳에 기록이 모여요."
        : "이 기수에는 내 기록이 없어요."));
      return;
    }
    var done = p.books.filter(function (b) { return b.done; }).length;
    var st = el("div", "stat");
    [c.label + " " + c.range, "책 " + p.books.length + "권", "완독 " + done + "권"].forEach(function (t) { st.appendChild(el("span", "chip", t)); });
    panel.appendChild(st);
    var s = el("section", "person");
    p.books.forEach(function (b) { s.appendChild(bookRow(b)); });
    panel.appendChild(s);
  }
  function show() {
    var who = "";
    var latest = null;
    cohorts.forEach(function (c) { if (results[c.id]) { who = results[c.id].name; latest = c.id; } });
    $("who").textContent = who + " 님의 기록";
    tabs.textContent = "";
    cohorts.forEach(function (c) {
      var b = el("button", "", c.label); b.setAttribute("role", "tab"); b.dataset.k = c.id;
      b.addEventListener("click", function () { select(c.id); });
      tabs.appendChild(b);
    });
    $("login").hidden = true; $("mine").hidden = false;
    select(latest);
  }
  function busy(on) { $("go").disabled = on; $("go").textContent = on ? "확인 중…" : "열기"; }
  async function login() {
    var n = nick.value;
    if (!RBCrypto.norm(n)) { say("닉네임을 입력해 주세요."); return; }
    say(""); busy(true);
    try {
      if (!cohorts.length) cohorts = (await getJson("data/cohorts.json")) || [];
      var list = await Promise.all(cohorts.map(function (c) { return RBCrypto.open(n, c.id, getJson); }));
      results = {};
      var any = false;
      cohorts.forEach(function (c, i) { results[c.id] = list[i]; if (list[i]) any = true; });
      if (!any) { say("닉네임을 확인해 주세요. 입력한 닉네임에 해당하는 기록이 없어요."); }
      else show();
    } catch (e) {
      say("기록을 불러오지 못했어요. 주소(https://…)로 열었는지 확인해 주세요.");
    }
    busy(false);
  }
  function logout() {
    results = {}; nick.value = "";
    panel.textContent = ""; tabs.textContent = "";
    $("mine").hidden = true; $("login").hidden = false; say("");
    nick.focus();
  }
  $("go").addEventListener("click", login);
  nick.addEventListener("keydown", function (e) { if (e.key === "Enter") login(); });
  $("peek").addEventListener("click", function () {
    var show = nick.type === "password";
    nick.type = show ? "text" : "password";
    $("peek").textContent = show ? "숨기기" : "보기";
  });
  $("out").addEventListener("click", logout);
})();
