/* Muninn frontend — vanilla JS (no framework, no build step, no CDN).
   api client + app state + hash router + renderers for the three-pane console and
   the insights dashboard. Everything degrades honestly if a backend is unreachable. */

"use strict";

/* ---- api client (concrete) ------------------------------------------------ */
const api = {
  // Mutating requests echo the JS-readable muninn_csrf cookie as X-CSRF-Token
  // (double-submit). The HttpOnly session cookie rides along via fetch's default
  // same-origin credentials — do NOT set credentials:"include".
  // Supabase mode: the persisted access token goes out as Authorization: Bearer —
  // the server validates it directly (no cookie, no CSRF in that mode).
  _authHeaders(h) {
    if (window.Auth && Auth.accessToken && Auth.accessToken()) {
      h["Authorization"] = `Bearer ${Auth.accessToken()}`;
    }
    return h;
  },
  _mutHeaders() {
    const h = { "Content-Type": "application/json", "Accept": "application/json" };
    const csrf = window.Auth && Auth.csrf();
    if (csrf) h["X-CSRF-Token"] = csrf;
    return this._authHeaders(h);
  },
  async get(path) {
    const r = await fetch(path, { headers: this._authHeaders({ "Accept": "application/json" }) });
    return this._json(r);
  },
  // True only for a 403 caused by a stale/invalid CSRF token — NOT an RBAC denial (which carries
  // a different message), so least-privilege 403s are never masked or retried.
  _isCsrfError(err) {
    return !!(err && err.status === 403 && /csrf/i.test(err.message || ""));
  },
  async _send(method, path, body) {
    const once = async () => {
      const r = await fetch(path, {
        method, headers: this._mutHeaders(), body: JSON.stringify(body || {}),
      });
      return this._json(r);
    };
    try {
      return await once();
    } catch (e) {
      // A stale-CSRF 403 usually means the server was restarted under an open tab. Re-establish
      // the session once and retry so a live run never surfaces the raw token error. _mutHeaders()
      // re-reads the now-fresh muninn_csrf cookie on the retry.
      if (this._isCsrfError(e) && window.Auth && Auth.reauth && (await Auth.reauth())) {
        return await once();
      }
      throw e;
    }
  },
  async post(path, body) { return this._send("POST", path, body); },
  async patch(path, body) { return this._send("PATCH", path, body); },
  async _json(r) {
    let data = null;
    try { data = await r.json(); } catch (_) { /* empty/non-json */ }
    if (!r.ok) {
      // A 401 here means the session lapsed mid-app (boot uses auth.js's own fetch,
      // so this never fires during the login gate) — bounce back to the auth screen.
      if (r.status === 401 && window.Auth) Auth.onUnauthorized();
      const msg = (data && (data.message || data.error)) || `HTTP ${r.status}`;
      const err = new Error(msg); err.status = r.status; err.data = data; throw err;
    }
    return data;
  },
  /* SSE for GET /api/triage/stream. Server emits named events (token/done/error).
     Returns the EventSource so callers can close it. */
  stream(path, { onToken, onDone, onError } = {}) {
    const es = new EventSource(path);
    es.addEventListener("token", (e) => {
      if (!onToken) return;
      try { onToken(JSON.parse(e.data).t); } catch (_) { onToken(e.data); }
    });
    es.addEventListener("done", (e) => {
      es.close();
      if (!onDone) return;
      try { onDone(JSON.parse(e.data)); } catch (_) { onDone(null); }
    });
    es.addEventListener("error", (e) => {
      es.close();
      if (onError) onError(e && e.data ? e.data : e);
    });
    return es;
  },
};

/* ---- app state ------------------------------------------------------------ */
const state = {
  incidents: [],
  selectedId: null,
  useMemory: true,   // Cold(false) <-> Warm(true) — the hero toggle
  brief: null,
  recall: null,
  health: null,
  queueFilter: { q: "", severity: "", service: "" },  // client-side queue narrowing
};

/* ---- tiny helpers --------------------------------------------------------- */
const $ = (sel) => document.querySelector(sel);
const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };
let _toastTimer = null;
function toast(msg) {
  const t = $("#toast"); t.textContent = msg; t.hidden = false;
  // Give longer messages more reading time (~200 wpm), clamped to a sane window.
  const ms = Math.min(8000, Math.max(3200, msg.length * 55));
  clearTimeout(_toastTimer); _toastTimer = setTimeout(() => (t.hidden = true), ms);
}
const sevNum = (sev) => ({ SEV1: 1, SEV2: 2, SEV3: 3 }[sev] || 3);
const pct = (x) => `${Math.round((Number(x) || 0) * 100)}%`;
function ago(ms) {
  if (!ms) return "";
  const s = Math.max(0, (Date.now() - ms) / 1000);
  if (s < 90) return `${Math.round(s)}s ago`;
  const m = s / 60; if (m < 90) return `${Math.round(m)}m ago`;
  const h = m / 60; if (h < 36) return `${Math.round(h)}h ago`;
  return `${Math.round(h / 24)}d ago`;
}
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

/* ---- health boot (concrete) ---------------------------------------------- */
async function bootHealth() {
  const wrap = $("#health");
  const set = (role, text, live) => {
    const b = wrap.querySelector(`[data-role="${role}"]`);
    if (!b) return;
    b.querySelector("b").textContent = text;
    b.classList.toggle("is-live", live === true);
    b.classList.toggle("is-local", live === false);
  };
  try {
    const h = await api.get("/api/health");
    state.health = h;
    set("memory", h.memory_backend || "?", (h.memory_backend === "hindsight"));
    set("llm", h.llm_backend || "?", (h.llm_backend === "groq"));
    set("count", String(h.n_memories ?? "—"));
  } catch (e) {
    // health endpoint not implemented yet (501) or backend down — stay honest, not broken
    set("memory", "offline"); set("llm", "offline"); set("count", "—");
  }
}

/* ---- view router (concrete) ---------------------------------------------- */
function router() {
  // "#/console" -> "console", "#/home"/"#home"/"#"/"" -> landing. Strip the leading
  // "#" and an optional "/" so both "#/x" and "#x" forms resolve the same way.
  let view = (location.hash.replace(/^#\/?/, "") || "home");
  // Users is admin-only — never route a non-admin into it (server 403s anyway).
  if (view === "users" && !(window.Auth && Auth.can("users"))) view = "console";
  const isLanding = view === "home" || view === "landing";
  const isInsights = view === "insights";
  const isUsers = view === "users";
  const isConsole = !isLanding && !isInsights && !isUsers;
  // body.on-landing hides the app statusbar and lets the landing's own nav take over.
  document.body.classList.toggle("on-landing", isLanding);
  const vLanding = $("#view-landing"); if (vLanding) vLanding.hidden = !isLanding;
  $("#view-console").hidden = !isConsole;
  $("#view-insights").hidden = !isInsights;
  $("#view-users").hidden = !isUsers;
  document.querySelectorAll(".viewlink").forEach((a) => {
    a.setAttribute("aria-current", a.dataset.view === view ? "page" : "false");
  });
  // Landing-only motion is owned by landing.js; enter/leave start & stop particles +
  // scroll-reveal so nothing animates (or holds listeners) while the console is up.
  if (window.MuninnLanding) { isLanding ? MuninnLanding.enter() : MuninnLanding.leave(); }
  if (isInsights) renderInsights();
  if (isUsers) renderUsers();
}

/* ---- render functions ----------------------------------------------------- */
// renderQueue(): GET /api/incidents -> toolbar (search + severity/service facets)
// over a listbox of dense incident rows. The toolbar persists across data refreshes;
// typing/filtering only re-renders the row list (renderQueueList), so focus is kept.
async function renderQueue() {
  const box = $("#queue");
  clear(box);
  box.appendChild(el("p", "q-empty", "Loading incidents…"));  // honest loading state
  try {
    const data = await api.get("/api/incidents");
    state.incidents = data.incidents || [];
  } catch (e) {
    clear(box); box.appendChild(el("p", "q-empty", "Queue unavailable.")); return;
  }
  clear(box);
  if (!state.incidents.length) {
    box.appendChild(el("p", "q-empty", "No incidents yet — seed the demo dataset."));
    return;
  }
  box.appendChild(buildQueueToolbar());
  const list = el("div", "q-list"); list.id = "queue-list";
  list.setAttribute("role", "listbox");
  list.setAttribute("aria-label", "Incidents");
  box.appendChild(list);
  renderQueueList();
}

// Search box + severity/service facets. Values are seeded from state.queueFilter so a
// data refresh (seed/resolve) doesn't drop the user's narrowing.
function buildQueueToolbar() {
  const bar = el("div", "q-toolbar");
  const f = state.queueFilter;

  const search = el("input", "field q-search");
  search.type = "search"; search.id = "q-search";
  search.placeholder = "Search incidents…";
  search.setAttribute("aria-label", "Search incidents");
  search.value = f.q;
  search.addEventListener("input", () => { f.q = search.value; renderQueueList(); });
  bar.appendChild(search);

  const facets = el("div", "q-facets");
  const sevSel = el("select", "field q-facet");
  sevSel.setAttribute("aria-label", "Filter by severity");
  [["", "All severities"], ["SEV1", "SEV1"], ["SEV2", "SEV2"], ["SEV3", "SEV3"]]
    .forEach(([v, t]) => { const o = el("option", null, t); o.value = v; sevSel.appendChild(o); });
  sevSel.value = f.severity;
  sevSel.addEventListener("change", () => { f.severity = sevSel.value; renderQueueList(); });
  facets.appendChild(sevSel);

  const svcSel = el("select", "field q-facet");
  svcSel.setAttribute("aria-label", "Filter by service");
  const allOpt = el("option", null, "All services"); allOpt.value = "";
  svcSel.appendChild(allOpt);
  const services = [...new Set(state.incidents.map((i) => i.service).filter(Boolean))].sort();
  services.forEach((s) => { const o = el("option", null, s); o.value = s; svcSel.appendChild(o); });
  if (!services.includes(f.service)) f.service = "";
  svcSel.value = f.service;
  svcSel.addEventListener("change", () => { f.service = svcSel.value; renderQueueList(); });
  facets.appendChild(svcSel);

  bar.appendChild(facets);
  return bar;
}

function _filteredIncidents() {
  const f = state.queueFilter;
  const q = f.q.trim().toLowerCase();
  return state.incidents.filter((inc) => {
    if (f.severity && inc.severity !== f.severity) return false;
    if (f.service && inc.service !== f.service) return false;
    if (q) {
      const hay = `${inc.title} ${inc.service} ${inc.external_id} ${inc.symptom || ""} ${(inc.tags || []).join(" ")}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

// Rows only — the toolbar stays put. Listbox with roving tabindex + arrow-key nav.
function renderQueueList() {
  const list = $("#queue-list");
  if (!list) return;
  clear(list);
  const rows = _filteredIncidents().sort((a, b) =>   // open first, then most-recent
    (a.status === "resolved") - (b.status === "resolved") || b.created_at - a.created_at);
  if (!rows.length) {
    list.appendChild(el("p", "q-empty", "No incidents match your filters."));
    return;
  }
  // roving tabindex target: the selected row if visible, else the first row
  const activeId = rows.some((r) => r.id === state.selectedId) ? state.selectedId : rows[0].id;
  rows.forEach((inc) => {
    const row = el("div", "q-row");
    row.setAttribute("role", "option");
    row.setAttribute("aria-selected", String(inc.id === state.selectedId));
    row.tabIndex = (inc.id === activeId) ? 0 : -1;
    row.dataset.id = inc.id;
    row.appendChild(el("span", `q-sev sev-${sevNum(inc.severity)}`));
    const mid = el("div", "q-mid");
    mid.appendChild(el("div", "q-title", inc.title));
    mid.appendChild(el("div", "q-svc", `${inc.external_id} · ${inc.service}`));
    row.appendChild(mid);
    const right = el("div", "q-right");
    right.appendChild(el("div", "q-age", ago(inc.created_at)));
    if (inc.status === "resolved") right.appendChild(el("span", "q-badge resolved", "resolved"));
    row.appendChild(right);
    row.addEventListener("click", () => selectIncident(inc.id));
    row.addEventListener("keydown", _queueKeydown);
    list.appendChild(row);
  });
}

// Listbox keyboard model: Up/Down/Home/End move focus (roving tabindex), Enter/Space
// selects the focused row.
function _queueKeydown(e) {
  const row = e.currentTarget;
  const items = Array.prototype.slice.call(row.parentNode.querySelectorAll(".q-row"));
  const i = items.indexOf(row);
  let next = -1;
  if (e.key === "ArrowDown") next = Math.min(items.length - 1, i + 1);
  else if (e.key === "ArrowUp") next = Math.max(0, i - 1);
  else if (e.key === "Home") next = 0;
  else if (e.key === "End") next = items.length - 1;
  else if (e.key === "Enter" || e.key === " ") { e.preventDefault(); selectIncident(Number(row.dataset.id)); return; }
  else return;
  e.preventDefault();
  if (next < 0 || next === i) return;
  items.forEach((n, k) => { n.tabIndex = k === next ? 0 : -1; });
  items[next].focus();
}

async function selectIncident(id) {
  state.selectedId = id;
  state.brief = null; state.recall = null;
  document.querySelectorAll(".q-row").forEach((r) => {
    const on = Number(r.dataset.id) === id;
    r.setAttribute("aria-selected", String(on));
    r.tabIndex = on ? 0 : -1;
  });
  await renderActive();
  renderRecall(null);
}

// renderActive(): GET /api/incidents/{id}; render header + Cold/Warm toggle + brief mount.
async function renderActive() {
  const host = $("#active");
  if (!state.selectedId) return;
  let inc, timeline = [];
  try {
    const data = await api.get(`/api/incidents/${state.selectedId}`);
    inc = data.incident; timeline = data.timeline || [];
  } catch (e) { toast(`Could not load incident: ${e.message}`); return; }
  state.active = inc;
  host.className = "active";
  clear(host);

  const head = el("div", "incident-head");
  const h = el("h2", null, inc.title);
  head.appendChild(h);
  head.appendChild(el("div", "incident-meta",
    `${inc.external_id} · ${inc.service} · ${inc.severity} · ${inc.status}`));
  head.appendChild(el("div", "sig mono", inc.error_signature || inc.symptom));
  host.appendChild(head);

  // HERO toggle: Cold (memory OFF) <-> Warm (memory ON)
  const toggle = el("div", "toggle");
  toggle.setAttribute("role", "group");
  toggle.setAttribute("aria-label", "Memory mode");
  const mk = (mode, label, sub) => {
    const b = el("button", null); b.dataset.mode = mode;
    b.setAttribute("aria-pressed", String((mode === "warm") === state.useMemory));
    b.appendChild(el("span", null, label));
    b.appendChild(el("span", "sub", sub));
    b.addEventListener("click", () => {
      state.useMemory = (mode === "warm");
      toggle.querySelectorAll("button").forEach((x) =>
        x.setAttribute("aria-pressed", String(x.dataset.mode === mode)));
    });
    return b;
  };
  toggle.appendChild(mk("cold", "Cold", "memory OFF"));
  toggle.appendChild(mk("warm", "Warm", "memory ON"));

  const actions = el("div", "active-actions");
  actions.appendChild(toggle);
  if (window.Auth && Auth.can("triage")) {
    const run = el("button", "btn", "Run triage");
    run.addEventListener("click", runTriage);
    actions.appendChild(run);
    const cmp = el("button", "btn btn-ghost", "Compare cold vs warm");
    cmp.addEventListener("click", renderCompare);
    actions.appendChild(cmp);
  } else {
    // Read-only analysis (triage/compare) is a viewer capability now, so any signed-in
    // account reaches the buttons above; this only shows if the session lapsed.
    actions.appendChild(el("span", "role-note", "Sign in to run triage."));
  }
  host.appendChild(actions);

  const mount = el("div", "brief-mount"); mount.id = "brief-mount";
  host.appendChild(mount);

  if (inc.status === "resolved") {
    host.appendChild(renderResolution(inc));
  } else if (window.Auth && Auth.can("mutate")) {
    host.appendChild(renderResolveForm(inc));
  }

  if (timeline.length) {
    const tl = el("div", "timeline");
    tl.appendChild(el("h3", "tl-head", "Timeline"));
    for (const ev of timeline) {
      const item = el("div", "tl-row");
      item.appendChild(el("span", "tl-kind mono", ev.kind));
      item.appendChild(el("span", "tl-msg", ev.message || ""));
      tl.appendChild(item);
    }
    host.appendChild(tl);
  }
}

// The exact recall query the backend builds (Incident.signature_text). Keeping the
// client in lockstep means the recall pane shows the SAME memories the warm brief
// cited, so citation chips (id == memory.source) always resolve to a visible row (S11).
function signatureText(inc) {
  if (!inc) return "";
  const tags = (inc.tags || []).join(", ");
  return `${inc.service}: ${inc.symptom} (${inc.error_signature || ""}). ${inc.title}. tags: ${tags}`;
}

// runTriage(): stream GET /api/triage/stream token-by-token for a live "thinking"
// reveal, then render the structured brief on `done`. Falls back to POST /api/triage
// when EventSource is unavailable or the stream errors before completing — so the demo
// never breaks. Only responders reach here (the button is role-gated), and EventSource
// sends the same-origin session cookie automatically (GET needs no CSRF header).
function runTriage() {
  if (!state.selectedId) return;
  const mount = $("#brief-mount");
  if (!mount) return;
  const useMem = state.useMemory;
  clear(mount);
  mount.appendChild(el("p", "thinking", "Muninn is thinking…"));
  if (window.EventSource) _streamTriage(useMem, mount);
  else postTriage(useMem, mount);
}

function _streamTriage(useMem, mount) {
  let settled = false;
  let buf = "";
  const live = el("pre", "stream-live");
  live.setAttribute("aria-live", "polite");
  const url = `/api/triage/stream?incident_id=${encodeURIComponent(state.selectedId)}` +
    `&use_memory=${useMem ? "true" : "false"}`;
  // EventSource cannot set an Authorization header: in Supabase mode the access token
  // rides in the query string (the only authenticated SSE consumer; see router auth note).
  const streamUrl = (window.Auth && Auth.accessToken && Auth.accessToken())
    ? `${url}&access_token=${encodeURIComponent(Auth.accessToken())}` : url;
  api.stream(streamUrl, {
    onToken(t) {
      if (settled) return;
      if (!live.isConnected) { clear(mount); mount.appendChild(live); }
      buf += t;
      live.textContent = buf;
    },
    onDone(brief) {
      if (settled) return;
      settled = true;
      if (!brief) { postTriage(useMem, mount); return; }  // malformed frame -> re-run
      state.brief = brief;
      renderBrief(brief);
      if (useMem && state.active) {
        api.post("/api/memory/recall", { query: signatureText(state.active), top_k: 5 })
          .then((rc) => { state.recall = rc; renderRecall(rc); })
          .catch(() => renderRecall(null));
      } else {
        state.recall = null;
        renderRecall(null);
      }
    },
    onError() {
      if (settled) return;
      settled = true;
      postTriage(useMem, mount);  // stream never completed -> plain request
    },
  });
}

// Non-streaming path: one POST returns brief AND the recall from the same run, so
// citations and recall rows are inherently aligned.
async function postTriage(useMem, mount) {
  try {
    const out = await api.post("/api/triage",
      { incident_id: state.selectedId, use_memory: useMem });
    state.brief = out.brief; state.recall = out.recall;
    renderBrief(out.brief);
    renderRecall(out.recall);
  } catch (e) {
    if (mount) { clear(mount); mount.appendChild(el("p", "thinking", `Triage failed: ${e.message}`)); }
  }
}

// renderBrief(brief): root cause, steps, runbook, citation chips linked to recall rows.
function renderBrief(brief, mountSel) {
  const mount = mountSel ? $(mountSel) : $("#brief-mount");
  if (!mount) return;
  clear(mount);
  if (!brief) return;
  const card = el("div", `brief ${brief.memory_used ? "is-warm" : "is-cold"}`);

  const top = el("div", "brief-top");
  top.appendChild(el("span", "brief-mode", brief.memory_used ? "WARM · memory on" : "COLD · memory off"));
  top.appendChild(el("span", "brief-conf mono", `confidence ${pct(brief.confidence)}`));
  card.appendChild(top);

  card.appendChild(el("p", "brief-summary", brief.summary || "—"));

  const rc = el("div", "brief-rc");
  rc.appendChild(el("h3", null, "Root-cause hypothesis"));
  rc.appendChild(el("p", null, brief.root_cause_hypothesis || "insufficient signal"));
  card.appendChild(rc);

  if ((brief.remediation_steps || []).length) {
    const steps = el("div", "brief-steps");
    steps.appendChild(el("h3", null, "Recommended remediation"));
    const ol = el("ol");
    for (const s of brief.remediation_steps) ol.appendChild(el("li", null, s));
    steps.appendChild(ol);
    card.appendChild(steps);
  }

  if (brief.runbook_ref) {
    const rb = el("div", "brief-rb");
    rb.appendChild(el("span", "label", "Runbook: "));
    rb.appendChild(el("span", "mono", brief.runbook_ref));
    card.appendChild(rb);
  }

  if ((brief.citations || []).length) {
    const cites = el("div", "brief-cites");
    cites.appendChild(el("span", "label", "Citations: "));
    for (const c of brief.citations) {
      const chip = el("button", "cite", `${c.id}${c.score != null ? " · " + pct(c.score) : ""}`);
      chip.title = c.excerpt || "recalled incident";
      chip.addEventListener("click", () => highlightRecall(c.id));
      cites.appendChild(chip);
    }
    card.appendChild(cites);
  } else if (!brief.memory_used) {
    card.appendChild(el("p", "brief-nocite", "No citations — memory is OFF (cold start)."));
  }

  if (brief.reflection) {
    const ref = el("div", "brief-reflection");
    ref.appendChild(el("h3", null, "Cross-incident reflection"));
    ref.appendChild(el("p", null, brief.reflection));
    card.appendChild(ref);
  }

  const prov = el("div", "brief-prov mono");
  prov.textContent = `memory: ${brief.memory_backend} · llm: ${brief.llm_backend} · ${brief.latency_ms}ms`;
  card.appendChild(prov);

  mount.appendChild(card);
}

// renderRecall(recall): recalled incidents w/ scores into #memory; hit-highlight.
function renderRecall(recall) {
  const box = $("#memory");
  clear(box);
  const mems = (recall && recall.memories) || [];
  if (!mems.length) {
    box.appendChild(el("p", "recall-empty",
      recall ? "No prior memories matched (cold start)." :
        "Run triage to recall what Muninn has seen before."));
    return;
  }
  for (const m of mems) {
    const row = el("div", `recall-row ${m.score >= 0.35 ? "is-hit" : ""}`);
    row.dataset.source = m.source || "";
    const head = el("div", "recall-head");
    head.appendChild(el("span", "score mono", pct(m.score)));
    head.appendChild(el("span", "provenance", `${m.source || "?"} · ${m.type}`));
    row.appendChild(head);
    row.appendChild(el("p", "recall-content", (m.content || "").slice(0, 320)));
    box.appendChild(row);
  }
}

function highlightRecall(source) {
  document.querySelectorAll(".recall-row").forEach((r) => {
    const on = r.dataset.source === source;
    r.classList.toggle("is-focus", on);
    if (on) r.scrollIntoView({ block: "nearest", behavior: "smooth" });
  });
}

// renderCompare(): POST /api/compare -> cold vs warm briefs side by side (centerpiece).
async function renderCompare() {
  if (!state.selectedId) return;
  const mount = $("#brief-mount");
  if (mount) { clear(mount); mount.appendChild(el("p", "thinking", "Running both cold and warm…")); }
  try {
    const out = await api.post("/api/compare", { incident_id: state.selectedId });
    clear(mount);
    const split = el("div", "compare");
    const coldCol = el("div", "compare-col"); coldCol.id = "cmp-cold";
    const warmCol = el("div", "compare-col"); warmCol.id = "cmp-warm";
    split.appendChild(coldCol); split.appendChild(warmCol);
    mount.appendChild(split);
    renderBrief(out.cold, "#cmp-cold");
    renderBrief(out.warm, "#cmp-warm");
    // Recall pane reflects the warm run. Query with the SAME signature_text the backend
    // recalls on, so the warm brief's citations (id == memory.source) line up with the
    // rows shown here and clicking a chip highlights a visible memory (S11).
    const rc = await api.post("/api/memory/recall",
      { query: signatureText(state.active), top_k: 5 })
      .catch(() => null);
    renderRecall(rc);
  } catch (e) {
    if (mount) { clear(mount); mount.appendChild(el("p", "thinking", `Compare failed: ${e.message}`)); }
  }
}

function renderResolveForm(inc) {
  const form = el("form", "resolve-form");
  form.appendChild(el("h3", null, "Resolve & remember"));
  const field = (id, labelText, ph, required) => {
    const row = el("div", "form-row");
    const label = el("label", null, labelText); label.htmlFor = id;
    const input = el("input", "field");
    input.id = id; input.name = id; input.placeholder = ph;
    if (required) input.required = true;
    row.appendChild(label); row.appendChild(input);
    form.appendChild(row);
    return input;
  };
  const rc = field("resolve-root-cause", "Root cause", "e.g. connection pool exhausted", true);
  const steps = field("resolve-steps", "Remediation steps", "comma-separated", false);
  const who = field("resolve-resolver", "Resolver", "e.g. oncall", false);
  const submit = el("button", "btn", "Resolve & retain to memory");
  submit.type = "submit";
  form.appendChild(submit);
  form.addEventListener("submit", (e) => { e.preventDefault(); resolveAndRemember(inc.id, {
    root_cause: rc.value.trim(),
    remediation_steps: steps.value.split(",").map((s) => s.trim()).filter(Boolean),
    resolver: who.value.trim() || "oncall",
  }); });
  return form;
}

function renderResolution(inc) {
  const box = el("div", "resolution");
  box.appendChild(el("h3", null, "Resolution"));
  box.appendChild(el("p", "res-rc", inc.root_cause || "—"));
  if ((inc.remediation_steps || []).length) {
    const ol = el("ol");
    for (const s of inc.remediation_steps) ol.appendChild(el("li", null, s));
    box.appendChild(ol);
  }
  const meta = el("div", "res-meta mono");
  meta.textContent = `resolver: ${inc.resolver || "—"}` +
    (inc.mttr_minutes != null ? ` · MTTR ${inc.mttr_minutes}m` : "");
  box.appendChild(meta);
  box.appendChild(el("p", "res-note", "✓ Retained to memory — future incidents will recall this."));
  return box;
}

// resolveAndRemember(): POST /api/incidents/{id}/resolve -> toast + bump memory count.
async function resolveAndRemember(id, payload) {
  if (!payload.root_cause) { toast("Root cause is required."); return; }
  try {
    await api.post(`/api/incidents/${id}/resolve`, payload);
    toast("Resolved — retained to memory.");
    await renderQueue();
    await renderActive();
    bootHealth();
  } catch (e) { toast(`Resolve failed: ${e.message}`); }
}

// renderInsights(): GET /api/metrics/summary -> stat cards + MTTR + learning-curve charts.
async function renderInsights() {
  const host = $("#insights");
  clear(host);
  let s;
  try { s = await api.get("/api/metrics/summary"); }
  catch (e) { host.appendChild(el("p", null, `Metrics unavailable: ${e.message}`)); return; }

  const stats = el("div", "stat-cards");
  const card = (label, val) => { const c = el("div", "stat"); c.appendChild(el("div", "stat-val mono", String(val))); c.appendChild(el("div", "stat-label", label)); return c; };
  stats.appendChild(card("mean MTTR (min)", (s.mttr && s.mttr.overall_min) || 0));
  stats.appendChild(card("incidents", s.n_incidents || 0));
  stats.appendChild(card("resolved", s.n_resolved || 0));
  stats.appendChild(card("memories", s.n_memories || 0));
  host.appendChild(stats);

  const grid = el("div", "chart-grid");
  const byService = (s.mttr && s.mttr.by_service) || {};
  const series = s.learning_curve || [];

  const mttrCard = el("div", "chart-card");
  mttrCard.appendChild(el("h3", null, "MTTR by service (min)"));
  const c1 = el("canvas"); mttrCard.appendChild(c1);
  mttrCard.appendChild(_chartLegend([{ label: "MTTR (min)", color: CHART.warm }]));
  mttrCard.appendChild(_mttrTable(byService));   // sr-only tabular fallback
  grid.appendChild(mttrCard);

  const lcCard = el("div", "chart-card");
  lcCard.appendChild(el("h3", null, "Learning curve — recall quality as memory grows"));
  const c2 = el("canvas"); lcCard.appendChild(c2);
  lcCard.appendChild(_chartLegend([
    { label: "Top match score", color: CHART.warm },
    { label: "Cumulative coverage", color: CHART.cold },
  ]));
  lcCard.appendChild(_lcTable(series));
  grid.appendChild(lcCard);
  host.appendChild(grid);

  // canvases must be laid out (in the DOM, view visible) before we size to clientWidth
  drawBarChart(c1, byService);
  drawLearningCurve(c2, series);
}

// seedDemo(): POST /api/demo/seed -> reload queue + health. resetDemo(): POST /api/demo/reset.
async function seedDemo() {
  try {
    const r = await api.post("/api/demo/seed");
    toast(`Seeded ${r.seeded.incidents} synthetic incidents.`);
    await renderQueue();
    if (!state.selectedId) renderEmptyActive();   // refresh the "select an incident" state
    bootHealth();
  } catch (e) { toast(`Seed failed: ${e.message}`); }
}

/* ---- canvas charts (no chart lib) ----------------------------------------- */
const CHART = { ink: "#141414", muted: "#525252", line: "#DEE5F0", warm: "#F15534", cold: "#3D3D3D" };

// Size the backing store to devicePixelRatio so charts stay crisp on HiDPI displays,
// then scale the context so drawing code works in CSS pixels. Returns logical W/H.
function hidpiCtx(canvas) {
  const cssW = canvas.clientWidth || 520;
  const cssH = Math.round(cssW * 0.5);   // 2:1 aspect
  const dpr = window.devicePixelRatio || 1;
  canvas.width = Math.round(cssW * dpr);
  canvas.height = Math.round(cssH * dpr);
  canvas.style.height = cssH + "px";     // CSS width:100% governs display width
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return { ctx, W: cssW, H: cssH };
}

// Screen-reader tabular fallbacks for the canvases (visually hidden via .sr-only).
function _srTable(caption, headers, rows) {
  const wrap = el("div", "sr-only");
  const table = el("table");
  table.appendChild(el("caption", null, caption));
  const htr = el("tr");
  headers.forEach((h) => { const th = el("th", null, h); th.scope = "col"; htr.appendChild(th); });
  const thead = el("thead"); thead.appendChild(htr); table.appendChild(thead);
  const tbody = el("tbody");
  rows.forEach((r) => {
    const tr = el("tr");
    r.forEach((cell) => tr.appendChild(el("td", null, String(cell))));
    tbody.appendChild(tr);
  });
  table.appendChild(tbody); wrap.appendChild(table);
  return wrap;
}
function _mttrTable(byService) {
  const rows = Object.entries(byService).sort((a, b) => b[1] - a[1]).map(([svc, v]) => [svc, v]);
  return _srTable("MTTR by service (minutes)", ["Service", "MTTR (min)"],
    rows.length ? rows : [["No data yet", "—"]]);
}
function _lcTable(series) {
  const rows = series.map((p, i) => [i + 1, p.n_memories, pct(p.avg_top_score), pct(p.coverage)]);
  return _srTable("Learning curve — recall quality as memory grows",
    ["Step", "Memories", "Top match", "Coverage"],
    rows.length ? rows : [["—", "—", "—", "—"]]);
}

function drawBarChart(canvas, byService) {
  const { ctx, W, H } = hidpiCtx(canvas);
  const pad = 34;
  ctx.clearRect(0, 0, W, H);
  ctx.textBaseline = "alphabetic";   // explicit: labels sit on their baselines
  const entries = Object.entries(byService).sort((a, b) => b[1] - a[1]).slice(0, 8);
  canvas.setAttribute("role", "img");
  canvas.setAttribute("aria-label", entries.length
    ? "Bar chart, MTTR by service in minutes: " + entries.map(([k, v]) => `${k} ${v}`).join(", ")
    : "Bar chart, MTTR by service: no data yet.");
  if (!entries.length) { _emptyChart(ctx, W, H); return; }
  const max = Math.max(...entries.map((e) => e[1]), 1);
  const bw = (W - pad * 2) / entries.length;
  ctx.strokeStyle = CHART.line; ctx.beginPath();
  ctx.moveTo(pad, H - pad); ctx.lineTo(W - pad, H - pad); ctx.stroke();
  entries.forEach(([svc, val], i) => {
    const h = (val / max) * (H - pad * 2);
    const x = pad + i * bw + bw * 0.15, w = bw * 0.7, y = H - pad - h;
    ctx.fillStyle = CHART.warm; ctx.fillRect(x, y, w, h);
    ctx.fillStyle = CHART.ink; ctx.font = "11px ui-monospace, monospace"; ctx.textAlign = "center";
    ctx.fillText(String(val), x + w / 2, y - 4);
    ctx.fillStyle = CHART.muted;
    ctx.fillText(svc.length > 10 ? svc.slice(0, 9) + "…" : svc, x + w / 2, H - pad + 14);
  });
}

function drawLearningCurve(canvas, series) {
  const { ctx, W, H } = hidpiCtx(canvas);
  const pad = 34;
  ctx.clearRect(0, 0, W, H);
  canvas.setAttribute("role", "img");
  if (!series.length) {
    canvas.setAttribute("aria-label", "Line chart, learning curve: no data yet.");
    _emptyChart(ctx, W, H); return;
  }
  const last = series[series.length - 1];
  canvas.setAttribute("aria-label",
    `Line chart of recall quality as memory grows over ${series.length} incidents. ` +
    `Final top-match score ${pct(last.avg_top_score)}, cumulative coverage ${pct(last.coverage)}.`);
  // axes
  ctx.strokeStyle = CHART.line; ctx.beginPath();
  ctx.moveTo(pad, pad); ctx.lineTo(pad, H - pad); ctx.lineTo(W - pad, H - pad); ctx.stroke();
  const n = series.length;
  const X = (i) => pad + (n === 1 ? 0 : (i / (n - 1)) * (W - pad * 2));
  const Y = (v) => H - pad - v * (H - pad * 2);   // v in [0,1]
  const plot = (key, color) => {
    ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.beginPath();
    series.forEach((p, i) => {
      const v = Math.max(0, Math.min(1, Number(p[key]) || 0));
      i === 0 ? ctx.moveTo(X(i), Y(v)) : ctx.lineTo(X(i), Y(v));
    });
    ctx.stroke();
    ctx.fillStyle = color;
    series.forEach((p, i) => {
      const v = Math.max(0, Math.min(1, Number(p[key]) || 0));
      ctx.beginPath(); ctx.arc(X(i), Y(v), 2.5, 0, Math.PI * 2); ctx.fill();
    });
  };
  plot("coverage", CHART.cold);
  plot("avg_top_score", CHART.warm);
  // Legend lives OUTSIDE the plot as DOM chips beneath the canvas (see _chartLegend in
  // renderInsights) so it never paints over the lines at narrow widths / high DPR.
}

function _emptyChart(ctx, W, H) {
  ctx.fillStyle = CHART.muted; ctx.font = "13px system-ui";
  ctx.textAlign = "center"; ctx.textBaseline = "middle";   // explicit: message centered in the box
  ctx.fillText("Seed the demo dataset to populate metrics.", W / 2, H / 2);
}

// Chart legend as DOM chips (kept OUT of the canvas plot). Decorative color key only:
// the canvas aria-label + the .sr-only data table carry the numbers for assistive tech.
function _chartLegend(items) {
  const wrap = el("div", "chart-legend");
  wrap.setAttribute("aria-hidden", "true");
  items.forEach(({ label, color }) => {
    const item = el("span", "legend-item");
    const dot = el("span", "legend-dot"); dot.style.background = color;
    item.appendChild(dot);
    item.appendChild(el("span", "legend-label", label));
    wrap.appendChild(item);
  });
  return wrap;
}

/* ---- new-incident form ---------------------------------------------------- */
// Inline labeled form in the active pane — replaces the old window.prompt chain
// (which is unlabelled, unstyled, and blocks the thread).
function newIncident() {
  const host = $("#active");
  if (!host) return;
  host.className = "active";
  clear(host);
  const form = el("form", "inline-form");
  form.setAttribute("aria-label", "New incident");
  form.appendChild(el("h2", null, "New incident"));

  const field = (id, labelText, ph, required) => {
    const row = el("div", "form-row");
    const label = el("label", null, labelText); label.htmlFor = id;
    const input = el("input", "field");
    input.id = id; input.name = id; input.placeholder = ph || "";
    if (required) input.required = true;
    row.appendChild(label); row.appendChild(input);
    form.appendChild(row);
    return input;
  };
  const title = field("ni-title", "Title", "e.g. Checkout latency spike", true);
  const service = field("ni-service", "Service", "e.g. checkout-api", true);
  service.value = "checkout-api";

  const sevRow = el("div", "form-row");
  const sevLabel = el("label", null, "Severity"); sevLabel.htmlFor = "ni-severity";
  const sev = el("select", "field"); sev.id = "ni-severity"; sev.name = "ni-severity";
  ["SEV1", "SEV2", "SEV3"].forEach((v) => { const o = el("option", null, v); o.value = v; sev.appendChild(o); });
  sevRow.appendChild(sevLabel); sevRow.appendChild(sev); form.appendChild(sevRow);

  const symptom = field("ni-symptom", "Symptom", "what's observed", false);

  const actions = el("div", "form-actions");
  const submit = el("button", "btn", "Create incident"); submit.type = "submit";
  const cancel = el("button", "btn btn-ghost", "Cancel"); cancel.type = "button";
  cancel.addEventListener("click", () => state.selectedId ? renderActive() : renderEmptyActive());
  actions.appendChild(submit); actions.appendChild(cancel);
  form.appendChild(actions);
  // __NI_SUBMIT__
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const t = title.value.trim(), svc = service.value.trim();
    if (!t || !svc) { toast("Title and service are required."); return; }
    submit.disabled = true; submit.textContent = "Creating…";
    try {
      const r = await api.post("/api/incidents",
        { title: t, service: svc, severity: sev.value, symptom: symptom.value.trim() || t });
      toast(`Created ${r.incident.external_id}.`);
      await renderQueue();
      selectIncident(r.incident.id);
    } catch (err) {
      toast(`Create failed: ${err.message}`);
      submit.disabled = false; submit.textContent = "Create incident";
    }
  });
  host.appendChild(form);
  title.focus();
}

// Empty active-pane state. Role-, demo-, and data-aware: when incidents exist it invites
// selection; when the store is truly empty it only offers/mentions seeding in the way the
// current role allows (never tell a viewer to seed a control they can't reach).
function renderEmptyActive() {
  const host = $("#active");
  if (!host) return;
  host.className = "active-empty";
  clear(host);
  const A = window.Auth || { can: () => false };
  if ((state.incidents || []).length) {
    host.appendChild(el("p", "empty-title", "Select an incident."));
    host.appendChild(el("p", "empty-sub",
      "Pick one from the queue to see its triage brief and the memories Muninn recalls."));
    return;
  }
  host.appendChild(el("p", "empty-title", "Muninn's memory is empty."));
  if (A.can("seed")) {
    host.appendChild(el("p", "empty-sub", "Seed the demo dataset to watch it recall past outages."));
    const b = el("button", "btn", "Seed demo data");
    b.addEventListener("click", seedDemo);
    host.appendChild(b);
  } else {
    host.appendChild(el("p", "empty-sub",
      "No incidents yet — an admin can seed the synthetic demo dataset to get things started."));
  }
}

/* ---- users view (admin-only role management) ------------------------------ */
// renderUsers(): GET /api/users -> table with a role <select> + Save per row.
// PATCH /api/users/{id} {role}. Editing your own row is disabled (changing your
// own role invalidates your session server-side — avoid locking yourself out).
async function renderUsers() {
  const host = $("#users-table");
  clear(host);
  if (!(window.Auth && Auth.can("users"))) {
    host.appendChild(el("p", null, "Admins only.")); return;
  }
  let users;
  try { users = (await api.get("/api/users")).users || []; }
  catch (e) { host.appendChild(el("p", null, `Users unavailable: ${e.message}`)); return; }
  if (!users.length) { host.appendChild(el("p", null, "No users.")); return; }

  const me = Auth.user();
  const table = el("table", "users-table");
  const thead = el("thead"), htr = el("tr");
  ["Name", "Email", "Role", ""].forEach((h) => htr.appendChild(el("th", null, h)));
  thead.appendChild(htr); table.appendChild(thead);
  const tbody = el("tbody");
  for (const u of users) {
    const isSelf = me && u.id === me.id;
    const tr = el("tr");
    tr.appendChild(el("td", null, u.name || "—"));
    tr.appendChild(el("td", "mono", u.email));
    const sel = el("select", "field role-select");
    sel.setAttribute("aria-label", `Role for ${u.email}`);
    ["viewer", "responder", "admin"].forEach((r) => {
      const opt = el("option", null, r); opt.value = r;
      if (u.role === r) opt.selected = true; sel.appendChild(opt);
    });
    sel.disabled = !!isSelf;
    const roleTd = el("td"); roleTd.appendChild(sel); tr.appendChild(roleTd);
    const save = el("button", "btn btn-ghost", "Save"); save.disabled = !!isSelf;
    save.addEventListener("click", async () => {
      _busy(save, true);
      try {
        await api.patch(`/api/users/${u.id}`, { role: sel.value });
        toast(`Updated ${u.email} → ${sel.value}.`);
      } catch (e) { toast(`Update failed: ${e.message}`); }
      _busy(save, false, "Save");
    });
    const actTd = el("td"); actTd.appendChild(isSelf ? el("span", "role-note", "you") : save);
    tr.appendChild(actTd);
    tbody.appendChild(tr);
  }
  table.appendChild(tbody); host.appendChild(table);
}
function _busy(btn, on, label) { btn.disabled = on; if (label != null) btn.textContent = label; }

/* ---- user chip + role gating --------------------------------------------- */
function renderUserChip(user) {
  const chip = $("#user-chip");
  if (!chip || !user) return;
  clear(chip); chip.hidden = false;
  const btn = el("button", "chip-btn");
  btn.setAttribute("aria-haspopup", "menu");
  btn.setAttribute("aria-expanded", "false");
  btn.appendChild(el("span", "chip-name", user.name || user.email));
  btn.appendChild(el("span", `role-badge role-${user.role}`, user.role));
  const menu = el("div", "chip-menu"); menu.hidden = true;
  menu.setAttribute("role", "menu");
  const out = el("button", "chip-item", "Sign out");
  out.setAttribute("role", "menuitem");
  out.addEventListener("click", () => Auth.logout());
  menu.appendChild(out);
  const setOpen = (open) => { menu.hidden = !open; btn.setAttribute("aria-expanded", String(open)); };
  btn.addEventListener("click", (e) => { e.stopPropagation(); setOpen(menu.hidden); });
  document.addEventListener("click", () => { if (!menu.hidden) setOpen(false); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !menu.hidden) setOpen(false); });
  chip.appendChild(btn); chip.appendChild(menu);
}

// Hide controls the current role can't use (the server still enforces; this just
// keeps the UI from offering a button that would 403). Mirrors the route table.
function applyRoleGating() {
  const A = window.Auth || { can: () => false };
  const canSeed = A.can("seed");     // demo/seed + demo/reset = admin
  const canMutate = A.can("mutate"); // create incident = responder
  const canUsers = A.can("users");   // user administration = admin
  const sb = document.getElementById("btn-seed"); if (sb) sb.hidden = !canSeed;
  const nb = $("#btn-new"); if (nb) nb.hidden = !canMutate;
  const nu = $("#nav-users"); if (nu) nu.hidden = !canUsers;
}

/* ---- open-demo mode: labeled role switcher in the status bar -------------- */
// Shown ONLY while the server has open-demo mode on AND the live session is a demo
// account (Auth.isDemo()). Real logins never see it. Every view still runs the REAL
// pipeline — recall, brief, metrics — only the seeded dataset is synthetic.
function renderDemoBar(user) {
  const bar = $("#demo-bar");
  if (!bar) return;
  clear(bar);
  if (!(window.Auth && Auth.isDemo())) { bar.hidden = true; return; }
  bar.hidden = false;
  bar.appendChild(el("span", "demo-label", "Demo mode — no login needed. Viewing as:"));
  const roles = el("div", "demo-roles");
  roles.setAttribute("role", "group");
  roles.setAttribute("aria-label", "Demo role");
  const current = (user && user.role) || "";
  Auth.demoRoles().forEach((role) => {
    const label = role.charAt(0).toUpperCase() + role.slice(1);
    const b = el("button", "demo-role", label);
    b.type = "button"; b.dataset.role = role;
    const on = role === current;
    b.classList.toggle("is-active", on);
    b.setAttribute("aria-pressed", String(on));
    b.disabled = on;   // already viewing as this role
    b.addEventListener("click", () => switchDemoRole(role));
    roles.appendChild(b);
  });
  bar.appendChild(roles);
  const login = el("button", "demo-login-link", "Log in");
  login.type = "button";
  login.addEventListener("click", () => Auth.openLogin());
  bar.appendChild(login);
}

// Mint a fresh REAL session for the chosen demo role (server-side) and re-boot the UI so
// RBAC gating, the queue, and the active pane all reflect the new capabilities. Selection
// is reset so no stale, now-forbidden control lingers.
async function switchDemoRole(role) {
  try {
    const user = await Auth.demoLogin(role);
    state.selectedId = null; state.brief = null; state.recall = null;
    toast(`Now viewing as ${role}.`);
    renderRecall(null);
    boot(user);
  } catch (e) {
    toast(`Could not switch role: ${e.message}`);
  }
}

/* ---- wire + boot ---------------------------------------------------------- */
let _wired = false;
function wire() {
  if (_wired) return; _wired = true;
  const sb = document.getElementById("btn-seed"); if (sb) sb.addEventListener("click", seedDemo);
  const nb = $("#btn-new"); if (nb) nb.addEventListener("click", newIncident);
  window.addEventListener("hashchange", router);
}

// Boot callback — runs only AFTER Auth.require() confirms a live session (real OR open-demo),
// so no app-data request ever fires while unauthenticated. Also re-invoked on a demo role
// switch to re-render everything under the new capabilities.
async function boot(user) {
  renderUserChip(user);
  renderDemoBar(user);
  applyRoleGating();
  router();
  bootHealth();
  await renderQueue();
  if (!state.selectedId) renderEmptyActive();   // role/demo/data-aware active pane
}

document.addEventListener("DOMContentLoaded", () => {
  wire();
  if (window.Auth) {
    Auth.onAuthenticated(boot);
    Auth.require();   // 200 -> boot(user); 401 -> auth screen, no data fetched
  } else {
    // auth.js failed to load — fail safe to the plain app rather than a blank page
    router(); bootHealth(); renderQueue();
  }
});
