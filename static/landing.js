/* Muninn landing page — vanilla JS, zero innerHTML (CSP-safe), no deps, no CDN.
   Renders the marketing landing into #landing-root (built once, idempotent), wires
   scroll-reveal (IntersectionObserver) + nav scroll state, and starts/stops the
   security-ops analyzer canvas. app.js's router calls MuninnLanding.enter()/leave()
   on route change.

   Landing-only motion lives here; the console/insights/users views get the shared
   design system + font but none of this. Respects prefers-reduced-motion (reveals are
   shown immediately and the analyzer paints a single static frame — see styles.css +
   socviz.js). */

"use strict";

(function () {
  // ---- EDIT ME: collaborators shown in the footer. name + GitHub profile URL. ----
  const COLLABORATORS = [
    { name: "Sai Akshith Reddy Gurijala", url: "https://github.com/SaiAkshithReddyGurijala" },
    { name: "Neha Roy", url: "https://github.com/neharoy3" },
    { name: "Vangapally Ramya ", url: "https://github.com/Ramya-Vangapally" },
  ];

  // ---- scrollytelling incidents: surface one-by-one on scroll; the lens recalls each. ----
  const INCIDENTS = [
    { sev: 1, service: "checkout-api · 5xx surge", signature: "Error rate 11% after the 14:02 deploy",
      recall: "INC-2043 · connection pool exhausted · 92% match" },
    { sev: 2, service: "auth-gateway · p99 latency", signature: "Login p99 breaching SLO for 6 min",
      recall: "INC-1180 · token-cache stampede · 87% match" },
    { sev: 3, service: "search-svc · 429s", signature: "Rate limiter shedding 1.2k req/min",
      recall: "INC-0974 · noisy-neighbor shard · 81% match" },
    { sev: 1, service: "payments-api · queue", signature: "Webhook retries flooding the DLQ",
      recall: "INC-2210 · idempotency-key gap · 90% match" },
    { sev: 2, service: "cdn-edge · cache", signature: "Hit ratio collapse in the AP region",
      recall: "INC-1562 · stale purge rule · 85% match" },
  ];

  const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  };
  const add = (parent, child) => { parent.appendChild(child); return child; };

  let _root = null, _observer = null, _navEl = null, _mounted = false;
  // lens scene state
  let _lensSec = null, _lensStage = null, _lensGlass = null, _lensItemsEls = [], _lensActive = -1, _lensCenters = [];
  // section scanners: each targeted section gets its own glass that inspects the card
  // nearest the viewport as you scroll (same incident-inspect motif as the lens scene)
  let _scanners = [];

  /* ---- small composite helpers ---- */
  function container(child) {
    const c = el("div", "lp-container");
    if (child) c.appendChild(child);
    return c;
  }
  function reveal(node, delayCls) {
    node.classList.add("reveal");
    if (delayCls) node.classList.add(delayCls);
    return node;
  }
  function sectionHead(idx, eyebrow, title, lead, center) {
    const head = el("div", "lp-section-head" + (center ? " center" : ""));
    const eb = el("div", "lp-eyebrow-text");
    add(eb, el("span", "lp-idx", idx));
    add(eb, el("span", "lp-ebw", eyebrow));
    add(head, eb);
    add(head, el("h2", "lp-title", title));
    if (lead) add(head, el("p", "lp-lead", lead));
    add(head, el("div", "lp-rule"));
    return head;
  }

  /* ---- nav ---- */
  function buildNav() {
    const nav = el("nav", "lp-nav");
    nav.setAttribute("aria-label", "Landing");
    const inner = el("div", "lp-container");
    const brand = el("a", "lp-nav-brand");
    brand.href = "#/home";
    add(brand, el("span", "rune", "ᛗ"));
    add(brand, el("span", "wordmark", "muninn"));
    inner.appendChild(brand);

    const links = el("div", "lp-nav-links");
    [["#what", "What it does"], ["#how", "How it works"], ["#features", "Features"], ["#tech", "Tech"]]
      .forEach(([href, label]) => {
        const a = el("a", "lp-nav-link", label);
        a.href = href;
        a.addEventListener("click", (e) => { e.preventDefault(); scrollToId(href.slice(1)); });
        links.appendChild(a);
      });
    inner.appendChild(links);

    const cta = el("a", "lp-nav-cta", "Launch console");
    cta.href = "#/console";
    inner.appendChild(cta);

    nav.appendChild(inner);
    _navEl = nav;
    return nav;
  }

  /* ---- hero ---- */
  function buildHero() {
    const hero = el("header", "lp-hero");
    const canvas = el("canvas");
    canvas.id = "socviz";
    canvas.setAttribute("aria-hidden", "true");
    hero.appendChild(canvas);

    const inner = el("div", "lp-hero-inner");
    add(inner, reveal(el("div", "lp-eyebrow", "Incident memory · AIOps copilot")));

    const h1 = reveal(el("h1"), "d1");
    h1.appendChild(document.createTextNode("The incident-response copilot that "));
    h1.appendChild(el("span", "grad", "remembers"));
    inner.appendChild(h1);

    add(inner, reveal(el("p", "lp-subhead",
      "Muninn recalls similar past outages on every new alert, synthesizes a cited triage "
      + "brief, and retains each resolution — so the system gets sharper with every incident."), "d2"));

    const row = reveal(el("div", "lp-cta-row"), "d3");
    const launch = el("a", "btn btn-lg", "Launch console");
    launch.href = "#/console";
    const how = el("a", "btn btn-ghost btn-lg", "See how it works");
    how.href = "#how";
    how.addEventListener("click", (e) => { e.preventDefault(); scrollToId("how"); });
    row.appendChild(launch); row.appendChild(how);
    inner.appendChild(row);

    const stats = reveal(el("div", "lp-hero-stats"), "d3");
    [["Cold → Warm", "memory on/off compare"],
     ["Offline-first", "no keys, no internet"],
     ["Hindsight", "agent memory core"]].forEach(([b, s]) => {
      const stat = el("div", "lp-hero-stat");
      add(stat, el("b", null, b));
      add(stat, el("span", null, s));
      stats.appendChild(stat);
    });
    inner.appendChild(stats);

    hero.appendChild(container(inner));

    // HUD telemetry strip (socviz.js updates the signal/threat counters live)
    const hudBar = el("div", "lp-hud");
    hudBar.setAttribute("aria-hidden", "true");
    const live = el("span", "live");
    live.appendChild(document.createTextNode("Analyzer "));
    add(live, el("b", null, "online"));
    hudBar.appendChild(live);
    const sig = el("span");
    sig.appendChild(document.createTextNode("Signals classified "));
    const sigB = el("b"); sigB.setAttribute("data-hud", "signals"); sigB.textContent = "0";
    sig.appendChild(sigB);
    hudBar.appendChild(sig);
    const thr = el("span");
    thr.appendChild(document.createTextNode("Threats flagged "));
    const thrB = el("b"); thrB.setAttribute("data-hud", "threats"); thrB.textContent = "0";
    thr.appendChild(thrB);
    hudBar.appendChild(thr);
    hero.appendChild(hudBar);

    return hero;
  }
  /* ---- scrollytelling: incidents surface as you scroll; the lens inspects each ---- */
  function buildLens() {
    const sec = el("section", "lp-section lp-lens");
    sec.id = "lens";
    const sticky = el("div", "lp-lens-sticky");
    const inner = el("div");
    inner.appendChild(reveal(sectionHead(
      "[01]",
      "Live triage",
      "Incidents surface — the lens recalls what Muninn has seen",
      "Scroll to sweep the field. As each alert pops, Muninn's memory lens settles on it "
      + "and surfaces the past outage behind it.", true)));

    const stage = el("div", "lp-lens-stage");
    _lensItemsEls = [];
    INCIDENTS.forEach((inc, i) => {
      const card = el("article", "lp-incident sev" + inc.sev + " pos-" + (i + 1));
      card.setAttribute("data-i", String(i));
      const head = el("div", "lp-inc-head");
      add(head, el("span", "lp-inc-dot"));
      add(head, el("span", "lp-inc-svc", inc.service));
      card.appendChild(head);
      add(card, el("div", "lp-inc-sig", inc.signature));
      const detail = el("div", "lp-inc-detail");
      add(detail, el("span", "lp-inc-arrow", "↳"));
      add(detail, el("span", null, inc.recall));
      card.appendChild(detail);
      stage.appendChild(card);
      _lensItemsEls.push(card);
    });

    const glass = el("div", "lp-lens-glass");
    glass.setAttribute("aria-hidden", "true");
    add(glass, el("div", "lp-lens-ring"));
    add(glass, el("div", "lp-lens-handle"));
    stage.appendChild(glass);
    _lensGlass = glass;
    _lensStage = stage;

    inner.appendChild(stage);
    sticky.appendChild(container(inner));
    sec.appendChild(sticky);
    _lensSec = sec;
    return sec;
  }

  /* ---- what it does: cold vs warm before/after ---- */
  function compareCard(variant, tag, rows) {
    const card = el("div", "lp-compare-card " + variant);
    add(card, el("span", "lp-cc-tag", tag));
    rows.forEach(([k, v, weak]) => {
      const row = el("div", "lp-cc-row");
      add(row, el("div", "lp-cc-k", k));
      add(row, el("div", "lp-cc-v" + (weak ? " weak" : ""), v));
      card.appendChild(row);
    });
    return card;
  }
  function buildWhat() {
    const sec = el("section", "lp-section");
    sec.id = "what";
    const inner = el("div");
    inner.appendChild(reveal(sectionHead(
      "[02]",
      "What it does",
      "A generic guess, or a cited fix from the last outage",
      "Flip memory off and Muninn is just another chatbot. Turn it on and the same alert "
      + "comes back answered — grounded in the incidents your team already resolved.", true)));

    const grid = reveal(el("div", "lp-compare"));
    const coldCard = compareCard("cold", "Cold · memory off", [
      ["Alert", "checkout-api · 5xx surge after 14:02 deploy"],
      ["Response", "Generic: check recent deploys, inspect logs, consider a rollback.", true],
      ["Citations", "none — cold start", true],
      ["Confidence", "low", true],
    ]);
    const warmCard = compareCard("warm", "Warm · memory on", [
      ["Alert", "checkout-api · 5xx surge after 14:02 deploy"],
      ["Response", "Connection pool exhausted post-deploy — raise pool size, recycle workers, verify DB connections."],
      ["Citations", "INC-2043 · 92% match"],
      ["Confidence", "high · cited"],
    ]);
    grid.appendChild(coldCard);
    grid.appendChild(warmCard);
    inner.appendChild(grid);
    sec.appendChild(container(inner));
    makeScanner(sec, [coldCard, warmCard]);
    return sec;
  }

  /* ---- how it works: retain → recall → reflect ---- */
  function buildHow() {
    const sec = el("section", "lp-section");
    sec.id = "how";
    const inner = el("div");
    inner.appendChild(reveal(sectionHead(
      "[03]",
      "How it works",
      "Retain, recall, reflect — a loop that compounds",
      "Muninn treats every outage as institutional memory. The more it resolves, the "
      + "faster the next one closes.", true)));

    const steps = el("div", "lp-steps");
    const stepEls = [];
    [["retain", "Retain",
      "Every resolved incident is written back as an experience memory: symptom, error "
      + "signature, root cause, fix, runbook, resolver, and MTTR."],
     ["recall", "Recall",
      "On a new alert, Muninn searches memory by the incident's signature and surfaces "
      + "scored, cited matches from past outages."],
     ["reflect", "Reflect",
      "The agent synthesizes across recalled incidents to spot cross-incident patterns "
      + "and cite the specific outages behind its triage brief."]]
      .forEach(([tag, title, body], i) => {
        const step = reveal(el("div", "lp-step"), ["d1", "d2", "d3"][i]);
        add(step, el("span", "lp-step-tag", tag));
        add(step, el("h3", null, title));
        add(step, el("p", null, body));
        steps.appendChild(step);
        stepEls.push(step);
      });
    inner.appendChild(steps);
    sec.appendChild(container(inner));
    makeScanner(sec, stepEls);
    return sec;
  }
  // __LANDING_SECTIONS_2__

  /* ---- features grid ---- */
  function buildFeatures() {
    const sec = el("section", "lp-section");
    sec.id = "features";
    const inner = el("div");
    inner.appendChild(reveal(sectionHead(
      "[04]", "Capabilities", "Everything an on-call engineer wishes they remembered", null, true)));

    const grid = el("div", "lp-features");
    const featEls = [];
    [["❝", "Cited triage briefs",
      "Each brief states a root-cause hypothesis, remediation steps, and runbook — with "
      + "citation chips that link straight to the recalled incidents behind it."],
     ["⊹", "Cross-incident patterns",
      "Reflection reads across recalled outages to flag recurring causes, not just the "
      + "single nearest match."],
     ["📈", "MTTR & learning curve",
      "Dashboards track mean time to resolve by service and show recall quality climbing "
      + "as memory grows — the system visibly learning."],
     ["⦿", "Offline-first by design",
      "Runs end to end with no API keys and no internet via a local memory store and "
      + "reasoner. Real Hindsight and Groq activate when credentials exist."]]
      .forEach(([ico, title, body], i) => {
        const f = reveal(el("div", "lp-feature"), ["d1", "d2", "d1", "d2"][i]);
        add(f, el("div", "lp-feature-ico", ico));
        add(f, el("h3", null, title));
        add(f, el("p", null, body));
        grid.appendChild(f);
        featEls.push(f);
      });
    inner.appendChild(grid);
    sec.appendChild(container(inner));
    makeScanner(sec, featEls);
    return sec;
  }

  /* ---- tech stack ---- */
  function buildTech() {
    const sec = el("section", "lp-section");
    sec.id = "tech";
    const inner = el("div");
    inner.appendChild(reveal(sectionHead(
      "[05]", "Under the hood", "Built on a memory core, served by the standard library", null, true)));

    const wrap = reveal(el("div", "lp-tech"));
    const hero = el("div", "lp-tech-chip hero");
    add(hero, el("b", null, "Hindsight — agent memory"));
    add(hero, el("span", null,
      "The memory core. Resolved incidents are retained as experience memories, recalled "
      + "by signature on new alerts, and reflected across for pattern synthesis."));
    wrap.appendChild(hero);
    const chipEls = [hero];

    [["Python stdlib backend", "http.server, sqlite3, urllib, json — no web framework, no pip installs."],
     ["SQLite system-of-record", "Incidents, timelines, accounts, and sessions persist in a single local file."],
     ["Pluggable LLM reasoner", "A local reasoner by default; Groq activates automatically when a key is present."],
     ["Vanilla JS frontend", "No framework, no bundler, no CDN — a dependency-free single-page console."]]
      .forEach(([t, d]) => {
        const chip = el("div", "lp-tech-chip");
        add(chip, el("b", null, t));
        add(chip, el("span", null, d));
        wrap.appendChild(chip);
        chipEls.push(chip);
      });
    inner.appendChild(wrap);
    sec.appendChild(container(inner));
    makeScanner(sec, chipEls);
    return sec;
  }

  /* ---- footer ---- */
  function buildFooter() {
    const foot = el("footer", "lp-footer");
    const inner = el("div");
    const grid = el("div", "lp-footer-grid");

    const brand = el("div", "lp-footer-brand");
    const mark = el("div", "lp-foot-mark");
    add(mark, el("span", "rune", "ᛗ"));
    add(mark, el("span", "wordmark", "muninn"));
    brand.appendChild(mark);
    add(brand, el("p",
      "An incident-response copilot with institutional memory. Built for Hack with "
      + "Hyderabad 3.0."));
    grid.appendChild(brand);

    const collab = el("div", "lp-collab");
    add(collab, el("h4", null, "Collaborators"));
    const list = el("div", "lp-collab-list");
    COLLABORATORS.forEach((c) => {
      const a = el("a", "lp-collab-link");
      a.href = c.url; a.target = "_blank"; a.rel = "noopener noreferrer";
      add(a, el("span", null, c.name));
      let handle = c.url;
      try { handle = "@" + new URL(c.url).pathname.replace(/\//g, ""); } catch (_) {}
      add(a, el("span", "gh", handle));
      list.appendChild(a);
    });
    collab.appendChild(list);
    grid.appendChild(collab);
    inner.appendChild(grid);

    const base = el("div", "lp-footer-base");
    add(base, el("span", null, "© " + new Date().getFullYear() + " Muninn"));
    add(base, el("span", null, "Offline-first · stdlib backend · Hindsight memory"));
    inner.appendChild(base);

    foot.appendChild(container(inner));
    return foot;
  }
  /* ---- lens scroll driver: measure incident centers, glide the glass, reveal recall ---- */
  function measureLens() {
    if (!_lensStage || !_lensItemsEls.length) return;
    _lensCenters = _lensItemsEls.map((n) => ({
      x: n.offsetLeft + n.offsetWidth / 2,
      y: n.offsetTop + n.offsetHeight / 2,
    }));
  }
  function placeGlass(i) {
    if (!_lensGlass || !_lensCenters[i]) return;
    const R = (_lensGlass.offsetWidth || 108) / 2;
    _lensGlass.style.setProperty("--gx", (_lensCenters[i].x - R) + "px");
    _lensGlass.style.setProperty("--gy", (_lensCenters[i].y - R) + "px");
  }
  function setActiveLens(idx) {
    if (idx === _lensActive) return;
    _lensActive = idx;
    _lensItemsEls.forEach((n, i) => {
      n.classList.toggle("is-on", i <= idx);
      n.classList.toggle("is-focus", i === idx);
    });
    placeGlass(idx);
  }
  function updateLens() {
    if (!_lensSec || reduce) return;
    const N = _lensItemsEls.length;
    if (!N) return;
    if (_lensCenters.length !== N) measureLens();   // self-heal if centers never measured (e.g. layout/font shift)
    const rect = _lensSec.getBoundingClientRect();
    const scrollable = _lensSec.offsetHeight - window.innerHeight;
    const p = scrollable > 0 ? Math.max(0, Math.min(1, -rect.top / scrollable)) : 0;
    setActiveLens(Math.max(0, Math.min(N - 1, Math.floor(p * N))));
  }
  function revealLensAll() {   // reduced-motion: show every incident + its recall, no glide
    _lensItemsEls.forEach((n) => { n.classList.add("is-on", "is-focus"); });
  }
  function onResize() {
    measureLens(); placeGlass(_lensActive < 0 ? 0 : _lensActive);
    measureScanners();
    _scanners.forEach((sc) => { if (sc.active >= 0) placeScanGlass(sc, sc.active); });
  }

  /* ---- section scanners: give every card grid its own magnifying glass that glides to
         the card nearest the viewport as you scroll — the lens motif, carried through the
         whole page. Text is untouched; only an overlay glass + a focus lift are added. ---- */
  function makeScanner(sec, items) {
    if (!sec || !items || !items.length) return;
    sec.classList.add("lp-scan");
    const glass = el("div", "lp-lens-glass lp-scan-glass");
    glass.setAttribute("aria-hidden", "true");
    add(glass, el("div", "lp-lens-ring"));
    add(glass, el("div", "lp-lens-handle"));
    sec.appendChild(glass);
    const sc = { sec: sec, items: items, glass: glass, centers: [], active: -1, hover: -1 };
    _scanners.push(sc);
    // hovering a card pulls the glass straight to it (overrides the scroll position);
    // leaving snaps it back to whichever card the scroll position points at
    items.forEach((n, i) => {
      n.addEventListener("mouseenter", () => {
        if (reduce) return;
        sc.hover = i;
        setScanActive(sc, i);
        placeScanGlass(sc, i);
        sc.glass.classList.add("is-live");
      });
      n.addEventListener("mouseleave", () => {
        if (reduce) return;
        sc.hover = -1;
        updateScanners();   // resume scroll-driven tracking from the current position
      });
    });
  }
  function measureScanners() {
    _scanners.forEach((sc) => {
      sc.centers = sc.items.map((n) => {
        // Sum offsets up the offsetParent chain to the section. offsetTop/Left are
        // layout-based (transform-immune), so this stays correct even when a card's
        // container is a transformed .reveal wrapper that becomes the offsetParent.
        let l = 0, t = 0, p = n;
        while (p && p !== sc.sec) { l += p.offsetLeft; t += p.offsetTop; p = p.offsetParent; }
        return { l: l, t: t, w: n.offsetWidth, h: n.offsetHeight };
      });
    });
  }
  function placeScanGlass(sc, i) {
    const c = sc.centers[i];
    if (!c) return;
    const R = sc.glass.offsetWidth || 92;
    let gx = c.l + c.w - R * 0.66;          // hover the card's top-right corner, not its text
    let gy = c.t - R * 0.26;
    const maxX = sc.sec.clientWidth - R - 8;
    if (gx > maxX) gx = maxX;
    if (gx < 8) gx = 8;
    if (gy < 8) gy = 8;
    sc.glass.style.setProperty("--gx", gx + "px");
    sc.glass.style.setProperty("--gy", gy + "px");
  }
  function setScanActive(sc, idx) {
    if (idx === sc.active) return;
    sc.active = idx;
    sc.items.forEach((n, i) => {
      n.classList.toggle("is-scan-on", i <= idx);
      n.classList.toggle("is-scan", i === idx);
    });
    if (idx >= 0) { placeScanGlass(sc, idx); sc.glass.classList.add("is-live"); }
  }
  function updateScanners() {
    if (reduce || !_scanners.length) return;
    const vh = window.innerHeight;
    const line = vh * 0.45;   // the sweep line the glass tracks as the section scrolls past
    _scanners.forEach((sc) => {
      if (!sc.centers.length) measureScanners();
      const r = sc.sec.getBoundingClientRect();
      if (r.bottom < vh * 0.1 || r.top > vh * 0.9) {   // section well out of view → park the glass
        if (sc.glass.classList.contains("is-live")) sc.glass.classList.remove("is-live");
        return;
      }
      if (sc.hover >= 0) {   // pointer wins over scroll while it's on a card
        setScanActive(sc, sc.hover);
        sc.glass.classList.add("is-live");
        return;
      }
      // Map scroll progress across the cards' vertical span to a card index, so the glass
      // steps through every box in order — including cards that share a row (what/tech),
      // where a nearest-center pick would never move off the first one.
      const N = sc.items.length;
      const first = sc.centers[0], lastC = sc.centers[N - 1];
      const spanTop = r.top + first.t;
      const spanBot = r.top + lastC.t + lastC.h;
      let p = (line - spanTop) / Math.max(1, spanBot - spanTop);
      if (p < 0) p = 0; else if (p > 0.9999) p = 0.9999;
      let idx = Math.floor(p * N);
      if (idx < 0) idx = 0; else if (idx > N - 1) idx = N - 1;
      setScanActive(sc, idx);
      // in view → glass is lit even if the focused card didn't change since it last parked
      if (!sc.glass.classList.contains("is-live")) { placeScanGlass(sc, idx); sc.glass.classList.add("is-live"); }
    });
  }
  function revealScanAll() {   // reduced-motion: no glide, cards simply stand revealed
    _scanners.forEach((sc) => sc.items.forEach((n) => n.classList.add("is-scan-on")));
  }

  /* ---- smooth scroll to an in-page section (console scroll untouched) ---- */
  function scrollToId(id) {
    const t = document.getElementById(id);
    if (!t) return;
    t.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "start" });
  }

  /* ---- build the DOM once ---- */
  function mount() {
    if (_mounted) return;
    _root = document.getElementById("landing-root");
    if (!_root) return;
    _scanners = [];
    while (_root.firstChild) _root.removeChild(_root.firstChild);
    _root.appendChild(buildNav());
    _root.appendChild(buildHero());
    _root.appendChild(buildLens());
    _root.appendChild(buildWhat());
    _root.appendChild(buildHow());
    _root.appendChild(buildFeatures());
    _root.appendChild(buildTech());
    _root.appendChild(buildFooter());
    _mounted = true;
  }

  /* ---- scroll-reveal via IntersectionObserver (reduced-motion: reveal immediately) ---- */
  function startReveal() {
    const nodes = _root ? _root.querySelectorAll(".reveal") : [];
    if (reduce || !("IntersectionObserver" in window)) {
      nodes.forEach((n) => n.classList.add("is-visible"));
      return;
    }
    _observer = new IntersectionObserver((entries) => {
      entries.forEach((e) => {
        if (e.isIntersecting) { e.target.classList.add("is-visible"); _observer.unobserve(e.target); }
      });
    }, { threshold: 0.14, rootMargin: "0px 0px -8% 0px" });
    nodes.forEach((n) => _observer.observe(n));
  }
  function stopReveal() {
    if (_observer) { _observer.disconnect(); _observer = null; }
  }

  /* ---- nav gets a solid background once the hero scrolls away; the analyzer
         canvas gets fed scroll progress so it reacts as the page moves ---- */
  function onScroll() {
    if (_navEl) _navEl.classList.toggle("is-scrolled", window.scrollY > 24);
    if (window.MuninnSOC) {
      const p = window.scrollY / Math.max(1, window.innerHeight * 0.85);
      window.MuninnSOC.setScroll(p);
    }
    updateLens();
    updateScanners();
  }

  /* ---- route lifecycle (called by app.js router) ---- */
  function enter() {
    mount();
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onResize, { passive: true });
    startReveal();
    if (reduce) {
      revealLensAll();
      revealScanAll();
    } else {
      _lensActive = -1;
      requestAnimationFrame(() => { measureLens(); measureScanners(); updateLens(); updateScanners(); });
      // the variable font can shift card metrics after first paint — re-measure once it lands
      if (document.fonts && document.fonts.ready) {
        document.fonts.ready.then(() => {
          measureLens(); measureScanners();
          placeGlass(_lensActive < 0 ? 0 : _lensActive);
          _scanners.forEach((sc) => { if (sc.active >= 0) placeScanGlass(sc, sc.active); });
        });
      }
    }
    if (window.MuninnSOC) window.MuninnSOC.start();
  }
  function leave() {
    window.removeEventListener("scroll", onScroll);
    window.removeEventListener("resize", onResize);
    stopReveal();
    if (window.MuninnSOC) window.MuninnSOC.stop();
  }

  window.MuninnLanding = { enter, leave, mount };
})();
