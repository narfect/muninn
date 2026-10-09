/* Muninn — security-operations analyzer (hero canvas). Vanilla JS, no deps, no CDN,
   CSP-safe (same-origin script, zero innerHTML). Replaces the old particle field.

   Concept: a live SOC analyzer. A scan bar sweeps the monitored field left→right; as it
   crosses a node (a service/signal), the node is classified — mostly benign (teal tick),
   occasionally a threat (red crosshair ring). Faint links wire nearby nodes; a subtle
   grid grounds it. Light-mode tuned (low contrast so hero copy dominates), cursor-parallax,
   scroll-reactive (landing.js feeds scroll progress), pauses when the tab is hidden, and
   is a no-op under prefers-reduced-motion (a single static frame is painted instead).

   app.js's router drives this through landing.js via window.MuninnSOC.start()/stop(). */

"use strict";

(function () {
  const PRM = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function tok(name, fallback) {
    try {
      const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
      return v || fallback;
    } catch (_) { return fallback; }
  }
  // "#rgb" / "#rrggbb" (+ optional alpha pair) → rgba() string at alpha `a`
  function rgba(hex, a) {
    hex = String(hex || "").trim().replace("#", "");
    if (hex.length === 3) hex = hex.split("").map((c) => c + c).join("");
    if (hex.length < 6) return "rgba(82,82,82," + a + ")";
    const r = parseInt(hex.slice(0, 2), 16);
    const g = parseInt(hex.slice(2, 4), 16);
    const b = parseInt(hex.slice(4, 6), 16);
    return "rgba(" + r + "," + g + "," + b + "," + a + ")";
  }

  let canvas = null, ctx = null, hud = null;
  let raf = 0, running = false, W = 0, H = 0, dpr = 1;
  let nodes = [], events = [], scanX = 0, last = 0, scrollP = 0;
  let signals = 0, threats = 0, hudAt = 0;
  const mouse = { x: 0.5, y: 0.5 };
  let COL = {};

  function readColors() {
    COL = {
      warm: tok("--warm", "#F15534"),
      cold: tok("--cold", "#3D3D3D"),
      danger: tok("--danger", "#E5484D"),
      ink: tok("--ink", "#141414"),
      muted: tok("--muted", "#525252"),
    };
  }

  function resize() {
    if (!canvas || !ctx) return;
    const r = canvas.getBoundingClientRect();
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = Math.max(1, Math.round(r.width));
    H = Math.max(1, Math.round(r.height));
    canvas.width = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    seed();
  }

  function seed() {
    const count = Math.max(14, Math.min(34, Math.round((W * H) / 27000)));
    nodes = [];
    for (let i = 0; i < count; i++) {
      nodes.push({
        x: Math.random() * W,
        y: Math.random() * H,
        r: 1.4 + Math.random() * 1.7,
        pulse: 0,
        scanned: false,
        base: 0.3 + Math.random() * 0.4,
      });
    }
    events = [];
    scanX = 0;
  }

  function step(dt) {
    // scan bar sweeps left→right; scroll progress nudges the cadence up a touch
    const speed = (W / 7) * (1 + scrollP * 0.6);   // px/sec
    const prev = scanX;
    scanX += speed * dt;
    if (scanX > W + 40) { scanX = -40; nodes.forEach((n) => { n.scanned = false; }); }

    // classify nodes the scan bar just crossed
    nodes.forEach((n) => {
      if (!n.scanned && prev <= n.x && scanX >= n.x) {
        n.scanned = true;
        n.pulse = 1;
        const threat = Math.random() < 0.16;
        if (threat) threats++;
        signals++;
        events.push({ x: n.x, y: n.y, age: 0, threat: threat });
      }
      if (n.pulse > 0) n.pulse = Math.max(0, n.pulse - dt * 1.6);
    });

    for (let i = events.length - 1; i >= 0; i--) {
      events[i].age += dt;
      if (events[i].age > 1.6) events.splice(i, 1);
    }

    if (hud) {
      hudAt += dt;
      if (hudAt > 0.4) {
        hudAt = 0;
        const s = hud.querySelector('[data-hud="signals"]');
        const th = hud.querySelector('[data-hud="threats"]');
        if (s) s.textContent = String(signals);
        if (th) th.textContent = String(threats);
      }
    }
  }

  // __SOC_DRAW__

  function draw() {
    if (!ctx) return;
    ctx.clearRect(0, 0, W, H);

    // subtle cursor + scroll parallax (clamped, so the field only breathes)
    const ox = (mouse.x - 0.5) * 10;
    const oy = (mouse.y - 0.5) * 8 - scrollP * 14;

    // faint reference grid
    const gstep = 46;
    ctx.lineWidth = 1;
    ctx.strokeStyle = rgba(COL.ink, 0.035);
    ctx.beginPath();
    for (let x = (ox % gstep); x < W; x += gstep) { ctx.moveTo(x, 0); ctx.lineTo(x, H); }
    for (let y = (oy % gstep); y < H; y += gstep) { ctx.moveTo(0, y); ctx.lineTo(W, y); }
    ctx.stroke();

    // links between nearby nodes
    const LINK = 132;
    for (let i = 0; i < nodes.length; i++) {
      const a = nodes[i];
      for (let j = i + 1; j < nodes.length; j++) {
        const b = nodes[j];
        const dx = a.x - b.x, dy = a.y - b.y;
        const d = Math.sqrt(dx * dx + dy * dy);
        if (d < LINK) {
          ctx.strokeStyle = rgba(COL.ink, 0.06 * (1 - d / LINK));
          ctx.beginPath();
          ctx.moveTo(a.x + ox, a.y + oy); ctx.lineTo(b.x + ox, b.y + oy);
          ctx.stroke();
        }
      }
    }

    // nodes (lit briefly as the scan bar classifies them)
    nodes.forEach((n) => {
      const x = n.x + ox, y = n.y + oy;
      if (n.pulse > 0) {
        ctx.fillStyle = rgba(COL.warm, 0.14 * n.pulse);
        ctx.beginPath(); ctx.arc(x, y, n.r + 7 * n.pulse, 0, Math.PI * 2); ctx.fill();
      }
      ctx.fillStyle = rgba(n.pulse > 0 ? COL.warm : COL.muted, n.base + n.pulse * 0.5);
      ctx.beginPath(); ctx.arc(x, y, n.r, 0, Math.PI * 2); ctx.fill();
    });

    // classification events: expanding ring, teal = benign, red crosshair = threat
    events.forEach((ev) => {
      const p = ev.age / 1.6;
      const x = ev.x + ox, y = ev.y + oy;
      const col = ev.threat ? COL.danger : COL.cold;
      ctx.lineWidth = ev.threat ? 1.6 : 1.2;
      ctx.strokeStyle = rgba(col, (ev.threat ? 0.55 : 0.4) * (1 - p));
      ctx.beginPath(); ctx.arc(x, y, 3 + p * (ev.threat ? 20 : 14), 0, Math.PI * 2); ctx.stroke();
      if (ev.threat) {
        const r = 9;
        ctx.beginPath();
        ctx.moveTo(x - r, y); ctx.lineTo(x + r, y);
        ctx.moveTo(x, y - r); ctx.lineTo(x, y + r);
        ctx.stroke();
      }
    });

    // the scan bar
    if (scanX >= -40 && scanX <= W + 40) {
      const sx = scanX + ox;
      const g = ctx.createLinearGradient(sx - 60, 0, sx, 0);
      g.addColorStop(0, rgba(COL.warm, 0));
      g.addColorStop(1, rgba(COL.warm, 0.1));
      ctx.fillStyle = g;
      ctx.fillRect(sx - 60, 0, 60, H);
      ctx.strokeStyle = rgba(COL.warm, 0.5);
      ctx.lineWidth = 1.5;
      ctx.beginPath(); ctx.moveTo(sx, 0); ctx.lineTo(sx, H); ctx.stroke();
    }
  }

  function frame(ts) {
    if (!running) return;
    if (!last) last = ts;
    const dt = Math.min(0.05, (ts - last) / 1000);
    last = ts;
    step(dt);
    draw();
    raf = requestAnimationFrame(frame);
  }

  function onMove(e) {
    if (!canvas) return;
    const r = canvas.getBoundingClientRect();
    if (!r.width || !r.height) return;
    mouse.x = Math.max(0, Math.min(1, (e.clientX - r.left) / r.width));
    mouse.y = Math.max(0, Math.min(1, (e.clientY - r.top) / r.height));
  }
  function onVisibility() {
    if (document.hidden) { cancelAnimationFrame(raf); raf = 0; }
    else if (running && !PRM && !raf) { last = 0; raf = requestAnimationFrame(frame); }
  }

  function start() {
    canvas = document.getElementById("socviz");
    if (!canvas) return;
    ctx = canvas.getContext("2d");
    if (!ctx) return;
    hud = document.querySelector(".lp-hud");
    readColors();
    resize();
    running = true;
    window.addEventListener("resize", resize, { passive: true });
    window.addEventListener("mousemove", onMove, { passive: true });
    document.addEventListener("visibilitychange", onVisibility);
    if (PRM) { draw(); return; }   // reduced motion: one static frame, no loop
    last = 0;
    raf = requestAnimationFrame(frame);
  }

  function stop() {
    running = false;
    cancelAnimationFrame(raf); raf = 0;
    window.removeEventListener("resize", resize);
    window.removeEventListener("mousemove", onMove);
    document.removeEventListener("visibilitychange", onVisibility);
    if (ctx) ctx.clearRect(0, 0, W, H);
  }

  function setScroll(p) { scrollP = Math.max(0, Math.min(1, p || 0)); }

  window.MuninnSOC = { start, stop, setScroll };
})();
