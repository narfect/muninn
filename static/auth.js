/* Muninn frontend auth — vanilla JS, no deps, no CDN, zero innerHTML.
   Owns the login/sign-up experience, the session boot gate (GET /api/auth/me),
   role gating (Auth.can), and the CSRF token echoed on mutating requests.
   Loaded BEFORE app.js; exposes window.Auth. Wrapped in an IIFE so it can keep
   its own el()/$ helpers without colliding with app.js's globals. */

"use strict";

(function () {
  const SESSION_COOKIE = "muninn_session";  // HttpOnly — invisible to JS (server-only)
  const CSRF_COOKIE = "muninn_csrf";         // readable — echoed as X-CSRF-Token
  // Supabase mode: the server returns a session (access + refresh token) in the body;
  // we persist it in localStorage and send it as a Bearer header. The HttpOnly cookie
  // stays empty in that mode — tokens live here, scoped to the app's own origin.
  const SB_KEY = "muninn.supabase.session";

  // Role hierarchy (mirrors backend/models.py ROLE_RANK) + client capability gates.
  // Capabilities mirror the SERVER route table (docs §5), so the UI never offers a
  // control the server would 403: the client hides, the server still enforces.
  const RANK = { viewer: 0, responder: 1, admin: 2 };
  const CAP_MIN = {
    view: "viewer", recall: "viewer",
    // Read-only analysis (run triage, cold/warm compare, reflect) is a viewer capability —
    // it mutates nothing. Writing (create/transition/resolve/feedback) needs responder.
    triage: "viewer", mutate: "responder",
    seed: "admin", reset: "admin", users: "admin",
  };
  const DEFAULT_DEMO_ROLES = ["viewer", "responder", "admin"];

  let _user = null;      // the authenticated account, or null when logged out
  let _csrf = "";        // cached CSRF token (cookie is authoritative — see csrf())
  let _session = null;   // {access_token, refresh_token, expires_in} in Supabase mode
  let _refreshTimer = null; // proactive token-refresh timer (Supabase mode)
  let _onAuth = null;    // app boot callback, registered by app.js via onAuthenticated()
  let _lastFocus = null; // element focused before the auth screen opened
  let _demo = false;     // is the current session an OPEN-DEMO session (no real login)?
  let _demoRoles = DEFAULT_DEMO_ROLES.slice();  // roles offered by the server's demo mode
  let _returnToDemo = false;  // show a "back to demo" escape on the auth screen
  let _backend = "local";    // active auth backend, as reported by /api/auth/me

  /* ---- tiny DOM helpers (local to this module) ---- */
  const qs = (sel, root) => (root || document).querySelector(sel);
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  };
  const clearNode = (n) => { while (n.firstChild) n.removeChild(n.firstChild); };
  function readCookie(name) {
    const parts = document.cookie ? document.cookie.split("; ") : [];
    for (const p of parts) {
      const i = p.indexOf("=");
      if (i > -1 && p.slice(0, i) === name) return decodeURIComponent(p.slice(i + 1));
    }
    return "";
  }

  /* ---- Supabase session persistence (localStorage + auto-refresh) ---- */
  function _loadSession() {
    try {
      const raw = window.localStorage.getItem(SB_KEY);
      if (!raw) return null;
      const s = JSON.parse(raw);
      return (s && s.access_token) ? s : null;
    } catch (_) { return null; }
  }
  function _saveSession(s) {
    _session = s && s.access_token ? s : null;
    try {
      if (_session) window.localStorage.setItem(SB_KEY, JSON.stringify(_session));
      else window.localStorage.removeItem(SB_KEY);
    } catch (_) { /* private mode / storage quota — session stays in memory */ }
  }
  function _clearRefreshTimer() {
    if (_refreshTimer) { clearTimeout(_refreshTimer); _refreshTimer = null; }
  }
  // Refresh ~1 minute before expiry; skip when the lifetime is unknown. Prefer the
  // persisted absolute `expires_at` (correct across reloads) and fall back to the
  // relative `expires_in` for a freshly-minted session that hasn't been stamped yet.
  function _scheduleRefresh() {
    _clearRefreshTimer();
    if (!_session || !_session.refresh_token) return;
    let remainingMs;
    if (_session.expires_at) remainingMs = _session.expires_at - Date.now();
    else if (_session.expires_in) remainingMs = _session.expires_in * 1000;
    else return;
    const delay = Math.max(30_000, remainingMs - 60_000);
    _refreshTimer = setTimeout(() => {
      Auth.refresh().catch(() => { /* 401 path handles the failed refresh */ });
    }, delay);
  }
  async function _refreshSession(refreshToken) {
    const data = await authFetch("/api/auth/refresh", {
      method: "POST", body: { refresh_token: refreshToken },
    });
    if (data && data.session && data.session.access_token) {
      _saveSession(data.session);
      _setUser(data.user, "");
      _scheduleRefresh();
    }
    return data;
  }

  /* ---- auth-owned fetch (bypasses app.js's global 401 handler) ----
     me()/login()/signup()/logout() go through here so a failed login (401) shows a
     form error rather than tripping the "session expired" boot loop in app.js. */
  async function authFetch(path, opts) {
    const o = opts || {};
    const headers = Object.assign({ "Accept": "application/json" }, o.headers || {});
    if (_session && _session.access_token) headers["Authorization"] = `Bearer ${_session.access_token}`;
    const mutating = o.method && o.method !== "GET";
    if (o.body != null) headers["Content-Type"] = "application/json";
    if (mutating) { const c = Auth.csrf(); if (c) headers["X-CSRF-Token"] = c; }
    const r = await fetch(path, {
      method: o.method || "GET", headers,
      body: o.body != null ? JSON.stringify(o.body) : undefined,
    });
    let data = null;
    try { data = await r.json(); } catch (_) { /* empty / non-JSON body */ }
    if (!r.ok) {
      const msg = (data && (data.message || data.error)) || `HTTP ${r.status}`;
      const err = new Error(msg); err.status = r.status; err.data = data; throw err;
    }
    return data;
  }

  function _setUser(user, csrf) {
    _user = user || null;
    if (csrf) _csrf = csrf;
  }

  function _applySessionData(data) {
    /* Shared post-login/signup handling: persist the Supabase session (when the server
       returned one) and record the user. Returns {user, pending} — pending=true means a
       Supabase signup that returned NO session (email confirmation required), so the
       caller must not enter the app with an unusable session. */
    let pending = false;
    if (data && data.session && data.session.access_token) {
      _saveSession(data.session);
      _scheduleRefresh();
    } else {
      // No session: either local mode (cookie was set) or a Supabase signup pending
      // email confirmation. Only the latter leaves the user without credentials.
      pending = !!(data && data.backend === "supabase" && data.user);
      if (!pending && !_isLocalCookieSession()) _saveSession(null);
    }
    _setUser(data.user, data.csrf || "");
    _demo = false; _returnToDemo = false;   // a real login supersedes any demo session
    return { user: data.user, pending };
  }
  // A local-mode session rides in the HttpOnly muninn_session cookie; the csrf cookie
  // is set alongside it. Used to avoid clobbering a live cookie session with a null
  // Supabase session on a /me response that has no body session.
  function _isLocalCookieSession() {
    return !!readCookie(CSRF_COOKIE) || _csrf !== "";
  }

  // A demo session is recognised by its account email: the server provisions one account
  // per role as `<role>@muninn.local` (see backend/services/auth.py DEMO_ACCOUNTS).
  function _isDemoEmail(email) {
    return !!email && _demoRoles.some((r) => email === r + "@muninn.local");
  }

  /* ---- public API surface (window.Auth) ---- */
  const Auth = {
    user() { return _user; },
    // The muninn_csrf cookie is JS-readable and always current; fall back to cache.
    csrf() { return readCookie(CSRF_COOKIE) || _csrf; },
    // The Supabase access token ("" in local mode) — app.js attaches it to every request.
    accessToken() { return (_session && _session.access_token) || ""; },
    backend() { return _backend; },

    // Proactive token refresh (Supabase mode): rotate the refresh token for a new
    // access token. Returns true on success; a failure clears the stale session.
    async refresh() {
      if (!_session || !_session.refresh_token) return false;
      try {
        await _refreshSession(_session.refresh_token);
        return true;
      } catch (e) {
        if (e && (e.status === 401 || e.status === 400)) {
          _saveSession(null); _clearRefreshTimer();
        }
        return false;
      }
    },
    can(cap) {
      if (!_user) return false;
      const need = CAP_MIN[cap];
      if (need == null) return false;
      const have = RANK[_user.role];
      return have != null && have >= RANK[need];
    },
    onAuthenticated(cb) { _onAuth = cb; },

    // Open-demo mode helpers (no-ops when the server has it disabled).
    isDemo() { return _demo; },
    demoRoles() { return _demoRoles.slice(); },
    async demoStatus() {
      try { return await authFetch("/api/auth/demo-status"); }
      catch (_) { return { enabled: false, roles: DEFAULT_DEMO_ROLES.slice() }; }
    },
    async demoLogin(role) {
      const data = await authFetch("/api/auth/demo-login", { method: "POST", body: { role } });
      _setUser(data.user, readCookie(CSRF_COOKIE));
      _demo = true;
      return data.user;
    },

    // Silently re-establish a session + fresh CSRF token when a mutation is rejected for a
    // stale/invalid token (typically the server was restarted under an open tab). Returns true
    // if a usable session was minted. In open-demo mode this re-runs demo-login as the current
    // role — demo-login is CSRF-exempt, so a stale token cannot block the recovery. With a real
    // account there is nothing to renew without credentials, so it reports failure and the
    // caller falls back to the normal sign-in gate.
    async reauth() {
      try {
        if (_demo) {
          const role = (_user && _user.role) || "admin";
          await Auth.demoLogin(role);
          return true;
        }
      } catch (_) { /* recovery unavailable — fall through */ }
      return false;
    },

    // Open the real login/sign-up screen even while in demo mode; a "back to demo" escape
    // is offered so the visitor is never trapped at the gate.
    openLogin() { _returnToDemo = _demo; _showAuth(); },

    async me() {
      const data = await authFetch("/api/auth/me");   // raw — bypasses global 401 handler
      _backend = data.backend || _backend;
      _setUser(data.user, data.csrf);
      return data.user;
    },

    async login(email, password) {
      const data = await authFetch("/api/auth/login", { method: "POST", body: { email, password } });
      _backend = data.backend || _backend;
      return _applySessionData(data).user;
    },

    async signup(email, password, name) {
      const data = await authFetch("/api/auth/signup",
        { method: "POST", body: { email, password, name: name || "" } });
      _backend = data.backend || _backend;
      return _applySessionData(data);   // {user, pending} — see _applySessionData
    },

    async logout() {
      try { await authFetch("/api/auth/logout", { method: "POST" }); }
      catch (_) { /* drop the client session regardless of the server's reply */ }
      _user = null; _csrf = ""; _demo = false;
      _saveSession(null); _clearRefreshTimer();
      // In open-demo mode there is no gate to fall back to — re-enter the demo instead of
      // stranding the visitor. Otherwise show the sign-in screen.
      Auth.require();
    },

    // Boot gate. Priority: (1) an existing session (real OR demo) via me(); (2) when none,
    // open-demo mode if the server enables it (default to admin so the demo is immediately
    // useful); (3) otherwise the login gate. me() bypasses the global 401 handler, so a
    // missing session never trips app.js's "session expired" loop.
    //
    // Supabase mode: a persisted session from localStorage rides as a Bearer header on
    // me(); when the access token has expired but a refresh token remains, one silent
    // refresh is attempted first — session persistence across reloads without the user
    // ever seeing a 401.
    async require() {
      _session = _loadSession();
      if (_session && _session.refresh_token && _session.expires_at &&
          Date.now() >= _session.expires_at - 60_000) {
        const ok = await Auth.refresh();
        if (!ok) _session = _loadSession();
      }
      let user = null;
      try { user = await Auth.me(); }
      catch (e) {
        // An expired access token with a live refresh token: one silent retry.
        if (e && e.status === 401 && _session && _session.refresh_token) {
          const ok = await Auth.refresh();
          if (ok) {
            try { user = await Auth.me(); } catch (_) { /* fall through to the gate */ }
          }
        }
      }
      const status = await Auth.demoStatus();
      const demoEnabled = !!(status && status.enabled);
      _demoRoles = (status && status.roles && status.roles.length)
        ? status.roles.slice() : DEFAULT_DEMO_ROLES.slice();
      if (user) {
        _demo = demoEnabled && _isDemoEmail(user.email);
        if (!_session && !_isLocalCookieSession()) _saveSession(null);  // tidy stale state
        if (_session) _scheduleRefresh();  // re-arm proactive refresh for a restored session
        _finishAuth(user);
        return user;
      }
      if (demoEnabled) {
        try {
          const demoUser = await Auth.demoLogin("admin");   // no login needed — default admin
          _finishAuth(demoUser);
          return demoUser;
        } catch (_) { /* demo bootstrap unavailable — fall through to the gate */ }
      }
      _showAuth();
      return null;
    },

    onUnauthorized(msg) {
      _user = null; _csrf = "";
      _saveSession(null); _clearRefreshTimer();
      _showAuth(msg || "Session expired — please sign in again.");
    },

    renderAuthScreen(message) { _renderAuthScreen(message); },
  };
  window.Auth = Auth;

  /* ---- screen show/hide ---- */
  function _showApp() {
    const root = qs("#auth-root");
    if (root) { root.hidden = true; root.setAttribute("aria-hidden", "true"); clearNode(root); }
    const app = qs("#app");
    if (app) app.hidden = false;
    document.removeEventListener("keydown", _trapFocus, true);
    if (_lastFocus && typeof _lastFocus.focus === "function") { try { _lastFocus.focus(); } catch (_) {} }
  }

  function _showAuth(message) {
    const app = qs("#app");
    if (app) app.hidden = true;
    _renderAuthScreen(message);
  }

  function _finishAuth(user) {
    _showApp();
    if (typeof _onAuth === "function") _onAuth(user);
  }

  // Persist an expiry timestamp alongside the session so reloads can decide whether a
  // silent refresh is needed before the first request.
  const _origSaveSession = _saveSession;
  _saveSession = function (s) {
    if (s && s.expires_in && !s.expires_at) {
      s = Object.assign({}, s, { expires_at: Date.now() + s.expires_in * 1000 });
    }
    _origSaveSession(s);
  };

  /* ---- form building blocks (labelled, accessible) ---- */
  function _formRow(id, labelText, type, autocomplete, required) {
    const row = el("div", "form-row");
    const label = el("label", null, labelText);
    label.htmlFor = id;
    const input = el("input", "field");
    input.id = id; input.name = id; input.type = type;
    if (autocomplete) input.autocomplete = autocomplete;
    if (required) input.required = true;
    row.appendChild(label); row.appendChild(input);
    return { row, input };
  }
  function _errorRegion(id) {
    const e = el("p", "field-error");
    e.id = id;
    e.setAttribute("role", "alert");
    e.setAttribute("aria-live", "assertive");
    e.hidden = true;
    return e;
  }
  function _setError(region, inputs, msg) {
    region.textContent = msg; region.hidden = false;
    (inputs || []).forEach((i) => i.setAttribute("aria-invalid", "true"));
  }
  function _clearError(region, inputs) {
    region.textContent = ""; region.hidden = true;
    (inputs || []).forEach((i) => i.removeAttribute("aria-invalid"));
  }
  function _busy(btn, on, label) { btn.disabled = on; btn.textContent = label; }

  function _buildLoginForm() {
    const form = el("form", "auth-form"); form.id = "login-form"; form.noValidate = true;
    form.setAttribute("role", "tabpanel");
    form.setAttribute("aria-labelledby", "tab-login");
    const err = _errorRegion("login-error");
    const email = _formRow("login-email", "Email", "email", "email", true);
    const pw = _formRow("login-password", "Password", "password", "current-password", true);
    const submit = el("button", "btn auth-submit", "Sign in"); submit.type = "submit";
    [err, email.row, pw.row, submit].forEach((n) => form.appendChild(n));
    const setError = (m) => _setError(err, [email.input, pw.input], m);
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      _clearError(err, [email.input, pw.input]);
      if (!email.input.value.trim() || !pw.input.value) { setError("Enter your email and password."); return; }
      _busy(submit, true, "Signing in…");
      try {
        const user = await Auth.login(email.input.value.trim(), pw.input.value);
        _finishAuth(user);
      } catch (ex) {
        setError(ex.status === 429 ? "Too many attempts — try again in a few minutes."
                                   : (ex.message || "Sign in failed."));
        _busy(submit, false, "Sign in");
        pw.input.focus();
      }
    });
    return { form, first: email.input, setError };
  }

  function _buildSignupForm(onPendingConfirmation) {
    const form = el("form", "auth-form"); form.id = "signup-form"; form.hidden = true;
    form.noValidate = true;
    form.setAttribute("role", "tabpanel");
    form.setAttribute("aria-labelledby", "tab-signup");
    const err = _errorRegion("signup-error");
    const name = _formRow("signup-name", "Display name (optional)", "text", "name", false);
    const email = _formRow("signup-email", "Email", "email", "email", true);
    const pw = _formRow("signup-password", "Password", "password", "new-password", true);
    const confirm = _formRow("signup-confirm", "Confirm password", "password", "new-password", true);
    const hint = el("p", "auth-hint", "At least 8 characters. The first account created becomes the admin.");
    const submit = el("button", "btn auth-submit", "Create account"); submit.type = "submit";
    [err, name.row, email.row, pw.row, confirm.row, hint, submit].forEach((n) => form.appendChild(n));
    const inputs = [name.input, email.input, pw.input, confirm.input];
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      _clearError(err, inputs);
      const emailV = email.input.value.trim();
      if (!emailV) { _setError(err, [email.input], "Email is required."); return; }
      if (pw.input.value.length < 8) { _setError(err, [pw.input], "Password must be at least 8 characters."); return; }
      if (pw.input.value !== confirm.input.value) {
        _setError(err, [pw.input, confirm.input], "Passwords don't match."); return;
      }
      _busy(submit, true, "Creating…");
      try {
        const { user, pending } = await Auth.signup(emailV, pw.input.value, name.input.value.trim());
        if (pending) {
          // Supabase email-confirmation flow: no session yet — hand control back to the
          // auth screen (it flips to the login tab and explains what to do next).
          _setUser(null, "");
          onPendingConfirmation();
          _busy(submit, false, "Create account");
          return;
        }
        _finishAuth(user);
      } catch (ex) {
        _setError(err, [email.input], ex.message || "Sign up failed.");
        _busy(submit, false, "Create account");
      }
    });
    return { form, first: name.input };
  }

  /* ---- the auth screen (centered card on a full-viewport backdrop) ---- */
  function _renderAuthScreen(message) {
    _lastFocus = document.activeElement;
    const root = qs("#auth-root");
    if (!root) return;
    clearNode(root);
    root.hidden = false; root.removeAttribute("aria-hidden");

    const card = el("div", "auth-card");
    card.setAttribute("role", "dialog");
    card.setAttribute("aria-modal", "true");
    card.setAttribute("aria-labelledby", "auth-title");

    const brand = el("div", "auth-brand");
    brand.appendChild(el("span", "rune", "ᛗ"));
    const title = el("h1", "auth-title", "muninn"); title.id = "auth-title";
    brand.appendChild(title);
    card.appendChild(brand);
    card.appendChild(el("p", "auth-tagline", "Incident memory — sign in to continue."));

    const tabs = el("div", "auth-tabs");
    tabs.setAttribute("role", "tablist");
    tabs.setAttribute("aria-label", "Log in or create an account");
    const loginTab = el("button", "auth-tab", "Log in"); loginTab.id = "tab-login";
    const signupTab = el("button", "auth-tab", "Sign up"); signupTab.id = "tab-signup";
    [loginTab, signupTab].forEach((t) => {
      t.type = "button"; t.setAttribute("role", "tab");
    });
    loginTab.setAttribute("aria-controls", "login-form");
    signupTab.setAttribute("aria-controls", "signup-form");
    tabs.appendChild(loginTab); tabs.appendChild(signupTab);
    card.appendChild(tabs);

    const login = _buildLoginForm();
    const signup = _buildSignupForm(() => {
      // Signup succeeded but no session came back (Supabase email confirmation is on):
      // the account exists — send them to log in after confirming.
      select("login");
      login.setError("Account created — check your inbox and confirm your email, then sign in.");
    });
    card.appendChild(login.form); card.appendChild(signup.form);

    // When the gate is opened voluntarily from open-demo mode, offer an escape back to the
    // running demo so the visitor is never stranded at a login they don't actually need.
    if (_returnToDemo && _user) {
      const back = el("button", "auth-back", "← Continue in demo mode");
      back.type = "button";
      back.addEventListener("click", () => { _returnToDemo = false; _finishAuth(_user); });
      card.appendChild(back);
    }
    root.appendChild(card);

    const select = (which) => {
      const isLogin = which === "login";
      loginTab.setAttribute("aria-selected", String(isLogin));
      signupTab.setAttribute("aria-selected", String(!isLogin));
      loginTab.tabIndex = isLogin ? 0 : -1;
      signupTab.tabIndex = isLogin ? -1 : 0;
      login.form.hidden = !isLogin;
      signup.form.hidden = isLogin;
      const first = (isLogin ? login : signup).first;
      if (first) first.focus();
    };
    loginTab.addEventListener("click", () => select("login"));
    signupTab.addEventListener("click", () => select("signup"));
    tabs.addEventListener("keydown", (e) => {
      if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
      e.preventDefault();
      select(document.activeElement === loginTab ? "signup" : "login");
    });

    select("login");
    if (message) login.setError(message);   // keep focus on the field, announce the message
    document.addEventListener("keydown", _trapFocus, true);
  }

  /* ---- focus trap: keep Tab inside the modal card while the gate is up ---- */
  function _trapFocus(e) {
    if (e.key !== "Tab") return;
    const root = qs("#auth-root");
    if (!root || root.hidden) return;
    const nodes = root.querySelectorAll(
      'a[href], button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])');
    const visible = Array.prototype.filter.call(nodes, (n) => n.offsetParent !== null);
    if (!visible.length) return;
    const first = visible[0], last = visible[visible.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  }
})();
