"""HTTP API endpoint handlers (FR-8/9/13 + happy path).

Each handler receives a ``Request`` and the wired ``AppContext`` (services) and returns
a ``Response``. Handlers are defensive: validate input, return structured JSON errors
with correct status codes, and never leak stack traces (the router logs + shapes 500s).
"""
from __future__ import annotations

import json
import queue
import threading
from typing import TYPE_CHECKING, Any, Optional

from ..config import ROOT
from ..errors import LockedError, NotFoundError
from ..models import ADMIN, RESPONDER, VIEWER, Incident
from ..router import Request, Response

if TYPE_CHECKING:  # avoid import cycle at runtime
    from ..server import AppContext

_SAMPLE = ROOT / "data" / "seed_sample.json"


class Routes:
    """Groups endpoint handlers around the wired application context."""

    def __init__(self, ctx: "AppContext") -> None:
        self.ctx = ctx

    # --- system -----------------------------------------------------------
    def health(self, req: "Request") -> "Response":
        # An anonymous probe gets liveness only. The backend/provenance detail below reveals
        # which memory/LLM backends are configured and how many memories exist — deployment
        # fingerprinting an unauthenticated caller has no need for — so it is authenticated-
        # only (any role). The frontend health badges run after the boot gate authenticates.
        if req.current_user is None:
            return Response.json({"status": "ok"})
        return Response.json({
            "status": "ok",
            "memory": self.ctx.memory.health(),
            "llm": self.ctx.reasoner.health(),
            "memory_backend": self.ctx.settings.resolved_memory_backend(),
            "llm_backend": self.ctx.settings.resolved_llm_backend(),
            "n_memories": self.ctx.memory.count(),
        })

    # --- auth -------------------------------------------------------------
    # In Supabase mode the session (access + refresh token) is returned in the JSON body
    # and the SPA persists it; cookies stay empty. In local mode the token rides in
    # HttpOnly cookies exactly as before. Both shapes share the "user" key.

    def _auth_response(self, user, token: str, csrf: str, status: int = 200,
                       session: Optional[dict] = None) -> "Response":
        """Build the auth response for the active backend (body + optional cookies)."""
        auth = self.ctx.auth
        payload = auth.build_session_payload(user, token, session=session)
        resp = Response.json(payload, status=status)
        cookie = auth.session_cookie(token)
        if cookie:
            resp.cookies = [cookie, auth.csrf_cookie(csrf)]
        return resp

    def signup(self, req: "Request") -> "Response":
        self._enforce_rate_limit(req, self.ctx.signup_limiter)
        body = req.json()
        user, token, csrf, session = self.ctx.auth.signup_full(
            email=str(body.get("email", "")), password=str(body.get("password", "")),
            name=str(body.get("name", "")))
        return self._auth_response(user, token, csrf, status=201, session=session)

    def login(self, req: "Request") -> "Response":
        self._enforce_rate_limit(req, self.ctx.login_limiter)
        body = req.json()
        user, token, csrf, session = self.ctx.auth.login_full(
            email=str(body.get("email", "")), password=str(body.get("password", "")))
        return self._auth_response(user, token, csrf, session=session)

    def refresh(self, req: "Request") -> "Response":
        """Rotate a Supabase refresh token into a fresh session (404 in local mode,
        where sessions are cookie-backed and never need explicit refresh)."""
        if not self.ctx.auth.using_supabase:
            return Response.error("not found", status=404, code="not_found")
        refresh_token = str(req.json().get("refresh_token", ""))
        payload = self.ctx.auth.refresh_session(refresh_token)
        return Response.json(payload)

    def logout(self, req: "Request") -> "Response":
        self.ctx.auth.logout(req.token)
        resp = Response.json({"ok": True})
        resp.cookies = self.ctx.auth.clear_cookies()
        return resp

    def auth_me(self, req: "Request") -> "Response":
        csrf = self.ctx.auth.csrf_token(req.token_hash)
        body: dict = {"user": req.current_user.as_dict(), "csrf": csrf,
                      "backend": self.ctx.auth.backend}
        resp = Response.json(body)
        # Re-issue the JS-readable CSRF cookie on every boot-gate check so the SPA always
        # holds a token derived from the CURRENT server secret. Without this, a session
        # minted under one MUNINN_SERVER_SECRET keeps a stale muninn_csrf cookie after the
        # secret rotates (e.g. a restart with the ephemeral default), and the double-submit
        # token stops matching csrf_token(token_hash) — every mutating request then 403s
        # even though the session itself still authenticates. This self-heals on the next
        # GET /api/auth/me (which auth.js runs at boot).
        cookie = self.ctx.auth.csrf_cookie(csrf)
        if cookie:
            resp.cookies = [cookie]
        return resp

    def get_profile(self, req: "Request") -> "Response":
        """Current user's profile row (Supabase mode; 404 in local mode)."""
        if not self.ctx.auth.using_supabase:
            return Response.error("not found", status=404, code="not_found")
        profile = self.ctx.auth.get_supabase_profile(
            str(req.current_user.id), req.token or "")
        return Response.json({"profile": profile.as_dict()})

    def update_profile(self, req: "Request") -> "Response":
        """Update the current user's own profile (Supabase mode; RLS-enforced)."""
        if not self.ctx.auth.using_supabase:
            return Response.error("not found", status=404, code="not_found")
        data = req.json()
        profile = self.ctx.auth.update_supabase_profile(
            str(req.current_user.id), req.token or "", data)
        return Response.json({"profile": profile.as_dict()})

    # --- open demo mode (explicitly enabled; public routes) ----------------------
    def demo_status(self, req: "Request") -> "Response":
        """Report whether explicitly enabled demo mode is available."""
        enabled = bool(self.ctx.settings.demo_open)
        return Response.json({"enabled": enabled,
                              "roles": [VIEWER, RESPONDER, ADMIN]})

    def demo_login(self, req: "Request") -> "Response":
        """Mint a local demo session regardless of the real-account backend."""
        if not self.ctx.settings.demo_open:
            return Response.error("not found", status=404, code="not_found")
        role = str(req.json().get("role", "")).strip().lower()
        user, token, csrf = self.ctx.auth.demo_login(role)
        resp = Response.json({"user": user.as_dict()})
        resp.cookies = [self.ctx.auth.demo_session_cookie(token),
                self.ctx.auth.demo_csrf_cookie(csrf)]
        return resp

    # --- users (admin) ----------------------------------------------------
    def list_users(self, req: "Request") -> "Response":
        # Goes through the auth facade, so Supabase mode lists Supabase profiles (service
        # role) rather than silently returning the local SQLite users table.
        return Response.json({"users": [u.as_dict() for u in self.ctx.auth.list_users()]})

    def set_user_role(self, req: "Request") -> "Response":
        body = req.json()
        role = str(body.get("role", "")).strip().lower()
        user = self.ctx.auth.set_role(self._user_ref(req), role)
        return Response.json({"user": user.as_dict()})

    # --- catalog ----------------------------------------------------------
    def list_services(self, req: "Request") -> "Response":
        return Response.json({"services": [s.as_dict() for s in self.ctx.repo.list_services()]})

    def list_runbooks(self, req: "Request") -> "Response":
        return Response.json({"runbooks": [r.as_dict() for r in self.ctx.repo.list_runbooks()]})

    # --- incidents --------------------------------------------------------
    def list_incidents(self, req: "Request") -> "Response":
        status = req.query.get("status") or None
        service = req.query.get("service") or None
        incs = self.ctx.repo.list_incidents(status=status, service=service)
        return Response.json({"incidents": [i.as_dict() for i in incs]})

    def create_incident(self, req: "Request") -> "Response":
        inc = self.ctx.incidents.create_incident(req.json())
        return Response.json({"incident": inc.as_dict()}, status=201)

    def get_incident(self, req: "Request") -> "Response":
        inc = self.ctx.repo.get_incident(self._id(req))
        if inc is None:
            return Response.error("incident not found", status=404, code="not_found")
        return Response.json({"incident": inc.as_dict(),
                              "timeline": self.ctx.repo.list_timeline(inc.id)})

    def transition_incident(self, req: "Request") -> "Response":
        body = req.json()
        inc = self.ctx.incidents.transition(self._id(req), str(body.get("status", "")))
        return Response.json({"incident": inc.as_dict()})

    def resolve_incident(self, req: "Request") -> "Response":
        body = req.json()
        inc = self.ctx.incidents.resolve(
            self._id(req), root_cause=str(body.get("root_cause", "")),
            remediation_steps=body.get("remediation_steps") or [],
            resolver=str(body.get("resolver", "")))
        return Response.json({"incident": inc.as_dict()})

    def incident_feedback(self, req: "Request") -> "Response":
        body = req.json()
        inc = self.ctx.incidents.record_feedback(
            self._id(req), helpful=bool(body.get("helpful")),
            root_cause_correct=bool(body.get("root_cause_correct")),
            note=str(body.get("note", "")))
        return Response.json({"incident": inc.as_dict()})

    # --- triage / agent ---------------------------------------------------
    def triage(self, req: "Request") -> "Response":
        body = req.json()
        incident = self._incident_from(body)
        use_memory = bool(body.get("use_memory", True))
        out = self.ctx.triage.triage(incident, use_memory=use_memory)
        return Response.json({
            "brief": out["brief"].as_dict(),
            "recall": out["recall"].as_dict() if out["recall"] else None,
        })

    def triage_stream(self, req: "Request") -> "Response":
        incident = self._incident_from(dict(req.query))
        use_memory = req.query.get("use_memory", "true").lower() != "false"
        q: "queue.Queue[tuple[str, Any]]" = queue.Queue()

        def worker() -> None:
            try:
                out = self.ctx.triage.triage(incident, use_memory=use_memory,
                                             stream=lambda t: q.put(("token", t)))
                q.put(("done", out["brief"].as_dict()))
            except Exception as exc:  # noqa: BLE001 - surface as an SSE error frame
                q.put(("error", str(exc)))
            finally:
                q.put(("end", None))

        def gen():
            threading.Thread(target=worker, daemon=True).start()
            while True:
                kind, data = q.get()
                if kind == "end":
                    break
                if kind == "token":
                    yield f"event: token\ndata: {json.dumps({'t': data})}\n\n"
                elif kind == "done":
                    yield f"event: done\ndata: {json.dumps(data)}\n\n"
                elif kind == "error":
                    yield f"event: error\ndata: {json.dumps({'error': data})}\n\n"
        return Response.sse(gen)

    def compare(self, req: "Request") -> "Response":
        incident = self._incident_from(req.json())
        out = self.ctx.triage.compare(incident)
        return Response.json({"cold": out["cold"].as_dict(), "warm": out["warm"].as_dict()})

    # --- memory inspector -------------------------------------------------
    def memory_recall(self, req: "Request") -> "Response":
        body = req.json()
        query = str(body.get("query", "")).strip()
        if not query:
            raise ValueError("query is required")
        # Clamp top_k so a client can't request an unbounded recall: coerce a falsy/absent
        # value to the configured default, floor at 1, and cap at 50. A non-numeric value is
        # a 400 (bad request) via the ValueError below, never an unhandled 500.
        default_k = self.ctx.settings.recall_top_k
        try:
            top_k = int(body.get("top_k", default_k) or default_k)
        except (TypeError, ValueError):
            raise ValueError("top_k must be an integer")
        top_k = max(1, min(top_k, 50))
        return Response.json(self.ctx.memory.recall(query, top_k=top_k).as_dict())

    def memory_reflect(self, req: "Request") -> "Response":
        query = str(req.json().get("query", "")).strip()
        if not query:
            raise ValueError("query is required")
        return Response.json({"reflection": self.ctx.memory.reflect(query),
                              "backend": self.ctx.memory.backend_name})

    # --- metrics ----------------------------------------------------------
    def metrics_summary(self, req: "Request") -> "Response":
        return Response.json(self.ctx.metrics.summary())

    def metrics_mttr(self, req: "Request") -> "Response":
        return Response.json(self.ctx.metrics.mttr(req.query.get("service") or None))

    def metrics_learning_curve(self, req: "Request") -> "Response":
        return Response.json({"series": self.ctx.metrics.learning_curve()})

    # --- demo controls ----------------------------------------------------
    def demo_seed(self, req: "Request") -> "Response":
        try:
            data = json.loads(_SAMPLE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return Response.error(f"seed dataset unavailable: {exc}", status=500,
                                  code="seed_error")
        counts = self.ctx.incidents.seed(data)
        return Response.json({"seeded": counts, "synthetic": True,
                              "note": data.get("meta", {}).get("note", "synthetic demo data")})

    def demo_reset(self, req: "Request") -> "Response":
        self.ctx.repo.reset()
        if hasattr(self.ctx.memory, "reset"):
            self.ctx.memory.reset()
        return Response.json({"reset": True})

    # --- helpers ----------------------------------------------------------
    @staticmethod
    def _enforce_rate_limit(req: "Request", limiter: Any) -> None:
        """Fixed-window per-IP throttle for the auth endpoints. Keys on the client IP ONLY
        (never the email), so it can't be abused to probe whether an account exists, and
        raises a generic ``LockedError`` -> HTTP 429 on overflow, preserving the uniform
        auth-error behaviour. A disabled limiter (limit/window 0) always allows."""
        if not limiter.allow(req.client_ip):
            raise LockedError("too many attempts; please try again later")

    def _id(self, req: "Request") -> int:
        try:
            return int(req.path_params["id"])
        except (KeyError, ValueError):
            raise ValueError("invalid incident id")

    def _user_ref(self, req: "Request") -> object:
        """A user identifier for the admin routes: the raw path segment (a UUID) in
        Supabase mode, or an int row id locally. Both are passed to the auth facade, which
        knows which backend is active."""
        raw = req.path_params.get("id", "")
        if self.ctx.auth.using_supabase:
            if not raw:
                raise ValueError("invalid user id")
            return raw
        try:
            return int(raw)
        except (TypeError, ValueError):
            raise ValueError("invalid user id")

    def _incident_from(self, data: dict[str, Any]) -> Incident:
        """Resolve an incident by id from the store, or build an inline one from fields."""
        inc_id = data.get("incident_id")
        if inc_id not in (None, ""):
            inc = self.ctx.repo.get_incident(int(inc_id))
            if inc is None:
                raise NotFoundError(f"incident {inc_id} not found")
            return inc
        service = str(data.get("service", "")).strip()
        title = str(data.get("title", "")).strip()
        if not service or not title:
            raise ValueError("provide incident_id, or inline title + service")
        tags = data.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        return Incident(
            external_id=str(data.get("external_id", "INLINE")), title=title,
            service=service, severity=str(data.get("severity", "SEV3")).upper(),
            symptom=str(data.get("symptom", title)),
            error_signature=str(data.get("error_signature", "")),
            tags=list(tags), log_excerpt=str(data.get("log_excerpt", "")))

    # --- routing table (CONCRETE STRUCTURE) -------------------------------
    def table(self) -> list[tuple[str, str, Any, Any]]:
        """(method, path_pattern, handler, required_role). ``{id}`` is a path parameter;
        ``required_role=None`` is a public route. The router matches these in order and
        enforces the role hierarchy (viewer < responder < admin); static/SPA is handled by
        the server. Roles follow docs/PRODUCTION_PLAN.md §5–§6: reads AND read-only analysis
        (triage/compare/reflect/recall) are viewer, incident mutations (create/transition/
        resolve/feedback) are responder, demo + user admin are admin. Open-demo status/login
        are public and self-gate on ``settings.demo_open`` (404 when off)."""
        return [
            ("GET", "/api/health", self.health, None),
            ("POST", "/api/auth/signup", self.signup, None),
            ("POST", "/api/auth/login", self.login, None),
            ("POST", "/api/auth/refresh", self.refresh, None),
            ("GET", "/api/auth/demo-status", self.demo_status, None),
            ("POST", "/api/auth/demo-login", self.demo_login, None),
            ("POST", "/api/auth/logout", self.logout, VIEWER),
            ("GET", "/api/auth/me", self.auth_me, VIEWER),
            ("GET", "/api/auth/profile", self.get_profile, VIEWER),
            ("PATCH", "/api/auth/profile", self.update_profile, VIEWER),
            ("GET", "/api/services", self.list_services, VIEWER),
            ("GET", "/api/runbooks", self.list_runbooks, VIEWER),
            ("GET", "/api/incidents", self.list_incidents, VIEWER),
            ("POST", "/api/incidents", self.create_incident, RESPONDER),
            ("GET", "/api/incidents/{id}", self.get_incident, VIEWER),
            ("POST", "/api/incidents/{id}/transition", self.transition_incident, RESPONDER),
            ("POST", "/api/incidents/{id}/resolve", self.resolve_incident, RESPONDER),
            ("POST", "/api/incidents/{id}/feedback", self.incident_feedback, RESPONDER),
            ("POST", "/api/triage", self.triage, VIEWER),
            ("GET", "/api/triage/stream", self.triage_stream, VIEWER),
            ("POST", "/api/compare", self.compare, VIEWER),
            ("POST", "/api/memory/recall", self.memory_recall, VIEWER),
            ("POST", "/api/memory/reflect", self.memory_reflect, VIEWER),
            ("GET", "/api/metrics/summary", self.metrics_summary, VIEWER),
            ("GET", "/api/metrics/mttr", self.metrics_mttr, VIEWER),
            ("GET", "/api/metrics/learning-curve", self.metrics_learning_curve, VIEWER),
            ("POST", "/api/demo/seed", self.demo_seed, ADMIN),
            ("POST", "/api/demo/reset", self.demo_reset, ADMIN),
            ("GET", "/api/users", self.list_users, ADMIN),
            ("PATCH", "/api/users/{id}", self.set_user_role, ADMIN),
        ]
