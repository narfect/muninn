"""Muninn HTTP server bootstrap (CONCRETE — wiring + transport, not business logic).

Wires the layered app together and serves it with the stdlib threaded HTTP server:

    settings -> init_db -> Repository
             -> build_memory_store(settings)      (Hindsight or offline Local)
             -> build_reasoner(settings)           (Groq or offline Local)
             -> TriageAgent(reasoner, memory, repo)
             -> IncidentService / TriageService / MetricsService
             -> Routes(ctx).table() -> Router
             -> ThreadingHTTPServer  (JSON API under /api/*, static SPA otherwise)

The API handlers themselves live in ``backend/api/routes.py`` and are stubs until
Claude Code implements them (they return HTTP 501 via the router). This bootstrap is
intentionally complete so ``python -m backend.server`` starts a running skeleton.
"""
from __future__ import annotations

import json
import logging
import mimetypes
import os
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .api import Routes
from .config import ROOT, Settings, settings as default_settings
from .db import Repository, init_db
from .llm import build_reasoner
from .llm.agent import TriageAgent
from .memory import build_memory_store
from .ratelimit import RateLimiter
from .router import Request, Response, Router
from .services.auth_unified import UnifiedAuthService as AuthService
from .services.incidents import IncidentService
from .services.metrics import MetricsService
from .services.triage import TriageService

log = logging.getLogger("muninn.server")

STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")
SAMPLE_PATH = ROOT / "data" / "seed_sample.json"


@dataclass
class AppContext:
    """Container for the wired application components (handed to Routes)."""

    settings: Settings
    repo: Repository
    memory: Any
    reasoner: Any
    agent: TriageAgent
    incidents: IncidentService
    triage: TriageService
    metrics: MetricsService
    auth: AuthService
    # Per-IP fixed-window throttles for the public auth endpoints (see backend/ratelimit.py).
    # Held on the context so each wired app (and each test) gets an isolated limiter.
    login_limiter: RateLimiter
    signup_limiter: RateLimiter


def build_context(settings: Settings = default_settings) -> AppContext:
    """Construct and wire every layer. Safe to call at import time (no I/O beyond db init)."""
    init_db(settings.db_path)
    repo = Repository(settings.db_path)
    memory = build_memory_store(settings)
    reasoner = build_reasoner(settings)
    agent = TriageAgent(reasoner=reasoner, memory=memory, repo=repo)
    incidents = IncidentService(repo=repo, memory=memory)
    triage = TriageService(memory=memory, agent=agent, repo=repo, top_k=settings.recall_top_k)
    metrics = MetricsService(repo=repo, memory=memory)
    auth = AuthService(repo=repo, settings=settings)
    return AppContext(settings=settings, repo=repo, memory=memory, reasoner=reasoner,
                      agent=agent, incidents=incidents, triage=triage, metrics=metrics,
                      auth=auth,
                      login_limiter=RateLimiter(settings.rl_login),
                      signup_limiter=RateLimiter(settings.rl_signup))


def build_router(ctx: AppContext) -> Router:
    return Router(Routes(ctx).table(), auth=ctx.auth)


def _maybe_autoseed(ctx: AppContext) -> None:
    """Load the labeled synthetic dataset when the DB has no incidents and autoseed is on,
    so the app is never a blank slate. No-op when data already exists or the flag is off."""
    if not ctx.settings.demo_autoseed:
        return
    if ctx.repo.list_incidents(limit=1):
        return  # data already present — leave it untouched
    try:
        data = json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("autoseed skipped: %s", exc)
        return
    counts = ctx.incidents.seed(data)  # reuses the exact /api/demo/seed path
    log.info("autoseeded synthetic demo dataset: %s", counts)


def bootstrap(ctx: AppContext) -> None:
    """Startup side effects for the LOCAL demo, both flag-gated and idempotent: autoseed an
    empty DB and provision the open-demo accounts. Kept out of :func:`build_context` so tests
    wire the app without these effects and invoke this explicitly when they want them."""
    _maybe_autoseed(ctx)
    # Open demo is local-only. In Supabase mode the demo routes self-gate on
    # ``using_supabase`` (demo-status reports disabled), so skip both the provisioning and
    # the warning — otherwise the log claims the login gate is bypassed when it is not.
    if ctx.settings.demo_open and not ctx.auth.using_supabase:
        log.warning(
            "OPEN DEMO MODE is ON (MUNINN_DEMO_OPEN): the login gate is bypassed and anyone "
            "who can reach this server may mint an ADMIN session via POST /api/auth/demo-login. "
            "This is for the LOCAL, offline demo ONLY. Any non-local deployment MUST set a real "
            "MUNINN_SERVER_SECRET (which force-disables open demo) and MUNINN_COOKIE_SECURE=true "
            "behind HTTPS."
        )
        ctx.auth.ensure_demo_accounts()


def _safe_static_path(url_path: str) -> str | None:
    """Resolve a URL path to a file inside STATIC_DIR, or None if it escapes/doesn't exist."""
    rel = "index.html" if url_path in ("", "/") else url_path.lstrip("/")
    target = os.path.normpath(os.path.join(STATIC_DIR, rel))
    if not target.startswith(os.path.abspath(STATIC_DIR) + os.sep) and target != os.path.abspath(STATIC_DIR):
        return None  # path traversal attempt
    return target if os.path.isfile(target) else None


def make_handler(router: Router, max_body_bytes: int = 1_048_576):
    class MuninnHandler(BaseHTTPRequestHandler):
        server_version = "Muninn/1.0"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: Any) -> None:  # route through logging
            log.info("%s - %s", self.address_string(), fmt % args)

        def _content_length(self) -> int:
            try:
                return max(0, int(self.headers.get("Content-Length", 0) or 0))
            except (TypeError, ValueError):
                return 0

        def _read_body(self) -> bytes:
            length = self._content_length()
            return self.rfile.read(length) if length else b""

        # SEC3: minimal response hardening headers applied to every response.
        _SECURITY_HEADERS = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            # Lock the SPA to same-origin resources. index.html + app.js/auth.js load only
            # same-origin scripts/styles and carry NO inline <script>/<style> or on* handlers
            # (dynamic styling goes through the CSSOM, which CSP doesn't gate), so no
            # 'unsafe-inline' is needed — and it is deliberately never added to script-src.
            "Content-Security-Policy": (
                "default-src 'self'; object-src 'none'; base-uri 'self'; "
                "frame-ancestors 'none'"
            ),
        }

        def _send_security_headers(self) -> None:
            for k, v in self._SECURITY_HEADERS.items():
                self.send_header(k, v)

        def _write(self, resp: Response) -> None:
            if resp.stream is not None:
                self._write_stream(resp)
                return
            self.send_response(resp.status)
            for k, v in resp.headers.items():
                self.send_header(k, v)
            self._send_security_headers()
            for cookie in resp.cookies:
                self.send_header("Set-Cookie", cookie)
            self.send_header("Content-Length", str(len(resp.body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(resp.body)

        def _write_stream(self, resp: Response) -> None:
            self.send_response(resp.status)
            for k, v in resp.headers.items():
                self.send_header(k, v)
            self._send_security_headers()
            for cookie in resp.cookies:
                self.send_header("Set-Cookie", cookie)
            # S10: one SSE response per connection — never keep it alive.
            self.close_connection = True
            if self.command == "HEAD":
                # A HEAD must not spawn the worker or stream a body: send headers and stop
                # BEFORE iterating resp.stream() (which is what starts the triage worker).
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.end_headers()
            try:
                for chunk in resp.stream():  # type: ignore[misc]
                    self.wfile.write(chunk.encode("utf-8"))
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                log.info("client disconnected from stream")

        def _serve_static(self) -> None:
            target = _safe_static_path(self.path.split("?", 1)[0])
            if target is None:
                # SPA fallback: unknown non-API GET -> index.html if present
                index = os.path.join(STATIC_DIR, "index.html")
                target = index if os.path.isfile(index) else None
            if target is None:
                self._write(Response.error("not found", status=404, code="not_found"))
                return
            ctype = mimetypes.guess_type(target)[0] or "application/octet-stream"
            with open(target, "rb") as fh:
                data = fh.read()
            self._write(Response(status=200, body=data, headers={"Content-Type": ctype}))

        def _handle(self, method: str) -> None:
            path = self.path.split("?", 1)[0]
            if method == "GET" and not path.startswith("/api/"):
                self._serve_static()
                return
            # S9: reject an oversized body from its declared Content-Length, BEFORE reading
            # it, so a bogus length can't exhaust memory. Close the connection since the
            # unread body would otherwise desync a kept-alive stream.
            if self._content_length() > max_body_bytes:
                self.close_connection = True
                self._write(Response.error("request body too large", status=413,
                                           code="payload_too_large"))
                return
            req = Request.build(method, self.path, dict(self.headers), self._read_body())
            # Real socket peer for per-IP auth rate limiting. NOT X-Forwarded-For: with no
            # trusted-proxy allowlist, a client-supplied forwarding header could spoof the IP.
            req.client_ip = self.client_address[0] if self.client_address else ""
            self._write(router.dispatch(req))

        def do_GET(self) -> None:
            self._handle("GET")

        def do_POST(self) -> None:
            self._handle("POST")

        def do_PATCH(self) -> None:
            self._handle("PATCH")

        def do_HEAD(self) -> None:
            self._handle("GET")

    return MuninnHandler


def run(settings: Settings = default_settings) -> None:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    ctx = build_context(settings)
    bootstrap(ctx)
    router = build_router(ctx)
    httpd = ThreadingHTTPServer((settings.host, settings.port),
                                make_handler(router, settings.max_body_bytes))
    log.info("Muninn listening on http://%s:%d  (memory=%s, llm=%s, demo_open=%s)",
             settings.host, settings.port,
             settings.resolved_memory_backend(), settings.resolved_llm_backend(),
             settings.demo_open)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log.info("shutting down")
    finally:
        httpd.server_close()
        # Leave the DB compact on a clean shutdown: flush + truncate the WAL.
        ctx.repo.checkpoint()


def main() -> None:
    run()


if __name__ == "__main__":
    main()
