"""Tiny dependency-free HTTP router (CONCRETE — transport plumbing, not business logic).

Provides ``Request``/``Response`` abstractions, ``{param}`` path matching, JSON and
SSE helpers, and defensive dispatch. Business logic lives in ``backend/api/routes.py``
(handlers) — this module only moves bytes and shapes errors. Handlers that are still
stubs raise ``NotImplementedError`` and are surfaced to the client as HTTP 501, so the
skeleton runs end-to-end before Claude Code implements the endpoints.
"""
from __future__ import annotations

import hmac
import json
import logging
import traceback
from dataclasses import dataclass, field
from http.cookies import CookieError, SimpleCookie
from typing import Any, Callable, Iterator, Optional
from urllib.parse import parse_qs, urlparse

from .errors import AuthError, ConflictError, ForbiddenError, LockedError, NotFoundError
from .models import ROLE_RANK

log = logging.getLogger("muninn.router")

# A streaming body is a generator yielding already-encoded SSE text chunks.
StreamFn = Callable[[], Iterator[str]]

# HTTP methods that mutate state and therefore require a CSRF check when authenticated.
_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}

# Auth types
_AUTH_COOKIE = "cookie"
_AUTH_BEARER = "bearer"


@dataclass
class Request:
    method: str
    path: str
    query: dict[str, str]
    headers: dict[str, str]
    body: bytes = b""
    path_params: dict[str, str] = field(default_factory=dict)
    # Populated by the router's auth middleware (None when unauthenticated).
    current_user: Optional[Any] = None
    token: Optional[str] = None
    token_hash: Optional[str] = None
    auth_type: Optional[str] = None  # "cookie" or "bearer"
    # Remote client IP, set by the server transport (empty in unit tests that build a Request
    # directly). Used only for per-IP auth rate limiting. NOTE: this is the real socket peer,
    # NOT X-Forwarded-For — there is no trusted-proxy allowlist, so honouring a client-supplied
    # forwarding header would let a caller spoof its IP and evade the limit.
    client_ip: str = ""

    def json(self) -> Any:
        """Parse the JSON body; returns {} for an empty body, raises ValueError on bad JSON."""
        if not self.body:
            return {}
        return json.loads(self.body.decode("utf-8"))

    def header(self, name: str, default: str = "") -> str:
        """Case-insensitive header lookup (HTTP header names are case-insensitive)."""
        name = name.lower()
        for k, v in self.headers.items():
            if k.lower() == name:
                return v
        return default

    def cookie(self, name: str) -> Optional[str]:
        """Read a single cookie value from the Cookie header, or None."""
        raw = self.header("cookie")
        if not raw:
            return None
        jar: SimpleCookie = SimpleCookie()
        try:
            jar.load(raw)
        except CookieError:
            return None
        morsel = jar.get(name)
        return morsel.value if morsel else None

    def bearer_token(self) -> Optional[str]:
        """Extract Bearer token from Authorization header."""
        auth = self.header("authorization")
        if auth and auth.lower().startswith("bearer "):
            return auth[7:].strip()
        return None

    @classmethod
    def build(cls, method: str, raw_path: str, headers: dict[str, str], body: bytes) -> "Request":
        parsed = urlparse(raw_path)
        flat = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        return cls(method=method.upper(), path=parsed.path, query=flat, headers=headers, body=body)


@dataclass
class Response:
    status: int = 200
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    stream: Optional[StreamFn] = None  # when set, server emits an SSE response
    cookies: list[str] = field(default_factory=list)  # raw Set-Cookie header values

    @classmethod
    def json(cls, data: Any, status: int = 200) -> "Response":
        payload = json.dumps(data, default=str).encode("utf-8")
        return cls(status=status, body=payload,
                   headers={"Content-Type": "application/json; charset=utf-8"})

    @classmethod
    def text(cls, text: str, status: int = 200, content_type: str = "text/plain; charset=utf-8") -> "Response":
        return cls(status=status, body=text.encode("utf-8"), headers={"Content-Type": content_type})

    @classmethod
    def error(cls, message: str, status: int = 400, code: str = "") -> "Response":
        return cls.json({"error": code or message, "message": message}, status=status)

    @classmethod
    def sse(cls, stream: StreamFn) -> "Response":
        # S10: SSE forces `Connection: close` (not keep-alive). Under HTTP/1.1 a stream
        # with no Content-Length on a kept-alive connection can make browsers auto-reconnect
        # and silently re-run triage; closing the connection after the stream avoids that.
        return cls(status=200, stream=stream,
                   headers={"Content-Type": "text/event-stream",
                            "Cache-Control": "no-cache",
                            "Connection": "close",
                            "X-Accel-Buffering": "no"})


class Router:
    """Matches (method, path) against a route table and enforces auth/RBAC/CSRF.

    Each route is either a 3-tuple ``(method, pattern, handler)`` — a public route — or a
    4-tuple ``(method, pattern, handler, required_role)``. When ``required_role`` is set the
    router requires a valid session (401 otherwise), enforces the role hierarchy via
    ``ROLE_RANK`` (403 if too low), and on mutating methods verifies CSRF (same-origin
    Origin/Referer when present + a double-submit ``X-CSRF-Token`` matching the session).

    ``auth`` is an ``AuthService`` (or None in transport-only tests, where every route is
    treated as public so the router stays backward-compatible with bare 3-tuples).
    """

    def __init__(self, routes: list, auth: Any = None) -> None:
        self.auth = auth
        self._routes = [self._normalize(r) for r in routes]

    def _normalize(self, route: tuple) -> tuple:
        if len(route) == 4:
            method, pattern, handler, required_role = route
        else:
            method, pattern, handler = route
            required_role = None
        return (method.upper(), self._split(pattern), pattern, handler, required_role)

    @staticmethod
    def _split(pattern: str) -> list[str]:
        return [seg for seg in pattern.strip("/").split("/") if seg != ""]

    def _match(self, method: str, path: str) -> Optional[tuple[Callable[[Request], Response], dict[str, str], Optional[str]]]:
        parts = [seg for seg in path.strip("/").split("/") if seg != ""]
        for r_method, r_segs, _pat, handler, required_role in self._routes:
            if r_method != method or len(r_segs) != len(parts):
                continue
            params: dict[str, str] = {}
            ok = True
            for r_seg, seg in zip(r_segs, parts):
                if r_seg.startswith("{") and r_seg.endswith("}"):
                    params[r_seg[1:-1]] = seg
                elif r_seg != seg:
                    ok = False
                    break
            if ok:
                return handler, params, required_role
        return None

    # --- auth middleware --------------------------------------------------
    def _authenticate(self, req: Request) -> None:
        """Resolve the session (Bearer token, query access_token, or cookie) onto the
        request. Never raises.

        The ``access_token`` query parameter exists ONLY for EventSource, which cannot
        set an Authorization header (Supabase mode). It is consulted last, after header
        and cookie auth, so normal requests never rely on it — and the SSE path in the
        SPA appends it only when a Bearer session is active. Tokens in URLs can leak via
        logs; the trade-off is accepted for this single streaming endpoint, and the
        Supabase JWT is short-lived (rotated hourly by refresh)."""
        if self.auth is None:
            return

        # Try Bearer token first (Supabase)
        bearer = req.bearer_token()
        if bearer:
            # For Supabase, authenticate uses the token directly
            result = self.auth.authenticate(bearer)
            if result:
                req.current_user, req.token_hash = result
                req.token = bearer
                req.auth_type = _AUTH_BEARER
                return

        # Fall back to cookie-based auth (local only). Skipped in Supabase mode: there are
        # no server-side session cookies there, so a lingering local cookie from a prior
        # local-mode login would otherwise be shipped to Supabase's /auth/v1/user on every
        # request and rejected as a malformed JWT — a benign but noisy ERROR on each call.
        token = None if getattr(self.auth, "using_supabase", False) \
            else req.cookie(self.auth.SESSION_COOKIE)
        if token:
            result = self.auth.authenticate(token)
            if result:
                req.current_user, req.token_hash = result
                req.token = token
                req.auth_type = _AUTH_COOKIE
                return

        # Last resort: EventSource can't attach headers/cookies beyond same-origin, so
        # SSE consumers may pass the access token in the query string.
        qp_token = req.query.get("access_token") or ""
        if qp_token:
            result = self.auth.authenticate(qp_token)
            if result:
                req.current_user, req.token_hash = result
                req.token = qp_token
                req.auth_type = _AUTH_BEARER

    @staticmethod
    def _same_origin(origin_or_referer: str, host: str) -> bool:
        return urlparse(origin_or_referer).netloc == host

    def _check_csrf(self, req: Request) -> None:
        """Reject cross-site state changes: same-origin Origin/Referer (when the browser
        sends one) plus a double-submit token that must match this session's CSRF token.
        Only applies to cookie-based auth; Bearer token auth is stateless and doesn't need CSRF."""
        if req.auth_type == _AUTH_BEARER:
            return  # Bearer tokens don't need CSRF protection
        origin = req.header("origin") or req.header("referer")
        if origin:
            host = req.header("host")
            if host and not self._same_origin(origin, host):
                raise ForbiddenError("cross-origin request blocked")
        provided = req.header("x-csrf-token")
        expected = self.auth.csrf_token(req.token_hash)
        if not provided or not hmac.compare_digest(provided, expected):
            raise ForbiddenError("missing or invalid CSRF token")

    def _authorize(self, req: Request, required_role: Optional[str]) -> None:
        if required_role is None:
            return
        if req.current_user is None:
            raise AuthError("authentication required")
        if ROLE_RANK.get(req.current_user.role, -1) < ROLE_RANK.get(required_role, 99):
            raise ForbiddenError("insufficient permissions for this action")
        if req.method in _MUTATING:
            self._check_csrf(req)

    def dispatch(self, req: Request) -> Response:
        """Route the request; enforce auth/RBAC/CSRF; map domain errors to status codes."""
        matched = self._match(req.method, req.path)
        if matched is None:
            return Response.error("no such route", status=404, code="not_found")
        handler, params, required_role = matched
        req.path_params = params
        try:
            self._authenticate(req)
            self._authorize(req, required_role)
            return handler(req)
        except AuthError as exc:
            return Response.error(str(exc) or "authentication required", status=401,
                                  code="unauthorized")
        except LockedError as exc:
            return Response.error(str(exc) or "temporarily locked", status=429, code="locked")
        except ForbiddenError as exc:
            return Response.error(str(exc) or "forbidden", status=403, code="forbidden")
        except NotFoundError as exc:
            return Response.error(str(exc) or "not found", status=404, code="not_found")
        except ConflictError as exc:
            return Response.error(str(exc) or "conflict", status=409, code="conflict")
        except NotImplementedError as exc:
            # SEC2: log the detail server-side, but never echo exception text to the client.
            log.warning("handler not implemented: %s %s (%s)", req.method, req.path, exc)
            return Response.error("endpoint not implemented yet", status=501,
                                  code="not_implemented")
        except json.JSONDecodeError as exc:
            # SEC2: a malformed request body is a client error, but the parser's message
            # ("Expecting value: line 1 ...") leaks internals — return a generic message.
            log.info("bad JSON body on %s %s: %s", req.method, req.path, exc)
            return Response.error("invalid JSON body", status=400, code="bad_request")
        except ValueError as exc:
            # Domain validation raises ValueError with a caller-safe message (e.g.
            # "remediation_steps must be a list") — surface it as-is.
            return Response.error(str(exc) or "bad request", status=400, code="bad_request")
        except Exception:  # never leak a traceback to the client
            log.error("unhandled error on %s %s\n%s", req.method, req.path, traceback.format_exc())
            return Response.error("internal server error", status=500, code="internal_error")
