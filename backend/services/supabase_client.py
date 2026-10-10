"""Supabase HTTP client — Auth API + PostgREST (REST) over stdlib urllib.

One thin transport for both Supabase surfaces:

* Auth API (``/auth/v1/*``) — signup, password grant, refresh, logout, user read/update.
* PostgREST (``/rest/v1/*``) — table access with explicit *acting identity*: the caller
  chooses whether a request runs as the end user (their access token, so **Row Level
  Security applies**) or with the ``service_role`` key (bypasses RLS, server-side only).

The auth server and PostgREST authenticate differently, and conflating them silently
401s: PostgREST wants ``Authorization: Bearer <user access token>`` + ``apikey``; the
Auth API wants the *anon* key in both headers plus the body/params. Every method here
takes the token explicitly so callers can never forget which identity they act as.
No third-party dependency; timeouts come from settings (request_timeout).
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

from ..config import Settings

log = logging.getLogger("muninn.supabase")


class SupabaseError(Exception):
    """Raised when Supabase returns an error response (or the config is broken)."""

    def __init__(self, message: str, status: int = 0, code: str = ""):
        super().__init__(message)
        self.status = status  # HTTP status (0 = transport-level failure)
        self.code = code      # Postgres/PostgREST error code, e.g. "23505"

    # --- semantic predicates (used for mapping to domain errors) ---
    @property
    def is_auth(self) -> bool:
        """A credential/token problem: 401/403/422 from the Auth API, or bad key config."""
        return self.status in (401, 403) or self.code in ("400", "401", "403", "invalid_credentials")

    @property
    def is_not_found(self) -> bool:
        return self.status == 404 or self.code == "PGRST116"

    @property
    def is_conflict(self) -> bool:
        # 23505 unique violation; PostgREST surfaces "already registered" for dup signups.
        return self.code in ("23505", "PGRST409") or "already registered" in str(self).lower()


def _build_url(base: str, path: str, query: Optional[dict[str, str]]) -> str:
    url = f"{base}{path}"
    if query:
        url += "?" + urllib.parse.urlencode(query)
    return url


class SupabaseClient:
    """Minimal, dependency-free Supabase client for Auth + Database operations."""

    # Transient-failure retry (mirrors the resilient Groq client). Supabase sits behind
    # Cloudflare; a momentary TLS handshake blip, DNS hiccup, connection reset, or edge
    # 5xx is intermittent and recovers on a retry a fraction of a second later. Without
    # this, such a blip surfaced to the user as a hard "auth service unreachable" login
    # failure (observed: an [SSL: CERTIFICATE_VERIFY_FAILED] hostname mismatch from one
    # Cloudflare PoP that succeeded immediately on the next attempt).
    _MAX_ATTEMPTS = 3
    _BACKOFF = (0.5, 1.5, 3.0)
    _RETRY_STATUS = (502, 503, 504)

    def __init__(self, settings: Settings) -> None:
        url = (settings.supabase_url or "").strip()
        if not url:
            raise SupabaseError("SUPABASE_URL is not configured", status=0, code="config_error")
        if not url.startswith(("http://", "https://")):
            raise SupabaseError("SUPABASE_URL must start with http:// or https://",
                                status=0, code="config_error")
        parsed = urllib.parse.urlsplit(url)
        if not parsed.netloc:
            raise SupabaseError("SUPABASE_URL must include a hostname",
                                status=0, code="config_error")
        # Accept a pasted REST endpoint defensively, but always build Auth and REST
        # requests from the Supabase project root.
        self.settings = settings
        self._url = f"{parsed.scheme}://{parsed.netloc}"
        self._anon_key = (settings.supabase_anon_key or "").strip()
        self._service_key = (settings.supabase_service_role_key or "").strip()

    # --- keys / header construction ---------------------------------------

    @property
    def base_url(self) -> str:
        return self._url

    def _key(self, service_role: bool) -> str:
        if service_role:
            if not self._service_key:
                raise SupabaseError("SUPABASE_SERVICE_ROLE_KEY is not configured",
                                    status=0, code="config_error")
            return self._service_key
        if not self._anon_key:
            raise SupabaseError("SUPABASE_ANON_KEY is not configured",
                                status=0, code="config_error")
        return self._anon_key

    def _headers(self, key: str, access_token: Optional[str] = None) -> dict[str, str]:
        """Headers for one request. ``access_token`` sets the *acting user* for PostgREST
        (RLS); without it the anonymous role applies. The Auth API ignores this and always
        uses the project key in Authorization, with the user token passed via body/params."""
        h = {
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if access_token:
            h["Authorization"] = f"Bearer {access_token}"
        return h

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[dict[str, Any]] = None,
        key: Optional[str] = None,
        access_token: Optional[str] = None,
        query: Optional[dict[str, str]] = None,
        extra_headers: Optional[dict[str, str]] = None,
    ) -> Any:
        url = _build_url(self._url, path, query)
        headers = self._headers(key if key is not None else self._key(False), access_token)
        if extra_headers:
            headers.update(extra_headers)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        for attempt in range(self._MAX_ATTEMPTS):
            last = attempt == self._MAX_ATTEMPTS - 1
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=self.settings.request_timeout) as resp:
                    payload = resp.read().decode("utf-8")
                    if not payload:
                        return None
                    return json.loads(payload)
            except urllib.error.HTTPError as exc:
                # Transient gateway errors from the CDN/Supabase edge recover on retry;
                # a definite 4xx (bad credentials, already-registered, RLS denial) does not,
                # so it falls straight through to the uniform SupabaseError mapping below.
                if exc.code in self._RETRY_STATUS and not last:
                    log.warning("Supabase %s %s -> %s (transient) — retry %d/%d in %.1fs",
                                method, path, exc.code, attempt + 1, self._MAX_ATTEMPTS,
                                self._BACKOFF[attempt])
                    time.sleep(self._BACKOFF[attempt])
                    continue
                raw = exc.read().decode("utf-8", errors="replace")
                try:
                    err = json.loads(raw)
                    msg = err.get("msg") or err.get("message") or err.get("error_description") \
                        or err.get("error") or raw
                    code = str(err.get("code") or err.get("error_code") or "")
                except json.JSONDecodeError:
                    msg, code = raw, ""
                # A 401/403 on the auth endpoints is a routine outcome — an expired, cleared,
                # or malformed token — that every caller already maps and handles. Logging it
                # at ERROR floods production logs (e.g. the /auth/v1/user check after logout),
                # so demote those to INFO; everything else stays ERROR.
                benign = path.startswith("/auth/") and exc.code in (401, 403)
                log.log(logging.INFO if benign else logging.ERROR,
                        "Supabase %s %s -> %s: %s", method, path, exc.code, msg)
                raise SupabaseError(str(msg), status=exc.code, code=code) from exc
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                # TLS handshake blips, DNS hiccups and connection resets to the Supabase edge
                # are transient and almost always clear on an immediate retry. Only the final
                # attempt maps to the uniform network_error (-> "auth service unreachable").
                if not last:
                    log.warning("Supabase %s %s -> transport error (%s) — retry %d/%d in %.1fs",
                                method, path, exc, attempt + 1, self._MAX_ATTEMPTS,
                                self._BACKOFF[attempt])
                    time.sleep(self._BACKOFF[attempt])
                    continue
                reason = getattr(exc, "reason", exc)
                log.error("Supabase %s %s -> network error: %s", method, path, exc)
                raise SupabaseError(f"network error reaching Supabase: {reason}",
                                    status=0, code="network_error") from exc
        # Unreachable: the loop either returns, continues, or raises on every path.
        raise SupabaseError("network error reaching Supabase", status=0, code="network_error")

    # ======================================================================
    # Auth API (/auth/v1)
    # ======================================================================

    def signup(self, email: str, password: str, name: str = "") -> dict[str, Any]:
        """Email/password signup. Returns the session bundle (user + tokens); an
        unconfirmed-email project returns only ``user`` — both shapes are valid."""
        return self._request(
            "POST", "/auth/v1/signup",
            body={"email": email, "password": password, "data": {"name": name}},
        )

    def login(self, email: str, password: str) -> dict[str, Any]:
        """Password-grant sign-in. Returns the full session bundle (access/refresh tokens)."""
        return self._request(
            "POST", "/auth/v1/token?grant_type=password",
            body={"email": email, "password": password},
        )

    def refresh(self, refresh_token: str) -> dict[str, Any]:
        """Rotate a refresh token into a fresh session bundle."""
        return self._request(
            "POST", "/auth/v1/token?grant_type=refresh_token",
            body={"refresh_token": refresh_token},
        )

    def logout(self, access_token: str) -> None:
        """Revoke the session server-side (the anon key identifies the project)."""
        self._request("POST", "/auth/v1/logout", body={}, access_token=access_token)

    def get_user(self, access_token: str) -> dict[str, Any]:
        """Fetch the user record for a valid access token. 401 when invalid/expired."""
        return self._request("GET", "/auth/v1/user", access_token=access_token)

    def update_user(self, access_token: str, data: dict[str, Any]) -> dict[str, Any]:
        """Update the user record (email/password/user_metadata) for a valid token."""
        return self._request("PUT", "/auth/v1/user", body=data, access_token=access_token)

    def admin_delete_user(self, user_id: str) -> None:
        """Delete a user with the service role key (admin only)."""
        self._request("DELETE", f"/auth/v1/admin/users/{user_id}", key=self._key(True))

    def admin_update_user(self, user_id: str, data: dict[str, Any]) -> dict[str, Any]:
        """Update an auth user with the service role key (admin only). ``data`` is the
        GoTrue admin body — notably ``{"app_metadata": {"role": "admin"}}``. Authorization
        claims must only ever be written through this path (the admin API), never through
        the user's own ``PUT /auth/v1/user``, which can edit ``user_metadata``."""
        return self._request("PUT", f"/auth/v1/admin/users/{user_id}", body=data,
                             key=self._key(True))

    # ======================================================================
    # PostgREST (/rest/v1)
    # ======================================================================

    @staticmethod
    def _eq_query(filters: Optional[dict[str, Any]], extra: Optional[dict[str, str]]) -> dict[str, str]:
        q = dict(extra or {})
        for k, v in (filters or {}).items():
            q[k] = f"eq.{v}"
        return q

    def select(
        self,
        table: str,
        columns: str = "*",
        filters: Optional[dict[str, Any]] = None,
        order: Optional[str] = None,
        limit: Optional[int] = None,
        single: bool = False,
        access_token: Optional[str] = None,
        service_role: bool = False,
    ) -> Any:
        """Select rows. Identity: ``access_token`` (RLS) or ``service_role`` (bypass).
        ``single=True`` returns one object (not a list) via the PostgREST Accept header."""
        extra: dict[str, str] = {"select": columns}
        if order:
            extra["order"] = order
        if limit is not None:
            extra["limit"] = str(limit)
        single_headers = {"Accept": "application/vnd.pgrst.object+json"} if single else None
        if single:
            extra["limit"] = "1"
        q = self._eq_query(filters, extra)
        return self._request(
            "GET", f"/rest/v1/{table}", query=q,
            key=self._key(service_role), access_token=access_token,
            extra_headers=single_headers,
        )

    def insert(
        self,
        table: str,
        data: dict[str, Any],
        access_token: Optional[str] = None,
        service_role: bool = False,
    ) -> Any:
        """Insert one row (PostgREST returns the created row as a list)."""
        return self._request(
            "POST", f"/rest/v1/{table}", body=data,
            key=self._key(service_role), access_token=access_token,
        )

    def upsert(
        self,
        table: str,
        data: dict[str, Any],
        access_token: Optional[str] = None,
        service_role: bool = False,
    ) -> Any:
        """Upsert one row (INSERT ... ON CONFLICT (pk) DO UPDATE via Prefer: resolution).

        Routed through :meth:`_request` so a transport failure surfaces as a
        ``SupabaseError`` (code ``network_error``) exactly like every other call — a raw
        ``URLError`` escaping this layer would break the uniform error contract callers
        depend on.
        """
        return self._request(
            "POST", f"/rest/v1/{table}", body=data,
            key=self._key(service_role), access_token=access_token,
            query={"on_conflict": "id"},
            extra_headers={"Prefer": "resolution=merge-duplicates,return=representation"},
        )

    def update(
        self,
        table: str,
        data: dict[str, Any],
        filters: dict[str, Any],
        access_token: Optional[str] = None,
        service_role: bool = False,
    ) -> Any:
        """Update rows matching ``filters`` (PATCH)."""
        q = self._eq_query(filters, None)
        return self._request(
            "PATCH", f"/rest/v1/{table}", body=data,
            key=self._key(service_role), access_token=access_token, query=q,
        )

    def delete(
        self,
        table: str,
        filters: dict[str, Any],
        access_token: Optional[str] = None,
        service_role: bool = False,
    ) -> None:
        """Delete rows matching ``filters``."""
        q = self._eq_query(filters, None)
        self._request(
            "DELETE", f"/rest/v1/{table}",
            key=self._key(service_role), access_token=access_token, query=q,
        )


def create_client(settings: Settings) -> SupabaseClient:
    """Factory validating that the mandatory Supabase settings are present."""
    if not (settings.supabase_url or "").strip():
        raise SupabaseError("SUPABASE_URL is not configured", status=0, code="config_error")
    if not (settings.supabase_anon_key or "").strip():
        raise SupabaseError("SUPABASE_ANON_KEY is not configured", status=0, code="config_error")
    return SupabaseClient(settings)
