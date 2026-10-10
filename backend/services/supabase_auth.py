"""Supabase Auth service — sessions, token refresh, and profile sync.

High-level operations over :class:`SupabaseClient`:

* signup / login / logout / refresh with uniform domain-error mapping (SupabaseError ->
  AuthError / ConflictError / ValueError), so the router's status codes stay identical
  to the local auth path.
* ``get_user`` validates a Bearer token against the Auth server (with a short-TTL cache)
  — this is what makes protected routes work without a server-side session table.
  Tokens are never stored or persisted anywhere; they stay with the client.
* profile read/update through :class:`SupabaseRepository` using the *caller's* access
  token, so Row Level Security — not application code — enforces user isolation.

No passwords (or hashes) ever live in this process: Supabase Auth is the credential
store. The service role key is used only for admin user deletion.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Optional

from ..config import Settings
from ..errors import AuthError, ConflictError, NotFoundError
from ..models import ROLES, VIEWER
from .supabase_client import SupabaseClient, SupabaseError, create_client
from .supabase_db import SupabaseRepository

log = logging.getLogger("muninn.supabase_auth")

# PostgREST/pg error codes handled explicitly.
_PG_UNIQUE_VIOLATION = "23505"

# In-process validation cache: access_token -> (user, expiry). Bounds how often each
# request hits the Auth server for the same token without weakening security much —
# revocation still propagates within the TTL. Entries are dropped when a logout or
# token update touches the same token.
_SESSION_CACHE_TTL = 60.0
_PROFILE_CACHE_TTL = 60.0


@dataclass
class AuthTokens:
    """Token bundle returned by Supabase Auth (also the wire shape for the SPA)."""
    access_token: str
    refresh_token: str
    expires_in: int
    token_type: str = "bearer"

    def as_dict(self) -> dict[str, Any]:
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "expires_in": self.expires_in,
            "token_type": self.token_type,
        }


@dataclass
class SupabaseUser:
    """User record from Supabase Auth (``auth.users`` row, as exposed by the Auth API)."""
    id: str
    email: str
    name: str = ""
    role: str = "viewer"
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    email_confirmed_at: Optional[str] = None
    user_metadata: Optional[dict[str, Any]] = None
    app_metadata: Optional[dict[str, Any]] = None

    @classmethod
    def from_supabase(cls, data: dict[str, Any]) -> "SupabaseUser":
        meta = data.get("user_metadata") or {}
        app_meta = data.get("app_metadata") or {}
        return cls(
            id=data["id"],
            email=data.get("email") or "",
            name=meta.get("name") or "",
            # SECURITY: the authorization role is read from ``app_metadata`` ONLY. That claim
            # is writable solely with the service role key (admin), whereas ``user_metadata``
            # is editable by the user themselves via PUT /auth/v1/user — trusting it would let
            # any user self-promote to admin. Never read a role from ``user_metadata``.
            role=app_meta.get("role") or VIEWER,
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
            email_confirmed_at=data.get("email_confirmed_at") or data.get("confirmed_at"),
            user_metadata=meta,
            app_metadata=app_meta,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "role": self.role,
            "created_at": self.created_at,
        }


@dataclass
class UserProfile:
    """Extended profile row from the ``profiles`` table (PK = ``auth.users.id``)."""
    id: str
    email: str
    name: str = ""
    role: str = "viewer"
    avatar_url: str = ""
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "UserProfile":
        return cls(
            id=row["id"],
            email=row.get("email") or "",
            name=row.get("name") or "",
            role=row.get("role") or "viewer",
            avatar_url=row.get("avatar_url") or "",
            created_at=row.get("created_at"),
            updated_at=row.get("updated_at"),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "role": self.role,
            "avatar_url": self.avatar_url,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class SupabaseAuthService:
    """Supabase-backed auth operations with domain-error mapping and caches."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._client: Optional[SupabaseClient] = None
        self._repo: Optional[SupabaseRepository] = None
        self._session_cache: dict[str, tuple[SupabaseUser, float]] = {}
        self._profile_cache: dict[str, tuple[UserProfile, float]] = {}

    # --- wiring -----------------------------------------------------------

    @property
    def client(self) -> SupabaseClient:
        if self._client is None:
            self._client = create_client(self.settings)
        return self._client

    @property
    def repo(self) -> SupabaseRepository:
        if self._repo is None:
            self._repo = SupabaseRepository(self.settings)
        return self._repo

    # --- error mapping ------------------------------------------------------

    @staticmethod
    def _map_error(exc: SupabaseError, action: str,
                   auth_message: str = "invalid email or password") -> Exception:
        """Translate a SupabaseError into the router's vocabulary so the HTTP contract
        matches the local auth path exactly (401 / 409 / 404 / 503-as-401)."""
        if exc.is_conflict:
            return ConflictError("email already registered")
        if exc.is_auth:
            return AuthError(auth_message)
        if exc.is_not_found:
            return NotFoundError("profile not found")
        if exc.code == "network_error":
            return AuthError("auth service unreachable; try again shortly")
        log.error("supabase %s failed: %s (status=%s code=%s)", action, exc, exc.status, exc.code)
        return AuthError(f"{action} failed")

    # --- token helpers ------------------------------------------------------

    @staticmethod
    def _parse_tokens(data: dict[str, Any]) -> AuthTokens:
        """Extract the token bundle from any Auth API session response."""
        try:
            return AuthTokens(
                access_token=data["access_token"],
                refresh_token=data.get("refresh_token") or "",
                expires_in=int(data.get("expires_in") or 3600),
                token_type=data.get("token_type") or "bearer",
            )
        except KeyError as exc:
            raise AuthError("authentication service returned no session") from exc

    @staticmethod
    def _session_user(data: dict[str, Any]) -> SupabaseUser:
        inner = data.get("user")
        if not isinstance(inner, dict):
            raise AuthError("authentication service returned no user")
        return SupabaseUser.from_supabase(inner)

    # --- auth operations ------------------------------------------------------

    def signup(self, email: str, password: str, name: str = "") -> tuple[SupabaseUser, AuthTokens]:
        """Create the auth user, then the profile row (explicitly, and idempotently —
        the SQL trigger also creates one; both paths converge via upsert semantics)."""
        if not (email or "").strip() or "@" not in email:
            raise ValueError("a valid email is required")
        if len(password or "") < 8:
            raise ValueError("password must be at least 8 characters")
        try:
            data = self.client.signup(email.strip(), password, name)
        except SupabaseError as exc:
            raise self._map_error(exc, "signup") from exc
        user = self._session_user(data)
        # Email-confirmation-enabled projects return no session; then there are no tokens
        # to hand back and the profile row is created by the SQL trigger.
        if not data.get("access_token"):
            log.info("supabase signup (confirmation pending): %s", user.email)
            return user, AuthTokens(access_token="", refresh_token="", expires_in=0)
        tokens = self._parse_tokens(data)
        self._ensure_profile(user, tokens.access_token)
        log.info("supabase signup: %s", user.email)
        return user, tokens

    def login(self, email: str, password: str) -> tuple[SupabaseUser, AuthTokens]:
        """Password grant; returns the user plus the full token bundle."""
        try:
            data = self.client.login((email or "").strip(), password or "")
        except SupabaseError as exc:
            raise self._map_error(exc, "login") from exc
        tokens = self._parse_tokens(data)
        user = self._session_user(data)
        self._cache_session(tokens.access_token, user)
        self._ensure_profile(user, tokens.access_token)
        log.info("supabase login: %s", user.email)
        return user, tokens

    def logout(self, access_token: Optional[str]) -> None:
        """Revoke the refresh token server-side and drop the local validation cache.
        Best-effort: an already-invalid token must not turn logout into an error."""
        if access_token:
            self._invalidate_session(access_token)
            try:
                self.client.logout(access_token)
            except SupabaseError as exc:
                log.info("supabase logout tolerated upstream error: %s", exc)
        log.info("supabase logout")

    def get_user(self, access_token: str) -> SupabaseUser:
        """Validate an access token and return its user (short-TTL cached)."""
        if not access_token:
            raise AuthError("authentication required")
        cached = self._get_cached_session(access_token)
        if cached:
            return cached
        try:
            data = self.client.get_user(access_token)
        except SupabaseError as exc:
            raise self._map_error(exc, "token validation",
                                  auth_message="invalid or expired token") from exc
        user = SupabaseUser.from_supabase(data)
        self._cache_session(access_token, user)
        return user

    def refresh_session(self, refresh_token: str) -> tuple[SupabaseUser, AuthTokens]:
        """Exchange a refresh token for a fresh session bundle (rotation)."""
        if not refresh_token:
            raise AuthError("refresh token required")
        try:
            data = self.client.refresh(refresh_token)
        except SupabaseError as exc:
            raise self._map_error(exc, "session refresh") from exc
        tokens = self._parse_tokens(data)
        user = self._session_user(data)
        self._cache_session(tokens.access_token, user)
        return user, tokens

    def update_user(self, access_token: str, name: Optional[str] = None) -> SupabaseUser:
        """Update the caller's own non-privileged user field (display name), then re-read.

        ``role`` is deliberately NOT a parameter here. A role claim is authorization data
        and must only ever be written through the admin (service-role) path — see
        :meth:`admin_set_role`. The user's own ``PUT /auth/v1/user`` can edit
        ``user_metadata``, so writing a role through it would be a self-promotion vector.
        """
        if name is not None:
            try:
                self.client.update_user(access_token, {"data": {"name": name}})
            except SupabaseError as exc:
                raise self._map_error(exc, "user update") from exc
            self._invalidate_session(access_token)
        user = self.get_user(access_token)
        self._invalidate_profile(user.id)
        return user

    # --- profile operations (through the caller's token => RLS applies) -------

    def _ensure_profile(self, user: SupabaseUser, access_token: str) -> UserProfile:
        """Create the profile row if missing (idempotent; tolerant of the SQL trigger
        having beaten us to it). Also repairs a profile whose email changed upstream."""
        profile_data = {
            "id": user.id, "email": user.email, "name": user.name, "role": user.role,
        }
        try:
            row = self.client.insert("profiles", profile_data, access_token=access_token)
        except SupabaseError as exc:
            # Auto-creation must NEVER block a successful signup/login: a duplicate key (the
            # SQL trigger or a racing request already created the row), an RLS/schema
            # rejection, or a transient error all fall through to a read of the existing row
            # below. A genuinely missing profile is logged, never raised.
            if exc.code != _PG_UNIQUE_VIOLATION:
                log.warning("profile insert skipped (%s); reading existing row", exc)
            row = None
        if isinstance(row, list) and row:
            row = row[0]
        if isinstance(row, dict):
            profile = UserProfile.from_row(row)
        else:
            try:
                profile = self._read_profile(user.id, access_token)
            except NotFoundError:
                # ``single=True`` maps an empty PostgREST result to PGRST116. Treat that
                # as a missing row here so signup/login can repair an existing Auth user.
                profile = None
            if profile is None and self.settings.supabase_service_role_key:
                # A user-token insert can be blocked when an older project has stale
                # grants/policies. Repair only from this server-side fallback; normal
                # profile reads and updates remain RLS-enforced with the user token.
                try:
                    row = self.client.upsert("profiles", profile_data, service_role=True)
                    if isinstance(row, list) and row:
                        row = row[0]
                    if isinstance(row, dict):
                        profile = UserProfile.from_row(row)
                except SupabaseError as exc:
                    log.warning("service-role profile repair failed for %s: %s", user.id, exc)
            if profile is None:
                # Row neither created nor visible: log loudly but don't fail the session.
                log.warning("profile row missing for user %s after signup", user.id)
                profile = UserProfile(id=user.id, email=user.email, name=user.name,
                                      role=user.role)
        self._cache_profile(user.id, profile)
        return profile

    def _read_profile(self, user_id: str, access_token: str) -> Optional[UserProfile]:
        """Read the caller's own profile row under RLS."""
        try:
            row = self.repo.get_profile(user_id, access_token)
        except SupabaseError as exc:
            raise self._map_error(exc, "profile lookup") from exc
        return UserProfile.from_row(row) if row else None

    def get_profile(self, user_id: str, access_token: str) -> UserProfile:
        """Get a profile with caching; 404 when RLS hides it (foreign id) or it's absent."""
        cached = self._get_cached_profile(user_id)
        if cached:
            return cached
        profile = self._read_profile(user_id, access_token)
        if profile is None:
            raise NotFoundError("profile not found")
        self._cache_profile(user_id, profile)
        return profile

    def update_profile(self, user_id: str, access_token: str, data: dict[str, Any]) -> UserProfile:
        """Patch the caller's own profile. RLS is the real guard; this method never
        widens access (it passes the caller's token, not the service key)."""
        allowed = {"name", "avatar_url"}  # role is privileged: only via user metadata
        filtered = {k: v for k, v in (data or {}).items() if k in allowed}
        if not filtered:
            return self.get_profile(user_id, access_token)
        try:
            rows = self.client.update("profiles", filtered, filters={"id": user_id},
                                      access_token=access_token)
        except SupabaseError as exc:
            raise self._map_error(exc, "profile update") from exc
        if isinstance(rows, list) and rows:
            profile = UserProfile.from_row(rows[0])
        else:
            profile = self._read_profile(user_id, access_token)
            if profile is None:
                raise NotFoundError("profile not found")
        self._cache_profile(user_id, profile)
        return profile

    # --- validation convenience -------------------------------------------------

    def validate_token(self, access_token: Optional[str]) -> Optional[SupabaseUser]:
        """Token -> user, or None for any invalid/expired/malformed token."""
        if not access_token:
            return None
        try:
            return self.get_user(access_token)
        except (AuthError, SupabaseError):
            return None

    # --- session/profile caches ---------------------------------------------------

    def _cache_session(self, access_token: str, user: SupabaseUser) -> None:
        self._session_cache[access_token] = (user, time.monotonic() + _SESSION_CACHE_TTL)

    def _get_cached_session(self, access_token: str) -> Optional[SupabaseUser]:
        entry = self._session_cache.get(access_token)
        if entry:
            user, expiry = entry
            if time.monotonic() < expiry:
                return user
            self._session_cache.pop(access_token, None)
        return None

    def _invalidate_session(self, access_token: str) -> None:
        self._session_cache.pop(access_token, None)

    def _invalidate_profile(self, user_id: str) -> None:
        """Drop a user's cached profile by id. Keyed on the id (not the token) so it can be
        called after the session cache entry has already been evicted."""
        self._profile_cache.pop(user_id, None)

    def _cache_profile(self, user_id: str, profile: UserProfile) -> None:
        self._profile_cache[user_id] = (profile, time.monotonic() + _PROFILE_CACHE_TTL)

    def _get_cached_profile(self, user_id: str) -> Optional[UserProfile]:
        entry = self._profile_cache.get(user_id)
        if entry:
            profile, expiry = entry
            if time.monotonic() < expiry:
                return profile
            self._profile_cache.pop(user_id, None)
        return None

    # --- admin (service role) -------------------------------------------------------

    def admin_delete_user(self, user_id: str) -> None:
        """Delete an auth user (service role). The profiles FK cascades the row."""
        try:
            self.client.admin_delete_user(user_id)
        except SupabaseError as exc:
            raise self._map_error(exc, "user deletion") from exc
        self._profile_cache.pop(user_id, None)

    def admin_set_role(self, user_id: str, role: str) -> UserProfile:
        """Set a user's authorization role (service role only).

        Writes ``app_metadata.role`` — the claim RBAC actually trusts and which no user can
        self-edit — and mirrors it onto the ``profiles`` row so admin listings and displays
        stay consistent. This is the ONLY sanctioned path for a role change.
        """
        if role not in ROLES:
            raise ValueError(f"role must be one of {', '.join(ROLES)}")
        try:
            self.client.admin_update_user(user_id, {"app_metadata": {"role": role}})
            self.repo.admin_update_profile(user_id, {"role": role})
        except SupabaseError as exc:
            raise self._map_error(exc, "role update") from exc
        self._invalidate_profile(user_id)
        row = self.repo.admin_get_profile(user_id)
        if row is None:
            raise NotFoundError("profile not found")
        return UserProfile.from_row(row)

    def admin_list_profiles(self, limit: int = 100) -> list[UserProfile]:
        rows = self.repo.admin_list_profiles(limit=limit)
        return [UserProfile.from_row(r) for r in rows]


def create_supabase_auth(settings: Settings) -> SupabaseAuthService:
    """Factory to create a SupabaseAuthService from settings."""
    return SupabaseAuthService(settings)
