"""Unified Authentication Service — local (SQLite) or Supabase, one interface.

The app (router, routes, server, tests) is written against the local AuthService
interface. This adapter keeps that contract EXACTLY regardless of backend:

* signup/login -> ``(user, token, csrf)``, ``authenticate(token) -> (user, token_hash)``,
  ``csrf_token(hash)``, cookie helpers, demo accounts, role management.
* Supabase mode mints no server-side session: the Supabase access token *is* the bearer
  token (validated per-request against the Auth server, TTL-cached), CSRF doesn't apply
  to stateless Bearer auth, and cookie helpers return empty strings so the HTTP contract
  stays uniform without leaking local semantics into Supabase mode.
* Users are keyed by UUID string in Supabase but by int rowid locally. The adapter
  converts through ``_user_from_supabase`` — ``User.id`` becomes the UUID string, so the
  SPA and any handlers that echo ids stay honest (int-specific admin routes stay
  local-only).

No password material is ever stored in this process in Supabase mode: Supabase Auth is
the credential store.
"""
from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime
from typing import Any, Optional, Union

from ..config import Settings
from ..db import Repository
from ..models import VIEWER, User, now_ms
from .auth import AuthService as LocalAuthService
from .supabase_client import create_client
from .supabase_auth import (
    AuthTokens,
    SupabaseAuthService,
    SupabaseUser,
    UserProfile,
    create_supabase_auth,
)

log = logging.getLogger("muninn.auth.unified")

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_INVALID_USER_ID = 0  # sentinel for int(id) conversions of non-local ids


def _iso_to_ms(iso: Optional[str]) -> int:
    """Parse an ISO-8601 timestamp to epoch milliseconds (0 when absent/malformed)."""
    if not iso:
        return 0
    try:
        return int(datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp() * 1000)
    except ValueError:
        return 0


def _stable_int_id(uid: str) -> int:
    """Deterministic 63-bit int from a UUID — display fallback only; never a DB key."""
    try:
        return int(uuid.uuid5(uuid.NAMESPACE_URL, f"muninn-user:{uid}"), 16) >> 1
    except (ValueError, AttributeError):
        return _INVALID_USER_ID


def _user_from_supabase(sb_user: Union[SupabaseUser, UserProfile],
                        ) -> User:
    """Map a Supabase identity onto the app's ``User`` model.

    ``id`` keeps the UUID STRING (authoritative key for profiles/API payloads);
    ``rowid`` is a derived stable int for code paths that insist on an int.
    ``password_hash`` stays empty — there is no password data in Supabase mode.
    """
    created = _iso_to_ms(getattr(sb_user, "created_at", None))
    return User(
        id=sb_user.id,  # UUID string — the app's serialization, not an int
        email=sb_user.email,
        name=sb_user.name,
        role=sb_user.role or VIEWER,
        password_hash="",  # no password storage in Supabase mode
        created_at=created or now_ms(),
    )


class UnifiedAuthService:
    """Single auth facade; selects local or Supabase from settings, delegates everything."""

    def __init__(self, repo: Repository, settings: Settings) -> None:
        self.repo = repo
        self._settings = settings
        self._local: Optional[LocalAuthService] = None
        self._supabase: Optional[SupabaseAuthService] = None
        # Demo sessions use SQLite even when real accounts use Supabase. This keeps the
        # public demo independent from external auth without changing real-user auth.
        self._demo = LocalAuthService(repo, settings)
        self._use_supabase = bool(settings.resolved_use_supabase())

        if self._use_supabase:
            # Fail fast on missing/invalid Supabase config (boot-time, not first-request):
            # a server that boots but 401s every request is far worse than one that
            # refuses to start with a clear message.
            create_client(settings)  # raises SupabaseError when URL/anon key are missing
            self._supabase = create_supabase_auth(settings)
            log.info("auth backend: Supabase (project %s)", (settings.supabase_url or "").strip())
        else:
            self._local = LocalAuthService(repo, settings)
            log.info("auth backend: local (SQLite)")

    @property
    def settings(self) -> Settings:
        return self._settings

    @settings.setter
    def settings(self, value: Settings) -> None:
        """Re-point settings on the facade AND the active delegate, so runtime swaps
        (e.g. a rotated MUNINN_SERVER_SECRET in tests) affect the real behavior."""
        self._settings = value
        if self._local is not None:
            self._local.settings = value
        self._demo.settings = value
        if self._supabase is not None:
            self._supabase.settings = value

    # --- backend selection --------------------------------------------------

    @property
    def backend(self) -> str:
        return "supabase" if self._use_supabase else "local"

    @property
    def using_supabase(self) -> bool:
        return self._use_supabase

    # ======================================================================
    # Core interface (signup / login / logout / authenticate)
    # ======================================================================

    def signup(self, email: str, password: str, name: str = "") -> tuple[User, str, str]:
        """Sign up. Returns (user, bearer/session token, csrf) — csrf is "" in Supabase
        mode (Bearer auth needs none)."""
        user, token, csrf, _ = self.signup_full(email, password, name)
        return user, token, csrf

    def signup_full(self, email: str, password: str,
                    name: str = "") -> tuple[User, str, str, Optional[dict[str, Any]]]:
        """Sign up with the full session for the wire: (user, access_token, csrf,
        session_dict | None). ``session_dict`` carries access/refresh tokens + expiry in
        Supabase mode (None in local mode, where the token rides an HttpOnly cookie)."""
        if self._use_supabase:
            sb_user, tokens = self._supabase.signup(email, password, name)
            user = _user_from_supabase(sb_user)
            session = tokens.as_dict() if tokens.access_token else None
            return user, tokens.access_token, "", session
        user, token, csrf = self._local.signup(email, password, name)
        return user, token, csrf, None

    def login(self, email: str, password: str) -> tuple[User, str, str]:
        """Log in. Returns (user, access token, csrf) — csrf is "" in Supabase mode."""
        user, token, csrf, _ = self.login_full(email, password)
        return user, token, csrf

    def login_full(self, email: str,
                   password: str) -> tuple[User, str, str, Optional[dict[str, Any]]]:
        """Log in with the full session for the wire (see :meth:`signup_full`)."""
        if self._use_supabase:
            sb_user, tokens = self._supabase.login(email, password)
            user = _user_from_supabase(sb_user)
            return user, tokens.access_token, "", tokens.as_dict()
        user, token, csrf = self._local.login(email, password)
        return user, token, csrf, None

    def logout(self, token: Optional[str]) -> None:
        if self._use_supabase:
            if self._demo.authenticate(token):
                self._demo.logout(token)
            else:
                self._supabase.logout(token)
        else:
            self._local.logout(token)

    def authenticate(self, token: Optional[str]) -> Optional[tuple[User, str]]:
        """Validate a session/bearer token -> (user, token_hash) or None.

        Supabase mode: the token is validated against the Auth API (60s TTL cache) and
        the "token_hash" is the token itself (used only for cache eviction on logout).
        """
        if not token:
            return None
        if self._use_supabase:
            demo_user = self._demo.authenticate(token)
            if demo_user:
                return demo_user
            sb_user = self._supabase.validate_token(token)
            if sb_user is None:
                return None
            return _user_from_supabase(sb_user), token
        return self._local.authenticate(token)

    def csrf_token(self, token_hash: Optional[str]) -> str:
        """CSRF token for a session. Supabase mode: Bearer auth is CSRF-immune, and
        /api/auth/me must not 500 when handed a bearer token — return ""."""
        if self._use_supabase:
            if token_hash and len(token_hash) == 64 and all(
                    c in "0123456789abcdef" for c in token_hash):
                return self._demo.csrf_token(token_hash)
            return ""
        return self._local.csrf_token(token_hash or "")

    # --- Supabase session payloads for the SPA --------------------------------

    def build_session_payload(self, user: User, token: str,
                              session: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Wire shape for the SPA: user + session (tokens only in Supabase mode)."""
        payload: dict[str, Any] = {
            "user": user.as_dict(),
            "backend": self.backend,
        }
        if self._use_supabase and session:
            payload["session"] = session
        return payload

    def refresh_session(self, refresh_token: str) -> dict[str, Any]:
        """Rotate a Supabase refresh token into a fresh session payload (Supabase only)."""
        if not self._use_supabase:
            raise NotImplementedError("session refresh requires Supabase Auth")
        sb_user, tokens = self._supabase.refresh_session(refresh_token)
        user = _user_from_supabase(sb_user)
        return self.build_session_payload(user, tokens.access_token,
                                          session=tokens.as_dict())

    def get_supabase_profile(self, user_id: str, access_token: str) -> UserProfile:
        """Fetch the caller's own profile (RLS-enforced via their token)."""
        if not self._use_supabase:
            raise NotImplementedError("profiles require Supabase")
        if not _UUID_RE.match(user_id or ""):
            raise ValueError("invalid user id")
        return self._supabase.get_profile(user_id, access_token)

    def update_supabase_profile(self, user_id: str, access_token: str,
                                data: dict[str, Any]) -> UserProfile:
        """Update the caller's own profile (name/avatar_url; role is not client-settable)."""
        if not self._use_supabase:
            raise NotImplementedError("profiles require Supabase")
        if not _UUID_RE.match(user_id or ""):
            raise ValueError("invalid user id")
        return self._supabase.update_profile(user_id, access_token, data or {})

    # --- lookups / admin ---------------------------------------------------------

    def get_user_by_email(self, email: str) -> Optional[User]:
        if self._use_supabase:
            return None  # Auth admin API needed; not exposed on this surface
        return self._local.repo.get_user_by_email(email)

    def get_user_by_id(self, user_id: int) -> Optional[User]:
        if self._use_supabase:
            return None
        return self._local.repo.get_user_by_id(user_id)

    def count_users(self) -> int:
        if self._use_supabase:
            return 0
        return self._local.repo.count_users()

    def set_role(self, user_id: Union[int, str], role: str) -> User:
        """Change a user's role. Local mode: SQLite row. Supabase mode: the service-role
        admin API writes ``app_metadata.role`` (the RBAC claim, which users cannot
        self-edit) and mirrors it onto the profile row. ``user_id`` is an int locally and
        a UUID string in Supabase mode."""
        if self._use_supabase:
            profile = self._supabase.admin_set_role(str(user_id), role)
            return _user_from_supabase(profile)
        return self._local.set_role(int(user_id), role)

    def list_users(self) -> list[User]:
        """List accounts. Supabase mode reads the ``profiles`` table with the service role
        (the only complete user view available server-side)."""
        if self._use_supabase:
            return [_user_from_supabase(p) for p in self._supabase.admin_list_profiles()]
        return self._local.repo.list_users()

    # --- demo mode ---------------------------------------------------------------

    def ensure_demo_accounts(self) -> int:
        return self._demo.ensure_demo_accounts()

    def demo_login(self, role: str) -> tuple[User, str, str]:
        """Mint a local SQLite session for a demo role in either auth backend."""
        return self._demo.demo_login(role)

    def authenticate_demo(self, token: Optional[str]) -> Optional[tuple[User, str]]:
        """Authenticate only the local demo cookie without probing Supabase."""
        return self._demo.authenticate(token)

    def demo_session_cookie(self, token: str) -> str:
        return self._demo.session_cookie(token)

    def demo_csrf_cookie(self, csrf: str) -> str:
        return self._demo.csrf_cookie(csrf)

    # --- cookie helpers (local sessions only) -----------------------------------

    SESSION_COOKIE = LocalAuthService.SESSION_COOKIE  # "muninn_session"
    CSRF_COOKIE = LocalAuthService.CSRF_COOKIE        # "muninn_csrf"

    def session_cookie(self, token: str) -> str:
        if self._use_supabase:
            return ""  # bearer token lives in the SPA, not a server cookie
        return self._local.session_cookie(token)

    def csrf_cookie(self, csrf: str) -> str:
        if self._use_supabase:
            return ""
        return self._local.csrf_cookie(csrf)

    def clear_cookies(self) -> list[str]:
        if self._use_supabase:
            return []
        return self._local.clear_cookies()


# Backward-compat alias: the app wires this class as "AuthService".
AuthService = UnifiedAuthService
