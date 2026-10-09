"""Supabase PostgreSQL (PostgREST) data layer for the ``profiles`` table.

Thin, explicit wrapper over :class:`SupabaseClient` where every method names its
*acting identity* — user-token requests (RLS enforced: a user can only touch their own
row) versus ``service_role`` requests (server-side admin, RLS bypassed). User-facing
methods take the caller's access token; admin methods never accept one.

Used by the auth service for auto-profile creation and by the (future) admin
surfaces for user management. No third-party dependency.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from ..config import Settings
from .supabase_client import SupabaseClient, SupabaseError, create_client

log = logging.getLogger("muninn.supabase_db")

_ALLOWED_PROFILE_FIELDS = frozenset({"name", "role", "avatar_url"})


def filter_profile_fields(data: dict[str, Any]) -> dict[str, Any]:
    """Keep only profile columns a client may set; drop unknown keys silently."""
    return {k: v for k, v in data.items() if k in _ALLOWED_PROFILE_FIELDS}


class SupabaseRepository:
    """Profiles-table operations via PostgREST with explicit identity per call."""

    def __init__(self, settings: Settings, access_token: Optional[str] = None) -> None:
        self.settings = settings
        self.access_token = access_token  # default acting user for token-mode calls
        self._client: Optional[SupabaseClient] = None

    @property
    def client(self) -> SupabaseClient:
        if self._client is None:
            self._client = create_client(self.settings)
        return self._client

    # --- user-identity operations (RLS enforced) ---------------------------

    def get_profile(self, user_id: str, access_token: Optional[str] = None) -> Optional[dict[str, Any]]:
        """Fetch the caller's own profile row. RLS limits the result to it; a foreign
        ``user_id`` simply yields no rows (None), never someone else's data."""
        token = access_token or self.access_token
        if not token:
            raise SupabaseError("get_profile requires an access token", status=0, code="config_error")
        row = self.client.select("profiles", filters={"id": user_id}, single=True,
                                 access_token=token)
        return row if isinstance(row, dict) else None

    def upsert_profile(self, profile: dict[str, Any], access_token: Optional[str] = None) -> Optional[dict[str, Any]]:
        """Create-or-update the caller's own profile row (RLS-checked)."""
        token = access_token or self.access_token
        if not token:
            raise SupabaseError("upsert_profile requires an access token", status=0, code="config_error")
        row = self.client.upsert("profiles", profile, access_token=token)
        if isinstance(row, list) and row:
            row = row[0]
        return row if isinstance(row, dict) else None

    def update_profile(self, user_id: str, data: dict[str, Any], access_token: Optional[str] = None) -> Optional[dict[str, Any]]:
        """Patch the caller's own profile; unknown/forbidden fields are dropped."""
        token = access_token or self.access_token
        if not token:
            raise SupabaseError("update_profile requires an access token", status=0, code="config_error")
        rows = self.client.update("profiles", filter_profile_fields(data),
                                  filters={"id": user_id}, access_token=token)
        if isinstance(rows, list) and rows:
            return rows[0]
        return None

    # --- admin operations (service role, RLS bypassed) ----------------------

    def admin_get_profile(self, user_id: str) -> Optional[dict[str, Any]]:
        row = self.client.select("profiles", filters={"id": user_id}, single=True,
                                 service_role=True)
        return row if isinstance(row, dict) else None

    def admin_list_profiles(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.client.select("profiles", order="created_at.desc", limit=limit,
                                  service_role=True)
        return rows if isinstance(rows, list) else []

    def admin_update_profile(self, user_id: str, data: dict[str, Any]) -> Optional[dict[str, Any]]:
        rows = self.client.update("profiles", filter_profile_fields(data),
                                  filters={"id": user_id}, service_role=True)
        if isinstance(rows, list) and rows:
            return rows[0]
        return None

    def admin_delete_profile(self, user_id: str) -> None:
        self.client.delete("profiles", filters={"id": user_id}, service_role=True)

    # --- generic table helpers (for future, non-profile tables) -------------

    def select(self, table: str, columns: str = "*", filters: Optional[dict[str, Any]] = None,
               order: Optional[str] = None, limit: Optional[int] = None,
               access_token: Optional[str] = None, service_role: bool = False) -> list[dict[str, Any]]:
        rows = self.client.select(table, columns=columns, filters=filters, order=order,
                                  limit=limit, access_token=access_token,
                                  service_role=service_role)
        return rows if isinstance(rows, list) else []

    def insert(self, table: str, data: dict[str, Any], access_token: Optional[str] = None,
               service_role: bool = False) -> Optional[dict[str, Any]]:
        rows = self.client.insert(table, data, access_token=access_token,
                                  service_role=service_role)
        if isinstance(rows, list) and rows:
            return rows[0]
        return rows if isinstance(rows, dict) else None

    def update(self, table: str, data: dict[str, Any], filters: dict[str, Any],
               access_token: Optional[str] = None, service_role: bool = False) -> Optional[dict[str, Any]]:
        rows = self.client.update(table, data, filters=filters, access_token=access_token,
                                  service_role=service_role)
        if isinstance(rows, list) and rows:
            return rows[0]
        return None

    def delete(self, table: str, filters: dict[str, Any], access_token: Optional[str] = None,
               service_role: bool = False) -> None:
        self.client.delete(table, filters=filters, access_token=access_token,
                           service_role=service_role)


def create_supabase_repo(settings: Settings, access_token: Optional[str] = None) -> SupabaseRepository:
    """Factory to create a SupabaseRepository bound to an acting user (or admin)."""
    return SupabaseRepository(settings, access_token)
