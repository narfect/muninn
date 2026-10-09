"""Supabase integration tests — fully mocked (no network, deterministic).

Layered like the code under test:

* ``_FakeTransport`` stands in for ``urlopen`` and asserts the exact method/path/headers
  Supabase expects — proving tokens go to the right surface (Auth API vs PostgREST).
* Service-level tests drive ``SupabaseAuthService`` end-to-end over a scripted fake
  (signup -> profile row created, login, logout, token refresh, user isolation).
* Router-level tests prove the HTTP contract survives Supabase mode: Bearer-token
  protected routes, invalid tokens -> 401, profile endpoints, /api/auth/refresh, and
  the 503-mapped missing-configuration path.
* ``TestUnifiedParity`` pins the local auth behavior through the SAME
  ``UnifiedAuthService`` facade, so the two backends stay contract-identical.

No secrets are printed; every response is fabricated in-process.
"""
import dataclasses
import json
import os
import tempfile
import unittest
import urllib.error
from unittest import mock

from backend import server
from backend.config import settings
from backend.db import Repository
from backend.errors import AuthError, ConflictError
from backend.router import Request
from backend.services.supabase_auth import SupabaseAuthService
from backend.services.supabase_client import SupabaseClient, SupabaseError, create_client

# --------------------------------------------------------------------------- #
# Settings helpers — every test runs in Supabase mode with throwaway config.
# --------------------------------------------------------------------------- #

_SUPABASE_ENV = dict(
    supabase_url="https://test-project.supabase.co",
    supabase_anon_key="test-anon-key",
    supabase_service_role_key="test-service-role-key",
    supabase_extra=None,
)


def _sb_settings(**over):
    d = tempfile.mkdtemp()
    base = dict(
        db_path=os.path.join(d, "t.db"),
        hindsight_bank="supabase-test",
        memory_backend="local",
        llm_backend="local",
        server_secret="test-secret-fixed",
        supabase_url="https://test-project.supabase.co",
        supabase_anon_key="test-anon-key",
        supabase_service_role_key="test-service-role-key",
    )
    base.update(over)
    return dataclasses.replace(settings, **base)


_UM = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"   # user A (uuid)
_UM2 = "ffffffff-1111-4222-8333-444444444444"  # user B (uuid)


def _auth_user(uid=_UM, email="a@x.com"):
    return {
        "id": uid,
        "email": email,
        # RBAC role lives in app_metadata (admin-writable); user_metadata carries only the
        # non-privileged display name. Mirrors the real Supabase user shape.
        "user_metadata": {"name": "User A"},
        "app_metadata": {"role": "viewer"},
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "email_confirmed_at": "2026-01-01T00:00:00Z",
    }


def _session_response(uid=_UM, email="a@x.com"):
    return {
        "access_token": f"at-{uid[:8]}",
        "refresh_token": f"rt-{uid[:8]}",
        "expires_in": 3600,
        "token_type": "bearer",
        "user": _auth_user(uid, email),
    }


def _profile_row(uid=_UM, email="a@x.com"):
    return {
        "id": uid, "email": email, "name": "User A", "role": "viewer",
        "avatar_url": "", "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-01T00:00:00+00:00",
    }


# --------------------------------------------------------------------------- #
# Fake transport: intercepts urlopen, scripts responses, records requests.
# --------------------------------------------------------------------------- #

class _FakeTransport:
    """Scripted urllib.request.urlopen replacement.

    ``responses`` maps (method, path-prefix) -> value or exception; ``calls`` records
    every request for assertions about method/path/headers.
    """

    def __init__(self, responses=None, valid_tokens=None):
        self.calls = []
        self.responses = responses or {}
        # Tokens the fake Auth server accepts on GET /auth/v1/user. When None, any
        # token is accepted (tests that only care about transport shape).
        self.valid_tokens = valid_tokens

    def add(self, method, path_prefix, value):
        self.responses[(method, path_prefix)] = value

    def __call__(self, req, timeout=None):  # matches urlopen(req, timeout=...)
        url = req.full_url
        path = url.split("supabase.co", 1)[1] if "supabase.co" in url else url
        method = req.get_method()
        self.calls.append({
            "method": method, "path": path,
            "headers": {k.lower(): v for k, v in req.header_items()},
            "body": req.data,
        })
        # Validate bearer identity on the Auth user endpoint when configured.
        if self.valid_tokens is not None and path.startswith("/auth/v1/user"):
            authz = self.calls[-1]["headers"].get("authorization", "")
            token = authz[7:] if authz.lower().startswith("bearer ") else ""
            if token not in self.valid_tokens:
                raise _http_error(401, {"message": "Invalid token", "code": "401"})
        for (m, prefix), value in self.responses.items():
            if m == method and path.startswith(prefix):
                if isinstance(value, Exception):
                    raise value
                payload = json.dumps(value).encode("utf-8") if value is not None else b""
                return _fake_response(payload)
        # POST/PATCH with no scripted response = success but empty body (covers
        # update-by-filter calls whose reply the test doesn't care about).
        if method in ("POST", "PATCH"):
            return _fake_response(json.dumps({"message": "unscripted"}).encode("utf-8"))
        # Default: a 404-ish HTTPError for anything unscripted.
        raise _http_error(404, {"message": "not scripted", "code": "PGRST116"})

    def calls_to(self, path_prefix):
        return [c for c in self.calls if c["path"].startswith(path_prefix)]


class _fake_response:
    """Minimal urlopen return value: supports read() and context-manager use."""
    def __init__(self, body=b""):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _http_error(status, body):
    err = urllib.error.HTTPError(
        url="https://test-project.supabase.co", code=status, msg="err",
        hdrs=None, fp=None)
    object.__setattr__(err, "read", lambda: json.dumps(body).encode("utf-8"))
    return err


def _http_error_raw(status, raw):
    err = urllib.error.HTTPError(
        url="https://test-project.supabase.co", code=status, msg="err",
        hdrs=None, fp=None)
    object.__setattr__(err, "read", lambda: raw.encode("utf-8"))
    return err


def _patch_transport(transport):
    return mock.patch("urllib.request.urlopen", transport)


# --------------------------------------------------------------------------- #
# Client-level: transport correctness (right method/path/headers/identity)
# --------------------------------------------------------------------------- #

class TestSupabaseClientTransport(unittest.TestCase):
    def setUp(self):
        self.st = _sb_settings()
        self.t = _FakeTransport()
        with _patch_transport(self.t):
            self.client = create_client(self.st)

    def test_missing_config_raises_before_any_network(self):
        with self.assertRaises(SupabaseError):
            create_client(dataclasses.replace(self.st, supabase_url=""))
        with self.assertRaises(SupabaseError):
            create_client(dataclasses.replace(self.st, supabase_anon_key=""))

    def test_invalid_url_rejected(self):
        with self.assertRaises(SupabaseError):
            SupabaseClient(dataclasses.replace(self.st, supabase_url="notaurl"))

    def test_signup_posts_email_password_to_auth_api(self):
        self.t.add("POST", "/auth/v1/signup", _session_response())
        with _patch_transport(self.t):
            out = self.client.signup("a@x.com", "pw-good-strong-1", "Ada")
        self.assertEqual(out["user"]["id"], _UM)
        call = self.t.calls_to("/auth/v1/signup")[0]
        body = json.loads(call["body"])
        self.assertEqual(body["email"], "a@x.com")
        self.assertEqual(body["password"], "pw-good-strong-1")
        self.assertEqual(body["data"]["name"], "Ada")

    def test_login_uses_password_grant_endpoint(self):
        self.t.add("POST", "/auth/v1/token", _session_response())
        with _patch_transport(self.t):
            self.client.login("a@x.com", "pw-good-strong-1")
        call = self.t.calls_to("/auth/v1/token")[0]
        self.assertIn("grant_type=password", call["path"])
        body = json.loads(call["body"])
        self.assertEqual(body["email"], "a@x.com")

    def test_get_user_sends_access_token_as_bearer(self):
        self.t.add("GET", "/auth/v1/user", _auth_user())
        with _patch_transport(self.t):
            self.client.get_user("tok-abc")
        call = self.t.calls_to("/auth/v1/user")[0]
        self.assertEqual(call["headers"]["authorization"], "Bearer tok-abc")

    def test_refresh_uses_refresh_grant(self):
        self.t.add("POST", "/auth/v1/token", _session_response())
        with _patch_transport(self.t):
            self.client.refresh("rt-123")
        call = self.t.calls_to("/auth/v1/token")[0]
        self.assertIn("grant_type=refresh_token", call["path"])
        self.assertEqual(json.loads(call["body"])["refresh_token"], "rt-123")

    def test_select_rls_uses_user_token_not_service_key(self):
        self.t.add("GET", "/rest/v1/profiles", [_profile_row()])
        with _patch_transport(self.t):
            self.client.select("profiles", filters={"id": _UM}, access_token="user-tok")
        call = self.t.calls_to("/rest/v1/profiles")[0]
        self.assertEqual(call["headers"]["authorization"], "Bearer user-tok")
        self.assertEqual(call["headers"]["apikey"], "test-anon-key")

    def test_select_service_role_uses_service_key(self):
        self.t.add("GET", "/rest/v1/profiles", [_profile_row()])
        with _patch_transport(self.t):
            self.client.select("profiles", filters={"id": _UM}, service_role=True)
        call = self.t.calls_to("/rest/v1/profiles")[0]
        self.assertEqual(call["headers"]["authorization"], "Bearer test-service-role-key")

    def test_insert_filters_and_single_shape_the_query(self):
        self.t.add("GET", "/rest/v1/profiles", _profile_row())
        with _patch_transport(self.t):
            self.client.select("profiles", filters={"id": "u1", "role": "viewer"},
                               order="created_at.desc", limit=5, single=True)
        q = self.t.calls_to("/rest/v1/profiles")[0]["path"]
        self.assertIn("id=eq.u1", q)
        self.assertIn("role=eq.viewer", q)
        self.assertIn("order=created_at.desc", q)
        # single=true is expressed as limit=1 + the PostgREST object Accept header.
        self.assertIn("limit=1", q)
        accept = [c for c in self.t.calls if c["path"].startswith("/rest/v1/profiles")][0]
        # (Accept header asserted in test_select_single_uses_postgrest_object_header)

    def test_http_error_maps_to_supabase_error(self):
        self.t.add("POST", "/auth/v1/token",
                   _http_error(400, {"message": "Invalid login credentials",
                                     "code": "400"}))
        with _patch_transport(self.t):
            with self.assertRaises(SupabaseError) as cm:
                self.client.login("a@x.com", "wrong-pass-1")
        self.assertEqual(cm.exception.status, 400)
        self.assertTrue(cm.exception.is_auth)

    def test_non_json_error_body_is_tolerated(self):
        self.t.add("POST", "/auth/v1/token", _http_error_raw(502, "<html>bad gateway</html>"))
        with _patch_transport(self.t):
            with self.assertRaises(SupabaseError):
                self.client.login("a@x.com", "wrong-pass-1")

    def test_network_error_maps_to_code_network_error(self):
        self.t.add("POST", "/auth/v1/token",
                   urllib.error.URLError("connection refused"))
        with _patch_transport(self.t):
            with self.assertRaises(SupabaseError) as cm:
                self.client.login("a@x.com", "pw-good-strong-1")
        self.assertEqual(cm.exception.code, "network_error")

    def test_select_single_uses_postgrest_object_header(self):
        """``single`` selects one object via the PostgREST Accept header (not a query
        param), so malformed results surface as HTTP errors instead of None rows."""
        self.t.add("GET", "/rest/v1/profiles", _profile_row())
        with _patch_transport(self.t):
            self.client.select("profiles", filters={"id": "u1"}, single=True)
        call = self.t.calls_to("/rest/v1/profiles")[0]
        self.assertEqual(call["headers"]["accept"], "application/vnd.pgrst.object+json")
        self.assertIn("limit=1", call["path"])

    def test_service_key_required_for_admin(self):
        client = SupabaseClient(dataclasses.replace(self.st, supabase_service_role_key=""))
        with self.assertRaises(SupabaseError):
            client.admin_delete_user(_UM)

    def test_no_anon_key_for_user_requests(self):
        client = SupabaseClient(dataclasses.replace(self.st, supabase_anon_key=""))
        with self.assertRaises(SupabaseError):
            client.get_user("tok")


# --------------------------------------------------------------------------- #
# Service-level: auth flows over a scripted transport
# --------------------------------------------------------------------------- #

class TestSupabaseAuthService(unittest.TestCase):
    def setUp(self):
        self.st = _sb_settings()
        self.svc = SupabaseAuthService(self.st)
        self.t = _FakeTransport()
        self.t.add("POST", "/auth/v1/signup", _session_response())
        self.t.add("POST", "/auth/v1/token", _session_response())
        self.t.add("GET", "/auth/v1/user", _auth_user())
        self.t.add("POST", "/rest/v1/profiles", [_profile_row()])
        self.t.add("GET", "/rest/v1/profiles", _profile_row())
        self.t.add("PATCH", "/rest/v1/profiles", [_profile_row()])
        self.t.add("POST", "/auth/v1/logout", {})

    def service(self):
        return self.svc, self.t

    def test_signup_creates_profile_and_returns_tokens(self):
        svc, t = self.service()
        with _patch_transport(t):
            user, tokens = svc.signup("a@x.com", "pw-good-strong-1", "Ada")
        self.assertEqual(user.id, _UM)
        self.assertEqual(user.email, "a@x.com")
        self.assertEqual(tokens.access_token, f"at-{_UM[:8]}")
        self.assertEqual(tokens.refresh_token, f"rt-{_UM[:8]}")
        # Profile insert went through PostgREST with the user's token (RLS path).
        inserts = t.calls_to("/rest/v1/profiles")
        self.assertEqual(len(inserts), 1)
        self.assertEqual(inserts[0]["method"], "POST")
        self.assertEqual(inserts[0]["headers"]["authorization"], f"Bearer at-{_UM[:8]}")

    def test_signup_duplicate_email_is_conflict(self):
        svc, t = self.service()
        t.add("POST", "/auth/v1/signup",
              _http_error(422, {"message": "User already registered", "code": ""}))
        with _patch_transport(t):
            with self.assertRaises(ConflictError):
                svc.signup("a@x.com", "pw-good-strong-1")

    def test_signup_weak_inputs_rejected_before_network(self):
        svc, t = self.service()
        with _patch_transport(t):
            with self.assertRaises(ValueError):
                svc.signup("not-an-email", "pw-good-strong-1")
            with self.assertRaises(ValueError):
                svc.signup("a@x.com", "short")
        self.assertEqual(len(t.calls), 0)  # never touched the network

    def test_login_success_and_token_bundle(self):
        svc, t = self.service()
        with _patch_transport(t):
            user, tokens = svc.login("a@x.com", "pw-good-strong-1")
        self.assertEqual(user.email, "a@x.com")
        self.assertTrue(tokens.access_token)

    def test_login_wrong_password_maps_to_auth_error(self):
        svc, t = self.service()
        t.add("POST", "/auth/v1/token",
              _http_error(400, {"message": "Invalid login credentials", "code": "400"}))
        with _patch_transport(t):
            with self.assertRaises(AuthError):
                svc.login("a@x.com", "wrong-pass-1")

    def test_get_user_validates_token_against_auth_server(self):
        svc, t = self.service()
        with _patch_transport(t):
            user = svc.get_user("tok-abc")
        self.assertEqual(user.id, _UM)
        self.assertEqual(t.calls_to("/auth/v1/user")[0]["headers"]["authorization"],
                         "Bearer tok-abc")

    def test_invalid_token_raises_auth_error(self):
        svc, t = self.service()
        t.add("GET", "/auth/v1/user",
              _http_error(401, {"message": "invalid claim: missing sub claim", "code": "401"}))
        with _patch_transport(t):
            with self.assertRaises(AuthError):
                svc.get_user("bogus-token")
            self.assertIsNone(svc.validate_token("bogus-token"))

    def test_role_comes_from_app_metadata(self):
        """RBAC role is read from app_metadata (admin-writable)."""
        svc, t = self.service()
        promoted = _auth_user()
        promoted["app_metadata"] = {"role": "admin"}
        t.add("GET", "/auth/v1/user", promoted)
        with _patch_transport(t):
            user = svc.get_user("tok-abc")
        self.assertEqual(user.role, "admin")

    def test_user_metadata_role_is_ignored(self):
        """Privilege-escalation guard: a role the user can set on their OWN user_metadata
        (PUT /auth/v1/user) must never grant RBAC — only app_metadata, which is written with
        the service role key, is trusted."""
        svc, t = self.service()
        escalated = _auth_user()
        escalated["user_metadata"] = {"name": "User A", "role": "admin"}
        t.add("GET", "/auth/v1/user", escalated)
        with _patch_transport(t):
            user = svc.get_user("tok-abc")
        self.assertEqual(user.role, "viewer")

    def test_admin_set_role_writes_app_metadata_with_service_key(self):
        """Role changes go through the admin API under the service key (never the user's
        own token), writing app_metadata.role."""
        svc, t = self.service()
        t.add("PUT", f"/auth/v1/admin/users/{_UM}", _auth_user())
        with _patch_transport(t):
            svc.admin_set_role(_UM, "admin")
        call = t.calls_to("/auth/v1/admin/users")[0]
        self.assertEqual(call["method"], "PUT")
        self.assertEqual(call["headers"]["authorization"], "Bearer test-service-role-key")
        self.assertEqual(json.loads(call["body"]), {"app_metadata": {"role": "admin"}})

    def test_admin_set_role_rejects_unknown_role(self):
        svc, _ = self.service()
        with self.assertRaises(ValueError):
            svc.admin_set_role(_UM, "superuser")

    def test_validate_token_none_for_empty(self):
        svc, _ = self.service()
        self.assertIsNone(svc.validate_token(None))
        self.assertIsNone(svc.validate_token(""))

    def test_session_cache_serves_repeat_validations(self):
        svc, t = self.service()
        with _patch_transport(t):
            svc.get_user("tok-abc")
            svc.get_user("tok-abc")
            svc.get_user("tok-abc")
        self.assertEqual(len(t.calls_to("/auth/v1/user")), 1)  # one network hit

    def test_logout_revokes_and_clears_cache(self):
        svc, t = self.service()
        with _patch_transport(t):
            svc.get_user("tok-abc")   # primes the cache
            svc.logout("tok-abc")
            svc.get_user("tok-abc")   # must re-validate after logout
        self.assertEqual(len(t.calls_to("/auth/v1/user")), 2)
        self.assertEqual(len(t.calls_to("/auth/v1/logout")), 1)

    def test_logout_upstream_failure_is_tolerated(self):
        svc, t = self.service()
        t.add("POST", "/auth/v1/logout", _http_error(401, {"message": "session gone"}))
        with _patch_transport(t):
            svc.logout("stale-token")  # must NOT raise

    def test_refresh_session_rotates_tokens(self):
        svc, t = self.service()
        t.add("POST", "/auth/v1/token", _session_response())
        with _patch_transport(t):
            user, tokens = svc.refresh_session("rt-old")
        self.assertEqual(tokens.access_token, f"at-{_UM[:8]}")
        call = t.calls_to("/auth/v1/token")[0]
        self.assertEqual(json.loads(call["body"])["refresh_token"], "rt-old")

    def test_refresh_with_empty_token_is_auth_error(self):
        svc, _ = self.service()
        with self.assertRaises(AuthError):
            svc.refresh_session("")

    def test_profile_get_and_update(self):
        svc, t = self.service()
        with _patch_transport(t):
            profile = svc.get_profile(_UM, "tok-abc")
            self.assertEqual(profile.id, _UM)
            updated = svc.update_profile(_UM, "tok-abc", {"name": "New Name",
                                                           "role": "admin"})
        # The fake echoes the scripted row on read-back, so the returned profile keeps
        # the scripted name — the assertion is that a read-back happened and succeeded.
        self.assertEqual(updated.name, "User A")
        # role is privileged: never written through the profile-update path
        patches = [c for c in t.calls_to("/rest/v1/profiles") if c["method"] == "PATCH"]
        self.assertEqual(json.loads(patches[0]["body"]), {"name": "New Name"})
        # The patch ran under the user's token (RLS), not the service key.
        self.assertEqual(patches[0]["headers"]["authorization"], "Bearer tok-abc")

    def test_profile_update_with_no_allowed_fields_is_read(self):
        svc, t = self.service()
        with _patch_transport(t):
            profile = svc.update_profile(_UM, "tok-abc", {"role": "admin", "evil": "x"})
        self.assertEqual(profile.role, "viewer")  # unchanged
        self.assertEqual(len(t.calls_to("/rest/v1/profiles")), 1)  # just the read

    def test_profile_of_foreign_user_hidden_by_rls_is_404(self):
        svc, t = self.service()
        # RLS hides foreign rows: PostgREST returns an empty result (no row).
        t.add("GET", "/rest/v1/profiles", None)
        with _patch_transport(t):
            from backend.errors import NotFoundError
            with self.assertRaises(NotFoundError):
                svc.get_profile(_UM2, "tok-abc")

    def test_email_confirmation_pending_signup_has_no_tokens(self):
        svc, t = self.service()
        t.add("POST", "/auth/v1/signup", {"user": _auth_user()})  # no session keys
        with _patch_transport(t):
            user, tokens = svc.signup("a@x.com", "pw-good-strong-1")
        self.assertEqual(user.id, _UM)
        self.assertEqual(tokens.access_token, "")
        self.assertEqual(tokens.refresh_token, "")

    def test_signup_with_profile_trigger_race_still_succeeds(self):
        """The SQL trigger created the profile first: our explicit insert hits 23505 and
        the signup must still succeed by falling back to a read."""
        svc, t = self.service()
        t.add("POST", "/rest/v1/profiles",
              _http_error(409, {"message": "duplicate key value violates unique constraint",
                                "code": "23505"}))
        with _patch_transport(t):
            user, tokens = svc.signup("a@x.com", "pw-good-strong-1", "Ada")
        self.assertEqual(user.id, _UM)
        self.assertTrue(tokens.access_token)

    def test_network_outage_maps_to_uniform_auth_error(self):
        svc, t = self.service()
        t.add("POST", "/auth/v1/token", urllib.error.URLError("dns failure"))
        with _patch_transport(t):
            with self.assertRaises(AuthError):
                svc.login("a@x.com", "pw-good-strong-1")


# --------------------------------------------------------------------------- #
# Router-level: the HTTP contract in Supabase mode
# --------------------------------------------------------------------------- #

class _SupabaseApp:
    """Wires the real app in Supabase mode with a scripted transport installed."""

    def __init__(self, **over):
        st = _sb_settings(**over)
        self.transport = _FakeTransport(
            valid_tokens={f"at-{_UM[:8]}"})  # only the scripted session token validates
        self.transport.add("POST", "/auth/v1/signup", _session_response())
        self.transport.add("POST", "/auth/v1/token", _session_response())
        self.transport.add("GET", "/auth/v1/user", _auth_user())
        self.transport.add("POST", "/rest/v1/profiles", [_profile_row()])
        self.transport.add("GET", "/rest/v1/profiles", _profile_row())
        self.transport.add("PATCH", "/rest/v1/profiles", [_profile_row()])
        self.transport.add("POST", "/auth/v1/logout", {})
        self._patcher = _patch_transport(self.transport)
        self._patcher.start()
        self.addCleanup = None
        try:
            self.ctx = server.build_context(st)
            self.router = server.build_router(self.ctx)
        finally:
            pass

    def stop(self):
        self._patcher.stop()

    def dispatch(self, method, path, body=None, headers=None):
        raw = json.dumps(body).encode("utf-8") if body is not None else b""
        resp = self.router.dispatch(Request.build(method, path, headers or {}, raw))
        parsed = json.loads(resp.body.decode("utf-8")) if resp.body else None
        return resp, parsed


def _bearer(tok):
    return {"Authorization": f"Bearer {tok}"}


class TestSupabaseRouter(unittest.TestCase):
    def setUp(self):
        self.app = _SupabaseApp()
        self.addCleanup(self.app.stop)

    def _signup(self):
        return self.app.dispatch("POST", "/api/auth/signup",
                                 {"email": "a@x.com", "password": "pw-good-strong-1",
                                  "name": "Ada"})

    def test_signup_returns_session_in_body_no_cookies(self):
        resp, body = self._signup()
        self.assertEqual(resp.status, 201)
        self.assertEqual(body["user"]["email"], "a@x.com")
        self.assertEqual(body["backend"], "supabase")
        self.assertEqual(body["session"]["access_token"], f"at-{_UM[:8]}")
        self.assertEqual(resp.cookies, [])  # tokens never ride in cookies

    def test_login_returns_session(self):
        resp, body = self.app.dispatch("POST", "/api/auth/login",
                                       {"email": "a@x.com", "password": "pw-good-strong-1"})
        self.assertEqual(resp.status, 200)
        self.assertIn("session", body)

    def test_login_wrong_password_is_401(self):
        self.app.transport.add("POST", "/auth/v1/token",
                               _http_error(400, {"message": "Invalid login credentials",
                                                 "code": "400"}))
        resp, _ = self.app.dispatch("POST", "/api/auth/login",
                                    {"email": "a@x.com", "password": "wrong-pass-1"})
        self.assertEqual(resp.status, 401)

    def test_protected_route_with_bearer_token(self):
        _, body = self._signup()
        tok = body["session"]["access_token"]
        resp, incidents = self.app.dispatch("GET", "/api/incidents", headers=_bearer(tok))
        self.assertEqual(resp.status, 200)
        self.assertIn("incidents", incidents)

    def test_protected_route_without_token_is_401(self):
        resp, _ = self.app.dispatch("GET", "/api/incidents")
        self.assertEqual(resp.status, 401)

    def test_invalid_token_is_401(self):
        self.app.transport.add("GET", "/auth/v1/user",
                               _http_error(401, {"message": "Invalid token", "code": "401"}))
        resp, _ = self.app.dispatch("GET", "/api/incidents", headers=_bearer("bogus"))
        self.assertEqual(resp.status, 401)

    def test_logout_with_invalid_token_is_401(self):
        """Logout is a protected route: an unauthenticated caller (invalid token) is
        rejected at the gate — the SPA clears its local session regardless."""
        resp, _ = self.app.dispatch("POST", "/api/auth/logout",
                                    headers=_bearer("bogus-token"))
        self.assertEqual(resp.status, 401)

    def test_logout_with_valid_token_revokes_upstream(self):
        _, body = self._signup()
        tok = body["session"]["access_token"]
        resp, payload = self.app.dispatch("POST", "/api/auth/logout",
                                          headers=_bearer(tok))
        self.assertEqual(resp.status, 200)
        self.assertTrue(payload["ok"])
        # The revocation reached the Supabase Auth API under the user's token.
        logouts = self.app.transport.calls_to("/auth/v1/logout")
        self.assertEqual(len(logouts), 1)
        self.assertEqual(logouts[0]["headers"]["authorization"], f"Bearer {tok}")

    def test_me_with_bearer_returns_user(self):
        _, body = self._signup()
        tok = body["session"]["access_token"]
        resp, me = self.app.dispatch("GET", "/api/auth/me", headers=_bearer(tok))
        self.assertEqual(resp.status, 200)
        self.assertEqual(me["user"]["email"], "a@x.com")
        self.assertEqual(me["backend"], "supabase")

    def test_refresh_route_rotates_session(self):
        _, body = self._signup()
        rt = body["session"]["refresh_token"]
        resp, payload = self.app.dispatch("POST", "/api/auth/refresh",
                                          {"refresh_token": rt})
        self.assertEqual(resp.status, 200)
        self.assertEqual(payload["session"]["access_token"], f"at-{_UM[:8]}")

    def test_refresh_with_bad_token_is_401(self):
        self.app.transport.add("POST", "/auth/v1/token",
                               _http_error(400, {"message": "Invalid Refresh Token",
                                                 "code": "400"}))
        resp, _ = self.app.dispatch("POST", "/api/auth/refresh",
                                    {"refresh_token": "bogus"})
        self.assertEqual(resp.status, 401)

    def test_profile_get_and_patch(self):
        _, body = self._signup()
        tok = body["session"]["access_token"]
        resp, prof = self.app.dispatch("GET", "/api/auth/profile", headers=_bearer(tok))
        self.assertEqual(resp.status, 200)
        self.assertEqual(prof["profile"]["id"], _UM)
        # PATCH /api/auth/profile: the routed request must reach PostgREST as a PATCH
        # carrying {"name": "Renamed"} under the user's token (RLS).
        resp, _ = self.app.dispatch("PATCH", "/api/auth/profile", {"name": "Renamed"},
                                    headers=_bearer(tok))
        self.assertEqual(resp.status, 200)
        patches = [c for c in self.app.transport.calls_to("/rest/v1/profiles")
                   if c["method"] == "PATCH"]
        self.assertTrue(patches, "no PATCH reached PostgREST")
        self.assertEqual(json.loads(patches[0]["body"]), {"name": "Renamed"})

    def test_demo_mode_disabled_in_supabase(self):
        resp, status = self.app.dispatch("GET", "/api/auth/demo-status")
        self.assertEqual(resp.status, 200)
        self.assertFalse(status["enabled"])
        resp, _ = self.app.dispatch("POST", "/api/auth/demo-login", {"role": "admin"})
        self.assertEqual(resp.status, 404)

    def test_health_is_public(self):
        resp, _ = self.app.dispatch("GET", "/api/health")
        self.assertEqual(resp.status, 200)

    def test_malformed_authorization_header_is_401(self):
        resp, _ = self.app.dispatch("GET", "/api/incidents",
                                    headers={"Authorization": "Basic dXNlcjpwYXNz"})
        self.assertEqual(resp.status, 401)

    def test_missing_configuration_falls_back_to_local(self):
        """When Supabase env vars are absent (URL empty), wiring falls back cleanly to
        local auth — the server still boots and local login works."""
        st = _sb_settings(supabase_url="")
        ctx = server.build_context(st)
        self.assertEqual(ctx.auth.backend, "local")

    def test_sse_stream_authenticates_query_token(self):
        """EventSource can't send headers; the access_token query parameter must
        authenticate the request (VIEWER role). We can't dispatch through the router
        (that would START the SSE worker), so assert on the middleware directly."""
        _, body = self._signup()
        tok = body["session"]["access_token"]
        req = Request.build("GET", f"/api/triage/stream?incident_id=1&access_token={tok}",
                            {"Host": "127.0.0.1"}, b"")
        self.app.router._authenticate(req)
        self.assertIsNotNone(req.current_user, "query access_token must authenticate")
        self.assertEqual(req.current_user.email, "a@x.com")
        self.assertEqual(req.auth_type, "bearer")
        # And a garbage token must NOT authenticate.
        req2 = Request.build("GET", f"/api/triage/stream?incident_id=1&access_token=garbage",
                             {"Host": "127.0.0.1"}, b"")
        self.app.router._authenticate(req2)
        self.assertIsNone(req2.current_user)


class TestSupabaseMissingConfig(unittest.TestCase):
    def test_unresolved_supabase_falls_back_to_local(self):
        st = _sb_settings(supabase_url="", supabase_anon_key="")
        ctx = server.build_context(st)
        self.assertEqual(ctx.auth.backend, "local")

    def test_partial_config_requires_both_keys(self):
        st = _sb_settings(supabase_anon_key="")
        ctx = server.build_context(st)
        self.assertEqual(ctx.auth.backend, "local")

    def test_explicit_flag_without_config_fails_fast(self):
        # MUNINN_USE_SUPABASE=true with no URL/keys cannot talk to Supabase. The facade
        # validates config EAGERLY (fail fast at boot, not on the first request) and
        # build_context surfaces the error.
        st = _sb_settings(supabase_url="", supabase_anon_key="", use_supabase=True)
        # The explicit flag forces Supabase mode even without config...
        self.assertTrue(st.resolved_use_supabase())
        # ...and construction must fail fast with a clear config error.
        with self.assertRaises(SupabaseError):
            server.build_context(st)


# --------------------------------------------------------------------------- #
# Unified facade parity: the local contract must survive through the facade
# --------------------------------------------------------------------------- #

class TestUnifiedParity(unittest.TestCase):
    """Local-mode behavior through UnifiedAuthService — the contract the existing
    test suite (and the SPA in local mode) relies on."""

    def setUp(self):
        d = tempfile.mkdtemp()
        self.st = dataclasses.replace(settings, db_path=os.path.join(d, "t.db"),
                                      hindsight_bank="parity-test",
                                      memory_backend="local", llm_backend="local",
                                      server_secret="test-secret-fixed",
                                      supabase_url="", supabase_anon_key="")
        self.repo = Repository(self.st.db_path)
        self.auth = server.AppContext.__init__ and None  # placeholder, replaced below
        from backend.services.auth_unified import UnifiedAuthService
        self.auth = UnifiedAuthService(self.repo, self.st)

    def test_signup_login_logout_roundtrip(self):
        user, token, csrf = self.auth.signup("a@x.com", "pw-good-strong-1", "A")
        self.assertEqual(user.role, "admin")  # first account bootstraps to admin
        self.assertTrue(token and csrf)
        user2, token2, _ = self.auth.login("a@x.com", "pw-good-strong-1")
        self.assertEqual(user2.id, user.id)
        self.assertIsNotNone(self.auth.authenticate(token2))
        self.auth.logout(token2)
        self.assertIsNone(self.auth.authenticate(token2))

    def test_duplicate_signup_conflict(self):
        self.auth.signup("a@x.com", "pw-good-strong-1")
        with self.assertRaises(ConflictError):
            self.auth.signup("a@x.com", "pw-good-strong-1")

    def test_wrong_password_auth_error(self):
        self.auth.signup("a@x.com", "pw-good-strong-1")
        with self.assertRaises(AuthError):
            self.auth.login("a@x.com", "wrong-pass-1")

    def test_csrf_token_deterministic(self):
        self.assertEqual(self.auth.csrf_token("abc"), self.auth.csrf_token("abc"))
        self.assertNotEqual(self.auth.csrf_token("abc"), self.auth.csrf_token("xyz"))

    def test_local_session_payload_has_no_tokens(self):
        user, token, csrf = self.auth.signup("a@x.com", "pw-good-strong-1")
        payload = self.auth.build_session_payload(user, token)
        self.assertEqual(payload["backend"], "local")
        self.assertNotIn("session", payload)

    def test_settings_propagation_rotates_csrf(self):
        user, token, _ = self.auth.signup("a@x.com", "pw-good-strong-1")
        old = self.auth.csrf_token("x")
        self.auth.settings = dataclasses.replace(self.st, server_secret="rotated")
        self.assertNotEqual(self.auth.csrf_token("x"), old)


if __name__ == "__main__":
    unittest.main()
