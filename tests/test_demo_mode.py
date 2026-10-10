"""Open demo mode, autoseed, and the viewer-can-triage RBAC realignment (docs
PRODUCTION_PLAN §5–§6). Offline + deterministic: temp SQLite DB, local memory + local
reasoner, requests dispatched through the real router (auth middleware included).
"""
import dataclasses
import json
import logging
import os
import tempfile
import unittest

from backend import server
from backend.config import settings
from backend.router import Request

_ORIGIN = {"Origin": "http://127.0.0.1", "Host": "127.0.0.1"}


def _settings(**over):
    d = tempfile.mkdtemp()
    base = dict(db_path=os.path.join(d, "t.db"), hindsight_bank="demo-test",
                memory_backend="local", llm_backend="local")
    base.update(over)
    return dataclasses.replace(settings, **base)


def _ctx_router(**over):
    ctx = server.build_context(_settings(**over))
    return ctx, server.build_router(ctx)


def _cookies_from(resp):
    token = csrf = ""
    for c in resp.cookies:
        name, _, rest = c.partition("=")
        value = rest.split(";", 1)[0]
        if name == "muninn_session":
            token = value
        elif name == "muninn_csrf":
            csrf = value
    return token, csrf


def _headers(token, csrf):
    return {"Cookie": f"muninn_session={token}", "X-CSRF-Token": csrf, **_ORIGIN}


def _dispatch(router, method, path, body=None, headers=None):
    raw = json.dumps(body).encode("utf-8") if body is not None else b""
    resp = router.dispatch(Request.build(method, path, dict(headers or _ORIGIN), raw))
    parsed = json.loads(resp.body.decode("utf-8")) if resp.body else None
    return resp, parsed


def _signup(router, email, pw, name=""):
    resp, body = _dispatch(router, "POST", "/api/auth/signup",
                           {"email": email, "password": pw, "name": name})
    token, csrf = _cookies_from(resp)
    return body, _headers(token, csrf)


class TestViewerRBAC(unittest.TestCase):
    """A viewer may run read-only analysis (triage/compare/reflect) but not mutate."""

    def test_viewer_can_triage_compare_but_not_mutate(self):
        ctx, router = _ctx_router(demo_open=False)  # isolate from open-demo bootstrap
        _, admin_h = _signup(router, "admin@x.io", "muninn-admin-1")
        _dispatch(router, "POST", "/api/demo/seed", {}, admin_h)  # need an incident to triage
        inc = ctx.repo.get_incident_by_external("INC-0058")

        v_body, v_h = _signup(router, "viewer@x.io", "muninn-viewer-1")
        self.assertEqual(v_body["user"]["role"], "viewer")

        r_triage, _ = _dispatch(router, "POST", "/api/triage", {"incident_id": inc.id}, v_h)
        self.assertEqual(r_triage.status, 200)
        r_compare, _ = _dispatch(router, "POST", "/api/compare", {"incident_id": inc.id}, v_h)
        self.assertEqual(r_compare.status, 200)
        r_reflect, _ = _dispatch(router, "POST", "/api/memory/reflect",
                                 {"query": "checkout 5xx conn_pool"}, v_h)
        self.assertEqual(r_reflect.status, 200)

        r_create, _ = _dispatch(router, "POST", "/api/incidents",
                                {"title": "x", "service": "checkout-api", "severity": "SEV1"}, v_h)
        self.assertEqual(r_create.status, 403)
        r_seed, _ = _dispatch(router, "POST", "/api/demo/seed", {}, v_h)
        self.assertEqual(r_seed.status, 403)


class TestAutoseed(unittest.TestCase):
    def test_autoseed_populates_empty_db(self):
        ctx, _ = _ctx_router(demo_open=False, demo_autoseed=True)
        self.assertEqual(ctx.repo.list_incidents(limit=1), [])
        server.bootstrap(ctx)
        self.assertGreater(len(ctx.repo.list_incidents()), 0)

    def test_autoseed_off_leaves_db_empty(self):
        ctx, _ = _ctx_router(demo_open=False, demo_autoseed=False)
        server.bootstrap(ctx)
        self.assertEqual(ctx.repo.list_incidents(), [])

    def test_autoseed_is_noop_when_data_exists(self):
        ctx, _ = _ctx_router(demo_open=False, demo_autoseed=True)
        server.bootstrap(ctx)
        first = {i.external_id for i in ctx.repo.list_incidents()}
        server.bootstrap(ctx)  # second run must not wipe/duplicate
        self.assertEqual({i.external_id for i in ctx.repo.list_incidents()}, first)


class TestDemoStatus(unittest.TestCase):
    def test_enabled_lists_roles(self):
        _, router = _ctx_router(demo_open=True)
        resp, body = _dispatch(router, "GET", "/api/auth/demo-status")
        self.assertEqual(resp.status, 200)
        self.assertTrue(body["enabled"])
        self.assertEqual(body["roles"], ["viewer", "responder", "admin"])

    def test_disabled_when_flag_off(self):
        _, router = _ctx_router(demo_open=False)
        resp, body = _dispatch(router, "GET", "/api/auth/demo-status")
        self.assertEqual(resp.status, 200)
        self.assertFalse(body["enabled"])


class TestDemoLogin(unittest.TestCase):
    def test_login_each_role_mints_matching_session_no_password(self):
        ctx, router = _ctx_router(demo_open=True)
        server.bootstrap(ctx)
        for role in ("viewer", "responder", "admin"):
            resp, body = _dispatch(router, "POST", "/api/auth/demo-login", {"role": role})
            self.assertEqual(resp.status, 200)
            self.assertEqual(body["user"]["role"], role)
            self.assertEqual(body["user"]["email"], f"{role}@muninn.local")
            # never expose secrets, in any shape
            self.assertNotIn("password", body["user"])
            self.assertNotIn("password_hash", body["user"])
            self.assertNotIn("password", resp.body.decode("utf-8").lower())
            token, csrf = _cookies_from(resp)
            self.assertTrue(token and csrf)

    def test_viewer_demo_session_enforces_rbac(self):
        ctx, router = _ctx_router(demo_open=True)
        server.bootstrap(ctx)  # also autoseeds -> incidents exist
        resp, _ = _dispatch(router, "POST", "/api/auth/demo-login", {"role": "viewer"})
        h = _headers(*_cookies_from(resp))
        inc = ctx.repo.get_incident_by_external("INC-0058")
        r_compare, _ = _dispatch(router, "POST", "/api/compare", {"incident_id": inc.id}, h)
        self.assertEqual(r_compare.status, 200)
        r_create, _ = _dispatch(router, "POST", "/api/incidents",
                                {"title": "x", "service": "checkout-api", "severity": "SEV1"}, h)
        self.assertEqual(r_create.status, 403)
        r_seed, _ = _dispatch(router, "POST", "/api/demo/seed", {}, h)
        self.assertEqual(r_seed.status, 403)

    def test_admin_demo_session_can_seed(self):
        ctx, router = _ctx_router(demo_open=True)
        server.bootstrap(ctx)
        resp, _ = _dispatch(router, "POST", "/api/auth/demo-login", {"role": "admin"})
        h = _headers(*_cookies_from(resp))
        r_seed, body = _dispatch(router, "POST", "/api/demo/seed", {}, h)
        self.assertEqual(r_seed.status, 200)
        self.assertTrue(body["synthetic"])

    def test_demo_login_404_when_flag_off(self):
        ctx, router = _ctx_router(demo_open=False)
        server.bootstrap(ctx)  # provisions NO demo accounts when flag off
        resp, _ = _dispatch(router, "POST", "/api/auth/demo-login", {"role": "admin"})
        self.assertEqual(resp.status, 404)

    def test_unknown_role_is_404(self):
        ctx, router = _ctx_router(demo_open=True)
        server.bootstrap(ctx)
        resp, _ = _dispatch(router, "POST", "/api/auth/demo-login", {"role": "superuser"})
        self.assertEqual(resp.status, 404)


class TestProductionDemoOptIn(unittest.TestCase):
    """A deployment can explicitly opt into demo mode even when it has a server secret."""

    def test_explicit_demo_flag_overrides_server_secret(self):
        from backend.config import Settings
        prev_secret = os.environ.get("MUNINN_SERVER_SECRET")
        prev_flag = os.environ.get("MUNINN_DEMO_OPEN")
        os.environ["MUNINN_SERVER_SECRET"] = "a-real-production-secret"
        os.environ["MUNINN_DEMO_OPEN"] = "true"
        try:
            self.assertTrue(Settings().demo_open)
        finally:
            for k, v in (("MUNINN_SERVER_SECRET", prev_secret),
                         ("MUNINN_DEMO_OPEN", prev_flag)):
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


class TestOpenDemoWarning(unittest.TestCase):
    """PRIORITY 2 (#3): bootstrap must log a clear WARNING whenever open demo mode is
    active (anyone can mint an admin session), and stay silent about it when it's off, so an
    accidental open deployment is visible in the logs."""

    @staticmethod
    def _warnings_during_bootstrap(ctx):
        logger = logging.getLogger("muninn.server")
        records: list[str] = []

        class _Capture(logging.Handler):
            def emit(self, record):
                records.append(record.getMessage())

        cap = _Capture(level=logging.WARNING)
        logger.addHandler(cap)
        try:
            server.bootstrap(ctx)
        finally:
            logger.removeHandler(cap)
        return records

    def test_open_demo_logs_warning(self):
        ctx, _ = _ctx_router(demo_open=True)
        warnings = self._warnings_during_bootstrap(ctx)
        self.assertTrue(any("OPEN DEMO MODE" in w for w in warnings),
                        f"expected an OPEN DEMO MODE warning, got: {warnings}")

    def test_closed_demo_is_silent(self):
        ctx, _ = _ctx_router(demo_open=False)
        warnings = self._warnings_during_bootstrap(ctx)
        self.assertFalse(any("OPEN DEMO MODE" in w for w in warnings))


if __name__ == "__main__":
    unittest.main()
