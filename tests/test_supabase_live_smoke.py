"""Guarded LIVE smoke test for Supabase (opt-in, mirrors test_hindsight_live_smoke.py).

Runs against a REAL Supabase project only when the environment is configured AND
``MUNINN_SUPABASE_SMOKE=1`` is set — so ``make test`` never touches the network. The
flow proves the live loop end-to-end:

    signup (unique address) -> profile auto-created -> /auth/v1/user validates ->
    profile read via RLS -> password login -> refresh rotation -> logout revocation ->
    wrong password rejected -> admin cleanup of the throwaway user.

Requires the project to have email confirmation disabled (the default for new
projects) and the ``profiles`` migration applied. No secret is printed; the created
user is deleted in a finally block.
"""
import os
import time
import unittest
import uuid

from backend.config import settings

_SMOKE_ENV = (
    os.getenv("SUPABASE_URL")
    and os.getenv("SUPABASE_ANON_KEY")
    and os.getenv("MUNINN_SUPABASE_SMOKE", "").strip().lower() in {"1", "true", "yes", "on"}
)


@unittest.skipUnless(_SMOKE_ENV,
                     "set SUPABASE_URL + SUPABASE_ANON_KEY (+ SUPABASE_SERVICE_ROLE_KEY "
                     "for cleanup) and MUNINN_SUPABASE_SMOKE=1 to run the live smoke test")
class TestSupabaseLiveSmoke(unittest.TestCase):
    def setUp(self):
        from backend.services.supabase_auth import SupabaseAuthService
        from backend.services.supabase_client import create_client

        create_client(settings)  # fail fast with a clear message on bad config
        self.svc = SupabaseAuthService(settings)
        # Unique address per run: the project may keep signed-up users between runs.
        self.email = f"muninn-smoke-{uuid.uuid4().hex[:10]}@example.com"
        self.password = "smoke-test-passphrase-1"

    def tearDown(self):
        # Best-effort cleanup with the service role key; skip silently when absent.
        if getattr(self, "_user_id", None) and settings.supabase_service_role_key:
            try:
                self.svc.admin_delete_user(self._user_id)
            except Exception:  # noqa: BLE001 - cleanup must never fail the test
                pass

    def test_signup_login_refresh_logout_roundtrip(self):
        svc = self.svc

        # 1. Signup -> session + auto-created profile row (trigger and/or explicit insert).
        user, tokens = svc.signup(self.email, self.password, "Muninn Smoke")
        self._user_id = user.id
        self.assertTrue(user.id and user.email)
        self.assertTrue(tokens.access_token, "project must have email confirmation disabled "
                                              "for the smoke test")

        # 2. Profile is readable through the caller's token (RLS path).
        profile = svc.get_profile(user.id, tokens.access_token)
        self.assertEqual(profile.id, user.id)
        self.assertEqual(profile.email, self.email)

        # 3. The access token validates against /auth/v1/user.
        me = svc.get_user(tokens.access_token)
        self.assertEqual(me.id, user.id)

        # 4. Password login returns a working session.
        login_user, login_tokens = svc.login(self.email, self.password)
        self.assertEqual(login_user.id, user.id)
        self.assertTrue(login_tokens.access_token)
        self.assertTrue(svc.validate_token(login_tokens.access_token))

        # 5. Refresh rotation issues a fresh, valid access token.
        r_user, r_tokens = svc.refresh_session(login_tokens.refresh_token)
        self.assertEqual(r_user.id, user.id)
        self.assertTrue(svc.validate_token(r_tokens.access_token))

        # 6. Logout revokes the refresh token: reusing it must now fail.
        svc.logout(r_tokens.access_token)
        time.sleep(0.5)
        from backend.errors import AuthError
        with self.assertRaises(AuthError):
            svc.refresh_session(r_tokens.refresh_token)

        # 7. A wrong password is rejected.
        with self.assertRaises(AuthError):
            svc.login(self.email, "definitely-wrong-password")

        # 8. RLS isolation: reading a foreign (nonexistent) id yields nothing.
        from backend.errors import NotFoundError
        foreign_id = str(uuid.uuid4())
        with self.assertRaises(NotFoundError):
            svc.get_profile(foreign_id, tokens.access_token)


if __name__ == "__main__":
    unittest.main()
