"""Package marker for the Muninn test suite (stdlib unittest).

Run:  python -m unittest discover -s tests -v
Concrete-layer tests are green now; behavior implemented by Claude Code is marked
with @unittest.skip and carries the exact assertions to write.
"""
import os

# ---------------------------------------------------------------------------
# Pin the suite to LOCAL auth. The repo's .env may hold a developer's real Supabase
# credentials; backend/config.py loads .env at import, which would otherwise auto-flip
# every offline test into Supabase mode (no cookies/CSRF, 401 on fake tokens) and the
# suite would fail for environment reasons, not code. Force local by setting an explicit
# opt-out BEFORE backend.config is imported. Setting the keys (rather than deleting them)
# also stops _load_dotenv from re-populating them from .env. test_supabase builds its own
# Settings with explicit Supabase config via dataclasses.replace and is unaffected.
#
# The opt-in live smoke test (make test-supabase-live) sets MUNINN_SUPABASE_SMOKE, which
# we honor by leaving the real env in place so it can reach the project.
# ---------------------------------------------------------------------------
if os.environ.get("MUNINN_SUPABASE_SMOKE", "").strip().lower() not in {"1", "true", "yes", "on"}:
    # Blank (not "false"): keeps supabase_force_local off so test_supabase's own
    # dataclasses.replace settings still auto-detect Supabase from their explicit URL/keys.
    os.environ["MUNINN_USE_SUPABASE"] = ""
    for _k in ("SUPABASE_URL", "SUPABASE_ANON_KEY", "SUPABASE_SERVICE_ROLE_KEY"):
        os.environ[_k] = ""
