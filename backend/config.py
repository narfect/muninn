"""Environment-driven configuration.

Reads settings from process environment and an optional ``.env`` file in the
project root. No third-party dependency (a tiny ``.env`` parser is included) so
the core runs with only the Python standard library.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

# Project root = two levels up from this file (backend/config.py -> project root)
ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    """Minimal ``.env`` loader: ``KEY=VALUE`` lines, ``#`` comments, optional quotes.

    Existing environment variables always win, so real secrets set in the shell are
    never overridden by a committed example file.
    """
    if not path.exists():
        return
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value
    except OSError:
        pass


_load_dotenv(ROOT / ".env")


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_bool(name: str, default: bool = False) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    """Immutable application settings resolved at import time."""

    # --- server ---
    host: str = field(default_factory=lambda: _env("MUNINN_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(_env("MUNINN_PORT", "8000") or 8000))
    db_path: str = field(
        default_factory=lambda: _env("MUNINN_DB", str(ROOT / "data" / "muninn.db"))
    )

    # --- Hindsight (memory) ---
    hindsight_base_url: str = field(
        default_factory=lambda: _env("HINDSIGHT_BASE_URL", "")
    )
    hindsight_api_key: str = field(
        default_factory=lambda: _env("HINDSIGHT_API_KEY", "")
    )
    hindsight_namespace: str = field(
        default_factory=lambda: _env("HINDSIGHT_NAMESPACE", "default")
    )
    hindsight_bank: str = field(
        default_factory=lambda: _env("HINDSIGHT_BANK", "muninn-incidents")
    )
    # Reflect mission for the bank — the natural-language identity that frames `reflect`
    # as an incident-memory analyst. Applied on bank create/update (see HindsightStore);
    # override via HINDSIGHT_BANK_MISSION. Keep it an SRE-analyst framing so synthesis
    # reads as grounded, blameless, action-oriented guidance.
    hindsight_bank_mission: str = field(
        default_factory=lambda: _env(
            "HINDSIGHT_BANK_MISSION",
            "You are the institutional memory for an on-call SRE team. Recall and "
            "synthesize past incidents — their root causes, fixes, and recurring failure "
            "patterns — to help responders triage new alerts faster. Prefer safe, "
            "reversible mitigations and always ground recommendations in prior incidents.",
        )
    )
    # auto | hindsight | local
    memory_backend: str = field(
        default_factory=lambda: _env("MUNINN_MEMORY_BACKEND", "auto").lower()
    )

    # --- LLM (reasoning) ---
    groq_api_key: str = field(default_factory=lambda: _env("GROQ_API_KEY", ""))
    groq_base_url: str = field(
        default_factory=lambda: _env("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
    )
    groq_model: str = field(
        default_factory=lambda: _env("GROQ_MODEL", "openai/gpt-oss-120b")
    )
    # auto | groq | local
    llm_backend: str = field(
        default_factory=lambda: _env("MUNINN_LLM_BACKEND", "auto").lower()
    )

    # --- behaviour ---
    request_timeout: float = field(
        default_factory=lambda: float(_env("MUNINN_HTTP_TIMEOUT", "30") or 30)
    )
    recall_top_k: int = field(
        default_factory=lambda: int(_env("MUNINN_RECALL_TOP_K", "5") or 5)
    )
    # The raw Hindsight relevance score (`scores.final`) a near-identical ("I've seen this exact
    # incident") match yields. Observed ~1.06-1.10 live; Hindsight's scale is NOT 0..1, so we
    # divide by this to normalize recall scores onto 0..1 (see HindsightStore.recall). Raise it
    # if live scores routinely exceed it (everything would saturate at 1.0 again); lower it if
    # genuine matches never approach 1.0. Only affects the Hindsight backend.
    hindsight_score_scale: float = field(
        default_factory=lambda: float(_env("HINDSIGHT_SCORE_SCALE", "1.1") or 1.1)
    )
    # --- transport hardening (S9) ---
    # Reject request bodies larger than this (bytes) with HTTP 413 before reading them,
    # so a bogus Content-Length can't exhaust memory. Default 1 MiB.
    max_body_bytes: int = field(
        default_factory=lambda: int(_env("MUNINN_MAX_BODY_BYTES", "1048576") or 1048576)
    )

    # --- auth / sessions (Phase 3) ---
    # A server-side secret used to derive per-session CSRF tokens (HMAC). MUST be set to a
    # strong random value in any non-local deployment; a random ephemeral value is generated
    # per process if unset (fine for the local demo, invalidates sessions on restart).
    server_secret: str = field(
        default_factory=lambda: _env("MUNINN_SERVER_SECRET", "")
        or __import__("secrets").token_urlsafe(32)
    )
    # Absolute session lifetime and idle timeout, in seconds (default 12h / 30m).
    session_ttl_seconds: int = field(
        default_factory=lambda: int(_env("MUNINN_SESSION_TTL", "43200") or 43200)
    )
    session_idle_seconds: int = field(
        default_factory=lambda: int(_env("MUNINN_SESSION_IDLE", "1800") or 1800)
    )
    # Add the `Secure` attribute to auth cookies. Off by default because browsers won't send
    # Secure cookies over http://127.0.0.1; turn on for any https deployment.
    cookie_secure: bool = field(
        default_factory=lambda: _env_bool("MUNINN_COOKIE_SECURE", False)
    )
    # Failed-login lockout: after this many failures, lock the account for the window.
    login_max_attempts: int = field(
        default_factory=lambda: int(_env("MUNINN_LOGIN_MAX_ATTEMPTS", "5") or 5)
    )
    login_lockout_seconds: int = field(
        default_factory=lambda: int(_env("MUNINN_LOGIN_LOCKOUT", "900") or 900)
    )
    # Per-IP fixed-window rate limits for the public auth endpoints (attempts per minute).
    # Independent of the per-account failed-login lockout above: this throttles a single
    # source host regardless of which/how many accounts it targets. Set to 0 to DISABLE.
    rl_login: int = field(
        default_factory=lambda: int(_env("MUNINN_RL_LOGIN", "10") or 10)
    )
    rl_signup: int = field(
        default_factory=lambda: int(_env("MUNINN_RL_SIGNUP", "5") or 5)
    )

    # --- Supabase Auth & PostgreSQL ---
    # Supabase project URL (e.g. https://xyz.supabase.co). When set, Supabase Auth is used
    # instead of the local email/password auth. The anon key is safe to expose to clients.
    supabase_url: str = field(default_factory=lambda: _env("SUPABASE_URL", ""))
    supabase_anon_key: str = field(default_factory=lambda: _env("SUPABASE_ANON_KEY", ""))
    # Service role key for admin operations (user management, RLS bypass). NEVER expose to clients.
    supabase_service_role_key: str = field(default_factory=lambda: _env("SUPABASE_SERVICE_ROLE_KEY", ""))
    # When true, use Supabase Auth; when false (default), use local auth. Auto-detects if URL+keys are set.
    use_supabase: bool = field(
        default_factory=lambda: _env_bool("MUNINN_USE_SUPABASE", False)
    )
    # Explicit opt-OUT: MUNINN_USE_SUPABASE set to a falsey value (false/0/no/off) forces
    # local mode even when SUPABASE_URL + anon key are present, suppressing auto-detection.
    # Lets a developer with a live .env pin local auth without blanking their credentials.
    supabase_force_local: bool = field(
        default_factory=lambda: _env("MUNINN_USE_SUPABASE") != ""
        and not _env_bool("MUNINN_USE_SUPABASE", False)
    )

    # --- local demo conveniences (LOCAL ONLY — must be OFF in any real deployment) ---
    # Autoseed the labeled synthetic dataset on startup when the incidents table is empty,
    # so the app is never a blank slate for a judge/demo. No-op when data already exists.
    demo_autoseed: bool = field(
        default_factory=lambda: _env_bool("MUNINN_DEMO_AUTOSEED", True)
    )
    # OPEN DEMO MODE: skip the login gate and expose one-click role switching over
    # pre-provisioned demo accounts. This means NO AUTHENTICATION, so it is force-disabled
    # whenever a real MUNINN_SERVER_SECRET is configured (the production signal) — presence
    # of that raw env var wins over the flag. `server_secret` itself is never empty (it
    # falls back to a random per-process value), so we must consult the raw environment.
    demo_open: bool = field(
        default_factory=lambda: _env_bool("MUNINN_DEMO_OPEN", True)
        and not bool(os.environ.get("MUNINN_SERVER_SECRET", "").strip())
    )

    def resolved_memory_backend(self) -> str:
        """Decide which memory backend will actually be used."""
        if self.memory_backend == "hindsight":
            return "hindsight"
        if self.memory_backend == "local":
            return "local"
        # auto
        if self.hindsight_base_url and self.hindsight_api_key:
            return "hindsight"
        return "local"

    def resolved_llm_backend(self) -> str:
        """Decide which reasoning backend will actually be used."""
        if self.llm_backend == "groq":
            return "groq"
        if self.llm_backend == "local":
            return "local"
        # auto
        return "groq" if self.groq_api_key else "local"

    def resolved_use_supabase(self) -> bool:
        """Decide whether to use Supabase Auth.

        Precedence: an explicit opt-in (use_supabase) wins; then an explicit opt-out
        (supabase_force_local) disables auto-detection; otherwise auto-detect from config.
        """
        if self.use_supabase:
            return True
        if self.supabase_force_local:
            return False
        # auto-detect: use Supabase if URL and anon key are configured
        return bool(self.supabase_url and self.supabase_anon_key)


settings = Settings()
