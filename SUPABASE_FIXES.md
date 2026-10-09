# Muninn — Supabase Auth/DB Fixes

**Scope:** the Supabase authentication + database integration (`backend/services/supabase_*.py`,
`backend/services/auth_unified.py`, the router/routes wiring, and
`migrations/001_create_profiles.sql`), plus the bugs found while reviewing the whole codebase.

> ⚠️ **Verification status:** these fixes are a static read-and-edit. The test suite was
> **not executed** because Bash was gated by an unavailable safety classifier during the
> session (`deepseek-v4-flash[1m] is temporarily unavailable`). Run
> `python3 -m unittest discover -s tests -q` (or `make test`) yourself to confirm. The
> migration SQL must be **re-applied** to an existing Supabase project (it is idempotent).

---

## Summary

| # | Severity | Area | Fix |
|---|----------|------|-----|
| 1 | 🔴 Critical | RBAC / Supabase | Role is now read from `app_metadata` (admin-only writable) instead of the user-writable `user_metadata` |
| 2 | 🟠 High | Supabase DB | `profiles.role` can no longer be self-edited: role-guard trigger + column-scoped `UPDATE` grant |
| 3 | 🟠 High | Admin API | `/api/users` and `PATCH /api/users/{id}` now go through the auth facade and work in Supabase mode (were returning local data / 501) |
| 4 | 🟡 Medium | Caching | Profile cache is invalidated correctly after a user update (was a no-op due to call order) |
| 5 | 🟡 Medium | Error contract | `SupabaseClient.upsert` now maps network failures to `SupabaseError` |
| 6 | 🟡 Medium | Robustness | Profile auto-creation is now genuinely non-fatal, matching its documented contract |
| 7 | 🟡 Low | Logging | The "OPEN DEMO MODE" warning no longer fires in Supabase mode (where demo is disabled) |
| 8 | 🟡 Low | Tests | Removed a duplicate `__init__` in the test fake; added regression tests for #1 |
| 9 | ℹ️ Docs | Setup | `.env.example` documents the admin-bootstrap requirement |

---

## 1. 🔴 Critical — privilege escalation via `user_metadata.role`

**Problem.** `SupabaseUser.from_supabase` read the authorization role from the user's
`user_metadata`. That claim is **writable by the user themselves** — any authenticated
user can call `PUT {SUPABASE_URL}/auth/v1/user` with `{"data": {"role": "admin"}}` using
their own access token (exactly what `SupabaseClient.update_user` does). Muninn then
re-fetches `/auth/v1/user`, trusts the new role, and `router._authorize` grants ADMIN —
unlocking `/api/demo/reset`, `/api/demo/seed`, and `/api/users`.

**Fix.**
- `backend/services/supabase_auth.py` — `SupabaseUser.from_supabase` now reads
  `app_metadata.role` (`app_metadata` can only be written with the service-role key).
  A new `app_metadata` field was added to the `SupabaseUser` dataclass.
- `update_user()` **no longer accepts `role`** — role changes must go through the new
  `admin_set_role()`, which uses the service-role admin API. This removes the in-app path
  that could write a role through the user's own token.

```python
# before — user-writable claim trusted for RBAC
meta = data.get("user_metadata") or {}
role = meta.get("role") or "viewer"

# after — admin-only claim
app_meta = data.get("app_metadata") or {}
role = app_meta.get("role") or VIEWER
```

## 2. 🟠 High — `profiles.role` was self-editable

**Problem.** The RLS policies scope *which row* a user may touch, not *which columns*.
`authenticated` had table-level `UPDATE`, so a user could `PATCH /rest/v1/profiles` their
own `role` to `admin` (or DELETE + re-INSERT with a role). Latent today because the app
doesn't read the role from `profiles`, but a real hole the moment anything does.

**Fix — `migrations/001_create_profiles.sql` (re-apply this file):**
- **Column-scoped grant:** table-level `UPDATE` for `authenticated` is revoked and replaced
  with `GRANT UPDATE (name, avatar_url)`. Without a column privilege on `role`, a user's
  token cannot write it even if the trigger is dropped. (The `REVOKE` matters because
  `GRANT` is additive — an earlier run of the file would otherwise leave the table-level
  grant in force.)
- **Role-guard trigger** `protect_profile_role()` (BEFORE INSERT OR UPDATE) silently
  reverts any role change made by a caller that is not `service_role` / `postgres` /
  `supabase_admin`. It runs as the invoker (no `SECURITY DEFINER`) so `current_user` is the
  requesting role under PostgREST.
- The `handle_new_user` trigger now reads the role from `raw_app_meta_data` (matching #1),
  so signup auto-provisioning stays consistent.

## 3. 🟠 High — admin user routes bypassed the auth facade

**Problem.** `routes.list_users` called `ctx.repo.list_users()` (the **local SQLite** repo)
directly, returning local users in Supabase mode; `set_user_role` hit
`UnifiedAuthService.set_role`, which raised `NotImplementedError` → HTTP 501. Supabase
deployments had no working user-management surface.

**Fix.**
- `backend/services/supabase_client.py` — added `admin_update_user(user_id, data)` (service
  role; `PUT /auth/v1/admin/users/{id}`).
- `backend/services/supabase_auth.py` — added `admin_set_role(user_id, role)`, which writes
  `app_metadata.role` via the admin API **and** mirrors it onto the `profiles` row.
- `backend/services/auth_unified.py` — `set_role` and `list_users` now have real Supabase
  implementations (int row id locally, UUID string in Supabase).
- `backend/api/routes.py` — `list_users` calls `ctx.auth.list_users()`; `set_user_role`
  uses a new `_user_ref()` helper (UUID in Supabase, int locally).

## 4. 🟡 Medium — stale profile cache after a user update

**Problem.** In `update_user`, `_invalidate_session(token)` ran *before*
`_invalidate_profile_cache_only(token)`, which looked the token up in the (now-empty)
session cache — so the profile cache was never invalidated and could serve stale data for
up to 60 s.

**Fix.** Replaced the token-ordered helper with `_invalidate_profile(user_id)`, keyed on
the user id, and call it after re-reading the user. Ordering can no longer defeat it.

## 5. 🟡 Medium — `upsert` broke the uniform error contract

**Problem.** `SupabaseClient.upsert` handled only `HTTPError`; a network failure leaked a
raw `urllib.error.URLError` instead of the `SupabaseError` every other method raises.

**Fix.** `upsert` now routes through `_request`, inheriting the `URLError`/`OSError` →
`SupabaseError(code="network_error")` mapping and all the existing logging.

## 6. 🟡 Medium — profile auto-creation comment contradicted the code

**Problem.** `_ensure_profile`'s docstring/comment said any non-unique insert failure is
non-fatal and falls through to a read, but the `is_auth or is_conflict` branch *raised* —
and `is_auth` includes 401/403 (RLS denial). A profile hiccup could therefore fail an
otherwise successful signup/login.

**Fix.** All `SupabaseError`s on the profile insert now fall through to the read (logged,
never raised); auto-creation can no longer block a successful auth.

## 7. 🟡 Low — misleading open-demo warning

`server.bootstrap` logged the loud "OPEN DEMO MODE" warning (and provisioned demo accounts)
whenever the flag was set — including in Supabase mode, where the demo routes self-gate and
report disabled. Now guarded with `and not ctx.auth.using_supabase`.

## 8. 🟡 Low — test fake + regression tests

- `tests/test_supabase.py` — removed a **duplicate `_FakeTransport.__init__`** (the second
  silently overrode the first; a merge artifact — the intermediate `add()` method was
  preserved).
- The `_auth_user` fixture now carries the role in `app_metadata` (matching the fix).
- Added regression tests:
  - `test_role_comes_from_app_metadata`
  - `test_user_metadata_role_is_ignored` ← pins the escalation guard
  - `test_admin_set_role_writes_app_metadata_with_service_key`
  - `test_admin_set_role_rejects_unknown_role`

---

## Re-applying the SQL migration (required)

Run the updated `migrations/001_create_profiles.sql` in the Supabase SQL Editor. It is
idempotent (`IF NOT EXISTS` / `OR REPLACE` / `DROP`-then-`CREATE`), so it is safe to re-run
on an existing project. It will:

1. Recreate `handle_new_user` to read the role from `raw_app_meta_data`.
2. Create the `trg_profiles_protect_role` trigger.
3. Replace the table-level `UPDATE` grant with the column-scoped `(name, avatar_url)` grant.

---

## Supabase setup (end to end)

1. **Create the project** in the Supabase dashboard. From *Settings → API* copy the
   **Project URL**, **anon** key, and **service_role** key (keep the last secret).
2. **Apply the schema** — run `migrations/001_create_profiles.sql` in the SQL Editor.
3. **Configure** `.env` (real env vars win over the file):
   ```
   SUPABASE_URL=https://<project-ref>.supabase.co
   SUPABASE_ANON_KEY=<anon key>
   SUPABASE_SERVICE_ROLE_KEY=<service_role key>
   MUNINN_USE_SUPABASE=true                        # optional; auto-detects URL+anon
   MUNINN_SERVER_SECRET=<openssl rand -base64 32>  # production signal; disables open demo
   MUNINN_DEMO_OPEN=false
   MUNINN_COOKIE_SECURE=false                      # true only behind HTTPS
   ```
   If `MUNINN_USE_SUPABASE=true` but keys are missing, the server **refuses to boot** with a
   clear config error (fail fast, by design).
4. **Auth settings** — for testing, turn **"Confirm email" off**
   (*Authentication → Providers → Email*) so signup returns a session immediately. With it
   on, the SPA shows the "check your inbox" flow instead.
5. **Grant the first admin.** Unlike local mode, the first Supabase signup does **not**
   become admin. Promote a user by setting `app_metadata.role` with the **service role key**
   (via the dashboard, the Admin API, or `PUT /auth/v1/admin/users/<id>` with
   `{"app_metadata": {"role": "admin"}}`). **Never** use `user_metadata` — that is the
   self-promotion vector fixed in #1.
6. **Verify** — start the server (`python3 -m backend.server`) and check that
   `GET /api/auth/me` returns `"backend": "supabase"`. Optionally run the live smoke test:
   `MUNINN_SUPABASE_SMOKE=1 make test-supabase-live`.
7. **Note on data scope** — Supabase stores **auth + the `profiles` table only**. Incidents,
   services, runbooks, and metrics remain in the local SQLite database (`data/muninn.db`).

---

## Files changed

| File | Change |
|------|--------|
| `backend/services/supabase_auth.py` | role from `app_metadata`; `update_user` no longer takes `role`; added `admin_set_role`; profile-cache invalidation by id; non-fatal profile insert |
| `backend/services/supabase_client.py` | added `admin_update_user`; `upsert` routed through `_request` |
| `backend/services/auth_unified.py` | real Supabase `set_role` / `list_users` |
| `backend/api/routes.py` | `list_users` via facade; new `_user_ref` helper for `set_user_role` |
| `backend/server.py` | open-demo warning guarded against Supabase mode |
| `migrations/001_create_profiles.sql` | role from `raw_app_meta_data`; role-guard trigger; column-scoped grants |
| `tests/test_supabase.py` | removed duplicate `__init__`; `app_metadata` fixture; 4 regression tests |
| `.env.example` | admin-bootstrap + migration note |
