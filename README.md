<h1 align="center">🐦‍⬛ Muninn</h1>
<p align="center"><em>The incident-response copilot that remembers.</em></p>
<p align="center">
  Recall what your org already learned from past outages — root cause, the exact fix,
  the runbook, the resolver, the MTTR — the moment a new alert fires.
</p>

---

> **Status:** feature build complete. Accounts + role-based access, the Hindsight
> learning loop (retain/recall/reflect), the cold⇄warm triage comparison, streaming
> briefs, and the MTTR + learning-curve dashboards are all implemented and verified
> (server boots, full test suite green). Runs fully offline; all incident data is
> **synthetic and labeled**.

## Why Muninn

On-call engineering has a memory problem. The same incident recurs months apart and the
next responder starts from zero — even though someone already diagnosed and fixed it. The
knowledge is scattered across chat threads, postmortems, and people who since changed
teams. Mean-time-to-resolve pays the price.

Muninn treats **institutional memory as a first-class system**. Every resolved incident
is *retained*; every new alert *recalls* the most similar past incidents and an LLM agent
drafts a **cited triage brief**. The longer it runs, the better it gets. In Norse myth,
Odin's raven **Muninn** ("memory") flies the world and returns with what it has seen — the
name is the product thesis.

Memory is powered by **[Hindsight](https://hindsight.vectorize.io)**, the mandatory
agent-memory technology for this hackathon, used for its three core operations —
**retain / recall / reflect** — as the heart of the system, not a bolt-on.

## The one demo that tells the story

A single toggle — **Cold ⇄ Warm** — triages the same live alert twice:

| | **Cold** (memory off) | **Warm** (memory on) |
|---|---|---|
| Root cause | generic guess, low confidence | names the DB-pool regression from prior incidents |
| Fix | "investigate…" | the exact rollback + `pgbouncer` bump that worked before |
| Citations | none | `INC-0007`, `INC-0021`, `INC-0039` (same family) |
| Runbook | — | `RB-001` |

Then **Resolve & remember** writes a new memory, the counter ticks up, and the
**Insights** view shows MTTR trending down and a **learning curve** rising as the bank
grows. (All over a clearly-labeled synthetic dataset.)

## Quick start

Muninn runs **fully offline** — no API keys, no internet, no install. All you need is
**Python 3.10+**.

```bash
git clone https://github.com/narfect/Muninn muninn && cd muninn
python3 -m backend.server
```

Then open **http://127.0.0.1:8000**. (Prefer `make`? `make run` does the same thing, and
`make help` lists every target.)

The app boots in **open demo mode** — no login needed. The queue is already seeded with
labeled synthetic incidents, and a status-bar switcher lets you act as **Viewer / Responder
/ Admin** (each mints a real session for that role). Pick a SEV1 alert and flip
**Cold ⇄ Warm**, or hit **Compare cold vs warm** — that's the whole thesis in one click.

Roles gate what the UI offers and what the server allows: **viewer** reads incidents,
recalled memory, and can run triage/compare; **responder** can also create and resolve
incidents; **admin** can seed/reset data and manage user roles. The client only hides
controls it can't use — the server still enforces every check.

Demo mode is an explicit public-demo opt-in. It works alongside Supabase: real accounts
continue using Supabase Auth while demo accounts use isolated local sessions. Set
`MUNINN_DEMO_OPEN=false` for deployments that require real authentication. The full running
guide, per-role capability table, and a judge walkthrough are in
[`docs/USING_MUNINN.md`](docs/USING_MUNINN.md).

### Stop & restart

The server runs in the foreground, so **Ctrl-C** stops it. To run it in the background
(handy for a demo so you keep the terminal), redirect its log and background it:

```bash
PYTHONPATH="$PWD" python3 -m backend.server > run.log 2>&1 &
```

Stop a backgrounded server with:

```bash
pkill -f backend.server
```

Restarting is safe even with the browser tab still open — the SPA automatically
re-establishes its session, so you never see a stale-token error after a restart.

### Run the tests

```bash
python3 -m unittest discover -s tests -q
```

On **macOS**, raise the open-file limit first (the full serial run opens many SQLite/WAL
file descriptors and the default limit of 256 is too low):

```bash
ulimit -n 8192 && python3 -m unittest discover -s tests -q
```

`make test` runs the suite and `make compile` is the import/syntax gate.

### Turn on the real backends (optional)

```bash
cp .env.example .env
```

Then edit `.env` and set:

- `GROQ_API_KEY` — real LLM reasoning via Groq (OpenAI-compatible).
- `HINDSIGHT_BASE_URL` + `HINDSIGHT_API_KEY` — the real Hindsight memory service.

Backend selection is automatic (`auto`): real service when credentials are present,
offline fallback otherwise. The UI badges always show which path is live (`hindsight`/
`local`, `groq`/`local`) so a demo is never misleading.

**Pacing a live demo:** Groq's free tier allows about 8000 tokens per minute. Rapid
back-to-back triages can briefly hit that ceiling — the client retries and honors the
rate-limit backoff, and any single call that can't reach a live backend degrades to the
labeled offline fallback rather than failing. If you're sweeping many incidents, give it a
few seconds between runs for the snappiest, always-live experience.

### Supabase Auth & PostgreSQL (optional)

Muninn can delegate authentication and profile storage to [Supabase](https://supabase.com)
(email/password auth, JWT bearer tokens, a `profiles` table guarded by Row Level Security).
It stays fully optional: with no Supabase env vars set, the built-in local auth (SQLite,
HttpOnly cookies, CSRF double-submit) runs exactly as before.

#### 1. Create the project + schema

1. Create a project at [supabase.com](https://supabase.com) (free tier is fine).
2. Open **SQL Editor** and run the contents of
   [`migrations/001_create_profiles.sql`](migrations/001_create_profiles.sql). It creates
   the `profiles` table (1:1 with `auth.users`, `ON DELETE CASCADE`), enables **Row Level
   Security** with owner-only policies, and installs a trigger that auto-creates each
   profile at signup. The migration is idempotent — re-running is safe.
3. In **Authentication → Providers**, keep **Email** enabled and (for the smoothest
   first-run experience) disable **Confirm email**, or handle the confirmation flow in
   your own UI. With confirmation on, signup returns no session until the user confirms.

#### 2. Configure the environment

Copy the Supabase block from [`.env.example`](.env.example) into your `.env`:

```bash
SUPABASE_URL=https://<project-ref>.supabase.co
SUPABASE_ANON_KEY=<anon/public key>
SUPABASE_SERVICE_ROLE_KEY=<service_role key — server-side ONLY, never ship to a client>
# Optional: force Supabase mode (auto-detects when URL + anon key are present)
# MUNINN_USE_SUPABASE=true
```

All three come from **Supabase → Project Settings → API**. The anon key is designed to be
public (RLS is the real guard); the **service_role key bypasses RLS** and must never leave
the server or be committed. `.env` is git-ignored.

Mode is picked automatically: `SUPABASE_URL` + `SUPABASE_ANON_KEY` present → Supabase;
otherwise local. Setting `MUNINN_USE_SUPABASE=true` forces it (and fails fast at boot if
the URL/key pair is incomplete). Demo mode is controlled independently by
`MUNINN_DEMO_OPEN` and can run alongside either backend.

#### 3. What changes when Supabase mode is on

| | Local mode | Supabase mode |
|---|---|---|
| Credentials | scrypt-hashed in SQLite | stored by Supabase Auth (never in this app) |
| Sessions | opaque token in an HttpOnly cookie | JWT access token + refresh token in the SPA (localStorage) |
| CSRF | double-submit `X-CSRF-Token` | not needed (stateless Bearer) |
| Transport | cookie on every request | `Authorization: Bearer <access_token>` header |
| Refresh | implicit (server session) | `POST /api/auth/refresh` (rotates the refresh token; the SPA auto-refreshes ~1 min before expiry) |
| Profiles | `users` table | `profiles` table via PostgREST, RLS-enforced |
| Demo mode | available when enabled | disabled (real accounts only) |

The SPA detects the mode from the auth responses and handles both transparently:
persisting/restoring the session across reloads, silent refresh, and Bearer headers on
every API call (including the SSE stream, which takes `?access_token=` since
`EventSource` cannot set headers).

#### 4. API surface (both modes unless noted)

```
POST   /api/auth/signup          create account (201; session in body when Supabase)
POST   /api/auth/login           email/password sign-in (session in body when Supabase)
GET    /api/auth/me              current user from the session/Bearer token
POST   /api/auth/logout          revoke the session/refresh token
POST   /api/auth/refresh         Supabase-only: rotate a refresh token
GET    /api/auth/profile         Supabase-only: own profile row (RLS)
PATCH  /api/auth/profile         Supabase-only: update own name/avatar (RLS)
```

All incident/triage/metrics routes are protected (viewer/responder/admin role gates) in
both modes; in Supabase mode they accept the Bearer token.

#### 5. Tests

`tests/test_supabase.py` runs fully mocked — no network, always green. A live smoke test
(`tests/test_supabase_live_smoke.py`) runs against a real project only when you opt in:

```bash
SUPABASE_URL=... SUPABASE_ANON_KEY=... [SUPABASE_SERVICE_ROLE_KEY=...] \
MUNINN_SUPABASE_SMOKE=1 python3 -m unittest tests.test_supabase_live_smoke -v
```

It signs up a throwaway user, checks the auto-created profile, exercises login/refresh/
logout, verifies RLS isolation, and deletes the user afterwards (needs the service role
key for that last step).

#### 6. Security notes

- Passwords never touch this application in Supabase mode — Supabase Auth is the
  credential store; the app only ever handles short-lived JWTs.
- The service_role key is used only for admin cleanup paths and RLS-bypassing admin reads.
- RLS is the isolation boundary: even a bug in app code cannot leak one user's profile to
  another, because every profile query runs under the *caller's* token.
- Keep `MUNINN_DEMO_OPEN=false` (or set `MUNINN_SERVER_SECRET`) for anything non-local;
  open-demo is additionally force-disabled in Supabase mode.

For any non-local deployment, also set **`MUNINN_SERVER_SECRET`** to a strong random value
(it keys the per-session CSRF tokens) and **`MUNINN_COOKIE_SECURE=true`** when serving over
HTTPS. Session lifetimes and login-lockout thresholds are configurable too — see the
commented **Auth & sessions** block in [`.env.example`](.env.example).

## How Hindsight is used (the memory core)

| Hindsight op | In Muninn |
|---|---|
| **retain** | On resolve, store a rich *experience* memory: symptom, error signature, root cause, exact fix, runbook, resolver, MTTR (`source = incident id`). |
| **recall** | On a new alert, query with the incident's signature; get scored, cited past incidents via TEMPR-style fusion (semantic + keyword + entity + temporal). |
| **reflect** | Synthesize cross-incident patterns ("we've seen this family 4× since June") into the brief. |

Memory banks isolate the incident corpus (`muninn-incidents`). The offline
`LocalMemoryStore` mirrors the same interface with a hybrid retriever so the concept is
demonstrable without the network. Full detail: [`docs/HINDSIGHT.md`](docs/HINDSIGHT.md).

## Architecture (at a glance)

```
Browser SPA (vanilla JS)  ──HTTP/JSON + SSE──▶  Python stdlib server (http.server)
                                                   │
                    ┌──────────────────────────────┼───────────────────────────┐
                    ▼                               ▼                           ▼
              Services layer                  Memory layer                 Reasoner
     (incidents · triage · metrics)   MemoryStore: Hindsight | Local   Groq | Local
                    │                               │
                    ▼                               ▼
             SQLite (system of record)     retain / recall / reflect
```

Two swappable seams — `MemoryStore` and `Reasoner` — mean the same code path runs against
real cloud services or fully offline. SQLite is the system of record; Hindsight is the
semantic memory. Details and diagrams: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Tech stack & why

- **Backend:** Python 3.10 standard library only (`http.server`, `sqlite3`, `urllib`,
  `json`). Zero-install is a feature: judges run it in one command, anywhere.
- **Frontend:** dependency-free vanilla JS/CSS SPA, served by the backend. No build step.
- **Memory:** Hindsight (cloud/OSS) with a faithful offline fallback.
- **LLM:** Groq (OpenAI-compatible) with an offline deterministic fallback.
- **Tests:** stdlib `unittest`.

## Project structure

```
backend/    config·models·db·router·server (concrete) + memory·llm·services·api
            + supabase_client / supabase_auth / supabase_db / auth_unified (optional
            Supabase Auth + PostgreSQL integration behind one facade)
static/     index.html · styles.css (design tokens) · app.js · auth.js (SPA + api client;
            handles both local cookie sessions and Supabase bearer sessions)
migrations/ 001_create_profiles.sql (Supabase schema: profiles + RLS + auto-profile trigger)
data/       seed_sample.json (labeled synthetic dataset)
tests/      stdlib unittest suite (memory · retrieval · agent · services · api ·
            auth · hardening · correctness · supabase [mocked] · supabase live smoke [opt-in])
docs/       SRS · ARCHITECTURE · PLAN · MVP · HINDSIGHT · TEST_PLAN · USING_MUNINN
```

## Testing & quality

```bash
make compile
make test
```

`make compile` is the import/syntax gate (compileall); `make test` runs the full unittest
suite.

Every layer ships with green tests — memory (local + Hindsight parity), retrieval, the
agent (including malformed-tool-call handling), services, the API endpoints, auth/RBAC,
transport hardening, and correctness regressions (see
[`docs/TEST_PLAN.md`](docs/TEST_PLAN.md)). Principles: offline-deterministic, no network
in unit tests, no fabricated passes.

## Judging-criteria fit

- **Innovation (30%)** — memory-as-a-system; the cold/warm before-after; a visible
  learning curve.
- **Use of Hindsight (25%)** — retain/recall/reflect are the core loop, surfaced in the UI.
- **Technical (20%)** — clean layered architecture, swappable backends, robust agent
  (tolerates malformed tool calls), tested.
- **UX (15%)** — a calm, purpose-built ops console; the whole thesis is one toggle.
- **Real-world impact (10%)** — MTTR reduction is the daily pain of every on-call team.

## Project status

The feature build is **complete and verified**. On top of the concrete contract layers
(config, models, DB, router, server, design tokens, dataset) the full application is
implemented:

- **Institutional memory** — retain / recall / reflect through a `MemoryStore` seam, with a
  real Hindsight client and a faithful offline `LocalMemoryStore` behind the same interface.
- **Agentic triage** — a tool-using reasoner (Groq or offline `LocalReasoner`) that emits a
  cited brief, streamed token-by-token over SSE, and tolerates malformed tool calls.
- **The learning loop** — resolving an incident retains a new memory and the counter ticks up.
- **Accounts + RBAC** — email/password auth, HttpOnly session cookies, double-submit CSRF,
  failed-login lockout, and a viewer/responder/admin role hierarchy enforced server-side
  (first account created becomes admin).
- **Dashboards** — MTTR by service and a learning curve, with accessible data-table fallbacks.

Everything runs under the original constraints: Python standard library only, dependency-free
vanilla-JS frontend, offline-first, no fabricated data (backends degrade to labeled offline
fallbacks), and a green `unittest` suite. All incident data is **synthetic** and labeled as
such. 

