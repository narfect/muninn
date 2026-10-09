-- Muninn — Supabase schema: profiles table linked to auth.users + Row Level Security.
--
-- Run this in the Supabase SQL editor (or `supabase db push`) ONCE per project.
-- It is idempotent: every statement is IF NOT EXISTS / OR REPLACE / DROP-then-CREATE,
-- so re-running is safe.
--
-- Design:
--   * profiles.id == auth.users.id (1:1, FK with ON DELETE CASCADE — deleting a user
--     removes their profile; no orphaned rows).
--   * RLS is the real guard: each policy checks auth.uid() = id, so a user can only
--     ever SELECT / INSERT / UPDATE their own row, no matter what the client sends.
--     The service_role key bypasses RLS for server-side admin operations.
--   * A SECURITY DEFINER trigger creates the profile automatically on every signup
--     (function owned by the schema owner, search_path pinned — required because the
--     trigger runs as the inserting role and needs to write without a user policy).
--   * `role` mirrors app roles (viewer/responder/admin) and is NOT writable by users
--     through the API layer; the trigger copies any signup-provided role metadata.

-- ---------------------------------------------------------------- profiles --
CREATE TABLE IF NOT EXISTS public.profiles (
    id          UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email       TEXT NOT NULL,
    name        TEXT NOT NULL DEFAULT '',
    role        TEXT NOT NULL DEFAULT 'viewer'
                CHECK (role IN ('viewer', 'responder', 'admin')),
    avatar_url  TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE public.profiles IS
    'Application profile, 1:1 with auth.users (id = auth.users.id). RLS: owner-only.';

CREATE INDEX IF NOT EXISTS idx_profiles_email ON public.profiles(email);

-- ------------------------------------------------------------- timestamps --
CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_profiles_updated_at ON public.profiles;
CREATE TRIGGER trg_profiles_updated_at
    BEFORE UPDATE ON public.profiles
    FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- ------------------------------------------------------------ auto-profile --
-- Called on every new auth.users row. SECURITY DEFINER so the insert runs with the
-- function owner's rights (RLS on profiles would otherwise block the inserting role).
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    INSERT INTO public.profiles (id, email, name, role)
    VALUES (
        NEW.id,
        COALESCE(NEW.email, ''),
        COALESCE(NEW.raw_user_meta_data ->> 'name', ''),
        -- The role is read from app_metadata (admin-writable), NEVER user_metadata: a user
        -- can edit their own user_metadata, so trusting a role from there would let them
        -- self-promote. Only known roles are accepted; everything else defaults to viewer.
        CASE
            WHEN NEW.raw_app_meta_data ->> 'role' IN ('viewer', 'responder', 'admin')
            THEN NEW.raw_app_meta_data ->> 'role'
            ELSE 'viewer'
        END
    )
    ON CONFLICT (id) DO NOTHING;  -- idempotent under retried/merged auth rows
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- -------------------------------------------------------------------- RLS --
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

-- Idempotent policy creation: drop + recreate on each run.
DROP POLICY IF EXISTS "profiles_select_own"     ON public.profiles;
DROP POLICY IF EXISTS "profiles_insert_own"     ON public.profiles;
DROP POLICY IF EXISTS "profiles_update_own"     ON public.profiles;
DROP POLICY IF EXISTS "profiles_delete_own"     ON public.profiles;

CREATE POLICY "profiles_select_own" ON public.profiles
    FOR SELECT TO authenticated
    USING (auth.uid() = id);

CREATE POLICY "profiles_insert_own" ON public.profiles
    FOR INSERT TO authenticated
    WITH CHECK (auth.uid() = id);

CREATE POLICY "profiles_update_own" ON public.profiles
    FOR UPDATE TO authenticated
    USING (auth.uid() = id)
    WITH CHECK (auth.uid() = id);

CREATE POLICY "profiles_delete_own" ON public.profiles
    FOR DELETE TO authenticated
    USING (auth.uid() = id);

-- No policy grants anything to `anon`: anonymous callers see zero rows. The
-- service_role key bypasses RLS entirely (built in), covering server-side admin.

-- ------------------------------------------------------- role is protected --
-- RLS scopes WHICH ROW a user may touch; it does not restrict WHICH COLUMNS. Without this
-- guard a user could PATCH their own profiles.role (or DELETE then re-INSERT with
-- role='admin') and escalate. This trigger silently reverts any role change made by a
-- caller that is not the service role. It runs as the INVOKER (no SECURITY DEFINER) so
-- ``current_user`` is the requesting role — under PostgREST that is 'authenticated' for a
-- user's JWT and 'service_role' for the admin key. The SQL trigger handle_new_user runs as
-- its owner (postgres), which is also allowed, so auto-creation still sets the role.
CREATE OR REPLACE FUNCTION public.protect_profile_role()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
    IF current_user NOT IN ('service_role', 'postgres', 'supabase_admin') THEN
        IF TG_OP = 'INSERT' THEN
            NEW.role := 'viewer';
        ELSIF NEW.role IS DISTINCT FROM OLD.role THEN
            NEW.role := OLD.role;
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_profiles_protect_role ON public.profiles;
CREATE TRIGGER trg_profiles_protect_role
    BEFORE INSERT OR UPDATE ON public.profiles
    FOR EACH ROW EXECUTE FUNCTION public.protect_profile_role();

-- ---------------------------------------------------------------- grants --
-- Least-privilege table grants; RLS still scopes every statement to the owner's row.
-- UPDATE is column-scoped as a second defence: even if the trigger were dropped, a user
-- has no column privilege on `role`, so their own token can only edit display fields.
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;
GRANT SELECT, INSERT, DELETE ON public.profiles TO authenticated;
-- Revoke any table-level UPDATE first (grants are additive, so an earlier run of this file
-- would otherwise leave it in force and override the column privilege entirely).
REVOKE UPDATE ON public.profiles FROM authenticated;
GRANT UPDATE (name, avatar_url) ON public.profiles TO authenticated;
GRANT ALL ON public.profiles TO service_role;
-- anon intentionally gets NO grant on profiles: unauthenticated callers cannot touch it.
REVOKE ALL ON public.profiles FROM anon;
