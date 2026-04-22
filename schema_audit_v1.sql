-- ============================================================
-- REP Platform — Production Audit & Refinement
-- schema_audit_v1.sql
-- ============================================================
-- Run this AFTER schema.sql — it is a patch, not a replacement.
-- Every fix is labeled with its severity and root cause.
-- ============================================================
-- TABLE OF CONTENTS:
--   §1  Performance — is_admin() caching (CRITICAL)
--   §2  Security   — RLS policy corrections
--   §3  Integrity  — Trigger & constraint fixes
--   §4  Timestamps — updated_at auto-maintenance
--   §5  Indexes    — Composite & missing indexes
--   §6  Immutability — report_logs DELETE block
--   §7  Snapshots  — exercise_name_snapshot guarantee
--   §8  Ordering   — position uniqueness
--   §9  Queries    — Optimized production query examples
--   §10 Checklist  — Final production readiness summary
-- ============================================================


-- ============================================================
-- §1  PERFORMANCE — CACHE is_admin() TO ELIMINATE N+1 QUERIES
-- ============================================================
-- ROOT CAUSE:
--   The current is_admin() executes a SELECT against user_profiles
--   for EVERY ROW evaluated by any RLS policy. On a table scan of
--   10,000 session_sets rows, that is 10,000 profile lookups.
--
-- FIX:
--   Cache the result in a transaction-local setting using
--   current_setting(). First call hits the DB; subsequent calls
--   within the same transaction read from memory.
--   SECURITY DEFINER ensures the cache read bypasses RLS on
--   user_profiles itself (preventing the recursive policy issue).
-- ============================================================

create or replace function public.is_admin()
returns boolean
language plpgsql
security definer
stable
set search_path = public
as $$
declare
  v_role text;
  v_cached text;
begin
  -- Check transaction-local cache first
  begin
    v_cached := current_setting('app.current_user_role');
  exception when others then
    v_cached := null;
  end;

  if v_cached is not null then
    return v_cached = 'admin';
  end if;

  -- Cache miss: query user_profiles and store for this transaction
  select role into v_role
  from public.user_profiles
  where id = auth.uid();

  -- Store in transaction-local setting (survives for the transaction duration)
  perform set_config('app.current_user_role', coalesce(v_role, 'user'), true);

  return v_role = 'admin';
end;
$$;

-- Companion: invalidate cache on role change (called by update trigger)
create or replace function public.invalidate_role_cache()
returns trigger
language plpgsql
security definer
as $$
begin
  -- Reset the cached value so the next RLS check re-reads the DB
  perform set_config('app.current_user_role', '', true);
  return new;
end;
$$;

drop trigger if exists invalidate_role_cache_on_update on public.user_profiles;
create trigger invalidate_role_cache_on_update
  after update of role on public.user_profiles
  for each row execute procedure public.invalidate_role_cache();


-- ============================================================
-- §2  SECURITY — RLS POLICY CORRECTIONS
-- ============================================================

-- ── §2.1  FIX: user_profiles UPDATE — recursive self-join bug ─
-- ROOT CAUSE:
--   The WITH CHECK clause reads user_profiles WHERE id = auth.uid().
--   That SELECT is itself subject to the SELECT RLS policy, which
--   calls is_admin(), which reads user_profiles — potential recursion
--   and definitely a repeated lookup.
--
-- FIX: Use a SECURITY DEFINER function to read role safely,
--   completely bypassing RLS on the inner lookup.
-- ─────────────────────────────────────────────────────────────

create or replace function public.get_my_role()
returns text
language sql
security definer
stable
set search_path = public
as $$
  select role from public.user_profiles where id = auth.uid();
$$;

drop policy if exists "users: update own profile" on public.user_profiles;
create policy "users: update own profile"
  on public.user_profiles for update
  using (id = auth.uid())
  with check (
    id = auth.uid()
    -- Prevent self-promotion: new role must equal current role
    -- get_my_role() is SECURITY DEFINER — no RLS recursion
    and role = public.get_my_role()
  );


-- ── §2.2  FIX: exercises INSERT — prevent created_by spoofing ─
-- ROOT CAUSE:
--   Current policy only checks auth.uid() is not null.
--   A malicious user could insert { created_by: victim_uuid }
--   gaining no direct privilege, but polluting the exercise library
--   with falsely attributed records.
--
-- FIX: WITH CHECK enforces created_by = auth.uid() OR created_by IS NULL
--   (null is allowed for seeded/system exercises).
-- ─────────────────────────────────────────────────────────────

drop policy if exists "exercises: insert" on public.exercises;
create policy "exercises: insert"
  on public.exercises for insert
  with check (
    auth.uid() is not null
    and (created_by = auth.uid() or created_by is null)
  );


-- ── §2.3  FIX: exercises UPDATE — also blocks type changes ────
-- ROOT CAUSE:
--   Changing an exercise type (counter→timer) after slots exist
--   would make all existing workout_slots invalid
--   (reps filled, but exercise now requires duration_seconds).
--   The validate_slot_type trigger catches this on INSERT,
--   but not on UPDATE of the exercise itself.
--
-- FIX: Prevent type changes if slots reference this exercise.
-- ─────────────────────────────────────────────────────────────

create or replace function public.prevent_exercise_type_change()
returns trigger
language plpgsql
as $$
begin
  if new.type <> old.type then
    if exists (
      select 1 from public.workout_slots where exercise_id = old.id
      union all
      select 1 from public.recommended_slots where exercise_id = old.id
    ) then
      raise exception
        'Cannot change exercise type: existing workout slots reference this exercise. '
        'Remove or update all slots first.';
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists prevent_exercise_type_change_trigger on public.exercises;
create trigger prevent_exercise_type_change_trigger
  before update of type on public.exercises
  for each row execute procedure public.prevent_exercise_type_change();


-- ── §2.4  FIX: workout_slots SELECT — admin can see all slots ─
-- ROOT CAUSE:
--   The SELECT policy filters deleted_at is null, which means:
--   (a) admin cannot see slots on soft-deleted workouts (inconsistent)
--   (b) the history join from sessions still needs slot data even
--       after a workout is soft-deleted
--
-- FIX: Remove deleted_at filter from SELECT (soft-delete is a
--   presentation concern, not an access-control concern).
--   Keep it in the app layer query WHERE clause instead.
-- ─────────────────────────────────────────────────────────────

drop policy if exists "slots: select via workout ownership" on public.workout_slots;
create policy "slots: select via workout ownership"
  on public.workout_slots for select
  using (
    exists (
      select 1 from public.workouts w
      where w.id = workout_id
        and (w.user_id = auth.uid() or public.is_admin())
      -- deleted_at intentionally removed: access follows ownership, not active status
    )
  );


-- ── §2.5  FIX: session_exercises — missing UPDATE policy ──────
-- ROOT CAUSE:
--   No UPDATE policy exists on session_exercises.
--   With RLS enabled and no UPDATE policy, updates are silently
--   blocked for all users including admin (default-deny).
--   The position field may need to be correctable.
-- ─────────────────────────────────────────────────────────────

drop policy if exists "sex: update via session ownership" on public.session_exercises;
create policy "sex: update via session ownership"
  on public.session_exercises for update
  using (
    exists (
      select 1 from public.sessions s
      where s.id = session_id
        and (s.user_id = auth.uid() or public.is_admin())
    )
  );


-- ── §2.6  FIX: session_sets — add explicit UPDATE policy ──────
-- ROOT CAUSE:
--   Same as above — no UPDATE policy means sets can never be
--   corrected (e.g. fixing a typo in actual_reps after save).
--   Whether this is intentional should be a product decision.
--   We add it here as permissive within session ownership,
--   but you can DROP this policy if sets must be immutable.
-- ─────────────────────────────────────────────────────────────

drop policy if exists "ssets: update via session ownership" on public.session_sets;
create policy "ssets: update via session ownership"
  on public.session_sets for update
  using (
    exists (
      select 1 from public.session_exercises se
        join public.sessions s on s.id = se.session_id
      where se.id = session_exercise_id
        and (s.user_id = auth.uid() or public.is_admin())
    )
  );


-- ── §2.7  FIX: recommended_workouts admin visibility ─────────
-- ROOT CAUSE:
--   The SELECT policy filters deleted_at is null.
--   Admin cannot see soft-deleted templates to restore or audit them.
--
-- FIX: Admin bypasses the deleted_at filter.
-- ─────────────────────────────────────────────────────────────

drop policy if exists "rec: read all authenticated" on public.recommended_workouts;
create policy "rec: read all authenticated"
  on public.recommended_workouts for select
  using (
    auth.uid() is not null
    and (deleted_at is null or public.is_admin())
  );


-- ============================================================
-- §3  INTEGRITY — TRIGGER & CONSTRAINT FIXES
-- ============================================================

-- ── §3.1  FIX: validate_slot_type — handle NULL exercise ──────
-- ROOT CAUSE:
--   If exercise_id is somehow null (FK is NOT NULL so this
--   shouldn't happen, but defensive coding matters), or if the
--   SELECT returns no row (race condition during exercise deletion
--   with RESTRICT), ex_type will be NULL and all conditions pass
--   silently. The trigger should fail loudly on unknown type.
-- ─────────────────────────────────────────────────────────────

create or replace function public.validate_slot_type()
returns trigger
language plpgsql
as $$
declare
  v_ex_type text;
begin
  select type into v_ex_type
  from public.exercises
  where id = new.exercise_id;

  -- Explicit NULL guard: exercise must exist and be readable
  if v_ex_type is null then
    raise exception
      'Cannot create slot: exercise % does not exist or has been deleted.',
      new.exercise_id;
  end if;

  -- Counter validation
  if v_ex_type = 'counter' then
    if new.reps is null then
      raise exception 'Counter exercise (id: %) requires reps to be set.', new.exercise_id;
    end if;
    if new.duration_seconds is not null then
      raise exception 'Counter exercise (id: %) must have duration_seconds = null.', new.exercise_id;
    end if;
  end if;

  -- Timer validation
  if v_ex_type = 'timer' then
    if new.duration_seconds is null then
      raise exception 'Timer exercise (id: %) requires duration_seconds to be set.', new.exercise_id;
    end if;
    if new.reps is not null then
      raise exception 'Timer exercise (id: %) must have reps = null.', new.exercise_id;
    end if;
  end if;

  -- Reject any unknown type (future-proofing)
  if v_ex_type not in ('counter', 'timer') then
    raise exception 'Unknown exercise type: %', v_ex_type;
  end if;

  return new;
end;
$$;
-- Triggers already exist on workout_slots and recommended_slots,
-- referencing this function by name — they pick up the new version automatically.


-- ── §3.2  FIX: check_exercise_not_in_use — add recommended_slots
-- ROOT CAUSE:
--   The hard-delete guard only checks workout_slots.
--   An exercise used only in recommended_slots can be hard-deleted,
--   orphaning those template slots (FK is RESTRICT, so Postgres
--   would actually block this via FK, but the error message
--   would be cryptic. Better to catch it here with a clear message).
-- ─────────────────────────────────────────────────────────────

create or replace function public.check_exercise_not_in_use()
returns trigger
language plpgsql
as $$
begin
  if exists (
    select 1 from public.workout_slots where exercise_id = old.id
    union all
    select 1 from public.recommended_slots where exercise_id = old.id
  ) then
    raise exception
      'Cannot delete exercise "%": it is referenced in workout or recommended slots. '
      'Soft-delete it by setting deleted_at = now() instead.',
      old.name;
  end if;
  return old;
end;
$$;


-- ── §3.3  FIX: recommended_slots missing rest_seconds CHECK ───
-- ROOT CAUSE:
--   workout_slots has CHECK (rest_seconds >= 0).
--   recommended_slots does not — negative rest values are accepted.
-- ─────────────────────────────────────────────────────────────

alter table public.recommended_slots
  add constraint rec_slots_rest_seconds_check
    check (rest_seconds >= 0);


-- ── §3.4  FIX: exercise name uniqueness (case-insensitive) ────
-- ROOT CAUSE:
--   Two exercises named "Push-ups" and "push-ups" can coexist,
--   causing confusion in the library and migration deduplication.
-- ─────────────────────────────────────────────────────────────

create unique index if not exists exercises_name_ci_unique
  on public.exercises (lower(trim(name)))
  where deleted_at is null;
-- Partial unique index: only among active exercises.
-- Soft-deleted exercises don't block re-creation of the same name.


-- ── §3.5  FIX: sessions duration_seconds constraint ───────────
-- ROOT CAUSE:
--   duration_seconds defaults to 0 but has no upper bound.
--   A client bug could store 2,147,483,647 seconds (68 years).
--   Also, 0 is technically valid by default but a completed session
--   should have duration > 0.
-- ─────────────────────────────────────────────────────────────

alter table public.sessions
  add constraint sessions_duration_reasonable
    check (duration_seconds >= 0 and duration_seconds < 86400);
-- Max 24 hours (86400 seconds). Adjust if ultra-marathons are in scope.


-- ============================================================
-- §4  TIMESTAMPS — AUTOMATIC updated_at MAINTENANCE
-- ============================================================
-- ROOT CAUSE:
--   updated_at exists on workouts, exercises, recommended_workouts,
--   and user_profiles but is never automatically updated.
--   Only reports has the auto-update trigger.
--   Any direct UPDATE bypasses the application layer and leaves
--   updated_at stale.
-- ─────────────────────────────────────────────────────────────

-- Generic trigger function (reusable across all tables)
create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

-- workouts
drop trigger if exists set_workouts_updated_at on public.workouts;
create trigger set_workouts_updated_at
  before update on public.workouts
  for each row execute procedure public.set_updated_at();

-- exercises
drop trigger if exists set_exercises_updated_at on public.exercises;
create trigger set_exercises_updated_at
  before update on public.exercises
  for each row execute procedure public.set_updated_at();

-- recommended_workouts
drop trigger if exists set_rec_workouts_updated_at on public.recommended_workouts;
create trigger set_rec_workouts_updated_at
  before update on public.recommended_workouts
  for each row execute procedure public.set_updated_at();

-- user_profiles
drop trigger if exists set_user_profiles_updated_at on public.user_profiles;
create trigger set_user_profiles_updated_at
  before update on public.user_profiles
  for each row execute procedure public.set_updated_at();

-- sessions — add updated_at column (currently missing)
alter table public.sessions
  add column if not exists updated_at timestamptz not null default now();

drop trigger if exists set_sessions_updated_at on public.sessions;
create trigger set_sessions_updated_at
  before update on public.sessions
  for each row execute procedure public.set_updated_at();

-- NOTE: The existing auto_log_report_status_change trigger on reports
-- sets new.updated_at = now() manually — that is still correct and
-- set_updated_at() would fire alongside it (same result, harmless).
-- To keep it clean, remove the manual assignment from the logging trigger:
create or replace function public.auto_log_report_status_change()
returns trigger
language plpgsql
security definer
as $$
begin
  -- Log status change
  if old.status is distinct from new.status then
    insert into public.report_logs (report_id, user_id, message, type)
    values (
      new.id,
      auth.uid(),
      'Status changed from "' || old.status || '" to "' || new.status || '"',
      'status_change'
    );
  end if;

  -- Log content edits
  if (old.title is distinct from new.title)
    or (old.description is distinct from new.description) then
    insert into public.report_logs (report_id, user_id, message, type)
    values (new.id, auth.uid(), 'Report content updated', 'updated');
  end if;

  -- updated_at is now handled by set_updated_at trigger — remove manual set
  -- (set_updated_at runs first because it fires on BEFORE UPDATE with lower priority)
  return new;
end;
$$;

drop trigger if exists set_reports_updated_at on public.reports;
create trigger set_reports_updated_at
  before update on public.reports
  for each row execute procedure public.set_updated_at();


-- ============================================================
-- §5  INDEXES — COMPOSITE & MISSING INDEXES
-- ============================================================
-- ROOT CAUSE:
--   The current schema has single-column indexes on FK columns,
--   which is correct as a baseline. However, the most common
--   query patterns involve multi-column filters that benefit
--   significantly from composite indexes.
-- ─────────────────────────────────────────────────────────────

-- ── §5.1  workouts: user_id + deleted_at (most common query filter)
-- Query pattern: WHERE user_id = $1 AND deleted_at IS NULL
-- Current single-column indexes would require two separate lookups.
drop index if exists workouts_user_idx;
drop index if exists workouts_deleted_idx;
create index if not exists workouts_user_active_idx
  on public.workouts (user_id, deleted_at)
  where deleted_at is null;
-- Partial index: only indexes active workouts (smaller, faster).

-- Keep a separate index for admin queries that need deleted workouts too
create index if not exists workouts_user_all_idx
  on public.workouts (user_id, created_at desc);


-- ── §5.2  sessions: user_id + date (dashboard, streak, history)
-- Query pattern: WHERE user_id = $1 ORDER BY date DESC
-- Also: WHERE user_id = $1 AND date >= $2 (streak calculation)
drop index if exists sessions_user_idx;
drop index if exists sessions_date_idx;
create index if not exists sessions_user_date_idx
  on public.sessions (user_id, date desc);

-- For streak queries (date range scans)
create index if not exists sessions_user_date_range_idx
  on public.sessions (user_id, date);


-- ── §5.3  session_exercises: session_id + position (ordered fetch)
-- Query pattern: WHERE session_id = $1 ORDER BY position
drop index if exists sex_session_idx;
create index if not exists sex_session_position_idx
  on public.session_exercises (session_id, position);


-- ── §5.4  session_sets: session_exercise_id + set_number (ordered fetch)
drop index if exists ssets_sex_idx;
create index if not exists ssets_sex_setnum_idx
  on public.session_sets (session_exercise_id, set_number);

-- For performance analytics (filter by completed sets)
create index if not exists ssets_completed_idx
  on public.session_sets (session_exercise_id, completed);


-- ── §5.5  exercises: name search (library autocomplete)
create index if not exists exercises_name_search_idx
  on public.exercises using gin (to_tsvector('english', name))
  where deleted_at is null;


-- ── §5.6  workout_slots: workout_id + position
drop index if exists slots_workout_idx;
create index if not exists slots_workout_position_idx
  on public.workout_slots (workout_id, position);


-- ── §5.7  reports: user_id + status + created_at (admin filter queries)
drop index if exists reports_user_idx;
drop index if exists reports_status_idx;
create index if not exists reports_user_status_idx
  on public.reports (user_id, status, created_at desc);

create index if not exists reports_status_created_idx
  on public.reports (status, created_at desc);


-- ── §5.8  report_logs: report_id + created_at (timeline queries)
drop index if exists rlogs_report_idx;
create index if not exists rlogs_report_created_idx
  on public.report_logs (report_id, created_at asc);
-- ASC: logs are always displayed oldest-first


-- ── §5.9  recommended_workouts: category (filter by type)
create index if not exists rec_workouts_category_idx
  on public.recommended_workouts (category)
  where deleted_at is null;


-- ── §5.10  sessions: workout_id (for "sessions using this workout" queries)
-- Already exists as sessions_workout_idx — leave as-is.


-- ============================================================
-- §6  IMMUTABILITY — BLOCK report_logs DELETE
-- ============================================================
-- ROOT CAUSE:
--   The prevent_log_update trigger blocks UPDATE but not DELETE.
--   A user with matching report ownership can delete their own
--   log entries via the RLS INSERT policy (which also allows DELETE
--   since no DELETE policy exists — default deny helps here, but
--   only because there is truly NO DELETE policy).
--   Making this explicit is safer than relying on omission.
-- ─────────────────────────────────────────────────────────────

-- Explicit: block all deletes at trigger level (belt + suspenders with RLS)
create or replace function public.prevent_log_delete()
returns trigger
language plpgsql
as $$
begin
  raise exception
    'report_logs are immutable. Rows cannot be deleted. '
    'Report ID: %, Log ID: %', old.report_id, old.id;
end;
$$;

drop trigger if exists report_logs_no_delete on public.report_logs;
create trigger report_logs_no_delete
  before delete on public.report_logs
  for each row execute procedure public.prevent_log_delete();

-- Explicit RLS: no DELETE policy on report_logs (default deny is the policy)
-- This comment documents the intent — absence of policy = deny.
-- DO NOT add a delete policy here.


-- ── §6.2  FIX: report_logs INSERT should be trigger-only ─────
-- ROOT CAUSE:
--   The current RLS INSERT policy allows any user who can read
--   a report to also insert logs directly. Logs should only be
--   inserted by the auto-logging triggers (security definer),
--   not by application code or the Supabase client.
--
-- FIX: Remove the permissive INSERT policy and rely exclusively
--   on the SECURITY DEFINER triggers to write logs.
-- ─────────────────────────────────────────────────────────────

drop policy if exists "rlogs: insert (system only)" on public.report_logs;
-- No replacement INSERT policy — triggers use SECURITY DEFINER and
-- bypass RLS entirely. Direct client inserts are now blocked by default-deny.

-- Verify the trigger functions are still SECURITY DEFINER (they are from schema.sql).
-- If you recreate them, always include: SECURITY DEFINER


-- ============================================================
-- §7  SNAPSHOTS — exercise_name_snapshot GUARANTEE
-- ============================================================
-- ROOT CAUSE:
--   exercise_name_snapshot can be NULL if the frontend omits it.
--   If the exercise is later soft-deleted, history displays nothing.
--   The snapshot is the last line of defence for historical accuracy.
-- ─────────────────────────────────────────────────────────────

-- Trigger: auto-populate exercise_name_snapshot from exercise library
-- if not provided by the application.
create or replace function public.populate_exercise_name_snapshot()
returns trigger
language plpgsql
as $$
begin
  if new.exercise_name_snapshot is null and new.exercise_id is not null then
    select name into new.exercise_name_snapshot
    from public.exercises
    where id = new.exercise_id;
  end if;

  -- Fallback: if exercise is already deleted or not found
  if new.exercise_name_snapshot is null then
    new.exercise_name_snapshot := 'Unknown Exercise';
  end if;

  return new;
end;
$$;

drop trigger if exists populate_snapshot_trigger on public.session_exercises;
create trigger populate_snapshot_trigger
  before insert on public.session_exercises
  for each row execute procedure public.populate_exercise_name_snapshot();


-- ============================================================
-- §8  ORDERING — position UNIQUENESS PER WORKOUT
-- ============================================================
-- ROOT CAUSE:
--   Two slots in the same workout can have position = 0,
--   making ORDER BY position produce non-deterministic results.
-- ─────────────────────────────────────────────────────────────

-- Unique position per workout
alter table public.workout_slots
  drop constraint if exists workout_slots_position_unique;
alter table public.workout_slots
  add constraint workout_slots_position_unique
    unique (workout_id, position)
    deferrable initially deferred;
-- DEFERRABLE: allows bulk inserts/reorders within a transaction
-- without intermediate violations.

-- Same for recommended_slots
alter table public.recommended_slots
  drop constraint if exists rec_slots_position_unique;
alter table public.recommended_slots
  add constraint rec_slots_position_unique
    unique (workout_id, position)
    deferrable initially deferred;


-- ============================================================
-- §9  OPTIMIZED PRODUCTION QUERIES
-- ============================================================
-- These are not executable statements — they are reference queries.
-- In Supabase JS, use .rpc() for complex ones or the query builder
-- for simpler ones. The SQL is provided for clarity and performance
-- analysis (can be run directly in the SQL editor to test plans).
-- ============================================================


-- ── §9.1  FULL SESSION HISTORY for a user ────────────────────
-- Fetches all sessions with exercises and sets in a single query.
-- Avoids N+1 by using JSON aggregation.
-- Use as a Supabase RPC function.

create or replace function public.get_session_history(p_user_id uuid, p_limit int default 20, p_offset int default 0)
returns jsonb
language sql
security definer
stable
set search_path = public
as $$
  select coalesce(jsonb_agg(session_data order by s.date desc, s.created_at desc), '[]'::jsonb)
  from (
    select
      s.id,
      s.date,
      s.duration_seconds,
      s.notes,
      s.created_at,
      -- Workout name: join, fallback to 'Deleted Workout' if soft-deleted or null
      coalesce(w.name, 'Deleted Workout') as workout_name,
      -- Aggregate exercises as JSON array, ordered by position
      coalesce(
        jsonb_agg(
          jsonb_build_object(
            'exercise_id',   se.exercise_id,
            'exercise_name', coalesce(e.name, se.exercise_name_snapshot, 'Unknown Exercise'),
            'position',      se.position,
            'sets',
            (
              select coalesce(jsonb_agg(
                jsonb_build_object(
                  'set_number',              ss.set_number,
                  'target_reps',             ss.target_reps,
                  'actual_reps',             ss.actual_reps,
                  'target_duration_seconds', ss.target_duration_seconds,
                  'actual_duration_seconds', ss.actual_duration_seconds,
                  'completed',               ss.completed,  -- generated column
                  'rpe',                     ss.rpe
                ) order by ss.set_number
              ), '[]'::jsonb)
              from public.session_sets ss
              where ss.session_exercise_id = se.id
            )
          ) order by se.position
        ),
        '[]'::jsonb
      ) as exercises
    from public.sessions s
    left join public.workouts w on w.id = s.workout_id
    left join public.session_exercises se on se.session_id = s.id
    left join public.exercises e on e.id = se.exercise_id
    where s.user_id = p_user_id
    group by s.id, s.date, s.duration_seconds, s.notes, s.created_at, w.name
    order by s.date desc, s.created_at desc
    limit p_limit offset p_offset
  ) session_data
$$;

-- Grant execute to authenticated users
grant execute on function public.get_session_history(uuid, int, int) to authenticated;

-- Usage from Supabase JS:
-- const { data } = await sb.rpc('get_session_history', {
--   p_user_id: currentUser.id,
--   p_limit: 20,
--   p_offset: 0
-- });


-- ── §9.2  EXERCISE PERFORMANCE AGGREGATION ───────────────────
-- Shows personal bests, average RPE, and volume per exercise.
-- Useful for a "progress" dashboard view.

create or replace function public.get_exercise_stats(p_user_id uuid)
returns jsonb
language sql
security definer
stable
set search_path = public
as $$
  select coalesce(jsonb_agg(stats), '[]'::jsonb)
  from (
    select
      e.id                                        as exercise_id,
      coalesce(e.name, se.exercise_name_snapshot,
               'Unknown Exercise')                as exercise_name,
      e.type                                      as exercise_type,
      count(distinct s.id)                        as total_sessions,
      count(ss.id)                                as total_sets,
      count(ss.id) filter (where ss.completed)    as completed_sets,

      -- Counter stats
      max(ss.actual_reps)                         as personal_best_reps,
      round(avg(ss.actual_reps) filter (
        where ss.actual_reps is not null), 1)     as avg_reps,

      -- Timer stats
      max(ss.actual_duration_seconds)             as personal_best_duration_seconds,
      round(avg(ss.actual_duration_seconds) filter (
        where ss.actual_duration_seconds is not null), 1) as avg_duration_seconds,

      -- Effort
      round(avg(ss.rpe) filter (
        where ss.rpe is not null), 1)             as avg_rpe,

      -- Last performed
      max(s.date)                                 as last_performed_date

    from public.sessions s
    join public.session_exercises se on se.session_id = s.id
    left join public.exercises e on e.id = se.exercise_id
    join public.session_sets ss on ss.session_exercise_id = se.id
    where s.user_id = p_user_id
    group by e.id, e.name, e.type, se.exercise_name_snapshot
    order by last_performed_date desc nulls last
  ) stats
$$;

grant execute on function public.get_exercise_stats(uuid) to authenticated;


-- ── §9.3  ADMIN: ALL REPORTS WITH LATEST LOG ─────────────────
-- Efficient for the admin reports view — avoids fetching all logs
-- for every report in the list. Fetch full logs separately on expand.

create or replace function public.admin_get_reports(
  p_status text default null,
  p_user_id_filter text default null
)
returns jsonb
language sql
security definer
stable
set search_path = public
as $$
  -- Security check: only admin can call this
  select
    case
      when not public.is_admin() then
        jsonb_build_object('error', 'Access denied')
      else (
        select coalesce(jsonb_agg(report_data order by r.created_at desc), '[]'::jsonb)
        from (
          select
            r.id,
            r.user_id,
            up.email                          as user_email,
            r.title,
            r.description,
            r.status,
            r.created_at,
            r.updated_at,
            -- Latest log entry (inline, avoids separate query)
            (
              select jsonb_build_object(
                'message', rl.message,
                'type',    rl.type,
                'date',    rl.created_at
              )
              from public.report_logs rl
              where rl.report_id = r.id
              order by rl.created_at desc
              limit 1
            )                                 as latest_log,
            count(rl_count.id)                as log_count
          from public.reports r
          left join public.user_profiles up on up.id = r.user_id
          left join public.report_logs rl_count on rl_count.report_id = r.id
          where
            (p_status is null or r.status = p_status)
            and (p_user_id_filter is null
                 or r.user_id::text ilike '%' || p_user_id_filter || '%'
                 or up.email ilike '%' || p_user_id_filter || '%')
          group by r.id, r.user_id, up.email, r.title, r.description,
                   r.status, r.created_at, r.updated_at
          order by r.created_at desc
        ) report_data
      )
    end
$$;

grant execute on function public.admin_get_reports(text, text) to authenticated;

-- Usage:
-- const { data } = await sb.rpc('admin_get_reports', {
--   p_status: 'open',        -- or null for all
--   p_user_id_filter: null   -- or partial email/uuid
-- });


-- ── §9.4  USER DASHBOARD — recent activity + streak ──────────
-- Returns last 5 sessions + streak count in a single RPC call.

create or replace function public.get_user_dashboard(p_user_id uuid)
returns jsonb
language sql
security definer
stable
set search_path = public
as $$
  with session_dates as (
    select date
    from public.sessions
    where user_id = p_user_id
    order by date desc
  ),
  streak_calc as (
    -- Walk backwards from today counting consecutive days
    select
      count(*) as streak
    from (
      select
        date,
        date - (row_number() over (order by date desc))::int as grp
      from session_dates
      where date <= current_date
    ) grouped
    where grp = current_date - (
      select count(*) from session_dates where date <= current_date
    )::int
  ),
  recent_sessions as (
    select
      s.id,
      s.date,
      s.duration_seconds,
      s.notes,
      coalesce(w.name, 'Deleted Workout') as workout_name,
      -- Completed set count (uses generated column)
      (
        select count(*) filter (where ss.completed)
        from public.session_exercises se
        join public.session_sets ss on ss.session_exercise_id = se.id
        where se.session_id = s.id
      ) as completed_sets,
      (
        select count(*)
        from public.session_exercises se
        join public.session_sets ss on ss.session_exercise_id = se.id
        where se.session_id = s.id
      ) as total_sets
    from public.sessions s
    left join public.workouts w on w.id = s.workout_id
    where s.user_id = p_user_id
    order by s.date desc, s.created_at desc
    limit 5
  )
  select jsonb_build_object(
    'streak',          (select streak from streak_calc),
    'total_sessions',  (select count(*) from public.sessions where user_id = p_user_id),
    'recent_sessions', (select coalesce(jsonb_agg(rs), '[]'::jsonb) from recent_sessions rs)
  )
$$;

grant execute on function public.get_user_dashboard(uuid) to authenticated;


-- ============================================================
-- §10  PRODUCTION READINESS CHECKLIST
-- ============================================================
-- Run this query to verify the audit fixes are in place.
-- Expected result: all checks return true.
-- ============================================================

create or replace view public.schema_health_check as
select

  -- §1: is_admin caching
  exists(
    select 1 from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public' and p.proname = 'is_admin'
      and p.prosecdef = true  -- SECURITY DEFINER
  ) as is_admin_is_security_definer,

  -- §2.1: user_profiles update policy exists
  exists(
    select 1 from pg_policies
    where schemaname = 'public' and tablename = 'user_profiles'
      and cmd = 'UPDATE'
  ) as user_profiles_has_update_policy,

  -- §3.3: recommended_slots has rest_seconds check
  exists(
    select 1 from pg_constraint c
    join pg_class t on t.oid = c.conrelid
    join pg_namespace n on n.oid = t.relnamespace
    where n.nspname = 'public' and t.relname = 'recommended_slots'
      and c.contype = 'c'
      and c.conname = 'rec_slots_rest_seconds_check'
  ) as rec_slots_has_rest_check,

  -- §4: updated_at triggers exist
  exists(
    select 1 from pg_trigger t join pg_class c on c.oid = t.tgrelid
    join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relname = 'workouts'
      and t.tgname = 'set_workouts_updated_at'
  ) as workouts_has_updated_at_trigger,

  -- §5: composite index on sessions
  exists(
    select 1 from pg_indexes
    where schemaname = 'public' and tablename = 'sessions'
      and indexname = 'sessions_user_date_idx'
  ) as sessions_has_composite_index,

  -- §6: report_logs delete trigger exists
  exists(
    select 1 from pg_trigger t join pg_class c on c.oid = t.tgrelid
    join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relname = 'report_logs'
      and t.tgname = 'report_logs_no_delete'
  ) as report_logs_has_delete_block,

  -- §7: snapshot trigger exists
  exists(
    select 1 from pg_trigger t join pg_class c on c.oid = t.tgrelid
    join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relname = 'session_exercises'
      and t.tgname = 'populate_snapshot_trigger'
  ) as snapshot_trigger_exists,

  -- §8: position uniqueness constraint
  exists(
    select 1 from pg_constraint c
    join pg_class t on t.oid = c.conrelid
    join pg_namespace n on n.oid = t.relnamespace
    where n.nspname = 'public' and t.relname = 'workout_slots'
      and c.contype = 'u'
      and c.conname = 'workout_slots_position_unique'
  ) as workout_slots_position_is_unique,

  -- RPC functions exist
  exists(
    select 1 from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public' and p.proname = 'get_session_history'
  ) as session_history_rpc_exists,

  exists(
    select 1 from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public' and p.proname = 'get_exercise_stats'
  ) as exercise_stats_rpc_exists,

  -- report_logs has no direct INSERT policy (should be false/absent)
  not exists(
    select 1 from pg_policies
    where schemaname = 'public' and tablename = 'report_logs'
      and cmd = 'INSERT'
  ) as report_logs_insert_is_trigger_only;

-- Run the health check:
-- SELECT * FROM public.schema_health_check;
-- All columns should be true.
