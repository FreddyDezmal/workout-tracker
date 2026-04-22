/**
 * REP Platform — Migration Script
 * ─────────────────────────────────
 * Run this ONCE per user to upload localStorage data into Supabase.
 *
 * HOW TO USE:
 *   1. Include this script in index.html (after supabase SDK)
 *   2. Call: await runMigration(supabaseClient, currentUserId)
 *      e.g. inside onSignedIn() after profile is loaded
 *   3. After successful migration, local keys are marked as migrated
 *      so this never runs twice for the same user
 *
 * WHAT IT DOES:
 *   Reads any of: rep_v31, rep_v3, rep_v2, rep_tracker_v1
 *   Normalises to v3.1 schema
 *   Uploads to Supabase in dependency order:
 *     exercises → workouts → workout_slots → sessions
 *     → session_exercises → session_sets
 *   Reports are skipped (they were local only and not meaningful to share)
 *   All inserts are idempotent (upsert on id)
 */

const MIGRATED_KEY = 'rep_migrated_to_supabase';

async function runMigration(sb, userId) {
  // Guard: already migrated for this user
  if (localStorage.getItem(MIGRATED_KEY + '_' + userId)) {
    console.log('[migration] Already migrated for user', userId);
    return { skipped: true };
  }

  // Find local data (try newest version first)
  const raw = (
    localStorage.getItem('rep_v31') ||
    localStorage.getItem('rep_v3')  ||
    localStorage.getItem('rep_v2')  ||
    localStorage.getItem('rep_tracker_v1')
  );

  if (!raw) {
    console.log('[migration] No local data found, marking clean.');
    localStorage.setItem(MIGRATED_KEY + '_' + userId, 'clean');
    return { skipped: true };
  }

  let local;
  try {
    local = JSON.parse(raw);
  } catch (e) {
    console.error('[migration] Could not parse local data:', e);
    return { error: 'parse_failed' };
  }

  // Normalise to v3.1 shape regardless of version
  const normalised = normaliseToV31(local);
  console.log('[migration] Starting migration for user', userId, normalised);

  const errors = [];

  // ── 1. Upload exercises (shared library — deduplicate by name) ────────
  if (normalised.exercises?.length) {
    for (const ex of normalised.exercises) {
      // Check if exercise with same name already exists in DB
      const { data: existing } = await sb
        .from('exercises')
        .select('id')
        .ilike('name', ex.name)
        .is('deleted_at', null)
        .maybeSingle();

      if (!existing) {
        const { error } = await sb.from('exercises').upsert({
          id:           ex.id,
          name:         ex.name,
          type:         ex.type || 'counter',
          muscle_group: ex.muscleGroup || ex.muscle_group || null,
          equipment:    ex.equipment  || null,
          created_by:   userId
        }, { onConflict: 'id', ignoreDuplicates: true });
        if (error) { console.warn('[migration] Exercise upsert error:', error); errors.push(error); }
      }
    }
  }

  // ── 2. Upload workouts + slots ────────────────────────────────────────
  if (normalised.workouts?.length) {
    // Fetch current exercise list from DB (includes seeded + just-inserted)
    const { data: dbExercises } = await sb
      .from('exercises')
      .select('id, name')
      .is('deleted_at', null);

    const dbExMap = {};
    (dbExercises || []).forEach(e => { dbExMap[e.id] = e.id; dbExMap[e.name.toLowerCase()] = e.id; });

    for (const w of normalised.workouts) {
      const { error: wErr } = await sb.from('workouts').upsert({
        id:          w.id,
        user_id:     userId,
        name:        w.name,
        description: w.description || null,
        created_at:  w.createdAt || new Date().toISOString()
      }, { onConflict: 'id', ignoreDuplicates: true });
      if (wErr) { errors.push(wErr); continue; }

      // Upload slots for this workout
      const slots = (w.exerciseSlots || w.exercise_slots || []);
      for (let i = 0; i < slots.length; i++) {
        const s = slots[i];
        // Resolve exercise ID — may have been remapped during seed
        const resolvedExId = dbExMap[s.exerciseId] || dbExMap[s.exercise_id] || null;
        if (!resolvedExId) { console.warn('[migration] Could not resolve exercise ID for slot:', s); continue; }

        // Look up type to enforce reps/duration_seconds exclusivity
        const { data: exRow } = await sb.from('exercises').select('type').eq('id', resolvedExId).single();
        const isTimer = exRow?.type === 'timer';

        const { error: sErr } = await sb.from('workout_slots').upsert({
          workout_id:       w.id,
          exercise_id:      resolvedExId,
          position:         i,
          sets:             s.sets || 3,
          reps:             isTimer ? null : (s.reps || 10),
          duration_seconds: isTimer ? (s.durationSeconds || s.duration_seconds || 30) : null,
          rest_seconds:     s.restSeconds || s.rest_seconds || 60
        }, { onConflict: 'id', ignoreDuplicates: true });
        if (sErr) { console.warn('[migration] Slot upsert error:', sErr); errors.push(sErr); }
      }
    }
  }

  // ── 3. Upload sessions ────────────────────────────────────────────────
  if (normalised.sessions?.length) {
    const { data: dbExercises } = await sb.from('exercises').select('id, name, type').is('deleted_at', null);
    const dbExById   = {};
    const dbExByName = {};
    (dbExercises || []).forEach(e => { dbExById[e.id] = e; dbExByName[e.name.toLowerCase()] = e; });

    for (const sess of normalised.sessions) {
      // Skip if already migrated (idempotency)
      const { data: existing } = await sb.from('sessions').select('id').eq('id', sess.id).maybeSingle();
      if (existing) continue;

      const { data: dbSess, error: sessErr } = await sb.from('sessions').insert({
        id:               sess.id,
        user_id:          userId,
        workout_id:       sess.workoutId || sess.workout_id || null,
        date:             sess.date,
        duration_seconds: sess.durationSeconds || sess.duration_seconds || sess.duration || 0,
        notes:            sess.notes || null
      }).select().single();
      if (sessErr) { errors.push(sessErr); continue; }

      // Upload session_exercises (grouped) and session_sets
      const exerciseGroups = sess.exercises || sess.exercise_groups || [];

      for (let gi = 0; gi < exerciseGroups.length; gi++) {
        const eg = exerciseGroups[gi];
        const exId = eg.exerciseId || eg.exercise_id;
        const resolvedEx = dbExById[exId] || dbExByName[(eg.exerciseName||'').toLowerCase()];

        const { data: dbSE, error: seErr } = await sb.from('session_exercises').insert({
          session_id:             dbSess.id,
          exercise_id:            resolvedEx?.id || null,
          exercise_name_snapshot: eg.exerciseName || resolvedEx?.name || 'Unknown Exercise',
          position:               gi
        }).select().single();
        if (seErr) { errors.push(seErr); continue; }

        const isTimer = resolvedEx?.type === 'timer';
        const sets = eg.sets || [];

        for (let si = 0; si < sets.length; si++) {
          const s = sets[si];
          const setPayload = {
            session_exercise_id: dbSE.id,
            set_number:          s.setNumber || s.set_number || (si + 1),
            rpe:                 s.rpe || null
          };
          // completed is a generated column — never insert it
          if (isTimer) {
            setPayload.target_duration_seconds = s.targetDurationSeconds || s.target_duration_seconds || 0;
            setPayload.actual_duration_seconds = s.actualDurationSeconds || s.actual_duration_seconds || 0;
          } else {
            setPayload.target_reps = s.targetReps || s.target_reps || 0;
            setPayload.actual_reps = s.actualReps || s.actual_reps || 0;
          }
          const { error: setsErr } = await sb.from('session_sets').insert(setPayload);
          if (setsErr) { console.warn('[migration] Set insert error:', setsErr); errors.push(setsErr); }
        }
      }
    }
  }

  // ── 4. Mark migration complete ────────────────────────────────────────
  const success = errors.length === 0;
  if (success) {
    localStorage.setItem(MIGRATED_KEY + '_' + userId, new Date().toISOString());
    console.log('[migration] Complete — no errors.');
  } else {
    console.warn('[migration] Completed with', errors.length, 'errors:', errors);
  }

  return { success, errors };
}


/**
 * Normalise any local schema version to v3.1-compatible shape.
 * Handles v1 (flat exercises), v2, v3.0, v3.1.
 */
function normaliseToV31(data) {
  if (!data) return { exercises: [], workouts: [], sessions: [] };

  const exercises = (data.exercises || []).map(e => ({
    id:          e.id,
    name:        e.name,
    type:        e.type || 'counter',
    muscleGroup: e.muscleGroup || e.muscle_group || '',
    equipment:   e.equipment  || ''
  }));

  // Build exercise name→id map for v1 migration
  const exNameMap = {};
  exercises.forEach(e => { exNameMap[e.name?.toLowerCase()?.trim()] = e.id; });

  // Handle v1 workouts (had exercises[] not exerciseSlots[])
  const workouts = (data.workouts || []).map(w => {
    const slots = (w.exerciseSlots || w.workout_slots || w.exercises || []).map(s => {
      const exId = s.exerciseId || s.exercise_id || exNameMap[s.name?.toLowerCase()?.trim()];
      return {
        exerciseId:      exId,
        sets:            s.sets   || 3,
        reps:            s.reps   || null,
        durationSeconds: s.durationSeconds || s.duration_seconds || null,
        restSeconds:     s.restSeconds || s.rest_seconds || 60
      };
    });
    return { id: w.id, name: w.name, description: w.description || '', createdAt: w.createdAt, exerciseSlots: slots };
  });

  // Handle all session formats
  const sessions = (data.sessions || []).map(sess => {
    let exerciseGroups = [];

    if (Array.isArray(sess.exercises)) {
      // v3.1 grouped format
      exerciseGroups = sess.exercises;
    } else if (Array.isArray(sess.sets)) {
      // v3.0 flat sets[] — group by exerciseId
      const grouped = {};
      sess.sets.forEach(s => {
        const key = s.exerciseId || s.exercise_id || s.exerciseName || 'unknown';
        if (!grouped[key]) grouped[key] = { exerciseId: s.exerciseId||s.exercise_id||null, exerciseName: s.exerciseName||'', sets: [] };
        const isT = s.targetDurationSeconds !== undefined || s.target_duration_seconds !== undefined;
        const entry = { rpe: s.rpe || null };
        if (isT) {
          entry.targetDurationSeconds = s.targetDurationSeconds || s.target_duration_seconds || 0;
          entry.actualDurationSeconds = s.actualDurationSeconds || s.actual_duration_seconds || 0;
        } else {
          entry.targetReps = s.targetReps || s.target_reps || 0;
          entry.actualReps = s.actualReps || s.actual_reps || 0;
        }
        grouped[key].sets.push(entry);
      });
      exerciseGroups = Object.values(grouped);
    }

    return {
      id:              sess.id,
      workoutId:       sess.workoutId || sess.workout_id || null,
      date:            sess.date,
      durationSeconds: sess.durationSeconds || sess.duration_seconds || sess.duration || 0,
      notes:           sess.notes || '',
      exercises:       exerciseGroups
    };
  });

  return { exercises, workouts, sessions };
}
