-- Think Fast — Super Admin Panel migration (ADMIN_PANEL_SPEC.md section 4)
-- Project: think-fast (https://stxirtoytwhtfzursxru.supabase.co)
-- Run AFTER the main migration. This file only ADDS: roles, ban/hide columns,
-- audit log, app_config, announcements, snapshots, admin RPCs, and updated
-- player RPCs (submit_session / get_leaderboard / get_my_rank).
-- It never drops a table, never deletes a user, never touches admission-path.
-- service_role is NEVER used here; all admin RPCs are SECURITY DEFINER with
-- a server-side role check as the first line. UI hiding is not security.
--
-- Documented choice (spec 4.7 auto-flag): an auto-flagged session is STORED
-- but contributes NOTHING to the profile (no high_score, no XP, no solved
-- count, no sessions_played) until an admin unflags it, at which point
-- admin_recompute_profile includes it. last_submit_at IS updated so the
-- 10s rate limit cannot be bypassed with flagged submits.

-- ========== 4.1 Role table + helpers ==========
create table if not exists public.user_roles (
  user_id    uuid primary key references auth.users(id) on delete cascade,
  role       text not null check (role in ('admin','superadmin')),
  granted_by uuid references auth.users(id),
  created_at timestamptz not null default now()
);
alter table public.user_roles enable row level security;
create policy "roles_select_own" on public.user_roles
  for select using (auth.uid() = user_id);
revoke insert, update, delete on public.user_roles from anon, authenticated;

create or replace function public.is_admin() returns boolean
language sql security definer set search_path = public stable as $$
  select exists (select 1 from public.user_roles where user_id = auth.uid() and role in ('admin','superadmin'));
$$;
create or replace function public.is_superadmin() returns boolean
language sql security definer set search_path = public stable as $$
  select exists (select 1 from public.user_roles where user_id = auth.uid() and role = 'superadmin');
$$;
grant execute on function public.is_admin(), public.is_superadmin() to authenticated;

-- ========== 4.2 New columns ==========
alter table public.profiles
  add column if not exists is_banned boolean not null default false,
  add column if not exists banned_reason text,
  add column if not exists banned_at timestamptz,
  add column if not exists hidden_from_leaderboard boolean not null default false,
  add column if not exists admin_notes text;

alter table public.game_sessions
  add column if not exists is_flagged boolean not null default false,
  add column if not exists flag_reason text,
  add column if not exists is_voided boolean not null default false;

-- ========== 4.3 Audit log (append-only) ==========
create table if not exists public.audit_log (
  id          bigint generated always as identity primary key,
  actor_id    uuid not null references auth.users(id),
  actor_role  text not null,
  action      text not null,
  target_type text,
  target_id   text,
  reason      text,
  details     jsonb not null default '{}'::jsonb,
  created_at  timestamptz not null default now()
);
create index if not exists idx_audit_created on public.audit_log (created_at desc);
create index if not exists idx_audit_target on public.audit_log (target_type, target_id);
alter table public.audit_log enable row level security;
revoke all on public.audit_log from anon, authenticated;

create or replace function public.log_admin(p_action text, p_target_type text, p_target_id text, p_reason text, p_details jsonb)
returns void language plpgsql security definer set search_path = public as $$
declare r text;
begin
  select role into r from public.user_roles where user_id = auth.uid();
  insert into public.audit_log(actor_id, actor_role, action, target_type, target_id, reason, details)
  values (auth.uid(), coalesce(r,'unknown'), p_action, p_target_type, p_target_id, p_reason, coalesce(p_details,'{}'));
end $$;
revoke all on function public.log_admin from public, anon, authenticated;

-- ========== 4.4 Remote config ==========
create table if not exists public.app_config (
  key        text primary key,
  value      jsonb not null,
  is_public  boolean not null default true,
  updated_by uuid references auth.users(id),
  updated_at timestamptz not null default now()
);
alter table public.app_config enable row level security;
revoke all on public.app_config from anon, authenticated;

insert into public.app_config(key, value, is_public) values
 ('maintenance',  '{"enabled": false, "message": "We are upgrading Think Fast. Back soon!"}', true),
 ('signups',      '{"enabled": true}', true),
 ('guest_play',   '{"enabled": true}', true),
 ('auth_methods', '{"google": true, "email": true}', true),
 ('scoring',      '{"wrong_penalty": 50, "speed_bonus_window_sec": 3.0, "speed_bonus_factor": 40, "combo_tiers": [{"streak":5,"mult":2},{"streak":10,"mult":3},{"streak":15,"mult":5}]}', true),
 ('timing',       '{"presets_minutes": [3,5,10,30], "max_custom_minutes": 180}', true),
 ('leaderboard',  '{"enabled": true, "size": 10}', true),
 ('anti_cheat',   '{"max_answers_per_sec": 4, "max_points_per_correct": 4200, "min_submit_interval_sec": 10, "auto_flag_points_per_correct": 3000, "min_duration_sec": 10, "max_duration_sec": 10800}', false)
on conflict (key) do nothing;

create or replace function public.get_public_config() returns jsonb
language sql security definer set search_path = public stable as $$
  select coalesce(jsonb_object_agg(key, value), '{}'::jsonb) from public.app_config where is_public;
$$;
grant execute on function public.get_public_config() to anon, authenticated;

-- ========== 4.5 Announcements ==========
create table if not exists public.announcements (
  id         uuid primary key default gen_random_uuid(),
  title      text not null,
  body       text not null,
  level      text not null default 'info' check (level in ('info','success','warning','critical')),
  is_active  boolean not null default true,
  starts_at  timestamptz not null default now(),
  ends_at    timestamptz,
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now()
);
alter table public.announcements enable row level security;
revoke all on public.announcements from anon, authenticated;

create or replace function public.get_active_announcements() returns setof public.announcements
language sql security definer set search_path = public stable as $$
  select * from public.announcements
  where is_active and starts_at <= now() and (ends_at is null or ends_at > now())
  order by created_at desc limit 5;
$$;
grant execute on function public.get_active_announcements() to anon, authenticated;

-- ========== 4.6 Leaderboard / season snapshots ==========
create table if not exists public.leaderboard_snapshots (
  id       uuid primary key default gen_random_uuid(),
  label    text not null,
  taken_by uuid references auth.users(id),
  taken_at timestamptz not null default now(),
  rows     jsonb not null
);
alter table public.leaderboard_snapshots enable row level security;
revoke all on public.leaderboard_snapshots from anon, authenticated;

-- ========== 4.7 Updated player RPCs ==========
-- Config helper: read one app_config value, or fall back to the old default.
create or replace function public.cfg_json(p_key text) returns jsonb
language sql security definer set search_path = public stable as $$
  select coalesce((select value from public.app_config where key = p_key), '{}'::jsonb);
$$;
revoke all on function public.cfg_json from public, anon, authenticated;

create or replace function public.submit_session(
  p_score int, p_duration int, p_asked int, p_correct int, p_max_streak int,
  p_operator_stats jsonb, p_config jsonb
) returns public.profiles
language plpgsql security definer set search_path = public as $$
declare
  uid uuid := auth.uid();
  prof public.profiles;
  new_xp bigint;
  ac jsonb := public.cfg_json('anti_cheat');
  mt jsonb := public.cfg_json('maintenance');
  max_ppc int := coalesce((ac->>'max_points_per_correct')::int, 4200);
  max_aps numeric := coalesce((ac->>'max_answers_per_sec')::numeric, 4);
  min_interval int := coalesce((ac->>'min_submit_interval_sec')::int, 10);
  min_dur int := coalesce((ac->>'min_duration_sec')::int, 10);
  max_dur int := coalesce((ac->>'max_duration_sec')::int, 10800);
  auto_flag_ppc int := coalesce((ac->>'auto_flag_points_per_correct')::int, 3000);
  auto_flagged boolean := false;
begin
  if uid is null then raise exception 'not_authenticated'; end if;
  if coalesce((mt->>'enabled')::boolean, false) then raise exception 'maintenance'; end if;

  select * into prof from public.profiles where id = uid for update;
  if prof is null then raise exception 'not_authenticated'; end if;
  if prof.is_banned then raise exception 'banned'; end if;

  if p_duration < min_dur or p_duration > max_dur then raise exception 'bad_duration'; end if;
  if p_asked < 0 or p_correct < 0 or p_correct > p_asked then raise exception 'bad_counts'; end if;
  if p_max_streak < 0 or p_max_streak > p_correct then raise exception 'bad_streak'; end if;
  if p_asked > (p_duration * max_aps) then raise exception 'too_fast'; end if;
  if p_score < 0 or p_score > p_correct * max_ppc then raise exception 'score_too_high'; end if;

  if prof.last_submit_at is not null
     and prof.last_submit_at > now() - (min_interval || ' seconds')::interval then
    raise exception 'rate_limited';
  end if;

  auto_flagged := (p_correct > 0 and p_score > p_correct * auto_flag_ppc);

  insert into public.game_sessions
    (user_id, score, duration_seconds, total_asked, total_correct, max_streak, operator_stats, config, is_flagged, flag_reason)
  values (uid, p_score, p_duration, p_asked, p_correct, p_max_streak,
          coalesce(p_operator_stats,'{}'), coalesce(p_config,'{}'),
          auto_flagged, case when auto_flagged then 'auto: high score per correct' else null end);

  if auto_flagged then
    -- Stored but contributes nothing until an admin unflags it (see header note).
    update public.profiles set last_submit_at = now(), updated_at = now() where id = uid returning * into prof;
    return prof;
  end if;

  new_xp := prof.total_xp + p_score;
  update public.profiles set
    high_score        = greatest(high_score, p_score),
    total_math_solved = total_math_solved + p_correct,
    total_xp          = new_xp,
    user_level        = public.level_from_xp(new_xp),
    sessions_played   = sessions_played + 1,
    last_submit_at    = now(),
    updated_at        = now()
  where id = uid
  returning * into prof;
  return prof;
end $$;
revoke all on function public.submit_session from public, anon;
grant execute on function public.submit_session to authenticated;

create or replace function public.get_leaderboard(p_limit int default 10)
returns table (rank bigint, user_id uuid, display_name text, avatar_url text,
               user_level int, high_score int)
language sql security definer set search_path = public stable as $$
  select row_number() over (order by high_score desc, updated_at asc) as rank,
         id, display_name, avatar_url, user_level, high_score
  from public.profiles
  where high_score > 0 and not is_banned and not hidden_from_leaderboard
    and coalesce(((select value from public.app_config where key = 'leaderboard')->>'enabled')::boolean, true)
  order by high_score desc, updated_at asc
  limit least(greatest(p_limit,1),
              coalesce(((select value from public.app_config where key = 'leaderboard')->>'size')::int, 10), 100);
$$;
grant execute on function public.get_leaderboard to anon, authenticated;

create or replace function public.get_my_rank() returns bigint
language sql security definer set search_path = public stable as $$
  select count(*) + 1 from public.profiles
  where high_score > (select high_score from public.profiles where id = auth.uid())
    and not is_banned and not hidden_from_leaderboard;
$$;
grant execute on function public.get_my_rank to authenticated;

-- ========== 4.8 Admin RPCs: internal recompute ==========
create or replace function public.admin_recompute_profile(p_user_id uuid)
returns public.profiles language plpgsql security definer set search_path = public as $$
declare prof public.profiles; s record;
begin
  select coalesce(max(score),0) as max_score, coalesce(sum(total_correct),0) as solved,
         coalesce(sum(score),0) as xp, coalesce(count(*),0) as cnt
    into s from public.game_sessions
    where user_id = p_user_id and not is_voided and not is_flagged;
  update public.profiles set
    high_score = s.max_score, total_math_solved = s.solved, total_xp = s.xp,
    user_level = public.level_from_xp(s.xp), sessions_played = s.cnt,
    updated_at = now()
  where id = p_user_id returning * into prof;
  return prof;
end $$;
revoke all on function public.admin_recompute_profile from public, anon, authenticated;

-- ========== Admin RPCs: dashboard ==========
create or replace function public.admin_dashboard_stats() returns jsonb
language plpgsql security definer set search_path = public as $$
declare out jsonb;
begin
  if not public.is_admin() then raise exception 'forbidden'; end if;
  select jsonb_build_object(
    'total_users', (select count(*) from auth.users),
    'new_users_7d', (select count(*) from auth.users where created_at > now() - interval '7 days'),
    'new_users_30d', (select count(*) from auth.users where created_at > now() - interval '30 days'),
    'active_users_24h', (select count(distinct user_id) from public.game_sessions where created_at > now() - interval '24 hours'),
    'active_users_7d', (select count(distinct user_id) from public.game_sessions where created_at > now() - interval '7 days'),
    'total_sessions', (select count(*) from public.game_sessions),
    'sessions_24h', (select count(*) from public.game_sessions where created_at > now() - interval '24 hours'),
    'avg_score', (select coalesce(avg(score),0) from public.game_sessions),
    'avg_accuracy', (select coalesce(avg(case when total_asked > 0 then total_correct::numeric / total_asked end),0) from public.game_sessions),
    'total_math_solved', (select coalesce(sum(total_correct),0) from public.game_sessions),
    'flagged_sessions_open', (select count(*) from public.game_sessions where is_flagged and not is_voided),
    'banned_users', (select count(*) from public.profiles where is_banned),
    'daily', (select coalesce(jsonb_agg(jsonb_build_object(
        'day', d, 'new_users', (select count(*) from auth.users where created_at::date = d),
        'sessions', (select count(*) from public.game_sessions where created_at::date = d),
        'avg_score', (select coalesce(avg(score),0) from public.game_sessions where created_at::date = d)
      ) order by d), '[]'::jsonb)
      from (select (current_date - s)::date as d from generate_series(0,29) s) days)
  ) into out;
  return out;
end $$;
revoke all on function public.admin_dashboard_stats() from public, anon;
grant execute on function public.admin_dashboard_stats() to authenticated;

-- ========== Admin RPCs: users ==========
create or replace function public.admin_list_users(
  p_search text default null, p_status text default 'all', p_sort text default 'created_at',
  p_dir text default 'desc', p_limit int default 50, p_offset int default 0)
returns table (id uuid, email text, display_name text, user_level int, high_score int,
  total_xp bigint, sessions_played int, is_banned boolean, hidden_from_leaderboard boolean,
  role text, created_at timestamptz, last_sign_in_at timestamptz, total_count bigint)
language plpgsql security definer set search_path = public as $$
declare sort_col text; dir text;
begin
  if not public.is_admin() then raise exception 'forbidden'; end if;
  sort_col := case p_sort when 'high_score' then 'high_score' when 'total_xp' then 'total_xp'
    when 'display_name' then 'display_name' when 'sessions_played' then 'sessions_played'
    else 'created_at' end;
  dir := case when lower(coalesce(p_dir,'desc')) = 'asc' then 'asc' else 'desc' end;
  return query execute format(
    'select p.id, u.email, p.display_name, p.user_level, p.high_score, p.total_xp, p.sessions_played,
       p.is_banned, p.hidden_from_leaderboard, r.role, u.created_at, u.last_sign_in_at,
       count(*) over() from public.profiles p
     join auth.users u on u.id = p.id
     left join public.user_roles r on r.user_id = p.id
     where ($1 is null or $1 = '''' or u.email ilike ''%%'' || $1 || ''%%'' or p.display_name ilike ''%%'' || $1 || ''%%'')
       and ($2 = ''all'' or ($2 = ''banned'' and p.is_banned)
            or ($2 = ''flagged'' and exists (select 1 from public.game_sessions s where s.user_id = p.id and s.is_flagged and not s.is_voided))
            or ($2 = ''admins'' and r.role is not null))
     order by %I %s limit $3 offset $4',
    sort_col, dir)
  using p_search, p_status, least(greatest(p_limit,1),200), greatest(p_offset,0);
end $$;
revoke all on function public.admin_list_users(text,text,text,text,int,int) from public, anon;
grant execute on function public.admin_list_users(text,text,text,text,int,int) to authenticated;

create or replace function public.admin_get_user(p_user_id uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare out jsonb;
begin
  if not public.is_admin() then raise exception 'forbidden'; end if;
  select jsonb_build_object(
    'profile', (select row_to_json(p) from public.profiles p where p.id = p_user_id),
    'email', (select email from auth.users where id = p_user_id),
    'role', (select role from public.user_roles where user_id = p_user_id),
    'created_at', (select created_at from auth.users where id = p_user_id),
    'last_sign_in_at', (select last_sign_in_at from auth.users where id = p_user_id),
    'sessions', (select coalesce(jsonb_agg(row_to_json(s) order by s.created_at desc), '[]'::jsonb)
                 from (select * from public.game_sessions where user_id = p_user_id order by created_at desc limit 20) s),
    'audit', (select coalesce(jsonb_agg(row_to_json(a) order by a.created_at desc), '[]'::jsonb)
              from (select * from public.audit_log where target_id = p_user_id::text order by created_at desc limit 50) a)
  ) into out;
  return out;
end $$;
revoke all on function public.admin_get_user(uuid) from public, anon;
grant execute on function public.admin_get_user(uuid) to authenticated;

create or replace function public.admin_set_ban(p_user_id uuid, p_banned boolean, p_reason text)
returns void language plpgsql security definer set search_path = public as $$
declare before jsonb; r text;
begin
  if not public.is_admin() then raise exception 'forbidden'; end if;
  if p_user_id = auth.uid() then raise exception 'forbidden'; end if;
  select role into r from public.user_roles where user_id = p_user_id;
  if r = 'superadmin' then raise exception 'forbidden'; end if;
  if p_banned and (p_reason is null or btrim(p_reason) = '') then raise exception 'reason_required'; end if;
  select row_to_json(p) into before from public.profiles p where p.id = p_user_id;
  update public.profiles set is_banned = p_banned,
    banned_reason = case when p_banned then p_reason else null end,
    banned_at = case when p_banned then now() else null end, updated_at = now()
  where id = p_user_id;
  perform public.log_admin(case when p_banned then 'user.ban' else 'user.unban' end, 'user',
    p_user_id::text, p_reason, jsonb_build_object('before', before,
    'after', (select row_to_json(p) from public.profiles p where p.id = p_user_id)));
end $$;
revoke all on function public.admin_set_ban(uuid,boolean,text) from public, anon;
grant execute on function public.admin_set_ban(uuid,boolean,text) to authenticated;

create or replace function public.admin_set_hidden(p_user_id uuid, p_hidden boolean, p_reason text)
returns void language plpgsql security definer set search_path = public as $$
declare before jsonb;
begin
  if not public.is_admin() then raise exception 'forbidden'; end if;
  select row_to_json(p) into before from public.profiles p where p.id = p_user_id;
  update public.profiles set hidden_from_leaderboard = p_hidden, updated_at = now() where id = p_user_id;
  perform public.log_admin(case when p_hidden then 'user.hide' else 'user.unhide' end, 'user',
    p_user_id::text, p_reason, jsonb_build_object('before', before,
    'after', (select row_to_json(p) from public.profiles p where p.id = p_user_id)));
end $$;
revoke all on function public.admin_set_hidden(uuid,boolean,text) from public, anon;
grant execute on function public.admin_set_hidden(uuid,boolean,text) to authenticated;

create or replace function public.admin_update_user(p_user_id uuid, p_display_name text, p_admin_notes text, p_reason text)
returns void language plpgsql security definer set search_path = public as $$
declare before jsonb;
begin
  if not public.is_superadmin() then raise exception 'forbidden'; end if;
  select row_to_json(p) into before from public.profiles p where p.id = p_user_id;
  update public.profiles set
    display_name = coalesce(p_display_name, display_name),
    admin_notes = coalesce(p_admin_notes, admin_notes), updated_at = now()
  where id = p_user_id;
  perform public.log_admin('user.update', 'user', p_user_id::text, p_reason,
    jsonb_build_object('before', before,
    'after', (select row_to_json(p) from public.profiles p where p.id = p_user_id)));
end $$;
revoke all on function public.admin_update_user(uuid,text,text,text) from public, anon;
grant execute on function public.admin_update_user(uuid,text,text,text) to authenticated;

create or replace function public.admin_adjust_user_stats(p_user_id uuid, p_high_score int, p_total_xp bigint, p_total_math_solved int, p_reason text)
returns void language plpgsql security definer set search_path = public as $$
declare before jsonb;
begin
  if not public.is_superadmin() then raise exception 'forbidden'; end if;
  if (p_reason is null or btrim(p_reason) = '') then raise exception 'reason_required'; end if;
  if coalesce(p_high_score,0) < 0 or coalesce(p_total_xp,0) < 0 or coalesce(p_total_math_solved,0) < 0 then raise exception 'invalid_stats'; end if;
  select row_to_json(p) into before from public.profiles p where p.id = p_user_id;
  update public.profiles set
    high_score = coalesce(p_high_score, high_score),
    total_xp = coalesce(p_total_xp, total_xp),
    total_math_solved = coalesce(p_total_math_solved, total_math_solved),
    user_level = public.level_from_xp(coalesce(p_total_xp, total_xp)), updated_at = now()
  where id = p_user_id;
  perform public.log_admin('user.adjust_stats', 'user', p_user_id::text, p_reason,
    jsonb_build_object('before', before,
    'after', (select row_to_json(p) from public.profiles p where p.id = p_user_id)));
end $$;
revoke all on function public.admin_adjust_user_stats(uuid,int,bigint,int,text) from public, anon;
grant execute on function public.admin_adjust_user_stats(uuid,int,bigint,int,text) to authenticated;

create or replace function public.admin_reset_user_stats(p_user_id uuid, p_reason text)
returns void language plpgsql security definer set search_path = public as $$
declare before jsonb;
begin
  if not public.is_superadmin() then raise exception 'forbidden'; end if;
  if (p_reason is null or btrim(p_reason) = '') then raise exception 'reason_required'; end if;
  select row_to_json(p) into before from public.profiles p where p.id = p_user_id;
  update public.game_sessions set is_voided = true where user_id = p_user_id and not is_voided;
  perform public.admin_recompute_profile(p_user_id);
  perform public.log_admin('user.reset_stats', 'user', p_user_id::text, p_reason,
    jsonb_build_object('before', before,
    'after', (select row_to_json(p) from public.profiles p where p.id = p_user_id)));
end $$;
revoke all on function public.admin_reset_user_stats(uuid,text) from public, anon;
grant execute on function public.admin_reset_user_stats(uuid,text) to authenticated;

-- ========== Admin RPCs: sessions ==========
create or replace function public.admin_list_sessions(
  p_user_id uuid default null, p_flagged_only boolean default false,
  p_limit int default 50, p_offset int default 0)
returns table (id uuid, user_id uuid, display_name text, score int, total_asked int,
  total_correct int, max_streak int, duration_seconds int, is_flagged boolean, flag_reason text,
  is_voided boolean, created_at timestamptz, total_count bigint)
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'forbidden'; end if;
  return query select s.id, s.user_id, p.display_name, s.score, s.total_asked, s.total_correct, s.max_streak,
    s.duration_seconds, s.is_flagged, s.flag_reason, s.is_voided, s.created_at, count(*) over()
  from public.game_sessions s join public.profiles p on p.id = s.user_id
  where (p_user_id is null or s.user_id = p_user_id)
    and (not p_flagged_only or s.is_flagged)
  order by s.created_at desc
  limit least(greatest(p_limit,1),200) offset greatest(p_offset,0);
end $$;
revoke all on function public.admin_list_sessions(uuid,boolean,int,int) from public, anon;
grant execute on function public.admin_list_sessions(uuid,boolean,int,int) to authenticated;

create or replace function public.admin_flag_session(p_session_id uuid, p_flagged boolean, p_reason text)
returns void language plpgsql security definer set search_path = public as $$
declare before jsonb; uid uuid;
begin
  if not public.is_admin() then raise exception 'forbidden'; end if;
  select row_to_json(s), s.user_id into before, uid from public.game_sessions s where s.id = p_session_id;
  if before is null then raise exception 'not_found'; end if;
  update public.game_sessions set is_flagged = p_flagged,
    flag_reason = case when p_flagged then p_reason else null end where id = p_session_id;
  perform public.admin_recompute_profile(uid);
  perform public.log_admin(case when p_flagged then 'session.flag' else 'session.unflag' end, 'session',
    p_session_id::text, p_reason, jsonb_build_object('before', before,
    'after', (select row_to_json(s) from public.game_sessions s where s.id = p_session_id)));
end $$;
revoke all on function public.admin_flag_session(uuid,boolean,text) from public, anon;
grant execute on function public.admin_flag_session(uuid,boolean,text) to authenticated;

create or replace function public.admin_void_session(p_session_id uuid, p_reason text)
returns void language plpgsql security definer set search_path = public as $$
declare before jsonb; uid uuid;
begin
  if not public.is_admin() then raise exception 'forbidden'; end if;
  if (p_reason is null or btrim(p_reason) = '') then raise exception 'reason_required'; end if;
  select row_to_json(s), s.user_id into before, uid from public.game_sessions s where s.id = p_session_id;
  if before is null then raise exception 'not_found'; end if;
  update public.game_sessions set is_voided = true where id = p_session_id;
  perform public.admin_recompute_profile(uid);
  perform public.log_admin('session.void', 'session', p_session_id::text, p_reason,
    jsonb_build_object('before', before,
    'after', (select row_to_json(s) from public.game_sessions s where s.id = p_session_id)));
end $$;
revoke all on function public.admin_void_session(uuid,text) from public, anon;
grant execute on function public.admin_void_session(uuid,text) to authenticated;

-- ========== Admin RPCs: config ==========
create or replace function public.admin_get_config()
returns table (key text, value jsonb, is_public boolean, updated_by uuid, updated_at timestamptz)
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_superadmin() then raise exception 'forbidden'; end if;
  return query select c.key, c.value, c.is_public, c.updated_by, c.updated_at from public.app_config c order by c.key;
end $$;
revoke all on function public.admin_get_config() from public, anon;
grant execute on function public.admin_get_config() to authenticated;

create or replace function public.admin_set_config(p_key text, p_value jsonb, p_reason text)
returns text language plpgsql security definer set search_path = public as $$
declare before jsonb; warn text := '';
  sc jsonb; ac jsonb; max_possible numeric;
begin
  if not public.is_superadmin() then raise exception 'forbidden'; end if;
  if p_key not in ('maintenance','signups','guest_play','auth_methods','scoring','timing','leaderboard','anti_cheat') then
    raise exception 'unknown_config_key';
  end if;
  if p_value is null or jsonb_typeof(p_value) <> 'object' then raise exception 'invalid_config'; end if;
  -- Per-key shape checks (sane ranges; booleans where expected).
  if p_key = 'maintenance' and jsonb_typeof(p_value->'enabled') <> 'boolean' then raise exception 'invalid_config'; end if;
  if p_key in ('signups','guest_play') and jsonb_typeof(p_value->'enabled') <> 'boolean' then raise exception 'invalid_config'; end if;
  if p_key = 'auth_methods' and (jsonb_typeof(p_value->'google') <> 'boolean' or jsonb_typeof(p_value->'email') <> 'boolean') then raise exception 'invalid_config'; end if;
  if p_key = 'scoring' and ((p_value->>'wrong_penalty')::numeric < 0 or (p_value->>'wrong_penalty')::numeric > 500
      or (p_value->>'speed_bonus_window_sec')::numeric < 0 or (p_value->>'speed_bonus_window_sec')::numeric > 60
      or (p_value->>'speed_bonus_factor')::numeric < 0 or (p_value->>'speed_bonus_factor')::numeric > 500) then raise exception 'invalid_config'; end if;
  if p_key = 'timing' and ((p_value->>'max_custom_minutes')::numeric < 1 or (p_value->>'max_custom_minutes')::numeric > 1440) then raise exception 'invalid_config'; end if;
  if p_key = 'leaderboard' and (jsonb_typeof(p_value->'enabled') <> 'boolean' or (p_value->>'size')::int < 1 or (p_value->>'size')::int > 100) then raise exception 'invalid_config'; end if;
  if p_key = 'anti_cheat' and ((p_value->>'max_answers_per_sec')::numeric < 1 or (p_value->>'max_answers_per_sec')::numeric > 20
      or (p_value->>'max_points_per_correct')::int < 1000
      or (p_value->>'auto_flag_points_per_correct')::int >= (p_value->>'max_points_per_correct')::int
      or (p_value->>'min_submit_interval_sec')::int < 0 or (p_value->>'min_submit_interval_sec')::int > 3600) then raise exception 'invalid_config'; end if;
  select row_to_json(c) into before from public.app_config c where c.key = p_key;
  insert into public.app_config(key, value, updated_by, updated_at)
    values (p_key, p_value, auth.uid(), now())
    on conflict (key) do update set value = excluded.value, updated_by = excluded.updated_by, updated_at = excluded.updated_at;
  perform public.log_admin('config.update', 'config', p_key, p_reason,
    jsonb_build_object('before', before,
    'after', (select row_to_json(c) from public.app_config c where c.key = p_key)));
  -- Spec 7 consistency warning: scoring ceiling must fit inside the anti-cheat cap.
  select value into sc from public.app_config where key = 'scoring';
  select value into ac from public.app_config where key = 'anti_cheat';
  max_possible := 780 * coalesce((select max((t->>'mult')::numeric) from jsonb_array_elements(sc->'combo_tiers') t), 1)
                  + coalesce((sc->>'speed_bonus_factor')::numeric, 0);
  if max_possible > coalesce((ac->>'max_points_per_correct')::numeric, 4200) then
    warn := 'Warning: scoring can legitimately produce ' || max_possible::text ||
            ' points per correct, above the anti-cheat cap ' || (ac->>'max_points_per_correct') ||
            '. Raise max_points_per_correct to at least ' || ceil(max_possible)::text || '.';
  end if;
  return warn;
end $$;
revoke all on function public.admin_set_config(text,jsonb,text) from public, anon;
grant execute on function public.admin_set_config(text,jsonb,text) to authenticated;

-- ========== Admin RPCs: announcements ==========
create or replace function public.admin_list_announcements()
returns setof public.announcements language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'forbidden'; end if;
  return query select * from public.announcements order by created_at desc;
end $$;
revoke all on function public.admin_list_announcements() from public, anon;
grant execute on function public.admin_list_announcements() to authenticated;

create or replace function public.admin_save_announcement(
  p_id uuid, p_title text, p_body text, p_level text, p_is_active boolean,
  p_starts_at timestamptz, p_ends_at timestamptz, p_reason text)
returns uuid language plpgsql security definer set search_path = public as $$
declare nid uuid; before jsonb;
begin
  if not public.is_admin() then raise exception 'forbidden'; end if;
  if btrim(coalesce(p_title,'')) = '' or btrim(coalesce(p_body,'')) = '' then raise exception 'invalid_announcement'; end if;
  if p_level not in ('info','success','warning','critical') then raise exception 'invalid_announcement'; end if;
  if p_id is not null then select row_to_json(a) into before from public.announcements a where a.id = p_id; end if;
  insert into public.announcements(id, title, body, level, is_active, starts_at, ends_at, created_by)
    values (coalesce(p_id, gen_random_uuid()), p_title, p_body, p_level, coalesce(p_is_active,true),
            coalesce(p_starts_at, now()), p_ends_at, auth.uid())
    on conflict (id) do update set title = excluded.title, body = excluded.body, level = excluded.level,
      is_active = excluded.is_active, starts_at = excluded.starts_at, ends_at = excluded.ends_at
    returning id into nid;
  perform public.log_admin('announcement.save', 'announcement', nid::text, p_reason,
    jsonb_build_object('before', before,
    'after', (select row_to_json(a) from public.announcements a where a.id = nid)));
  return nid;
end $$;
revoke all on function public.admin_save_announcement(uuid,text,text,text,boolean,timestamptz,timestamptz,text) from public, anon;
grant execute on function public.admin_save_announcement(uuid,text,text,text,boolean,timestamptz,timestamptz,text) to authenticated;

create or replace function public.admin_delete_announcement(p_id uuid, p_reason text)
returns void language plpgsql security definer set search_path = public as $$
declare before jsonb;
begin
  if not public.is_admin() then raise exception 'forbidden'; end if;
  select row_to_json(a) into before from public.announcements a where a.id = p_id;
  delete from public.announcements where id = p_id;
  perform public.log_admin('announcement.delete', 'announcement', p_id::text, p_reason, jsonb_build_object('before', before));
end $$;
revoke all on function public.admin_delete_announcement(uuid,text) from public, anon;
grant execute on function public.admin_delete_announcement(uuid,text) to authenticated;

-- ========== Admin RPCs: leaderboard snapshots / reset ==========
create or replace function public.admin_take_leaderboard_snapshot(p_label text)
returns uuid language plpgsql security definer set search_path = public as $$
declare nid uuid; rows jsonb;
begin
  if not public.is_superadmin() then raise exception 'forbidden'; end if;
  select coalesce(jsonb_agg(row_to_json(l)), '[]'::jsonb) into rows
  from (select * from public.get_leaderboard(100)) l;
  insert into public.leaderboard_snapshots(label, taken_by, rows) values (p_label, auth.uid(), rows) returning id into nid;
  perform public.log_admin('leaderboard.snapshot', 'system', nid::text, null, jsonb_build_object('label', p_label));
  return nid;
end $$;
revoke all on function public.admin_take_leaderboard_snapshot(text) from public, anon;
grant execute on function public.admin_take_leaderboard_snapshot(text) to authenticated;

create or replace function public.admin_reset_leaderboard(p_label text, p_reason text)
returns void language plpgsql security definer set search_path = public as $$
declare sid uuid;
begin
  if not public.is_superadmin() then raise exception 'forbidden'; end if;
  if (p_reason is null or btrim(p_reason) = '') then raise exception 'reason_required'; end if;
  sid := public.admin_take_leaderboard_snapshot(p_label);
  update public.profiles set high_score = 0, updated_at = now();
  perform public.log_admin('leaderboard.reset', 'system', sid::text, p_reason, jsonb_build_object('label', p_label, 'snapshot_id', sid));
end $$;
revoke all on function public.admin_reset_leaderboard(text,text) from public, anon;
grant execute on function public.admin_reset_leaderboard(text,text) to authenticated;

-- ========== Admin RPCs: audit + admins + exports ==========
create or replace function public.admin_list_audit(
  p_actor uuid default null, p_action text default null, p_target_type text default null,
  p_from timestamptz default null, p_to timestamptz default null,
  p_limit int default 50, p_offset int default 0)
returns table (id bigint, actor_id uuid, actor_role text, action text, target_type text,
  target_id text, reason text, details jsonb, created_at timestamptz, total_count bigint)
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'forbidden'; end if;
  return query select a.id, a.actor_id, a.actor_role, a.action, a.target_type, a.target_id, a.reason,
    a.details, a.created_at, count(*) over()
  from public.audit_log a
  where (p_actor is null or a.actor_id = p_actor)
    and (p_action is null or a.action = p_action)
    and (p_target_type is null or a.target_type = p_target_type)
    and (p_from is null or a.created_at >= p_from)
    and (p_to is null or a.created_at <= p_to)
  order by a.created_at desc
  limit least(greatest(p_limit,1),200) offset greatest(p_offset,0);
end $$;
revoke all on function public.admin_list_audit(uuid,text,text,timestamptz,timestamptz,int,int) from public, anon;
grant execute on function public.admin_list_audit(uuid,text,text,timestamptz,timestamptz,int,int) to authenticated;

create or replace function public.admin_list_admins()
returns table (user_id uuid, email text, role text, granted_by uuid, created_at timestamptz)
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_superadmin() then raise exception 'forbidden'; end if;
  return query select r.user_id, u.email, r.role, r.granted_by, r.created_at
  from public.user_roles r join auth.users u on u.id = r.user_id order by r.created_at;
end $$;
revoke all on function public.admin_list_admins() from public, anon;
grant execute on function public.admin_list_admins() to authenticated;

create or replace function public.admin_set_role(p_user_id uuid, p_role text, p_reason text)
returns void language plpgsql security definer set search_path = public as $$
declare before text; n_super int;
begin
  if not public.is_superadmin() then raise exception 'forbidden'; end if;
  if p_role is not null and p_role not in ('admin','superadmin') then raise exception 'invalid_role'; end if;
  if (p_reason is null or btrim(p_reason) = '') then raise exception 'reason_required'; end if;
  select role into before from public.user_roles where user_id = p_user_id;
  -- Never self-demote, never remove the last superadmin.
  if p_user_id = auth.uid() and p_role is distinct from 'superadmin' and before = 'superadmin' then
    raise exception 'forbidden';
  end if;
  select count(*) into n_super from public.user_roles where role = 'superadmin';
  if before = 'superadmin' and p_role is distinct from 'superadmin' and n_super <= 1 then
    raise exception 'last_superadmin';
  end if;
  if p_role is null then
    delete from public.user_roles where user_id = p_user_id;
  else
    insert into public.user_roles(user_id, role, granted_by)
      values (p_user_id, p_role, auth.uid())
      on conflict (user_id) do update set role = excluded.role, granted_by = excluded.granted_by;
  end if;
  perform public.log_admin(case when before is null then 'role.grant' when p_role is null then 'role.revoke' else 'role.change' end,
    'user', p_user_id::text, p_reason, jsonb_build_object('before', before, 'after', p_role));
end $$;
revoke all on function public.admin_set_role(uuid,text,text) from public, anon;
grant execute on function public.admin_set_role(uuid,text,text) to authenticated;

create or replace function public.admin_export_users_csv() returns text
language plpgsql security definer set search_path = public as $$
declare out text;
begin
  if not public.is_superadmin() then raise exception 'forbidden'; end if;
  select 'id,email,display_name,user_level,high_score,total_xp,sessions_played,is_banned,hidden_from_leaderboard,created_at' || chr(10) ||
    coalesce(string_agg(
      '"' || p.id::text || '","' || replace(u.email,'"','""') || '","' || replace(p.display_name,'"','""') || '",' ||
      p.user_level || ',' || p.high_score || ',' || p.total_xp || ',' || p.sessions_played || ',' ||
      p.is_banned || ',' || p.hidden_from_leaderboard || ',"' || u.created_at::text || '"', chr(10)), '')
    into out
  from public.profiles p join auth.users u on u.id = p.id;
  perform public.log_admin('export.users', 'system', null, null, jsonb_build_object('rows', (select count(*) from public.profiles)));
  return out;
end $$;
revoke all on function public.admin_export_users_csv() from public, anon;
grant execute on function public.admin_export_users_csv() to authenticated;

create or replace function public.admin_export_sessions_csv(p_from timestamptz default null, p_to timestamptz default null)
returns text language plpgsql security definer set search_path = public as $$
declare out text;
begin
  if not public.is_superadmin() then raise exception 'forbidden'; end if;
  select 'id,user_id,score,duration_seconds,total_asked,total_correct,max_streak,is_flagged,is_voided,created_at' || chr(10) ||
    coalesce(string_agg(
      '"' || s.id::text || '","' || s.user_id::text || '",' || s.score || ',' || s.duration_seconds || ',' ||
      s.total_asked || ',' || s.total_correct || ',' || s.max_streak || ',' || s.is_flagged || ',' || s.is_voided ||
      ',"' || s.created_at::text || '"', chr(10) order by s.created_at), '')
    into out
  from public.game_sessions s
  where (p_from is null or s.created_at >= p_from) and (p_to is null or s.created_at <= p_to);
  perform public.log_admin('export.sessions', 'system', null, null, jsonb_build_object('from', p_from, 'to', p_to));
  return out;
end $$;
revoke all on function public.admin_export_sessions_csv(timestamptz,timestamptz) from public, anon;
grant execute on function public.admin_export_sessions_csv(timestamptz,timestamptz) to authenticated;

-- ========== 4.9 Bootstrap (owner runs separately with their own email) ==========
-- insert into public.user_roles(user_id, role)
-- select id, 'superadmin' from auth.users where email = 'OWNER_EMAIL_HERE'
-- on conflict (user_id) do update set role = 'superadmin';
-- Think Fast — admin patch 1 (run after admin_migration.sql)
-- Two RPCs the admin panel needs that were not in the first admin migration:
-- admin_list_snapshots (Leaderboard page) and admin_get_session (session detail).
-- Additive only: no drops, no deletes.

create or replace function public.admin_list_snapshots()
returns setof public.leaderboard_snapshots language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'forbidden'; end if;
  return query select * from public.leaderboard_snapshots order by taken_at desc limit 50;
end $$;
revoke all on function public.admin_list_snapshots() from public, anon;
grant execute on function public.admin_list_snapshots() to authenticated;

create or replace function public.admin_get_session(p_session_id uuid)
returns public.game_sessions language plpgsql security definer set search_path = public as $$
declare s public.game_sessions;
begin
  if not public.is_admin() then raise exception 'forbidden'; end if;
  select * into s from public.game_sessions where id = p_session_id;
  if s is null then raise exception 'not_found'; end if;
  return s;
end $$;
revoke all on function public.admin_get_session(uuid) from public, anon;
grant execute on function public.admin_get_session(uuid) to authenticated;
