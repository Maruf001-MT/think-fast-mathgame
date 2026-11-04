-- Think Fast — Supabase migration (spec section 3, run as one SQL migration)
-- Project: think-fast (https://stxirtoytwhtfzursxru.supabase.co)
-- Run in Supabase SQL Editor. Creates profiles + game_sessions, trigger,
-- level function, RLS, and RPCs submit_session / get_leaderboard / get_my_rank.
-- No email column in public data. Browser never writes score/XP/level directly.

-- ========== TABLES ==========
create table if not exists public.profiles (
  id               uuid primary key references auth.users(id) on delete cascade,
  display_name     text not null default 'Operator',
  avatar_url       text,
  high_score       integer not null default 0,
  total_math_solved integer not null default 0,
  total_xp         bigint  not null default 0,
  user_level       integer not null default 1,
  sessions_played  integer not null default 0,
  last_submit_at   timestamptz,
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now()
);
-- NOTE: no email column here. Email lives in auth.users only.

create table if not exists public.game_sessions (
  id               uuid primary key default gen_random_uuid(),
  user_id          uuid not null references auth.users(id) on delete cascade,
  score            integer not null,
  duration_seconds integer not null,
  total_asked      integer not null,
  total_correct    integer not null,
  max_streak       integer not null,
  operator_stats   jsonb   not null default '{}'::jsonb,
  config           jsonb   not null default '{}'::jsonb,
  created_at       timestamptz not null default now()
);
create index if not exists idx_sessions_user_time on public.game_sessions(user_id, created_at desc);
create index if not exists idx_profiles_high_score on public.profiles(high_score desc);

-- ========== LEVEL FUNCTION (mirror of frontend getLevelFromXp) ==========
create or replace function public.level_from_xp(xp bigint) returns integer
language plpgsql immutable as $$
declare lvl int := 2; req bigint := 500000;
begin
  if xp is null or xp < 100000 then return 1; end if;
  while xp >= req loop lvl := lvl + 1; req := req * 5; end loop;
  return lvl;
end $$;

-- ========== AUTO-CREATE PROFILE ON SIGNUP ==========
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, display_name, avatar_url)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'full_name',
             new.raw_user_meta_data->>'name',
             split_part(new.email, '@', 1), 'Operator'),
    coalesce(new.raw_user_meta_data->>'avatar_url',
             new.raw_user_meta_data->>'picture')
  ) on conflict (id) do nothing;
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- ========== RLS ==========
alter table public.profiles      enable row level security;
alter table public.game_sessions enable row level security;

-- profiles: owner can read own row; nobody reads others directly (leaderboard goes through RPC)
create policy "profiles_select_own" on public.profiles
  for select using (auth.uid() = id);

-- owner may update ONLY display_name / avatar_url (column-level grant below)
create policy "profiles_update_own" on public.profiles
  for update using (auth.uid() = id) with check (auth.uid() = id);

revoke insert, update, delete on public.profiles from anon, authenticated;
grant  update (display_name, avatar_url) on public.profiles to authenticated;

-- game_sessions: owner can read own history; NO direct insert/update/delete
create policy "sessions_select_own" on public.game_sessions
  for select using (auth.uid() = user_id);
revoke insert, update, delete on public.game_sessions from anon, authenticated;

-- ========== RPC: submit_session ==========
create or replace function public.submit_session(
  p_score int, p_duration int, p_asked int, p_correct int, p_max_streak int,
  p_operator_stats jsonb, p_config jsonb
) returns public.profiles
language plpgsql security definer set search_path = public as $$
declare
  uid uuid := auth.uid();
  prof public.profiles;
  new_xp bigint;
begin
  if uid is null then raise exception 'not_authenticated'; end if;

  -- plausibility checks (cheap anti-cheat)
  if p_duration < 10 or p_duration > 10800 then raise exception 'bad_duration'; end if;
  if p_asked < 0 or p_correct < 0 or p_correct > p_asked then raise exception 'bad_counts'; end if;
  if p_max_streak < 0 or p_max_streak > p_correct then raise exception 'bad_streak'; end if;
  if p_asked > (p_duration / 0.25) then raise exception 'too_fast'; end if;      -- >4 answers/sec
  if p_score < 0 or p_score > p_correct * 4200 then raise exception 'score_too_high'; end if;
  -- max per answer ≈ 780 weight * x5 combo + 120 speed bonus ≈ 4020 (4200 = safety margin)

  select * into prof from public.profiles where id = uid for update;
  if prof.last_submit_at is not null
     and prof.last_submit_at > now() - interval '10 seconds' then
    raise exception 'rate_limited';
  end if;

  insert into public.game_sessions
    (user_id, score, duration_seconds, total_asked, total_correct, max_streak, operator_stats, config)
  values (uid, p_score, p_duration, p_asked, p_correct, p_max_streak,
          coalesce(p_operator_stats,'{}'), coalesce(p_config,'{}'));

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

-- ========== RPC: leaderboard (public-safe columns only) ==========
create or replace function public.get_leaderboard(p_limit int default 10)
returns table (rank bigint, user_id uuid, display_name text, avatar_url text,
               user_level int, high_score int)
language sql security definer set search_path = public stable as $$
  select row_number() over (order by high_score desc, updated_at asc) as rank,
         id, display_name, avatar_url, user_level, high_score
  from public.profiles
  where high_score > 0
  order by high_score desc, updated_at asc
  limit least(greatest(p_limit,1), 100);
$$;
grant execute on function public.get_leaderboard to anon, authenticated;

-- ========== RPC: my rank ==========
create or replace function public.get_my_rank() returns bigint
language sql security definer set search_path = public stable as $$
  select count(*) + 1 from public.profiles
  where high_score > (select high_score from public.profiles where id = auth.uid());
$$;
grant execute on function public.get_my_rank to authenticated;
