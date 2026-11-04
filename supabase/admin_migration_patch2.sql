-- ============================================================
-- Think Fast — admin migration PATCH 2 (2026-11-04)
-- Fixes found by the 2026-11-04 panel retest (commit 9ade68e):
--  1) admin_list_users returned "structure of query does not match
--     function result type" on every Users page load, which blocked
--     Users listing, panel ban/unban, panel user delete, and the
--     Users CSV export button. Fix: cast every selected column to
--     the declared output type explicitly, and qualify the ORDER BY
--     column (created_at exists on both profiles and auth.users).
--  2) Deleting an admin auth user failed with "Database error
--     deleting user" because four public FKs to auth.users had no
--     ON DELETE action: user_roles.granted_by, audit_log.actor_id,
--     app_config.updated_by, announcements.created_by,
--     leaderboard_snapshots.taken_by. Fix: re-create them all as
--     ON DELETE SET NULL. Audit rows are KEPT (append-only is
--     preserved); only the actor reference is anonymised to NULL
--     when that user is deleted. audit_log.actor_id becomes
--     nullable for the same reason.
-- This patch is idempotent and changes no config values, no roles,
-- and deletes no users or audit rows.
-- ============================================================

-- ---------- 1) admin_list_users: explicit casts + qualified sort ----------
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
  -- Whitelisted, fully qualified sort targets only (never raw user input).
  sort_col := case p_sort when 'high_score' then 'p.high_score' when 'total_xp' then 'p.total_xp'
    when 'display_name' then 'p.display_name' when 'sessions_played' then 'p.sessions_played'
    else 'u.created_at' end;
  dir := case when lower(coalesce(p_dir,'desc')) = 'asc' then 'asc' else 'desc' end;
  return query execute format(
    'select p.id::uuid, u.email::text, p.display_name::text, p.user_level::int, p.high_score::int,
       p.total_xp::bigint, p.sessions_played::int, p.is_banned::boolean, p.hidden_from_leaderboard::boolean,
       r.role::text, u.created_at::timestamptz, u.last_sign_in_at::timestamptz,
       (count(*) over())::bigint from public.profiles p
     join auth.users u on u.id = p.id
     left join public.user_roles r on r.user_id = p.id
     where ($1 is null or $1 = '''' or u.email ilike ''%%'' || $1 || ''%%'' or p.display_name ilike ''%%'' || $1 || ''%%'')
       and ($2 = ''all'' or ($2 = ''banned'' and p.is_banned)
            or ($2 = ''flagged'' and exists (select 1 from public.game_sessions s where s.user_id = p.id and s.is_flagged and not s.is_voided))
            or ($2 = ''admins'' and r.role is not null))
     order by %s %s limit $3 offset $4',
    sort_col, dir)
  using p_search, p_status, least(greatest(p_limit,1),200), greatest(p_offset,0);
end $$;
revoke all on function public.admin_list_users(text,text,text,text,int,int) from public, anon;
grant execute on function public.admin_list_users(text,text,text,text,int,int) to authenticated;

-- ---------- 2) FKs to auth.users: ON DELETE SET NULL ----------
alter table public.user_roles
  drop constraint if exists user_roles_granted_by_fkey,
  add constraint user_roles_granted_by_fkey
    foreign key (granted_by) references auth.users(id) on delete set null;

alter table public.audit_log
  alter column actor_id drop not null,
  drop constraint if exists audit_log_actor_id_fkey,
  add constraint audit_log_actor_id_fkey
    foreign key (actor_id) references auth.users(id) on delete set null;

alter table public.app_config
  drop constraint if exists app_config_updated_by_fkey,
  add constraint app_config_updated_by_fkey
    foreign key (updated_by) references auth.users(id) on delete set null;

alter table public.announcements
  drop constraint if exists announcements_created_by_fkey,
  add constraint announcements_created_by_fkey
    foreign key (created_by) references auth.users(id) on delete set null;

alter table public.leaderboard_snapshots
  drop constraint if exists leaderboard_snapshots_taken_by_fkey,
  add constraint leaderboard_snapshots_taken_by_fkey
    foreign key (taken_by) references auth.users(id) on delete set null;
