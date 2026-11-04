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
