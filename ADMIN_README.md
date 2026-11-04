# Think Fast — Super Admin Panel

Admin URL: **https://incandescent-bonbon-a1a880.netlify.app/admin.html**
(also reachable at `/admin`). The page is `noindex,nofollow` and framed pages are
denied. All protection is server-side: every admin RPC starts with a role
check, and hiding buttons in the UI is not security.

## How to log in

1. Open `/admin.html` and sign in with an admin account (email/password or Google).
2. Non-admins see "Access denied" and no panel data.
3. The first superadmin is `me.marufzisan@gmail.com` (bootstrapped via SQL).
4. MFA: the panel nags admins without a verified TOTP factor and offers
   enroll + verify in the banner. Superadmin writes are additionally gated by
   the role check on every RPC; if MFA is enrolled, sign in through the
   normal Supabase MFA flow for the account.
5. Idle auto-logout: 30 minutes of no activity signs the panel out.

## How to add admins

- Superadmin only, in the panel: **Admins** page → enter the user's email
  (the user must already have signed up to the game), pick `admin` or
  `superadmin`, give a reason, Grant.
- Guards (server-side): you cannot demote yourself, cannot delete yourself,
  and the system always keeps at least 1 superadmin.
- Roles live in `user_roles`; clients cannot write that table.

## What admins can do

| Action | admin | superadmin |
|---|---|---|
| View dashboard, users, sessions, audit log | yes | yes |
| Ban / unban user, hide from leaderboard | yes | yes |
| Flag / unflag / void a session | yes | yes |
| Edit display name, adjust XP/score/stats, reset user stats | no | yes |
| Delete user, send password reset, force sign-out | no | yes |
| Edit game config, maintenance mode, anti-cheat thresholds | no | yes |
| Create / edit announcements | yes | yes |
| Reset leaderboard / season, data export | no | yes |
| Grant / revoke roles | no | yes |

Ban is two steps in the panel: the profile ban (RPC) plus the auth ban
(Edge Function), so a banned user cannot sign in and `submit_session`
returns `banned`. Unban reverses both.

## Game behaviour driven by the panel (remote config)

- **Maintenance on**: players see a full-screen overlay and cannot start a
  game; admins see a badge instead and can still play.
- **Announcements**: banner under the header, dismissible per session.
- **Scoring / timing**: wrong penalty, speed-bonus window/factor, combo
  tiers, time presets and max custom minutes come from config; built-in
  defaults (50 / 3.0s / 40 / 5→x2, 10→x3, 15→x5 / 3,5,10,30 / 180) apply
  if config fails to load, so the game never breaks.
- **Signups / auth methods / guest play**: the related buttons are hidden
  or disabled; with guest play off, login is required before starting.
- **Leaderboard**: hidden when disabled; size comes from config.
- **Safe-minimum rule**: the Config page shows the safe minimum for
  `max_points_per_correct` = 780 × highest combo multiplier + speed bonus
  factor, and `admin_set_config` returns a warning if the cap is below it.

## Audit trail

Every admin write writes a row to `audit_log` (append-only; no update or
delete for anyone, including superadmin). The Audit page filters by actor,
action and target type and expands before/after JSON. Export actions are
audited too. CSV exports contain emails but never password data (there is
none in the database).

## Edge Function

`supabase/functions/admin-user-actions/index.ts` handles auth-level actions
(ban/unban, delete user, password reset, force sign-out) because those need
the auth admin API. Its secret `SUPABASE_SERVICE_ROLE_KEY` is a **reserved
default secret** in Supabase Edge Functions — the dashboard refuses a custom
secret with that name, and none is needed: the function reads it from its
environment. The key value is never in code, git, chat, or the panel.

## Known limits

- **Force sign-out** only works when the target session's JWT is available
  to the function; otherwise rely on short JWT expiry (documented in the
  function code and spec section 5).
- **Season reset** sets every `high_score` to 0 after snapshotting the top
  100, but does not delete sessions — recomputing a profile from its
  sessions would restore its high_score.
- **Auto-flagged sessions** are stored but contribute nothing to the
  profile until an admin unflags them (then the profile is recomputed).
- **Email**: password-reset emails go through Supabase's built-in sender
  and are subject to its hourly project-wide rate limit; custom SMTP is
  still the durable production fix (not set up yet).
- **Google sign-in** for the game is not configured yet (needs the owner's
  Google Cloud OAuth Client ID/Secret); the admin Google button will fail
  until then, same as the game's.
- **Session detail** needs `admin_get_session` and **snapshots list** needs
  `admin_list_snapshots` — both are in `supabase/admin_migration.sql`
  (patch 1, appended at the end) and were run after the first migration.
- **Patch 2 (2026-11-04, after the panel retest):** `admin_list_users`
  now casts every column to its declared type and qualifies the sort
  column — the first version returned "structure of query does not match
  function result type" on every Users load. All FKs from public tables
  to `auth.users` that lacked an `ON DELETE` action (roles `granted_by`,
  audit `actor_id`, config `updated_by`, announcements `created_by`,
  snapshots `taken_by`) are now `ON DELETE SET NULL`, so deleting an
  admin user no longer fails with "Database error deleting user". Audit
  rows are kept when their actor is deleted; only `actor_id` becomes
  NULL (audit content is never deleted by a user delete).

## Files

- `supabase/admin_migration.sql` — roles, audit, config, announcements,
  snapshots, admin RPCs, updated player RPCs.
- `supabase/functions/admin-user-actions/index.ts` — Edge Function (deployed
  via the Supabase dashboard; URL `/functions/v1/admin-user-actions`).
- `admin.html` — the panel (same neon design system as the game).
- `index.html` — game now obeys remote config, maintenance, announcements,
  bans; game logic and visuals otherwise unchanged.
- `netlify.toml` — admin headers (DENY framing, strict CSP) + `/admin`
  redirect to `/admin.html`.
