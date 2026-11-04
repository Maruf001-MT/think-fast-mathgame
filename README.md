# Think Fast

Mental-math arcade game. Single-file frontend (index.html), backend on Supabase (project think-fast).

Live site: https://incandescent-bonbon-a1a880.netlify.app

## How it works

- Guest mode works without an account: stats stay in localStorage on the device and are never merged into an account.
- Signed-in users: profiles and sessions live in Supabase. The browser never writes score, XP, or level directly — every finished session goes through the `submit_session` RPC, which validates plausibility (duration, counts, streak, speed, score cap, 10-second rate limit) and updates the profile server-side.
- Leaderboard comes from the `get_leaderboard` RPC (public-safe columns only, no email); your rank comes from `get_my_rank`.
- All Supabase calls live in one class, `BackendService`, in index.html above `ThinkFastApp`. Game/UI code never calls Supabase directly.

## Database

`supabase/migration.sql` (spec section 3) creates, in order:

- `public.profiles` and `public.game_sessions` (no email column in public data)
- `level_from_xp()` and the `handle_new_user()` signup trigger on `auth.users`
- RLS: profiles select-own, update of `display_name`/`avatar_url` only; game_sessions select-own, no direct insert/update/delete
- RPCs: `submit_session`, `get_leaderboard`, `get_my_rank`

The migration was run on project think-fast and verified: 2 tables, 5 routines, 3 policies, 1 trigger (`on_auth_user_created` on `auth.users`).

## Setup (already done for this deployment)

- Supabase project: think-fast, https://stxirtoytwhtfzursxru.supabase.co, org Maruf001-MT's Org (FREE), region Southeast Asia (Singapore)
- Email auth enabled with Confirm email ON
- Supabase URL Configuration: Site URL https://incandescent-bonbon-a1a880.netlify.app, Redirect URLs that URL plus http://localhost:3000 and http://127.0.0.1:5500
- Netlify: GitHub repo Maruf001-MT/think-fast-mathgame, branch main, build command empty, publish directory "."

## Remaining manual step

- Google OAuth is NOT set up yet. It needs the owner's own Google Cloud OAuth Client ID + Secret. Authorized redirect URI for Google Cloud: `https://stxirtoytwhtfzursxru.supabase.co/auth/v1/callback`. The "Continue with Google" button is in the auth modal and will show an error until Google is configured; Email signup/login already works.

## Known limitation

Questions are generated and answered in the browser, so a determined cheater can still fake plausible numbers within the caps. The caps in `submit_session` only stop obvious cheating. A stronger design (future): server-issued session token + seeded question generation + answer log verification via a Supabase Edge Function. Not required for v1.
