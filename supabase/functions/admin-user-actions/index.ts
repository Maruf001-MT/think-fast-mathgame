// Think Fast — Edge Function: admin-user-actions (ADMIN_PANEL_SPEC.md section 5)
// Auth admin APIs need service_role, so they live ONLY here. The service-role
// key is never in HTML/JS, never in git, never in chat. It is set as a
// function secret (SUPABASE_SERVICE_ROLE_KEY) in the Supabase dashboard.
// Every request: verify the caller's JWT + role via rpc('is_admin') /
// rpc('is_superadmin') first. Never trust a role sent in the request body.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const ALLOWED_ORIGINS = new Set([
  "https://incandescent-bonbon-a1a880.netlify.app",
  "http://localhost:3000",
  "http://127.0.0.1:5500",
]);

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY") ?? "";
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function corsHeaders(origin: string | null): Record<string, string> {
  const o = origin && ALLOWED_ORIGINS.has(origin) ? origin : "";
  return {
    "Access-Control-Allow-Origin": o,
    "Access-Control-Allow-Headers": "authorization, content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Content-Type": "application/json",
  };
}

function json(body: unknown, status: number, origin: string | null) {
  return new Response(JSON.stringify(body), { status, headers: corsHeaders(origin) });
}

Deno.serve(async (req: Request) => {
  const origin = req.headers.get("Origin");
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders(origin) });
  }
  if (req.method !== "POST") return json({ ok: false, error: "method_not_allowed" }, 405, origin);

  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return json({ ok: false, error: "invalid_json" }, 400, origin);
  }
  const action = String(body.action ?? "");
  const targetId = String(body.user_id ?? "");
  const email = String(body.email ?? "");

  // Role required per action (spec section 5).
  const needSuper = action === "delete_user" || action === "send_password_reset" || action === "force_signout";
  const known = ["ban_auth", "unban_auth", "delete_user", "send_password_reset", "force_signout"];
  if (!known.includes(action)) return json({ ok: false, error: "unknown_action" }, 400, origin);
  if (action !== "send_password_reset" && !UUID_RE.test(targetId)) {
    return json({ ok: false, error: "invalid_user_id" }, 400, origin);
  }
  if (action === "send_password_reset" && !EMAIL_RE.test(email)) {
    return json({ ok: false, error: "invalid_email" }, 400, origin);
  }

  // 1. Verify caller from their JWT (never trust the body).
  const authHeader = req.headers.get("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) return json({ ok: false, error: "unauthorized" }, 401, origin);
  const caller = createClient(SUPABASE_URL, ANON_KEY, {
    global: { headers: { Authorization: authHeader } },
  });
  const { data: userData, error: userErr } = await caller.auth.getUser();
  if (userErr || !userData?.user) return json({ ok: false, error: "unauthorized" }, 401, origin);
  const actorId = userData.user.id;
  const { data: isAdmin } = await caller.rpc("is_admin");
  const { data: isSuper } = await caller.rpc("is_superadmin");
  if (!isAdmin) return json({ ok: false, error: "forbidden" }, 403, origin);
  if (needSuper && !isSuper) return json({ ok: false, error: "forbidden" }, 403, origin);

  // 2. Service-role client (secret only, from function env).
  if (!SERVICE_KEY) return json({ ok: false, error: "service_not_configured" }, 500, origin);
  const admin = createClient(SUPABASE_URL, SERVICE_KEY, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  // Guards that need the target's role (service client bypasses RLS for reads).
  let targetRole: string | null = null;
  if (targetId) {
    const { data } = await admin.from("user_roles").select("role").eq("user_id", targetId).maybeSingle();
    targetRole = (data as { role?: string } | null)?.role ?? null;
  }
  if (action === "delete_user") {
    if (targetId === actorId) return json({ ok: false, error: "cannot_delete_self" }, 403, origin);
    if (targetRole === "superadmin") return json({ ok: false, error: "cannot_delete_superadmin" }, 403, origin);
  }

  // 3. Execute, then audit (service client, verified actor id).
  const audit = async (a: string, t: string | null, reason: string | null, details: unknown) => {
    await admin.from("audit_log").insert({
      actor_id: actorId,
      actor_role: isSuper ? "superadmin" : "admin",
      action: a,
      target_type: "user",
      target_id: t,
      reason,
      details: details ?? {},
    });
  };

  try {
    if (action === "ban_auth") {
      const { error } = await admin.auth.admin.updateUserById(targetId, { ban_duration: "876000h" });
      if (error) throw error;
      await audit("user.ban", targetId, null, { via: "auth" });
    } else if (action === "unban_auth") {
      const { error } = await admin.auth.admin.updateUserById(targetId, { ban_duration: "none" });
      if (error) throw error;
      await audit("user.unban", targetId, null, { via: "auth" });
    } else if (action === "delete_user") {
      const { error } = await admin.auth.admin.deleteUser(targetId);
      if (error) throw error;
      // Audit row for a deleted user would violate the actor/target FK if it
      // referenced the deleted user, so only the actor is recorded here and
      // the RPC-side audit (admin panel) carries the target details.
      await audit("user.delete", null, null, { deleted_user_id: targetId });
    } else if (action === "send_password_reset") {
      const { error } = await admin.auth.resetPasswordForEmail(email, {
        redirectTo: "https://incandescent-bonbon-a1a880.netlify.app",
      });
      if (error) throw error;
      await audit("user.password_reset", email, null, {});
    } else if (action === "force_signout") {
      const jwt = String(body.jwt ?? "");
      if (!jwt) {
        return json({ ok: false, error: "force_signout needs the target session JWT; otherwise rely on short JWT expiry" }, 400, origin);
      }
      const { error } = await admin.auth.admin.signOut(jwt);
      if (error) throw error;
      await audit("user.signout", targetId, null, {});
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return json({ ok: false, error: msg }, 400, origin);
  }
  return json({ ok: true }, 200, origin);
});
