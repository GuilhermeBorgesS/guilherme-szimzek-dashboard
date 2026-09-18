// functions/api/me.js
// Resolve a sessão local a partir do cookie __Host-session e devolve
// apenas o perfil mínimo. Nunca devolve tokens nem identificadores brutos.

import { sha256Base64Url } from "../_shared/crypto.js";
import { parseCookies } from "../_shared/cookies.js";

export async function onRequestGet(context) {
  const { request, env } = context;

  const cookies = parseCookies(request);
  const sessionId = cookies["__Host-session"];

  if (!sessionId) {
    return new Response("Unauthorized", {
      status: 401,
      headers: { "Cache-Control": "no-store" },
    });
  }

  const sessionHash = await sha256Base64Url(sessionId);
  const now = Math.floor(Date.now() / 1000);

  const row = await context.env.DB.prepare(
    `SELECT issuer, subject, email, display_name, expires_at
     FROM sessions WHERE id_hash = ?`
  )
    .bind(sessionHash)
    .first();

  if (!row || row.expires_at <= now) {
    return new Response("Unauthorized", {
      status: 401,
      headers: { "Cache-Control": "no-store" },
    });
  }

  return Response.json(
    {
      issuer: row.issuer,
      email: row.email,
      displayName: row.display_name,
    },
    { headers: { "Cache-Control": "no-store" } }
  );
}
