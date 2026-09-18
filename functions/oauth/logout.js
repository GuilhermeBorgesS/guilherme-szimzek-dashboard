// functions/oauth/logout.js
// Revoga somente a sessão local. Não encerra a sessão global no Google/GitHub.

import { sha256Base64Url } from "../_shared/crypto.js";
import { parseCookies, clearSessionCookie } from "../_shared/cookies.js";

export async function onRequestPost(context) {
  const { request, env } = context;

  // 2. exigir Origin exatamente igual a PUBLIC_BASE_URL
  const origin = request.headers.get("Origin");
  if (origin !== env.PUBLIC_BASE_URL) {
    return new Response("Origem inválida", {
      status: 403,
      headers: { "Cache-Control": "no-store" },
    });
  }

  const cookies = parseCookies(request);
  const sessionId = cookies["__Host-session"];

  if (sessionId) {
    const sessionHash = await sha256Base64Url(sessionId);
    // 3. remover a linha da sessão no D1
    await env.DB.prepare(`DELETE FROM sessions WHERE id_hash = ?`).bind(sessionHash).run();
  }

  // 4-5. expirar o cookie e responder sem cache
  return new Response(null, {
    status: 204,
    headers: {
      "Cache-Control": "no-store",
      "Set-Cookie": clearSessionCookie(),
    },
  });
}

// Qualquer outro método não é permitido nesta rota.
export async function onRequestGet() {
  return new Response("Method Not Allowed", { status: 405 });
}
