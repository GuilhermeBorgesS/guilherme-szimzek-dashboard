// functions/oauth/callback/[provider].js
// Processa a resposta do provedor: valida a transação (cookie + state),
// troca o código por token, confirma a identidade e cria a sessão local.

import { randomToken, sha256Base64Url } from "../../_shared/crypto.js";
import { isValidProvider, PROVIDERS } from "../../_shared/providers.js";
import { parseCookies, clearTxCookie, setSessionCookie } from "../../_shared/cookies.js";
import { verifyGoogleIdToken } from "../../_shared/oidc.js";

function noStoreHeaders(extra = {}) {
  const headers = new Headers(extra);
  headers.set("Cache-Control", "no-store");
  return headers;
}

export async function onRequestGet(context) {
  const { request, params, env } = context;
  const provider = params.provider;

  if (!isValidProvider(provider)) {
    return new Response("Not found", { status: 404 });
  }

  const url = new URL(request.url);
  const error = url.searchParams.get("error");
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  // 1. recusar error ou ausência de code/state
  if (error || !code || !state) {
    return new Response("Falha na autenticação", {
      status: 400,
      headers: noStoreHeaders(),
    });
  }

  // 2. exigir o cookie de transação
  const cookies = parseCookies(request);
  const txId = cookies["__Host-oauth-tx"];
  if (!txId) {
    return new Response("Transação ausente", {
      status: 400,
      headers: noStoreHeaders(),
    });
  }

  // 3. localizar transação não expirada pelo resumo do cookie
  const idHash = await sha256Base64Url(txId);
  const stateHash = await sha256Base64Url(state);
  const now = Math.floor(Date.now() / 1000);

  const row = await env.DB.prepare(
    `SELECT * FROM oauth_transactions WHERE id_hash = ? AND provider = ? AND expires_at > ?`
  )
    .bind(idHash, provider, now)
    .first();

  // 4. comparar o resumo de state
  if (!row || row.state_hash !== stateHash) {
    const headers = noStoreHeaders();
    headers.append("Set-Cookie", clearTxCookie());
    return new Response("Transação inválida", { status: 400, headers });
  }

  // 5. apagar a transação antes de concluir o fluxo (evita reuso)
  await env.DB.prepare(`DELETE FROM oauth_transactions WHERE id_hash = ?`).bind(idHash).run();

  const cfg = PROVIDERS[provider];
  const redirectUri = `${env.PUBLIC_BASE_URL}/oauth/callback/${provider}`;
  const clientId = provider === "google" ? env.GOOGLE_CLIENT_ID : env.GITHUB_CLIENT_ID;
  const clientSecret = provider === "google" ? env.GOOGLE_CLIENT_SECRET : env.GITHUB_CLIENT_SECRET;

  let identity;

  try {
    if (provider === "google") {
      // 6. trocar o código com code_verifier e Client Secret
      const tokenRes = await fetch(cfg.tokenUrl, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: clientId,
          client_secret: clientSecret,
          code,
          code_verifier: row.code_verifier,
          redirect_uri: redirectUri,
          grant_type: "authorization_code",
        }),
      });
      if (!tokenRes.ok) throw new Error("token_exchange_failed");
      const tokenData = await tokenRes.json();
      if (!tokenData.id_token) throw new Error("missing_id_token");

      // 7. validar a resposta de identidade (JWT/JWKS)
      const payload = await verifyGoogleIdToken(tokenData.id_token, {
        clientId,
        expectedNonce: row.nonce,
        discoveryUrl: cfg.discoveryUrl,
        issuer: cfg.issuer,
      });

      identity = {
        issuer: "https://accounts.google.com",
        subject: payload.sub,
        email: payload.email || null,
        displayName: payload.name || payload.email || "Usuário Google",
      };
    } else {
      // GitHub: troca do código por access_token
      const tokenRes = await fetch(cfg.tokenUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "application/json",
        },
        body: new URLSearchParams({
          client_id: clientId,
          client_secret: clientSecret,
          code,
          redirect_uri: redirectUri,
          code_verifier: row.code_verifier,
        }),
      });
      if (!tokenRes.ok) throw new Error("token_exchange_failed");
      const tokenData = await tokenRes.json();
      if (!tokenData.access_token || !/^bearer$/i.test(tokenData.token_type || "")) {
        throw new Error("invalid_token_response");
      }

      // 9-10. consultar o perfil autenticado
      const userRes = await fetch(cfg.userUrl, {
        headers: {
          Authorization: `Bearer ${tokenData.access_token}`,
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2026-03-10",
          "User-Agent": "oauth-pages-lab",
        },
      });
      if (userRes.status !== 200) throw new Error("github_user_failed");
      const userData = await userRes.json();
      if (!Number.isInteger(userData.id)) throw new Error("invalid_github_id");

      // revogar a autorização concedida à OAuth App
      const revokeRes = await fetch(cfg.grantUrl(clientId), {
        method: "DELETE",
        headers: {
          Authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2026-03-10",
          "Content-Type": "application/json",
          "User-Agent": "oauth-pages-lab",
        },
        body: JSON.stringify({ access_token: tokenData.access_token }),
      });
      if (revokeRes.status !== 204) throw new Error("github_revoke_failed");

      identity = {
        issuer: "https://github.com",
        subject: String(userData.id),
        email: userData.email || null,
        displayName: userData.name || userData.login || "Usuário GitHub",
      };
    }
  } catch (e) {
    const headers = noStoreHeaders();
    headers.append("Set-Cookie", clearTxCookie());
    return new Response("Falha na confirmação de identidade", { status: 400, headers });
  }

  // 8. criar sessão opaca somente após identidade confirmada
  const sessionId = randomToken();
  const sessionHash = await sha256Base64Url(sessionId);
  const sessionExpiresAt = now + 28800; // 8 horas

  await env.DB.prepare(
    `INSERT INTO sessions (id_hash, issuer, subject, email, display_name, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      sessionHash,
      identity.issuer,
      identity.subject,
      identity.email,
      identity.displayName,
      sessionExpiresAt,
      now
    )
    .run();

  // 9-10. limpar cookie temporário e redirecionar para a URL base
  const headers = noStoreHeaders({ Location: env.PUBLIC_BASE_URL });
  headers.append("Set-Cookie", clearTxCookie());
  headers.append("Set-Cookie", setSessionCookie(sessionId));

  return new Response(null, { status: 302, headers });
}
