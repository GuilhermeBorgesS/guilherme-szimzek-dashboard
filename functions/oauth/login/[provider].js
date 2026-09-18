// functions/oauth/login/[provider].js
// Inicia o fluxo OAuth/OIDC: cria a transação com PKCE, grava o resumo no D1,
// seta o cookie temporário e redireciona (302) ao provedor.

import { randomToken, sha256Base64Url } from "../../_shared/crypto.js";
import { isValidProvider, PROVIDERS } from "../../_shared/providers.js";
import { setTxCookie } from "../../_shared/cookies.js";

export async function onRequestGet(context) {
  const { params, env } = context;
  const provider = params.provider;

  if (!isValidProvider(provider)) {
    return new Response("Not found", { status: 404 });
  }

  const cfg = PROVIDERS[provider];

  const txId = randomToken();
  const state = randomToken();
  const codeVerifier = randomToken();
  const codeChallenge = await sha256Base64Url(codeVerifier);
  const nonce = provider === "google" ? randomToken() : null;

  const idHash = await sha256Base64Url(txId);
  const stateHash = await sha256Base64Url(state);
  const expiresAt = Math.floor(Date.now() / 1000) + 600;

  await env.DB.prepare(
    `INSERT INTO oauth_transactions (id_hash, provider, state_hash, nonce, code_verifier, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  )
    .bind(idHash, provider, stateHash, nonce, codeVerifier, expiresAt)
    .run();

  const redirectUri = `${env.PUBLIC_BASE_URL}/oauth/callback/${provider}`;
  const clientId = provider === "google" ? env.GOOGLE_CLIENT_ID : env.GITHUB_CLIENT_ID;

  const authUrl = new URL(cfg.authorizeUrl);
  authUrl.searchParams.set("client_id", clientId);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  if (provider === "google") {
    authUrl.searchParams.set("scope", cfg.scope);
    authUrl.searchParams.set("nonce", nonce);
  }
  // No GitHub: scope e nonce são propositalmente omitidos.

  return new Response(null, {
    status: 302,
    headers: {
      Location: authUrl.toString(),
      "Set-Cookie": setTxCookie(txId),
      "Cache-Control": "no-store",
    },
  });
}
