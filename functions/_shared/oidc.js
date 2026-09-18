// functions/_shared/oidc.js
// Validação do id_token do Google usando apenas Web Crypto e fetch.
// Sem bibliotecas externas: JWT é decodificado, e a assinatura é verificada
// contra a chave pública (JWKS) apontada pelo documento de descoberta OIDC.

import { base64UrlDecode } from "./crypto.js";

let discoveryCache = null;
let jwksCache = null;
let jwksCacheAt = 0;
const JWKS_CACHE_MS = 10 * 60 * 1000;

async function getDiscovery(discoveryUrl) {
  if (discoveryCache) return discoveryCache;
  const res = await fetch(discoveryUrl);
  if (!res.ok) throw new Error("discovery_failed");
  discoveryCache = await res.json();
  return discoveryCache;
}

async function getJwks(jwksUri) {
  const now = Date.now();
  if (jwksCache && now - jwksCacheAt < JWKS_CACHE_MS) return jwksCache;
  const res = await fetch(jwksUri);
  if (!res.ok) throw new Error("jwks_failed");
  jwksCache = await res.json();
  jwksCacheAt = now;
  return jwksCache;
}

function decodeJwtSegment(segment) {
  const bytes = base64UrlDecode(segment);
  const text = new TextDecoder().decode(bytes);
  return JSON.parse(text);
}

export async function verifyGoogleIdToken(idToken, { clientId, expectedNonce, discoveryUrl, issuer }) {
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("invalid_jwt_format");
  const [headerB64, payloadB64, signatureB64] = parts;

  const header = decodeJwtSegment(headerB64);
  const payload = decodeJwtSegment(payloadB64);

  if (header.alg !== "RS256") throw new Error("invalid_alg");

  const discovery = await getDiscovery(discoveryUrl);
  const jwks = await getJwks(discovery.jwks_uri);

  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error("key_not_found");

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const signedData = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = base64UrlDecode(signatureB64);

  const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", publicKey, signature, signedData);
  if (!valid) throw new Error("invalid_signature");

  const now = Math.floor(Date.now() / 1000);
  const expectedIssuer = discovery.issuer || issuer;

  if (payload.iss !== expectedIssuer) throw new Error("invalid_issuer");
  if (payload.aud !== clientId) throw new Error("invalid_audience");
  if (!payload.exp || payload.exp < now) throw new Error("token_expired");
  if (!payload.iat || payload.iat > now + 60) throw new Error("invalid_iat");
  if (payload.nonce !== expectedNonce) throw new Error("invalid_nonce");

  return payload;
}
