// functions/_shared/providers.js
// Dados fixos de cada provedor. Nenhum segredo aqui.

export const PROVIDERS = {
  google: {
    authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    discoveryUrl: "https://accounts.google.com/.well-known/openid-configuration",
    issuer: "https://accounts.google.com",
    scope: "openid email profile",
  },
  github: {
    authorizeUrl: "https://github.com/login/oauth/authorize",
    tokenUrl: "https://github.com/login/oauth/access_token",
    userUrl: "https://api.github.com/user",
    grantUrl: (clientId) => `https://api.github.com/applications/${clientId}/grant`,
    issuer: "https://github.com",
  },
};

export function isValidProvider(name) {
  return name === "google" || name === "github";
}
