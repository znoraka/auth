# auth

Zero-registration Google sign-in broker for `*.gawaak.ovh` — a self-hosted
[shoo](https://shoo.dev). Apps identify by their origin; no per-app OAuth
clients, dashboards, or registration. Issues ES256 `id_token`s verifiable via
standard JWKS.

## Flow

1. App sends the browser to `GET /authorize?redirect_uri=…&code_challenge=…&state=…` (S256 PKCE only).
2. auth redirects to Google (single shared OAuth client), gets the identity back on `GET /callback`.
3. Optional `ALLOWED_EMAILS` gate, then a 60s one-time code is redirected to the app.
4. App `POST /token {code, code_verifier}` → `{ id_token, pairwise_sub }`.
5. App backend verifies against `GET /.well-known/jwks.json`
   (`iss` = broker base URL, `aud` = `origin:<app origin>`,
   `sub` = `ps_<HMAC-SHA256(PAIRWISE_SECRET, google_sub + origin)>`).

## Client (browser)

```html
<script src="https://auth.gawaak.ovh/auth.js"></script>
<a href="#" onclick="auth.startSignIn(); return false">Login</a>
<script>
  auth.ready.then(() => {
    const c = auth.claims();          // null if signed out
    // fetch("/api/me", { headers: { Authorization: "Bearer " + auth.token() } })
  });
</script>
```

## Server (Go)

```go
import "github.com/znoraka/auth/verify"

v := verify.New("https://auth.gawaak.ovh", baseURL)
mux.Handle("/api/", v.Middleware(apiHandler))   // claims := verify.FromContext(r.Context())
```

## One-time Google setup

Only the broker needs a Google OAuth client (apps never do):
console.cloud.google.com → new project → OAuth consent screen (External, add
yourself as test user) → Credentials → OAuth client ID (Web application) with
redirect URI `https://auth.gawaak.ovh/callback`.

## Deploy (Coolify)

Docker Compose resource pointing at this repo, FQDN `https://auth.gawaak.ovh`.
Env to set: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`,
`PAIRWISE_SECRET` (e.g. `openssl rand -base64 32` — changing it changes every
user id), `ALLOWED_EMAILS` (comma list; empty = anyone with a Google account).
Optional: `ALLOWED_ORIGIN_SUFFIXES` (default `.gawaak.ovh`; add
`,.taile0xxx.ts.net` for tailnet apps), `TOKEN_TTL` (default `168h`).

The ES256 signing key is generated on first boot into `/data/auth.db`.
`http://localhost` redirect URIs are allowed for local dev.

## Local dev

```sh
GOOGLE_CLIENT_ID=… GOOGLE_CLIENT_SECRET=… PAIRWISE_SECRET=dev \
BASE_URL=http://localhost:8080 DATABASE_PATH=./auth.db go run .
```

(Requires adding `http://localhost:8080/callback` as a redirect URI on the
Google client.)
