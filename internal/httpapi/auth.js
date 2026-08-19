// auth.js — drop-in client for auth.gawaak.ovh.
// Usage:
//   <script src="https://auth.gawaak.ovh/auth.js"></script>
//   <a href="#" onclick="auth.startSignIn(); return false">Login</a>
// On page load it auto-completes the callback (?code=...) and stores the
// id_token in localStorage under "auth_id_token".
(function () {
  const BASE = new URL(document.currentScript.src).origin;
  const b64url = (buf) =>
    btoa(String.fromCharCode(...new Uint8Array(buf)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  async function startSignIn(redirectUri) {
    const bytes = crypto.getRandomValues(new Uint8Array(48));
    const verifier = b64url(bytes.buffer);
    sessionStorage.setItem("auth_pkce_verifier", verifier);
    const challenge = b64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
    const u = new URL(BASE + "/authorize");
    u.searchParams.set("redirect_uri", redirectUri || location.origin + location.pathname);
    u.searchParams.set("code_challenge", challenge);
    u.searchParams.set("code_challenge_method", "S256");
    location.href = u;
  }

  async function handleCallback() {
    const q = new URLSearchParams(location.search);
    const code = q.get("code");
    const verifier = sessionStorage.getItem("auth_pkce_verifier");
    if (!code || !verifier) return null;
    sessionStorage.removeItem("auth_pkce_verifier");
    const resp = await fetch(BASE + "/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code, code_verifier: verifier }),
    });
    if (!resp.ok) throw new Error("auth: token exchange failed");
    const { id_token } = await resp.json();
    localStorage.setItem("auth_id_token", id_token);
    q.delete("code"); q.delete("state");
    history.replaceState(null, "", location.pathname + (q.size ? "?" + q : ""));
    return id_token;
  }

  function token() {
    const t = localStorage.getItem("auth_id_token");
    if (!t) return null;
    try {
      const { exp } = JSON.parse(atob(t.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
      if (exp * 1000 < Date.now()) { signOut(); return null; }
    } catch { return null; }
    return t;
  }

  const claims = () => {
    const t = token();
    return t ? JSON.parse(atob(t.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))) : null;
  };
  const signOut = () => localStorage.removeItem("auth_id_token");

  window.auth = { startSignIn, handleCallback, token, claims, signOut };
  window.auth.ready = handleCallback().catch((e) => { console.error(e); return null; });
})();
