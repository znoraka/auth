package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/znoraka/auth/internal/httpapi"
	"github.com/znoraka/auth/internal/store"
	"github.com/znoraka/auth/internal/token"
	"github.com/znoraka/auth/verify"
)

// Round-trip covering everything except the Google leg: /authorize (PKCE,
// origin check) → simulated Google identity → one-time code → /token →
// verify.Verify on the issued id_token.
func TestAuthorizeTokenVerifyRoundTrip(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/auth.db")
	if err != nil {
		t.Fatal(err)
	}
	kid, pem, err := st.EnsureKey(token.GenerateKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := token.ParseKey(pem)
	if err != nil {
		t.Fatal(err)
	}
	signer := &token.Signer{Kid: kid, Key: key, TTL: time.Hour, Pair: []byte("test-secret")}
	srv := httpapi.New(&httpapi.Server{
		Store: st, Signer: signer,
		Keys:           map[string]*ecdsa.PrivateKey{kid: key},
		OriginSuffixes: []string{".gawaak.ovh"},
	}, "cid", "csecret")

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	signer.Iss = ts.URL

	noRedirect := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	pkceVerifier := "0123456789012345678901234567890123456789012345678901234567890123"
	sum := sha256.Sum256([]byte(pkceVerifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	// Disallowed origin is rejected.
	resp, err := noRedirect.Get(ts.URL + "/authorize?redirect_uri=" +
		url.QueryEscape("https://evil.example.com/") + "&code_challenge=" + challenge)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("evil origin: got %d, want 400", resp.StatusCode)
	}

	// Allowed origin redirects to Google with our request id as state.
	resp, err = noRedirect.Get(ts.URL + "/authorize?redirect_uri=" +
		url.QueryEscape("https://lifts.gawaak.ovh/") + "&code_challenge=" + challenge + "&state=abc")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: got %d, want 302", resp.StatusCode)
	}
	gURL, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || gURL.Host != "accounts.google.com" {
		t.Fatalf("expected redirect to Google, got %q", resp.Header.Get("Location"))
	}
	reqID := gURL.Query().Get("state")

	// Simulate the /callback outcome: attach the Google identity + mint code.
	code := store.RandID()
	if err := st.AttachIdentity(reqID, code, "gsub-123", "noe@example.com", "Noé", "",
		time.Now().Add(time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}

	// Wrong verifier fails PKCE.
	body, _ := json.Marshal(map[string]string{"code": code, "code_verifier": "wrong"})
	resp, err = http.Post(ts.URL+"/token", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad verifier: got %d, want 400", resp.StatusCode)
	}

	// Code was burned by the failed attempt — mint a fresh one, then exchange.
	code = store.RandID()
	if err := st.AttachIdentity(reqID, code, "gsub-123", "noe@example.com", "Noé", "",
		time.Now().Add(time.Minute).Unix()); err == nil {
		t.Fatal("expected AttachIdentity to fail on used request")
	}
	// used=1 blocks reuse of the same request: run a fresh authorize instead.
	resp, err = noRedirect.Get(ts.URL + "/authorize?redirect_uri=" +
		url.QueryEscape("https://lifts.gawaak.ovh/") + "&code_challenge=" + challenge)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	gURL, _ = url.Parse(resp.Header.Get("Location"))
	reqID = gURL.Query().Get("state")
	code = store.RandID()
	if err := st.AttachIdentity(reqID, code, "gsub-123", "noe@example.com", "Noé", "",
		time.Now().Add(time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}

	body, _ = json.Marshal(map[string]string{"code": code, "code_verifier": pkceVerifier})
	resp, err = http.Post(ts.URL+"/token", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || out.IDToken == "" {
		t.Fatalf("token exchange failed: %d", resp.StatusCode)
	}

	// Replay of the burned code fails.
	body, _ = json.Marshal(map[string]string{"code": code, "code_verifier": pkceVerifier})
	resp, _ = http.Post(ts.URL+"/token", "application/json", bytes.NewReader(body))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("code replay: got %d, want 400", resp.StatusCode)
	}

	// Verify like a consuming app would (JWKS over HTTP).
	v := verify.New(ts.URL, "https://lifts.gawaak.ovh")
	claims, err := v.Verify(context.Background(), out.IDToken)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Email != "noe@example.com" || !bytes.HasPrefix([]byte(claims.Sub), []byte("ps_")) {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if claims.Sub != signer.PairwiseSub("gsub-123", "https://lifts.gawaak.ovh") {
		t.Fatal("pairwise sub mismatch")
	}

	// Wrong audience is rejected.
	if _, err := verify.New(ts.URL, "https://plans.gawaak.ovh").Verify(context.Background(), out.IDToken); err == nil {
		t.Fatal("expected audience mismatch")
	}
}
