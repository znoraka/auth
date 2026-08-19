// auth — zero-registration Google sign-in broker for *.gawaak.ovh.
package main

import (
	"crypto/ecdsa"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/znoraka/auth/internal/httpapi"
	"github.com/znoraka/auth/internal/store"
	"github.com/znoraka/auth/internal/token"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		resp, err := http.Get("http://127.0.0.1:" + env("PORT", "8080") + "/healthz")
		if err != nil || resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		return
	}

	baseURL := strings.TrimSuffix(env("BASE_URL", "http://localhost:8080"), "/")
	clientID, clientSecret := os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET")
	pairwise := os.Getenv("PAIRWISE_SECRET")
	if clientID == "" || clientSecret == "" || pairwise == "" {
		log.Fatal("GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET and PAIRWISE_SECRET are required")
	}

	st, err := store.Open(env("DATABASE_PATH", "/data/auth.db"))
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	kid, _, err := st.EnsureKey(token.GenerateKey)
	if err != nil {
		log.Fatalf("signing key: %v", err)
	}
	all, err := st.AllKeys()
	if err != nil {
		log.Fatalf("load keys: %v", err)
	}
	keys := map[string]*ecdsa.PrivateKey{}
	for id, p := range all {
		k, err := token.ParseKey(p)
		if err != nil {
			log.Fatalf("parse key %s: %v", id, err)
		}
		keys[id] = k
	}

	ttl, err := time.ParseDuration(env("TOKEN_TTL", "168h"))
	if err != nil {
		log.Fatalf("bad TOKEN_TTL: %v", err)
	}

	srv := httpapi.New(&httpapi.Server{
		Store: st,
		Signer: &token.Signer{
			Kid: kid, Key: keys[kid], Iss: baseURL, TTL: ttl, Pair: []byte(pairwise),
		},
		Keys:           keys,
		BaseURL:        baseURL,
		AllowedEmails:  splitList(os.Getenv("ALLOWED_EMAILS")),
		OriginSuffixes: splitList(env("ALLOWED_ORIGIN_SUFFIXES", ".gawaak.ovh")),
	}, clientID, clientSecret)

	go func() {
		for range time.Tick(time.Hour) {
			st.Cleanup()
		}
	}()

	addr := ":" + env("PORT", "8080")
	log.Printf("auth listening on %s (issuer %s, key %s)", addr, baseURL, kid)
	log.Fatal(http.ListenAndServe(addr, srv.Handler()))
}
