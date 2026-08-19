package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/znoraka/auth/internal/store"
	"github.com/znoraka/auth/internal/token"
)

//go:embed auth.js
var authJS []byte

//go:embed index.html
var indexHTML []byte

const codeTTL = 60 * time.Second

type Server struct {
	Store          *store.Store
	Signer         *token.Signer
	Keys           map[string]*ecdsa.PrivateKey // all keys, for JWKS
	OAuth          *oauth2.Config
	BaseURL        string
	AllowedEmails  []string // empty = anyone
	OriginSuffixes []string // e.g. .gawaak.ovh
}

func New(s *Server, clientID, clientSecret string) *Server {
	s.OAuth = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     google.Endpoint,
		RedirectURL:  s.BaseURL + "/callback",
		Scopes:       []string{"openid", "email", "profile"},
	}
	return s
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexHTML)
	})
	mux.HandleFunc("GET /auth.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Write(authJS)
	})
	mux.HandleFunc("GET /.well-known/openid-configuration", cors(s.oidcConfig))
	mux.HandleFunc("GET /authorize", s.authorize)
	mux.HandleFunc("GET /callback", s.callback)
	mux.HandleFunc("POST /token", cors(s.token))
	mux.HandleFunc("OPTIONS /token", cors(nil))
	mux.HandleFunc("GET /.well-known/jwks.json", cors(s.jwks))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	return mux
}

func cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if next == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

// validRedirect enforces: https + an allowed origin suffix, or localhost for dev.
func (s *Server) validRedirect(raw string) (origin string, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	if host == "localhost" || host == "127.0.0.1" {
		return u.Scheme + "://" + u.Host, nil
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("redirect_uri must be https")
	}
	for _, suf := range s.OriginSuffixes {
		if host == strings.TrimPrefix(suf, ".") || strings.HasSuffix(host, suf) {
			return "https://" + u.Host, nil
		}
	}
	return "", fmt.Errorf("origin %q not allowed", host)
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirectURI, challenge := q.Get("redirect_uri"), q.Get("code_challenge")
	if m := q.Get("code_challenge_method"); m != "" && m != "S256" {
		http.Error(w, "only S256 code_challenge_method is supported", http.StatusBadRequest)
		return
	}
	if redirectURI == "" || challenge == "" {
		http.Error(w, "redirect_uri and code_challenge are required", http.StatusBadRequest)
		return
	}
	origin, err := s.validRedirect(redirectURI)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req := store.AuthRequest{
		ID: store.RandID(), CodeChallenge: challenge,
		RedirectURI: redirectURI, Origin: origin, ClientState: q.Get("state"), Nonce: q.Get("nonce"),
		ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
	}
	if err := s.Store.CreateRequest(req); err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, s.OAuth.AuthCodeURL(req.ID), http.StatusFound)
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	req, err := s.Store.GetRequest(q.Get("state"))
	if err != nil || req.Used || time.Now().Unix() > req.ExpiresAt {
		http.Error(w, "unknown or expired auth request", http.StatusBadRequest)
		return
	}
	if e := q.Get("error"); e != "" {
		s.redirectBack(w, r, req, url.Values{"error": {e}})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	tok, err := s.OAuth.Exchange(ctx, q.Get("code"))
	if err != nil {
		http.Error(w, "google exchange failed", http.StatusBadGateway)
		return
	}
	ui, err := fetchUserinfo(ctx, s.OAuth, tok)
	if err != nil {
		http.Error(w, "google userinfo failed", http.StatusBadGateway)
		return
	}
	if len(s.AllowedEmails) > 0 && !slices.Contains(s.AllowedEmails, strings.ToLower(ui.Email)) {
		log.Printf("denied login for %s (origin %s)", ui.Email, req.Origin)
		s.redirectBack(w, r, req, url.Values{"error": {"access_denied"}})
		return
	}
	code := store.RandID()
	if err := s.Store.AttachIdentity(req.ID, code, ui.Sub, ui.Email, ui.Name, ui.Picture,
		time.Now().Add(codeTTL).Unix()); err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	log.Printf("login %s → %s", ui.Email, req.Origin)
	s.redirectBack(w, r, req, url.Values{"code": {code}})
}

func (s *Server) redirectBack(w http.ResponseWriter, r *http.Request, req *store.AuthRequest, extra url.Values) {
	u, _ := url.Parse(req.RedirectURI) // already validated at /authorize
	q := u.Query()
	for k, vs := range extra {
		q[k] = vs
	}
	if req.ClientState != "" {
		q.Set("state", req.ClientState)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

type userinfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

func fetchUserinfo(ctx context.Context, cfg *oauth2.Config, tok *oauth2.Token) (*userinfo, error) {
	resp, err := cfg.Client(ctx, tok).Get("https://openidconnect.googleapis.com/v1/userinfo")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo status %d", resp.StatusCode)
	}
	ui := &userinfo{}
	if err := json.NewDecoder(resp.Body).Decode(ui); err != nil {
		return nil, err
	}
	if ui.Sub == "" {
		return nil, fmt.Errorf("no sub in userinfo")
	}
	// An unverified address is one Google will not vouch for; drop it rather
	// than let downstream apps treat it as an identity hint.
	if !ui.EmailVerified {
		ui.Email = ""
	}
	return ui, nil
}

// oidcConfig advertises standard OIDC discovery so stock clients (go-oidc,
// oidc-client-ts, …) can use the broker as an issuer with zero custom code.
func (s *Server) oidcConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                s.BaseURL,
		"authorization_endpoint":                s.BaseURL + "/authorize",
		"token_endpoint":                        s.BaseURL + "/token",
		"jwks_uri":                              s.BaseURL + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
		"subject_types_supported":               []string{"pairwise"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
	})
}

// token accepts both the native JSON body and standard OAuth2
// application/x-www-form-urlencoded (grant_type=authorization_code).
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code         string `json:"code"`
		CodeVerifier string `json:"code_verifier"`
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err != nil {
			httpJSONError(w, "bad form", http.StatusBadRequest)
			return
		}
		if g := r.PostForm.Get("grant_type"); g != "" && g != "authorization_code" {
			httpJSONError(w, "unsupported grant_type", http.StatusBadRequest)
			return
		}
		in.Code, in.CodeVerifier = r.PostForm.Get("code"), r.PostForm.Get("code_verifier")
	} else if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		httpJSONError(w, "bad request body", http.StatusBadRequest)
		return
	}
	if in.Code == "" || in.CodeVerifier == "" {
		httpJSONError(w, "code and code_verifier are required", http.StatusBadRequest)
		return
	}
	req, err := s.Store.RedeemCode(in.Code)
	if err != nil {
		httpJSONError(w, "invalid or expired code", http.StatusBadRequest)
		return
	}
	sum := sha256.Sum256([]byte(in.CodeVerifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(want), []byte(req.CodeChallenge)) != 1 {
		httpJSONError(w, "PKCE verification failed", http.StatusBadRequest)
		return
	}
	idToken, err := s.Signer.Sign(req.GoogleSub, req.Origin, req.Email, req.Name, req.Picture, req.Nonce, time.Now())
	if err != nil {
		httpJSONError(w, "signing failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"id_token":     idToken,
		"pairwise_sub": s.Signer.PairwiseSub(req.GoogleSub, req.Origin),
		// OAuth2 compatibility for stock OIDC clients; the id_token is the
		// only credential this broker issues.
		"access_token": idToken,
		"token_type":   "Bearer",
	})
}

func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	out, err := token.JWKS(s.Keys)
	if err != nil {
		http.Error(w, "jwks error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Write(out)
}

func httpJSONError(w http.ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
