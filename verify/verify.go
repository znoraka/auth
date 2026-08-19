// Package verify validates id_tokens issued by an auth broker instance
// (auth.gawaak.ovh). It only needs the stdlib: JWKS fetch + ES256 verify.
//
//	v := verify.New("https://auth.gawaak.ovh", baseURL)
//	claims, err := v.Verify(ctx, idToken)
package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Claims struct {
	Iss     string `json:"iss"`
	Sub     string `json:"sub"` // ps_… pairwise subject: use as your user id
	Aud     string `json:"aud"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
	Iat     int64  `json:"iat"`
	Exp     int64  `json:"exp"`
}

type Verifier struct {
	issuer   string
	audience string

	mu      sync.Mutex
	keys    map[string]*ecdsa.PublicKey
	fetched time.Time
}

// New creates a Verifier. issuer is the broker base URL; appOrigin is your
// app's public base URL (only its origin is used for the audience check).
func New(issuer, appOrigin string) *Verifier {
	origin := appOrigin
	if u, err := url.Parse(appOrigin); err == nil && u.Scheme != "" {
		origin = u.Scheme + "://" + u.Host
	}
	return &Verifier{
		issuer:   strings.TrimSuffix(issuer, "/"),
		audience: "origin:" + origin,
	}
}

func (v *Verifier) Verify(ctx context.Context, idToken string) (*Claims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed token")
	}
	dec := func(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

	hdrB, err := dec(parts[0])
	if err != nil {
		return nil, fmt.Errorf("bad header: %w", err)
	}
	var hdr struct{ Alg, Kid string }
	if err := json.Unmarshal(hdrB, &hdr); err != nil || hdr.Alg != "ES256" {
		return nil, fmt.Errorf("unsupported alg")
	}
	key, err := v.key(ctx, hdr.Kid)
	if err != nil {
		return nil, err
	}

	sig, err := dec(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, fmt.Errorf("bad signature encoding")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(key, sum[:], r, s) {
		return nil, fmt.Errorf("invalid signature")
	}

	claimsB, err := dec(parts[1])
	if err != nil {
		return nil, fmt.Errorf("bad claims: %w", err)
	}
	c := &Claims{}
	if err := json.Unmarshal(claimsB, c); err != nil {
		return nil, err
	}
	switch {
	case c.Iss != v.issuer:
		return nil, fmt.Errorf("wrong issuer %q", c.Iss)
	case c.Aud != v.audience:
		return nil, fmt.Errorf("wrong audience %q (want %q)", c.Aud, v.audience)
	case time.Now().Unix() >= c.Exp:
		return nil, fmt.Errorf("token expired")
	}
	return c, nil
}

func (v *Verifier) key(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	// Unknown kid: refetch at most once a minute (handles key rotation).
	if time.Since(v.fetched) < time.Minute && v.keys != nil {
		return nil, fmt.Errorf("unknown key id %q", kid)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.issuer+"/.well-known/jwks.json", nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwks fetch: %w", err)
	}
	defer resp.Body.Close()
	var jwks struct {
		Keys []struct{ Kty, Crv, Kid, X, Y string } `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("jwks decode: %w", err)
	}
	v.keys = map[string]*ecdsa.PublicKey{}
	v.fetched = time.Now()
	for _, k := range jwks.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" {
			continue
		}
		xb, errX := base64.RawURLEncoding.DecodeString(k.X)
		yb, errY := base64.RawURLEncoding.DecodeString(k.Y)
		if errX != nil || errY != nil {
			continue
		}
		v.keys[k.Kid] = &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(xb),
			Y:     new(big.Int).SetBytes(yb),
		}
	}
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("unknown key id %q", kid)
}

// Middleware rejects requests without a valid Bearer id_token and stores
// the claims in the request context (retrieve with FromContext).
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		claims, err := v.Verify(r.Context(), tok)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsKey{}, claims)))
	})
}

type claimsKey struct{}

func FromContext(ctx context.Context) *Claims {
	c, _ := ctx.Value(claimsKey{}).(*Claims)
	return c
}
