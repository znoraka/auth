// Package token issues and describes ES256-signed id_tokens, verifiable
// with plain JWKS — consumers never need this package (see verify/).
package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

type Signer struct {
	Kid  string
	Key  *ecdsa.PrivateKey
	Iss  string
	TTL  time.Duration
	Pair []byte // PAIRWISE_SECRET
}

type Claims struct {
	Iss     string `json:"iss"`
	Sub     string `json:"sub"`
	Aud     string `json:"aud"`
	Email   string `json:"email,omitempty"`
	Name    string `json:"name,omitempty"`
	Picture string `json:"picture,omitempty"`
	Nonce   string `json:"nonce,omitempty"`
	Iat     int64  `json:"iat"`
	Exp     int64  `json:"exp"`
}

func GenerateKey() (kid, privPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(der)
	kid = base64.RawURLEncoding.EncodeToString(sum[:8])
	privPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	return kid, privPEM, nil
}

func ParseKey(privPEM string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, fmt.Errorf("bad key PEM")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

// PairwiseSub derives ps_<base64url(HMAC-SHA256(secret, google_sub+origin))>:
// stable per app origin, uncorrelatable across origins.
func (s *Signer) PairwiseSub(googleSub, origin string) string {
	mac := hmac.New(sha256.New, s.Pair)
	mac.Write([]byte(googleSub + origin))
	return "ps_" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *Signer) Sign(googleSub, origin, email, name, picture, nonce string, now time.Time) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": s.Kid})
	claims, _ := json.Marshal(Claims{
		Iss: s.Iss, Sub: s.PairwiseSub(googleSub, origin), Aud: "origin:" + origin,
		Email: email, Name: name, Picture: picture, Nonce: nonce,
		Iat: now.Unix(), Exp: now.Add(s.TTL).Unix(),
	})
	b64 := base64.RawURLEncoding.EncodeToString
	signing := b64(header) + "." + b64(claims)
	sum := sha256.Sum256([]byte(signing))
	r, sv, err := ecdsa.Sign(rand.Reader, s.Key, sum[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sv.FillBytes(sig[32:])
	return signing + "." + b64(sig), nil
}

// JWKS renders the public keys in standard JWK format.
func JWKS(keys map[string]*ecdsa.PrivateKey) ([]byte, error) {
	type jwk struct {
		Kty, Crv, X, Y, Kid, Use, Alg string
	}
	var out struct {
		Keys []map[string]string `json:"keys"`
	}
	pad := func(b *big.Int) string {
		buf := make([]byte, 32)
		b.FillBytes(buf)
		return base64.RawURLEncoding.EncodeToString(buf)
	}
	for kid, k := range keys {
		out.Keys = append(out.Keys, map[string]string{
			"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig",
			"kid": kid, "x": pad(k.PublicKey.X), "y": pad(k.PublicKey.Y),
		})
	}
	return json.Marshal(out)
}
