package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS signing_keys (
  kid        TEXT PRIMARY KEY,
  priv_pem   TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_requests (
  id             TEXT PRIMARY KEY,           -- state we hand to Google
  code           TEXT UNIQUE,                -- one-time code for the app
  code_challenge TEXT NOT NULL,
  redirect_uri   TEXT NOT NULL,
  origin         TEXT NOT NULL,
  client_state   TEXT NOT NULL DEFAULT '',
  google_sub     TEXT, email TEXT, name TEXT, picture TEXT,
  created_at     INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL,
  used           INTEGER NOT NULL DEFAULT 0
);
`

type Store struct{ DB *sql.DB }

type AuthRequest struct {
	ID, Code, CodeChallenge, RedirectURI, Origin, ClientState string
	GoogleSub, Email, Name, Picture                           string
	ExpiresAt                                                 int64
	Used                                                      bool
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	return &Store{DB: db}, nil
}

func RandID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// EnsureKey returns the newest signing key, generating one on first boot.
func (s *Store) EnsureKey(generate func() (kid, pem string, err error)) (kid, pem string, err error) {
	err = s.DB.QueryRow(`SELECT kid, priv_pem FROM signing_keys ORDER BY created_at DESC LIMIT 1`).Scan(&kid, &pem)
	if err == sql.ErrNoRows {
		if kid, pem, err = generate(); err != nil {
			return
		}
		_, err = s.DB.Exec(`INSERT INTO signing_keys (kid, priv_pem, created_at) VALUES (?,?,?)`,
			kid, pem, time.Now().Unix())
	}
	return
}

func (s *Store) AllKeys() (map[string]string, error) {
	rows, err := s.DB.Query(`SELECT kid, priv_pem FROM signing_keys`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var kid, pem string
		if err := rows.Scan(&kid, &pem); err != nil {
			return nil, err
		}
		out[kid] = pem
	}
	return out, rows.Err()
}

func (s *Store) CreateRequest(r AuthRequest) error {
	_, err := s.DB.Exec(`INSERT INTO auth_requests
	  (id, code_challenge, redirect_uri, origin, client_state, created_at, expires_at)
	  VALUES (?,?,?,?,?,?,?)`,
		r.ID, r.CodeChallenge, r.RedirectURI, r.Origin, r.ClientState,
		time.Now().Unix(), r.ExpiresAt)
	return err
}

func (s *Store) GetRequest(id string) (*AuthRequest, error) {
	r := &AuthRequest{ID: id}
	var code, gsub, email, name, pic sql.NullString
	err := s.DB.QueryRow(`SELECT code, code_challenge, redirect_uri, origin, client_state,
	    google_sub, email, name, picture, expires_at, used
	  FROM auth_requests WHERE id = ?`, id).Scan(
		&code, &r.CodeChallenge, &r.RedirectURI, &r.Origin, &r.ClientState,
		&gsub, &email, &name, &pic, &r.ExpiresAt, &r.Used)
	if err != nil {
		return nil, err
	}
	r.Code, r.GoogleSub, r.Email, r.Name, r.Picture =
		code.String, gsub.String, email.String, name.String, pic.String
	return r, nil
}

// AttachIdentity stores the Google identity and mints the one-time code.
func (s *Store) AttachIdentity(id, code, gsub, email, name, picture string, expires int64) error {
	res, err := s.DB.Exec(`UPDATE auth_requests
	  SET code=?, google_sub=?, email=?, name=?, picture=?, expires_at=?
	  WHERE id=? AND used=0`, code, gsub, email, name, picture, expires, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// RedeemCode fetches and burns a one-time code atomically.
func (s *Store) RedeemCode(code string) (*AuthRequest, error) {
	var id string
	err := s.DB.QueryRow(`UPDATE auth_requests SET used=1
	  WHERE code=? AND used=0 AND expires_at > ? RETURNING id`,
		code, time.Now().Unix()).Scan(&id)
	if err != nil {
		return nil, err
	}
	return s.GetRequest(id)
}

func (s *Store) Cleanup() {
	s.DB.Exec(`DELETE FROM auth_requests WHERE expires_at < ?`, time.Now().Add(-time.Hour).Unix())
}
