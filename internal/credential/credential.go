// Package credential loads the application's certificate and private key and
// builds the signed client assertions that authenticate it to Microsoft Entra
// ID (RFC 7523 / "private_key_jwt").
package credential

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA-1 is mandated by the x5t thumbprint header, not used for security.
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// Assertion lifetime parameters. nbf is backdated to tolerate clock skew.
const (
	assertionLifetime = 5 * time.Minute
	assertionSkew     = 30 * time.Second
)

// Credential is a parsed certificate and its matching RSA private key.
type Credential struct {
	cert     *x509.Certificate
	key      *rsa.PrivateKey
	x5t      string
	x5tS256  string
	notAfter time.Time
}

// Parse builds a Credential from PEM data. certPEM may contain a chain; the
// first CERTIFICATE block is the credential. keyPEM must hold an unencrypted
// RSA key in PKCS#1 ("RSA PRIVATE KEY") or PKCS#8 ("PRIVATE KEY") form, and
// must match the certificate.
func Parse(certPEM, keyPEM []byte) (*Credential, error) {
	cert, err := parseCertificate(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("credential: certificate public key is %T, want RSA", cert.PublicKey)
	}
	if !pub.Equal(&key.PublicKey) {
		return nil, errors.New("credential: private key does not match certificate")
	}
	sum1 := sha1.Sum(cert.Raw) //nolint:gosec // see import comment.
	sum256 := sha256.Sum256(cert.Raw)
	return &Credential{
		cert:     cert,
		key:      key,
		x5t:      base64.RawURLEncoding.EncodeToString(sum1[:]),
		x5tS256:  base64.RawURLEncoding.EncodeToString(sum256[:]),
		notAfter: cert.NotAfter,
	}, nil
}

func parseCertificate(data []byte) (*x509.Certificate, error) {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, errors.New("credential: no CERTIFICATE block found")
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("credential: parse certificate: %w", err)
		}
		return cert, nil
	}
}

func parseKey(data []byte) (*rsa.PrivateKey, error) {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, errors.New("credential: no RSA PRIVATE KEY or PRIVATE KEY block found")
		}
		switch block.Type {
		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("credential: parse PKCS#1 key: %w", err)
			}
			return key, nil
		case "PRIVATE KEY":
			parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("credential: parse PKCS#8 key: %w", err)
			}
			key, ok := parsed.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("credential: PKCS#8 key is %T, want RSA", parsed)
			}
			return key, nil
		case "ENCRYPTED PRIVATE KEY":
			return nil, errors.New("credential: encrypted private keys are not supported")
		}
	}
}

// Thumbprints returns the base64url SHA-1 (x5t) and SHA-256 (x5t#S256)
// certificate thumbprints.
func (c *Credential) Thumbprints() (sha1Thumb, sha256Thumb string) {
	return c.x5t, c.x5tS256
}

// NotAfter returns the certificate expiry time.
func (c *Credential) NotAfter() time.Time { return c.notAfter }

type header struct {
	Alg     string `json:"alg"`
	Typ     string `json:"typ"`
	X5t     string `json:"x5t"`
	X5tS256 string `json:"x5t#S256"`
}

type claims struct {
	Aud string `json:"aud"`
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Jti string `json:"jti"`
	Iat int64  `json:"iat"`
	Nbf int64  `json:"nbf"`
	Exp int64  `json:"exp"`
}

// Assertion returns a freshly signed client assertion JWT for the given client
// ID and audience (the token endpoint URL), valid from now-30s to now+5m.
func (c *Credential) Assertion(clientID, audience string, now time.Time) (string, error) {
	jti, err := newUUIDv4()
	if err != nil {
		return "", err
	}
	hdr, err := json.Marshal(header{Alg: "RS256", Typ: "JWT", X5t: c.x5t, X5tS256: c.x5tS256})
	if err != nil {
		return "", fmt.Errorf("credential: encode header: %w", err)
	}
	body, err := json.Marshal(claims{
		Aud: audience,
		Iss: clientID,
		Sub: clientID,
		Jti: jti,
		Iat: now.Unix(),
		Nbf: now.Add(-assertionSkew).Unix(),
		Exp: now.Add(assertionLifetime).Unix(),
	})
	if err != nil {
		return "", fmt.Errorf("credential: encode claims: %w", err)
	}
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(hdr) + "." + enc.EncodeToString(body)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("credential: sign assertion: %w", err)
	}
	return signingInput + "." + enc.EncodeToString(sig), nil
}

func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("credential: random: %w", err)
	}
	b[6] = b[6]&0x0f | 0x40 // version 4
	b[8] = b[8]&0x3f | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// Signer holds the current Credential loaded from disk and can swap it
// atomically on reload. It is safe for concurrent use.
type Signer struct {
	certFile, keyFile string
	now               func() time.Time

	mu  sync.RWMutex
	cur *Credential
}

// NewSigner loads the certificate and key files. A nil clock means time.Now.
func NewSigner(certFile, keyFile string, now func() time.Time) (*Signer, error) {
	if now == nil {
		now = time.Now
	}
	s := &Signer{certFile: certFile, keyFile: keyFile, now: now}
	if err := s.Reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// Reload re-reads the files. On failure the previously loaded credential stays
// in effect and the error is returned.
func (s *Signer) Reload() error {
	certPEM, err := os.ReadFile(s.certFile)
	if err != nil {
		return fmt.Errorf("credential: read certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(s.keyFile)
	if err != nil {
		return fmt.Errorf("credential: read key: %w", err)
	}
	cred, err := Parse(certPEM, keyPEM)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.cur = cred
	s.mu.Unlock()
	return nil
}

// Current returns the credential in effect, or nil if none is loaded.
func (s *Signer) Current() *Credential {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cur
}

// Loaded reports whether a credential is available.
func (s *Signer) Loaded() bool { return s.Current() != nil }

// Assertion signs a client assertion with the current credential.
func (s *Signer) Assertion(clientID, audience string) (string, error) {
	cur := s.Current()
	if cur == nil {
		return "", errors.New("credential: no credential loaded")
	}
	return cur.Assertion(clientID, audience, s.now())
}
