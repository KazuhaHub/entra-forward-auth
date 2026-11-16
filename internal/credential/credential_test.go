package credential

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

type material struct {
	key     *rsa.PrivateKey
	certDER []byte
	certPEM []byte
	pkcs1   []byte
	pkcs8   []byte
}

func newMaterial(t *testing.T) material {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour).Truncate(time.Second),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	p8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return material{
		key:     key,
		certDER: der,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pkcs1:   pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
		pkcs8:   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p8}),
	}
}

func decodePart(t *testing.T, s string, v any) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

func TestAssertion(t *testing.T) {
	m := newMaterial(t)
	for name, keyPEM := range map[string][]byte{"pkcs1": m.pkcs1, "pkcs8": m.pkcs8} {
		t.Run(name, func(t *testing.T) {
			cred, err := Parse(m.certPEM, keyPEM)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Unix(1_700_000_000, 0)
			const aud = "https://login.microsoftonline.com/tenant/oauth2/v2.0/token"
			jwt, err := cred.Assertion("client-id", aud, now)
			if err != nil {
				t.Fatal(err)
			}
			parts := strings.Split(jwt, ".")
			if len(parts) != 3 {
				t.Fatalf("want 3 parts, got %d", len(parts))
			}

			var hdr map[string]any
			decodePart(t, parts[0], &hdr)
			s1 := sha1.Sum(m.certDER)
			s256 := sha256.Sum256(m.certDER)
			wantHdr := map[string]any{
				"alg":      "RS256",
				"typ":      "JWT",
				"x5t":      base64.RawURLEncoding.EncodeToString(s1[:]),
				"x5t#S256": base64.RawURLEncoding.EncodeToString(s256[:]),
			}
			if len(hdr) != len(wantHdr) {
				t.Fatalf("header = %v, want %v", hdr, wantHdr)
			}
			for k, v := range wantHdr {
				if hdr[k] != v {
					t.Errorf("header[%s] = %v, want %v", k, hdr[k], v)
				}
			}

			var cl claims
			decodePart(t, parts[1], &cl)
			uuidRE := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
			switch {
			case cl.Aud != aud, cl.Iss != "client-id", cl.Sub != "client-id":
				t.Errorf("claims identity wrong: %+v", cl)
			case !uuidRE.MatchString(cl.Jti):
				t.Errorf("jti %q is not a UUIDv4", cl.Jti)
			case cl.Iat != now.Unix(), cl.Nbf != now.Unix()-30, cl.Exp != now.Unix()+300:
				t.Errorf("claims times wrong: %+v", cl)
			}

			sig, err := base64.RawURLEncoding.DecodeString(parts[2])
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
			if err := rsa.VerifyPKCS1v15(&m.key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
				t.Fatalf("signature does not verify: %v", err)
			}

			// A second assertion must carry a different jti.
			jwt2, _ := cred.Assertion("client-id", aud, now)
			var cl2 claims
			decodePart(t, strings.Split(jwt2, ".")[1], &cl2)
			if cl2.Jti == cl.Jti {
				t.Error("jti reused")
			}
			if want, _ := x509.ParseCertificate(m.certDER); !cred.NotAfter().Equal(want.NotAfter) {
				t.Errorf("NotAfter = %v, want %v", cred.NotAfter(), want.NotAfter)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	m := newMaterial(t)
	other := newMaterial(t)
	ecKey, _ := x509.MarshalPKCS8PrivateKey(mustEC(t))
	tests := []struct {
		name     string
		cert     []byte
		key      []byte
		contains string
	}{
		{"mismatch", m.certPEM, other.pkcs8, "does not match"},
		{"no cert", []byte("nope"), m.pkcs8, "no CERTIFICATE"},
		{"only key in cert file", m.pkcs8, m.pkcs8, "no CERTIFICATE"},
		{"bad cert der", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}), m.pkcs8, "parse certificate"},
		{"no key", m.certPEM, []byte("nope"), "no RSA PRIVATE KEY"},
		{"bad pkcs1", m.certPEM, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("junk")}), "PKCS#1"},
		{"bad pkcs8", m.certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("junk")}), "PKCS#8"},
		{"ec pkcs8", m.certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecKey}), "want RSA"},
		{"encrypted", m.certPEM, pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("x")}), "encrypted"},
		{"ec certificate", ecCert(t), m.pkcs8, "want RSA"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.cert, tc.key)
			if err == nil || !strings.Contains(err.Error(), tc.contains) {
				t.Fatalf("err = %v, want containing %q", err, tc.contains)
			}
		})
	}
}

func TestParseChainAndSkipsOtherBlocks(t *testing.T) {
	m := newMaterial(t)
	other := newMaterial(t)
	// The first certificate is the credential; unrelated blocks are skipped.
	chain := append([]byte{}, pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: []byte{1}})...)
	chain = append(chain, m.certPEM...)
	chain = append(chain, other.certPEM...)
	keyFile := append(pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: []byte{1}}), m.pkcs1...)
	cred, err := Parse(chain, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	s1, s256 := cred.Thumbprints()
	sum := sha256.Sum256(m.certDER)
	if s256 != base64.RawURLEncoding.EncodeToString(sum[:]) || s1 == "" {
		t.Fatal("thumbprints do not belong to the first certificate")
	}

	// Chain in the wrong order: first cert does not match the key.
	if _, err := Parse(append(append([]byte{}, other.certPEM...), m.certPEM...), m.pkcs8); err == nil {
		t.Fatal("expected mismatch when the first certificate is not the key's")
	}
}

func TestSignerReload(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	a, b := newMaterial(t), newMaterial(t)
	write := func(m material) {
		t.Helper()
		if err := os.WriteFile(certPath, m.certPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, m.pkcs8, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(a)

	now := time.Unix(1_700_000_000, 0)
	s, err := NewSigner(certPath, keyPath, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if !s.Loaded() {
		t.Fatal("not loaded")
	}
	_, first := s.Current().Thumbprints()

	jwt, err := s.Assertion("cid", "aud")
	if err != nil {
		t.Fatal(err)
	}
	var cl claims
	decodePart(t, strings.Split(jwt, ".")[1], &cl)
	if cl.Iat != now.Unix() {
		t.Fatalf("injected clock not used: iat=%d", cl.Iat)
	}

	// Successful reload swaps the credential.
	write(b)
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, second := s.Current().Thumbprints(); second == first {
		t.Fatal("credential not swapped")
	}

	// A broken reload keeps the old credential.
	_, kept := s.Current().Thumbprints()
	if err := os.WriteFile(keyPath, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err == nil {
		t.Fatal("expected reload error")
	}
	if _, now2 := s.Current().Thumbprints(); now2 != kept {
		t.Fatal("failed reload replaced credential")
	}
	if _, err := s.Assertion("cid", "aud"); err != nil {
		t.Fatalf("old credential should still sign: %v", err)
	}
}

func TestSignerErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewSigner(filepath.Join(dir, "missing.pem"), filepath.Join(dir, "k.pem"), nil); err == nil {
		t.Fatal("expected error for missing certificate")
	}
	m := newMaterial(t)
	certPath := filepath.Join(dir, "c.pem")
	if err := os.WriteFile(certPath, m.certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSigner(certPath, filepath.Join(dir, "missing.pem"), nil); err == nil {
		t.Fatal("expected error for missing key")
	}

	var empty Signer
	if empty.Loaded() {
		t.Fatal("zero Signer must not be loaded")
	}
	if _, err := empty.Assertion("c", "a"); err == nil {
		t.Fatal("expected error from empty signer")
	}
}
