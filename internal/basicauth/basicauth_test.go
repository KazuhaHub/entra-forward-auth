package basicauth

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestParse(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		user     string
		password string
		err      error
	}{
		{"simple", "Basic " + b64("alice:secret"), "alice", "secret", nil},
		{"lowercase scheme", "basic " + b64("alice:secret"), "alice", "secret", nil},
		{"uppercase scheme", "BASIC " + b64("alice:secret"), "alice", "secret", nil},
		{"colon in password", "Basic " + b64("alice:se:cr:et"), "alice", "se:cr:et", nil},
		{"space in password", "Basic " + b64("alice:se cret "), "alice", "se cret ", nil},
		{"upn user", "Basic " + b64("alice@example.com:pw"), "alice@example.com", "pw", nil},
		{"utf8", "Basic " + b64("jörg:pässwörd"), "jörg", "pässwörd", nil},
		{"long credential", "Basic " + b64("u:"+strings.Repeat("p", 1000)), "u", strings.Repeat("p", 1000), nil},
		{"empty header", "", "", "", ErrNoCredentials},
		{"other scheme", "Bearer abc", "", "", ErrMalformed},
		{"scheme only", "Basic", "", "", ErrMalformed},
		{"scheme and space only", "Basic ", "", "", ErrMalformed},
		{"two spaces", "Basic  " + b64("a:b"), "", "", ErrMalformed},
		{"tab separator", "Basic\t" + b64("a:b"), "", "", ErrMalformed},
		{"no padding", "Basic " + strings.TrimRight(b64("alice:secre"), "="), "", "", ErrMalformed},
		{"bad base64", "Basic !!!!", "", "", ErrMalformed},
		{"url-safe alphabet", "Basic " + base64.URLEncoding.EncodeToString([]byte("a:b>>>>?")), "", "", ErrMalformed},
		{"embedded newline", "Basic " + b64("a:b")[:2] + "\n" + b64("a:b")[2:], "", "", ErrMalformed},
		{"trailing newline", "Basic " + b64("a:b") + "\r\n", "", "", ErrMalformed},
		{"no colon", "Basic " + b64("alice"), "", "", ErrMalformed},
		{"empty user", "Basic " + b64(":secret"), "", "", ErrMalformed},
		{"empty password", "Basic " + b64("alice:"), "", "", ErrMalformed},
		{"only colon", "Basic " + b64(":"), "", "", ErrMalformed},
		{"control char in user", "Basic " + b64("al\x01ce:pw"), "", "", ErrMalformed},
		{"nul in user", "Basic " + b64("al\x00ce:pw"), "", "", ErrMalformed},
		{"invalid utf8", "Basic " + base64.StdEncoding.EncodeToString([]byte{'a', ':', 0xff, 0xfe}), "", "", ErrMalformed},
		{"too long", "Basic " + b64("u:"+strings.Repeat("p", MaxHeaderLen)), "", "", ErrMalformed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			user, pw, err := Parse(tc.header)
			if !errors.Is(err, tc.err) {
				t.Fatalf("err = %v, want %v", err, tc.err)
			}
			if user != tc.user || pw != tc.password {
				t.Fatalf("got (%q, %q), want (%q, %q)", user, pw, tc.user, tc.password)
			}
		})
	}
}

func TestEncodeRoundTrip(t *testing.T) {
	user, pw, err := Parse(Encode("bob@example.com", "p:w d"))
	if err != nil || user != "bob@example.com" || pw != "p:w d" {
		t.Fatalf("round trip failed: %q %q %v", user, pw, err)
	}
}

func FuzzParse(f *testing.F) {
	seeds := []string{
		"", "Basic", "Basic ", "Basic " + b64("a:b"), "basic " + b64("alice:se:cret"),
		"Basic " + b64("jörg:pässwörd"), "Basic !!!!", "Bearer x", "Basic " + b64(":"),
		"Basic " + b64("a\x00b:c"), "Basic " + strings.Repeat("A", 400), "Basic =",
		"Basic " + b64("a:b") + "\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, header string) {
		user, pw, err := Parse(header)
		if err != nil {
			if !errors.Is(err, ErrNoCredentials) && !errors.Is(err, ErrMalformed) {
				t.Fatalf("unexpected error type: %v", err)
			}
			if user != "" || pw != "" {
				t.Fatalf("values returned alongside error: %q %q", user, pw)
			}
			return
		}
		if user == "" || pw == "" || strings.Contains(user, ":") {
			t.Fatalf("invalid accepted result: %q %q", user, pw)
		}
		// Anything accepted must round-trip through Encode and Parse.
		u2, p2, err := Parse(Encode(user, pw))
		if err != nil || u2 != user || p2 != pw {
			t.Fatalf("round trip mismatch: (%q,%q) -> (%q,%q,%v)", user, pw, u2, p2, err)
		}
	})
}
