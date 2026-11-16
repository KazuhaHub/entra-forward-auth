// Package basicauth parses the HTTP "Authorization: Basic" request header.
//
// The parser is deliberately stricter than RFC 7617 requires: it exists to
// feed a credential check, so anything unusual is rejected rather than
// guessed at.
package basicauth

import (
	"encoding/base64"
	"errors"
	"strings"
	"unicode/utf8"
)

// MaxHeaderLen is the longest Authorization header value accepted.
const MaxHeaderLen = 4096

var (
	// ErrNoCredentials means the header is absent or empty.
	ErrNoCredentials = errors.New("basicauth: no credentials")
	// ErrMalformed means the header is present but is not a valid
	// Basic credential carrying a non-empty user and password.
	ErrMalformed = errors.New("basicauth: malformed credentials")
)

const scheme = "Basic "

// Parse extracts the user and password from an Authorization header value.
//
// The scheme name is matched case-insensitively and must be followed by
// exactly one space and canonical padded base64. The decoded value must be
// valid UTF-8, split at the first colon into a non-empty user (free of control
// characters) and a non-empty password. An empty header yields
// ErrNoCredentials; everything else that is not acceptable yields
// ErrMalformed.
func Parse(header string) (user, password string, err error) {
	if header == "" {
		return "", "", ErrNoCredentials
	}
	if len(header) > MaxHeaderLen || len(header) <= len(scheme) ||
		!strings.EqualFold(header[:len(scheme)], scheme) {
		return "", "", ErrMalformed
	}
	enc := header[len(scheme):]

	// base64.StdEncoding silently skips CR and LF; refuse them instead.
	if strings.ContainsAny(enc, "\r\n") {
		return "", "", ErrMalformed
	}

	// Decode into a stack buffer when the credential is small, which is the
	// overwhelmingly common case.
	var stack [256]byte
	buf := stack[:]
	if n := base64.StdEncoding.DecodedLen(len(enc)); n > len(buf) {
		buf = make([]byte, n)
	}
	n, derr := base64.StdEncoding.Decode(buf, []byte(enc))
	if derr != nil {
		return "", "", ErrMalformed
	}
	decoded := buf[:n]
	if !utf8.Valid(decoded) {
		return "", "", ErrMalformed
	}

	colon := -1
	for i, b := range decoded {
		if b == ':' {
			colon = i
			break
		}
		if b < 0x20 || b == 0x7f {
			return "", "", ErrMalformed
		}
	}
	if colon <= 0 || colon == len(decoded)-1 {
		return "", "", ErrMalformed
	}
	return string(decoded[:colon]), string(decoded[colon+1:]), nil
}

// Encode builds an Authorization header value for the given credentials. It
// is the inverse of Parse for any input Parse accepts and is used by tests and
// tooling.
func Encode(user, password string) string {
	return scheme + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}
