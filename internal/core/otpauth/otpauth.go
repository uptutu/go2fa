// Package otpauth parses and generates otpauth:// URIs as defined by Google
// Authenticator's keyuri format. Used for both import (paste a URI) and
// export (write a QR code / display a string).
//
// Spec reference: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
package otpauth

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"2fa/internal/core/totp"
)

// Type is the OTP kind; only "totp" is supported by this tool (HOTP is rare).
type Type string

const (
	TOTP Type = "totp"
)

// URI is the parsed form of an otpauth:// URI.
type URI struct {
	Type      Type
	Issuer    string
	Account   string
	Secret    totp.Secret
	Algorithm totp.Algo
	Digits    int
	Period    int
}

// Parse accepts an otpauth URI and returns its parsed form.
func Parse(s string) (URI, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return URI{}, fmt.Errorf("otpauth: bad URL: %w", err)
	}
	if u.Scheme != "otpauth" {
		return URI{}, errors.New("otpauth: not an otpauth:// URI")
	}
	if u.Host != "totp" {
		return URI{}, fmt.Errorf("otpauth: unsupported type %q (only totp)", u.Host)
	}
	rawLabel := strings.TrimPrefix(u.Path, "/")
	if rawLabel == "" {
		return URI{}, errors.New("otpauth: missing label")
	}
	var issuer, account string
	if i := strings.Index(rawLabel, ":"); i >= 0 {
		issuer = urlDecode(rawLabel[:i])
		account = urlDecode(rawLabel[i+1:])
	} else {
		account = urlDecode(rawLabel)
	}
	q := u.Query()
	if q.Get("secret") == "" {
		return URI{}, errors.New("otpauth: missing secret")
	}
	secret, err := totp.DecodeSecret(q.Get("secret"))
	if err != nil {
		return URI{}, err
	}
	algo, err := totp.ParseAlgo(q.Get("algorithm"))
	if err != nil {
		return URI{}, err
	}
	digits := parseIntDefault(q.Get("digits"), 6)
	period := parseIntDefault(q.Get("period"), 30)
	if qi := q.Get("issuer"); qi != "" {
		issuer = qi
	}
	if issuer == "" {
		if i := strings.Index(account, ":"); i >= 0 {
			issuer = account[:i]
			account = account[i+1:]
		}
	}
	if account == "" {
		return URI{}, errors.New("otpauth: missing account")
	}
	return URI{
		Type:      TOTP,
		Issuer:    issuer,
		Account:   account,
		Secret:    secret,
		Algorithm: algo,
		Digits:    digits,
		Period:    period,
	}, nil
}

// String renders the URI back to its canonical string form.
func (u URI) String() string {
	q := url.Values{}
	q.Set("secret", totp.EncodeSecret(u.Secret))
	q.Set("algorithm", u.Algorithm.String())
	q.Set("digits", fmt.Sprintf("%d", u.Digits))
	q.Set("period", fmt.Sprintf("%d", u.Period))
	if u.Issuer != "" {
		q.Set("issuer", u.Issuer)
	}
	label := urlEncode(u.Account)
	if u.Issuer != "" {
		label = urlEncode(u.Issuer) + ":" + label
	}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

func parseIntDefault(s string, def int) int {
	if s == "" {
		return def
	}
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	if n == 0 {
		return def
	}
	return n
}

func urlDecode(s string) string {
	if v, err := url.PathUnescape(s); err == nil {
		return v
	}
	return s
}

func urlEncode(s string) string { return url.PathEscape(s) }