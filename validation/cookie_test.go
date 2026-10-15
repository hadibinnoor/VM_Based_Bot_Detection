package validation

import (
	"net/http/httptest"
	"strings"
	"testing"
)

var testSecret = []byte("0123456789abcdef0123456789abcdef")

func TestCookieRoundTrip(t *testing.T) {
	const binding = "binding-A"
	w := httptest.NewRecorder()
	IssueValidationCookie(w, "sess-1234", 0.07, testSecret, true, binding)

	resp := w.Result()
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		t.Fatal("no cookie set")
	}
	var tok string
	for _, c := range cookies {
		if c.Name == CookieName {
			tok = c.Value
		}
	}
	if tok == "" {
		t.Fatal("bd_token cookie not found")
	}
	if !VerifyCookie(tok, testSecret, binding) {
		t.Fatal("VerifyCookie rejected a token it just issued")
	}
}

func TestCookieRejectsTampered(t *testing.T) {
	const binding = "binding-A"
	w := httptest.NewRecorder()
	IssueValidationCookie(w, "sess-1234", 0.07, testSecret, true, binding)
	tok := w.Result().Cookies()[0].Value

	parts := strings.SplitN(tok, ".", 2)
	if len(parts) != 2 {
		t.Fatal("token does not have two parts")
	}
	// Flip a byte in the payload segment.
	b := []byte(parts[0])
	b[0] ^= 0x01
	tampered := string(b) + "." + parts[1]
	if VerifyCookie(tampered, testSecret, binding) {
		t.Fatal("tampered cookie accepted")
	}
}

func TestCookieRejectsWrongSecret(t *testing.T) {
	const binding = "binding-A"
	w := httptest.NewRecorder()
	IssueValidationCookie(w, "sess-9", 0.1, testSecret, true, binding)
	tok := w.Result().Cookies()[0].Value

	other := []byte("ffffffffffffffffffffffffffffffff")
	if VerifyCookie(tok, other, binding) {
		t.Fatal("cookie verified under wrong secret")
	}
}

func TestCookieRejectsWrongBinding(t *testing.T) {
	w := httptest.NewRecorder()
	IssueValidationCookie(w, "sess-9", 0.1, testSecret, true, "binding-A")
	tok := w.Result().Cookies()[0].Value
	if VerifyCookie(tok, testSecret, "binding-B") {
		t.Fatal("cookie verified under wrong request binding")
	}
}
