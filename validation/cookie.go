package validation

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// CookieName is the name of the signed clearance cookie issued to
// humans who pass the challenge.
const CookieName = "bd_token"

// cookieTTL is the lifetime of the clearance cookie. After it expires
// the browser must pass a new challenge.
const cookieTTL = 24 * time.Hour

// tokenClaims is the payload carried inside the cookie.
// The wire format is: base64url(JSON(claims)) "." base64url(HMAC).
type tokenClaims struct {
	SessionID string  `json:"sid"` // original challenge session ID
	IssuedAt  int64   `json:"iat"` // unix seconds
	ExpiresAt int64   `json:"exp"` // unix seconds
	BotScore  float64 `json:"bsc"` // ML probability this user is a bot
	Binding   string  `json:"bdg"` // request-level binding digest
}

// IssueValidationCookie writes a signed HttpOnly SameSite=Strict
// clearance cookie on the response. The secret must be the same
// byte-slice used by VerifyCookie on subsequent requests.
//
// secure controls the cookie's Secure flag: true in production (HTTPS),
// false in local development where the browser would otherwise drop
// Secure cookies over plain HTTP. SameSite is also relaxed to Lax when
// secure is false so local development over plain HTTP works without a cert.
func IssueValidationCookie(
	w http.ResponseWriter,
	sessionID string,
	botProb float64,
	secret []byte,
	secure bool,
	binding string,
) {
	now := time.Now()
	claims := tokenClaims{
		SessionID: sessionID,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(cookieTTL).Unix(),
		BotScore:  botProb,
		Binding:   binding,
	}
	claimsJSON, _ := json.Marshal(claims)
	encoded := base64.RawURLEncoding.EncodeToString(claimsJSON)

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(encoded))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	sameSite := http.SameSiteStrictMode
	if !secure {
		// Browsers reject SameSite=None without Secure; Strict over
		// plain HTTP is fine but noisy in some dev tools. Lax is the
		// most compatible default for local development.
		sameSite = http.SameSiteLaxMode
	}

	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    encoded + "." + sig,
		Path:     "/",
		MaxAge:   int(cookieTTL.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
	})
}

// VerifyCookie returns true iff the cookie value carries a valid
// signature and has not yet expired. The check is constant-time to
// avoid timing oracles on the MAC comparison.
func VerifyCookie(tokenValue string, secret []byte, binding string) bool {
	parts := strings.SplitN(tokenValue, ".", 2)
	if len(parts) != 2 {
		return false
	}
	encoded, sig := parts[0], parts[1]

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(encoded))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return false
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}
	var claims tokenClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return false
	}
	if time.Now().Unix() >= claims.ExpiresAt {
		return false
	}
	return claims.Binding != "" && hmac.Equal([]byte(claims.Binding), []byte(binding))
}

// BuildRequestBinding derives a coarse request fingerprint used to bind
// clearance cookies to a client context (UA + language + IP bucket).
func BuildRequestBinding(r *http.Request) string {
	ua := strings.TrimSpace(r.Header.Get("User-Agent"))
	lang := strings.TrimSpace(strings.Split(strings.Split(r.Header.Get("Accept-Language"), ",")[0], ";")[0])
	raw := fmt.Sprintf("%s|%s|%s", ua, strings.ToLower(lang), clientIPBucket(r))
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func clientIPBucket(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		host = strings.TrimSpace(r.RemoteAddr)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "ip:unknown"
	}
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("v4:%d.%d.%d.0/24", v4[0], v4[1], v4[2])
	}
	v6 := ip.To16()
	if v6 == nil {
		return "ip:unknown"
	}
	return fmt.Sprintf("v6:%x:%x:%x:%x:%x:%x:%x00/56",
		v6[0], v6[1], v6[2], v6[3], v6[4], v6[5], v6[6])
}
