// Package middleware provides HTTP middleware for the bot-defense service.
//
// The only exported middleware is BotGuard, which gates downstream
// handlers on a valid bd_token clearance cookie issued by the
// /challenge/verify endpoint.
package middleware

import (
	"net/http"

	"bot-defense/validation"
)

// BotGuard returns a middleware that rejects requests lacking a valid
// bd_token cookie. Wrap any protected route group with it.
//
// Rejections surface as HTTP 403 with a short textual reason:
//   - "bot defense: no token"       cookie not present
//   - "bot defense: invalid token"  signature mismatch or expired
func BotGuard(secret []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(validation.CookieName)
			if err != nil {
				http.Error(w, "bot defense: no token", http.StatusForbidden)
				return
			}
			binding := validation.BuildRequestBinding(r)
			if !validation.VerifyCookie(cookie.Value, secret, binding) {
				http.Error(w, "bot defense: invalid token", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
