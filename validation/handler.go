package validation

import (
	"encoding/json"
	"log"
	"net/http"

	"bot-defense/session"
)

// Handler wires the validation pipeline together:
// decode → session lookup → token verify → feature extraction → ML → decision.
type Handler struct {
	sessions     *session.Store
	ml           *MLClient
	secret       []byte
	secureCookie bool // set on the "Secure" flag of the clearance cookie
}

// NewHandler constructs a Handler. The secret MUST be the same
// byte-slice passed to BotGuard middleware on protected routes.
//
// secureCookie should be true in production (HTTPS) and false in local
// development (plain HTTP) — see config.Config.SecureCookie.
func NewHandler(sessions *session.Store, ml *MLClient, secret []byte, secureCookie bool) *Handler {
	return &Handler{
		sessions:     sessions,
		ml:           ml,
		secret:       secret,
		secureCookie: secureCookie,
	}
}

// Verify handles POST /challenge/verify.
//
// Response contract:
//
//	200 + {"ok": true}       → clearance cookie set
//	403 + {"ok": false}      → missing/expired session, token mismatch, or
//	                           classified as bot (deliberately identical)
//	503 + {"ok": false}      → ML service unavailable (fail closed)
//	400 + "bad payload"      → malformed JSON
//
// Rejections are opaque: the client cannot tell which stage failed or
// how close the classifier score was, so a corrupted token or a near-miss
// gives an analyst no feedback.
func (h *Handler) Verify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// 1. Decode payload.
	var payload SensorPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}
	if payload.SessionID == "" {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}

	// 2. Validate session exists and hasn't expired.
	sess, err := h.sessions.Get(r.Context(), payload.SessionID)
	if err != nil {
		log.Printf("session lookup error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":     false,
			"reason": "internal",
		})
		return
	}
	if sess == nil {
		// Missing or expired Redis key — consistent with either a
		// replay attempt or a bot that POSTed without first running
		// the challenge.
		reject(w)
		return
	}

	// 3. Invalidate the session to prevent replay.
	if err := h.sessions.Delete(r.Context(), payload.SessionID); err != nil {
		log.Printf("session delete warning: %v", err)
		// Non-fatal: proceed to classify. TTL will eventually clear it.
	}

	// 4. Cryptographically verify the VM token using the recipe that
	// was stored alongside the session. The browser executed the VM
	// over its own sensor values and shipped both the token and the
	// raw values; we recompute the hash locally using the same
	// per-session permutation. Any mismatch proves the bytecode was
	// bypassed, the inputs were forged, the cache was tampered with,
	// or a token from a different session was replayed.
	if !VerifyChallengeToken(&payload, sess.TokenRecipe) {
		log.Printf("challenge token mismatch for session %s", payload.SessionID)
		reject(w)
		return
	}

	// 5. Build feature vector.
	uaString := r.Header.Get("User-Agent")
	features := ExtractFeatures(&payload, sess.IssuedAt, uaString, r.Header.Get("Accept-Language"))

	// 6. Call ML service.
	mlResult, err := h.ml.Predict(r.Context(), features.ToSlice())
	if err != nil {
		// Fail closed when ML is unavailable. This avoids turning model
		// outages into an allow-all bypass vector.
		log.Printf("ml service error (failing closed): %v", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false})
		return
	}

	// 7. Bot decision.
	if mlResult.IsBot {
		reject(w)
		return
	}

	// 8. Human — issue signed clearance cookie and respond OK.
	binding := BuildRequestBinding(r)
	IssueValidationCookie(w, payload.SessionID, mlResult.BotProb, h.secret, h.secureCookie, binding)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// reject writes the single opaque rejection used for every verification
// failure (session, token or classifier).
func reject(w http.ResponseWriter) {
	writeJSON(w, http.StatusForbidden, map[string]any{"ok": false})
}

// writeJSON is a tiny helper to set status + body. Errors from
// json.Encode are logged but not surfaced because the status has
// already been written.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("write json: %v", err)
	}
}
