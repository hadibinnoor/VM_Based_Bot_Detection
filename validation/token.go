package validation

import (
	"encoding/base64"
	"fmt"
	"unicode/utf16"

	"bot-defense/session"
)

// fnv1a32 computes the 32-bit FNV-1a hash of s using the same
// iteration semantics the browser-side VM uses.
//
// The JS implementation iterates via `s.charCodeAt(i)` which yields
// UTF-16 code units. To match it byte-for-byte we encode each Go rune
// into UTF-16 and hash the code units. For pure-ASCII inputs (which is
// the common case: user-agent, base64 canvas slice, hex data) this is
// identical to iterating bytes, but it also handles non-ASCII payloads
// correctly.
//
// Multiplication naturally wraps in Go's uint32 arithmetic, which
// matches JavaScript's `Math.imul` wrap semantics.
func fnv1a32(s string) uint32 {
	const offsetBasis = uint32(0x811c9dc5)
	const prime = uint32(0x01000193)

	units := utf16.Encode([]rune(s))
	h := offsetBasis
	for _, u := range units {
		h ^= uint32(u)
		h *= prime
	}
	return h
}

// ExpectedTokenInput carries the raw sensor strings used to recompute
// the per-session token. Field semantics mirror the VM register layout
// documented in challenge.BuildChallengeProgram; the *order* in which
// these fields are concatenated is now defined per-session by the
// session.TokenRecipe persisted in Redis.
//
// The hash is FNV-1a 32-bit, rendered as lowercase hex, then base64
// encoded (std encoding, with padding) — matching the JS chain
//
//	btoa(unescape(encodeURIComponent(hashHex)))
//
// For ASCII inputs this is equivalent to base64(hashHex) which is what
// we emit here. Hash hex is always ASCII so the equivalence is exact.
//
// SessionID is included as one of the 17 segments; because the SID is
// unique per request and issued by the server (unforgeable 32-hex
// bytes), an attacker who farms (sensors, token) from one session
// cannot replay that token against a fresh session.
type ExpectedTokenInput struct {
	UserAgent string
	ScreenW   string
	ScreenH   string
	Timezone  string
	CanvasFP  string
	WebGL     string
	MouseXStr string
	MouseYStr string
	TimingFP  string
	Platform  string
	ColorDep  string
	SessionID string // server-issued SID, bound into the hash
	WebDriver string
	AutoSig   string
	Plugins   string
	Languages string
	Notif     string
	TZOffset  string
	DPR       string
}

// segmentForIndex returns the string segment for a given recipe index.
// The mapping mirrors the register layout in
// challenge.BuildChallengeProgram and is the single source of truth
// for the index ↔ field correspondence.
func segmentForIndex(in ExpectedTokenInput, idx byte) string {
	switch idx {
	case 0:
		return in.UserAgent
	case 1:
		return in.ScreenW + in.ScreenH
	case 2:
		return in.Timezone
	case 3:
		return in.CanvasFP
	case 4:
		return in.WebGL
	case 5:
		return in.MouseXStr + in.MouseYStr
	case 6:
		return in.TimingFP
	case 7:
		return in.Platform
	case 8:
		return in.ColorDep
	case 9:
		return in.SessionID
	case 10:
		return in.WebDriver
	case 11:
		return in.AutoSig
	case 12:
		return in.Plugins
	case 13:
		return in.Languages
	case 14:
		return in.Notif
	case 15:
		return in.TZOffset
	case 16:
		return in.DPR
	default:
		return ""
	}
}

// ExpectedTokenWithRecipe rebuilds the token the VM would have emitted
// for the given sensor values under the supplied recipe.
func ExpectedTokenWithRecipe(in ExpectedTokenInput, recipe session.TokenRecipe) string {
	var concat string
	for _, idx := range recipe.Permutation {
		concat += segmentForIndex(in, idx)
	}
	h := fnv1a32(concat)
	hexStr := fmt.Sprintf("%x", h)
	return base64.StdEncoding.EncodeToString([]byte(hexStr))
}

// VerifyChallengeToken returns true when the token submitted by the
// browser matches the token the server independently recomputes from
// the raw sensor values the browser also submitted, under the recipe
// stored alongside the session.
//
// If they differ, the bytecode was either not executed, executed with
// tampered inputs, executed against a different recipe, or the sensor
// cache was forged. All of those are treated as a bot signal — the
// caller should reject the request.
func VerifyChallengeToken(p *SensorPayload, recipe session.TokenRecipe) bool {
	if !recipe.IsValid() {
		return false
	}
	expected := ExpectedTokenWithRecipe(ExpectedTokenInput{
		UserAgent: p.UserAgent,
		ScreenW:   p.ScreenW,
		ScreenH:   p.ScreenH,
		Timezone:  p.Timezone,
		CanvasFP:  p.CanvasFP,
		WebGL:     p.WebGLVendor,
		MouseXStr: p.MouseXStr,
		MouseYStr: p.MouseYStr,
		TimingFP:  p.TimingFP,
		Platform:  p.Platform,
		ColorDep:  p.ColorDepth,
		SessionID: p.SessionID,
		WebDriver: p.WebDriver,
		AutoSig:   p.AutoSig,
		Plugins:   p.PluginsLen,
		Languages: p.Languages,
		Notif:     p.NotifCohere,
		TZOffset:  p.TZOffset,
		DPR:       p.DevicePixel,
	}, recipe)
	return constantTimeStringEq(expected, p.Token)
}

// constantTimeStringEq avoids early-exit timing leaks when comparing
// tokens. The lengths differing is not a secret (the hash length is
// fixed), so an early length check is fine.
func constantTimeStringEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
