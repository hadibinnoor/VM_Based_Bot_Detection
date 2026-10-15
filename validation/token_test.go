package validation

import (
	"encoding/base64"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"bot-defense/session"
)

// identityRecipe returns a recipe whose Permutation is [0, 1, ..., 16]
// — i.e. the natural left-to-right order. Used in tests to make the
// expected token computation deterministic and easy to reason about.
func identityRecipe() session.TokenRecipe {
	var r session.TokenRecipe
	for i := 0; i < session.NumTokenSegments; i++ {
		r.Permutation[i] = byte(i)
	}
	return r
}

// TestFNV1aASCII cross-checks the hash function against a couple of
// known FNV-1a 32-bit values. These values match the JavaScript code
// path when the input is pure ASCII (the common production case).
func TestFNV1aASCII(t *testing.T) {
	// Standard FNV-1a 32-bit reference vectors.
	cases := map[string]uint32{
		"":       0x811c9dc5,
		"a":      0xe40c292c,
		"foobar": 0xbf9cf968,
	}
	for in, want := range cases {
		if got := fnv1a32(in); got != want {
			t.Errorf("fnv1a32(%q) = 0x%08x, want 0x%08x", in, got, want)
		}
	}
}

// TestExpectedTokenShape validates that ExpectedTokenWithRecipe under
// the identity permutation produces a reasonably-sized base64 string
// and that the underlying hash matches what the JS VM would emit for
// the same canonical (left-to-right) order.
func TestExpectedTokenShape(t *testing.T) {
	in := ExpectedTokenInput{
		UserAgent: "Mozilla/5.0",
		ScreenW:   "1920", ScreenH: "1080",
		Timezone:  "America/New_York",
		CanvasFP:  "abc123",
		WebGL:     "Intel Inc.",
		MouseXStr: "120", MouseYStr: "340",
		TimingFP:  "12.5:3.4",
		Platform:  "MacIntel",
		ColorDep:  "24",
		SessionID: "deadbeefcafebabedeadbeefcafebabe",
		WebDriver: "false",
		AutoSig:   "none",
		Plugins:   "5",
		Languages: "en-US,en",
		Notif:     "prompt",
		TZOffset:  "300",
		DPR:       "2",
	}
	recipe := identityRecipe()
	tok := ExpectedTokenWithRecipe(in, recipe)

	raw, err := base64.StdEncoding.DecodeString(tok)
	if err != nil {
		t.Fatalf("token is not valid base64: %v", err)
	}
	// The hash-hex is 1..8 lowercase hex chars so base64 decodes to
	// between 1 and 8 bytes.
	if len(raw) == 0 || len(raw) > 8 {
		t.Errorf("decoded length %d out of range", len(raw))
	}
	for _, b := range raw {
		if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')) {
			t.Errorf("non-hex byte %q in token", b)
			break
		}
	}

	// Reconstruct the canonical concat order and assert equality with
	// the documented formula. Under the identity recipe the order is
	// the same as the original VM register layout.
	concat := in.UserAgent + in.ScreenW + in.ScreenH +
		in.Timezone + in.CanvasFP + in.WebGL +
		in.MouseXStr + in.MouseYStr +
		in.TimingFP + in.Platform + in.ColorDep +
		in.SessionID + in.WebDriver + in.AutoSig + in.Plugins +
		in.Languages + in.Notif + in.TZOffset + in.DPR
	wantTok := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%x", fnv1a32(concat))))
	if tok != wantTok {
		t.Errorf("ExpectedTokenWithRecipe mismatch under identity recipe\n got: %s\nwant: %s", tok, wantTok)
	}
}

// TestExpectedTokenRecipeSensitivity verifies that a non-identity
// recipe produces a different token from the identity recipe for the
// same sensor inputs — i.e. the per-session permutation actually
// changes the hash. It also confirms that swapping back to the
// identity recipe reproduces the original token.
func TestExpectedTokenRecipeSensitivity(t *testing.T) {
	in := ExpectedTokenInput{
		UserAgent: "Mozilla/5.0", ScreenW: "1920", ScreenH: "1080",
		Timezone: "Europe/Paris", CanvasFP: "deadbeef",
		WebGL: "NVIDIA", MouseXStr: "111", MouseYStr: "222",
		TimingFP: "1.23:4.56", Platform: "Linux x86_64", ColorDep: "32",
		SessionID: "sess", WebDriver: "false", AutoSig: "none",
		Plugins: "3", Languages: "en-US,en", Notif: "prompt",
		TZOffset: "300", DPR: "2",
	}
	idRecipe := identityRecipe()
	idTok := ExpectedTokenWithRecipe(in, idRecipe)

	// Construct a deterministic non-identity recipe by reversing the
	// permutation. Reversing 17 distinct elements is guaranteed to
	// disagree with the identity recipe at every position except
	// possibly the centre.
	var reversed session.TokenRecipe
	for i := 0; i < session.NumTokenSegments; i++ {
		reversed.Permutation[i] = byte(session.NumTokenSegments - 1 - i)
	}
	revTok := ExpectedTokenWithRecipe(in, reversed)
	if revTok == idTok {
		t.Errorf("reversed recipe should produce a different token\n id: %s\nrev: %s", idTok, revTok)
	}

	// Swapping back to the identity recipe must reproduce the
	// original token byte-for-byte.
	if back := ExpectedTokenWithRecipe(in, idRecipe); back != idTok {
		t.Errorf("identity recipe not stable\n got: %s\nwant: %s", back, idTok)
	}
}

// TestVerifyChallengeToken verifies that a payload whose fields match
// the token is accepted, and that flipping any participating field
// causes rejection.
func TestVerifyChallengeToken(t *testing.T) {
	p := &SensorPayload{
		SessionID:   "sess",
		UserAgent:   "Mozilla/5.0",
		ScreenW:     "1920",
		ScreenH:     "1080",
		Timezone:    "Europe/Paris",
		CanvasFP:    "deadbeef",
		WebGLVendor: "NVIDIA",
		MouseXStr:   "111",
		MouseYStr:   "222",
		TimingFP:    "1.23:4.56",
		Platform:    "Linux x86_64",
		ColorDepth:  "32",
		WebDriver:   "false",
		AutoSig:     "none",
		PluginsLen:  "3",
		Languages:   "en-US,en",
		NotifCohere: "prompt",
		TZOffset:    "300",
		DevicePixel: "2",
	}
	recipe := identityRecipe()
	// Populate Token from the server-side expectation.
	p.Token = ExpectedTokenWithRecipe(ExpectedTokenInput{
		UserAgent: p.UserAgent,
		ScreenW:   p.ScreenW, ScreenH: p.ScreenH,
		Timezone:  p.Timezone,
		CanvasFP:  p.CanvasFP,
		WebGL:     p.WebGLVendor,
		MouseXStr: p.MouseXStr, MouseYStr: p.MouseYStr,
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

	if !VerifyChallengeToken(p, recipe) {
		t.Fatal("token should verify for matching payload")
	}

	// Flip each participating field — verification should break.
	tamper := []func(*SensorPayload){
		func(s *SensorPayload) { s.UserAgent += "x" },
		func(s *SensorPayload) { s.ScreenW = "1024" },
		func(s *SensorPayload) { s.ScreenH = "768" },
		func(s *SensorPayload) { s.Timezone = "UTC" },
		func(s *SensorPayload) { s.CanvasFP = "cafebabe" },
		func(s *SensorPayload) { s.WebGLVendor = "AMD" },
		func(s *SensorPayload) { s.MouseXStr = "0" },
		func(s *SensorPayload) { s.MouseYStr = "0" },
		func(s *SensorPayload) { s.TimingFP = "9.99:0.01" },
		func(s *SensorPayload) { s.Platform = "Win32" },
		func(s *SensorPayload) { s.ColorDepth = "16" },
		func(s *SensorPayload) { s.WebDriver = "true" },
		func(s *SensorPayload) { s.AutoSig = "wd_eval" },
		func(s *SensorPayload) { s.PluginsLen = "0" },
		func(s *SensorPayload) { s.Languages = "" },
		func(s *SensorPayload) { s.NotifCohere = "denied" },
		func(s *SensorPayload) { s.TZOffset = "-120" },
		func(s *SensorPayload) { s.DevicePixel = "0.5" },
	}
	for i, mut := range tamper {
		c := *p
		mut(&c)
		if VerifyChallengeToken(&c, recipe) {
			t.Errorf("tamper #%d should have broken verification", i)
		}
	}

	// An empty/missing token must never verify.
	bad := *p
	bad.Token = ""
	if VerifyChallengeToken(&bad, recipe) {
		t.Error("empty token must not verify")
	}

	// Swapping to a different SessionID (replay scenario) MUST break
	// verification — this is the core server-bound-challenge guarantee.
	replay := *p
	replay.SessionID = "a-different-session-id"
	if VerifyChallengeToken(&replay, recipe) {
		t.Error("token replay across sessions must be rejected")
	}

	// Verifying the same payload under a *different* recipe must
	// also fail — recipes are bound to the session that issued them.
	var rotated session.TokenRecipe
	for i := 0; i < session.NumTokenSegments; i++ {
		rotated.Permutation[i] = byte((i + 1) % session.NumTokenSegments)
	}
	if VerifyChallengeToken(p, rotated) {
		t.Error("verification under a different recipe must be rejected")
	}

	// A zero-value recipe is malformed (Permutation = [0,0,...,0])
	// and must be rejected even if the rest of the payload is valid.
	var zero session.TokenRecipe
	if VerifyChallengeToken(p, zero) {
		t.Error("zero-value recipe must not verify")
	}
}

// TestCookieSecureFlag validates that the env-aware Secure flag is
// honoured and that SameSite falls back to Lax for dev so the browser
// doesn't drop the cookie over plain HTTP.
func TestCookieSecureFlag(t *testing.T) {
	// Production mode: Secure=true, SameSite=Strict.
	w := httptest.NewRecorder()
	IssueValidationCookie(w, "sess", 0.01, testSecret, true, "binding-prod")
	setCookie := w.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "Secure") {
		t.Errorf("production cookie missing Secure flag: %q", setCookie)
	}
	if !strings.Contains(setCookie, "SameSite=Strict") {
		t.Errorf("production cookie should be SameSite=Strict: %q", setCookie)
	}

	// Dev mode: Secure=false, SameSite=Lax.
	w2 := httptest.NewRecorder()
	IssueValidationCookie(w2, "sess", 0.01, testSecret, false, "binding-dev")
	setCookie2 := w2.Header().Get("Set-Cookie")
	if strings.Contains(setCookie2, "Secure") {
		t.Errorf("dev cookie should NOT have Secure flag: %q", setCookie2)
	}
	if !strings.Contains(setCookie2, "SameSite=Lax") {
		t.Errorf("dev cookie should be SameSite=Lax: %q", setCookie2)
	}
}
