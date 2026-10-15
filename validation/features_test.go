package validation

import (
	"math"
	"testing"
)

func TestFeatureVectorSliceOrder(t *testing.T) {
	f := FeatureVector{
		MouseMoved: 1, MouseX: 2, MouseY: 3, MouseDistance: 4,
		TimingCount: 5, TimingMean: 6, TimingVariance: 7,
		TimingMin: 8, TimingMax: 9, TimingRange: 10,
		ResponseLatencyMs: 11, CanvasBlocked: 12, WebGLBlocked: 13,
		TouchClaimed: 14, UALength: 15, TokenValid: 16,
		TimingJitterRatio: 17, SubmissionHour: 18, WebDriverTrue: 19,
		AutomationGlobals: 20, PluginsEmpty: 21, LanguagesMissing: 22,
		NotifDenied: 23, UAPlatformMatch: 24, AcceptLangMatch: 25,
		TZConsistency: 26, DevicePixelValid: 27,
	}
	s := f.ToSlice()
	if len(s) != len(FeatureNames) {
		t.Fatalf("slice len %d != names len %d", len(s), len(FeatureNames))
	}
	for i, v := range s {
		if int(v) != i+1 {
			t.Errorf("index %d (%s): got %v, want %d",
				i, FeatureNames[i], v, i+1)
		}
	}
}

func TestExtractFeaturesHuman(t *testing.T) {
	p := &SensorPayload{
		SessionID: "abc",
		Token:     "Z1p0Q2RoXw==",
		MouseX:    820, MouseY: 411,
		Timings:     []float64{50, 75, 90, 110, 60, 80},
		TimingFP:    "12.34567:820.12345",
		Timestamp:   1_000_000_000 + 3000,
		CanvasFP:    "abc123def456", // any non-empty, non-err string
		WebGLVendor: "Intel Inc.",
		TouchClaim:  "false",
		Timezone:    "America/New_York",
		WebDriver:   "false",
		AutoSig:     "none",
		PluginsLen:  "5",
		Languages:   "en-US,en",
		NotifCohere: "prompt",
		TZOffset:    "300",
		DevicePixel: "2",
		UserAgent:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_0)",
		Platform:    "MacIntel",
		Language:    "en-US",
	}
	f := ExtractFeatures(
		p,
		1_000_000_000,
		"Mozilla/5.0 (Macintosh; Intel) Gecko Firefox/120.0",
		"en-US,en;q=0.9",
	)

	if f.MouseMoved != 1.0 {
		t.Error("MouseMoved should be 1")
	}
	wantDist := math.Sqrt(820*820 + 411*411)
	if math.Abs(f.MouseDistance-wantDist) > 1e-9 {
		t.Errorf("MouseDistance: got %v, want %v", f.MouseDistance, wantDist)
	}
	if f.TimingCount != 6 {
		t.Errorf("TimingCount: got %v, want 6", f.TimingCount)
	}
	if f.ResponseLatencyMs != 3000 {
		t.Errorf("ResponseLatencyMs: got %v, want 3000", f.ResponseLatencyMs)
	}
	if f.TokenValid != 1 {
		t.Error("TokenValid should be 1 for non-trivial token")
	}
	if f.UALength < 20 {
		t.Errorf("UALength too small: %v", f.UALength)
	}
	if f.TimingVariance <= 0 {
		t.Errorf("TimingVariance should be positive, got %v", f.TimingVariance)
	}
	if f.WebDriverTrue != 0 || f.AutomationGlobals != 0 || f.PluginsEmpty != 0 {
		t.Errorf("unexpected automation flags for human: wd=%v ag=%v pe=%v",
			f.WebDriverTrue, f.AutomationGlobals, f.PluginsEmpty)
	}
	if f.UAPlatformMatch != 1 || f.AcceptLangMatch != 1 || f.TZConsistency != 1 || f.DevicePixelValid != 1 {
		t.Errorf("expected coherence checks to pass: up=%v al=%v tz=%v dpr=%v",
			f.UAPlatformMatch, f.AcceptLangMatch, f.TZConsistency, f.DevicePixelValid)
	}
}

func TestExtractFeaturesHeadlessBot(t *testing.T) {
	p := &SensorPayload{
		SessionID: "abc",
		Token:     "",
		MouseX:    0, MouseY: 0,
		Timings:     nil,
		TimingFP:    "0.80000:0.00020",
		Timestamp:   1_000_000_000 + 120,
		CanvasFP:    "canvas_err",
		WebGLVendor: "no_webgl",
		TouchClaim:  "false",
		Timezone:    "America/New_York",
		WebDriver:   "true",
		AutoSig:     "wd_eval|k:cdc_foo",
		PluginsLen:  "0",
		Languages:   "",
		NotifCohere: "denied",
		TZOffset:    "-500",
		DevicePixel: "0.1",
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		Platform:    "Linux x86_64",
		Language:    "",
	}
	f := ExtractFeatures(p, 1_000_000_000, "HeadlessChrome/110", "en-US,en;q=0.9")

	if f.MouseMoved != 0 {
		t.Error("MouseMoved should be 0")
	}
	if f.TokenValid != 0 {
		t.Error("TokenValid should be 0")
	}
	if f.CanvasBlocked != 1 {
		t.Error("CanvasBlocked should be 1")
	}
	if f.WebGLBlocked != 1 {
		t.Error("WebGLBlocked should be 1")
	}
	if f.ResponseLatencyMs != 120 {
		t.Errorf("ResponseLatencyMs: got %v, want 120", f.ResponseLatencyMs)
	}
	// With no mousemove timings but a TimingFP, jitter ratio should
	// come from the FP: 0.00020 / 0.80000 = 2.5e-4.
	if f.TimingJitterRatio == 0 {
		t.Error("TimingJitterRatio should fall back to TimingFP when Timings is empty")
	}
	if f.TimingJitterRatio > 0.001 {
		t.Errorf("TimingJitterRatio should be near zero for bot, got %v", f.TimingJitterRatio)
	}
	if f.WebDriverTrue != 1 || f.AutomationGlobals != 1 || f.PluginsEmpty != 1 || f.LanguagesMissing != 1 {
		t.Errorf("expected automation features to trigger, got wd=%v ag=%v pe=%v lm=%v",
			f.WebDriverTrue, f.AutomationGlobals, f.PluginsEmpty, f.LanguagesMissing)
	}
	if f.NotifDenied != 1 {
		t.Errorf("expected notif denied flag, got %v", f.NotifDenied)
	}
	if f.UAPlatformMatch != 0 || f.DevicePixelValid != 0 {
		t.Errorf("expected coherence mismatch for bot, got up=%v dpr=%v", f.UAPlatformMatch, f.DevicePixelValid)
	}
}

func TestParseTimingFP(t *testing.T) {
	cases := []struct {
		in       string
		wantMean float64
		wantVar  float64
		wantOK   bool
	}{
		{"12.5:3.4", 12.5, 3.4, true},
		{"0.00040:0.00012", 0.0004, 0.00012, true},
		{"", 0, 0, false},
		{"malformed", 0, 0, false},
		{"12.5", 0, 0, false},
	}
	for _, tc := range cases {
		m, v, ok := parseTimingFP(tc.in)
		if ok != tc.wantOK {
			t.Errorf("%q: ok=%v, want %v", tc.in, ok, tc.wantOK)
			continue
		}
		if ok {
			if math.Abs(m-tc.wantMean) > 1e-9 || math.Abs(v-tc.wantVar) > 1e-9 {
				t.Errorf("%q: (%v,%v), want (%v,%v)", tc.in, m, v, tc.wantMean, tc.wantVar)
			}
		}
	}
}
