// Package validation implements Module 3 of the pipeline: decode the
// sensor payload submitted by the browser, extract engineered features,
// call the external ML service, and — if the caller scores as human —
// issue a signed HttpOnly clearance cookie.
package validation

import (
	"math"
	"strconv"
	"strings"
	"time"
)

// SensorPayload is the JSON body produced by the JS challenge and
// POSTed to /challenge/verify.
//
// Field tags match the short keys used by the JS template to keep the
// wire payload small and harder to pattern-match.
type SensorPayload struct {
	SessionID string    `json:"sid"` // 32-hex-char challenge session ID
	Token     string    `json:"tok"` // VM return value (base64 hash)
	MouseX    float64   `json:"mx"`  // last mousemove clientX
	MouseY    float64   `json:"my"`  // last mousemove clientY
	Timings   []float64 `json:"mt"`  // up to 30 mousemove timing samples (ms)
	TimingFP  string    `json:"tfp"` // "mean:variance" jitter fingerprint
	Timestamp int64     `json:"ts"`  // Date.now() at submission

	// Raw cached sensor values. These are populated as a side-effect of
	// the VM's CALL_ENV instructions and submitted verbatim so the
	// server can (a) recompute the expected token and (b) derive
	// environment-level features (canvas/webgl/touch blocking).
	UserAgent   string `json:"ua"`
	ScreenW     string `json:"sw"`
	ScreenH     string `json:"sh"`
	Timezone    string `json:"tz"`
	Language    string `json:"lang"`
	CanvasFP    string `json:"cfp"`
	WebGLVendor string `json:"wgl"`
	Platform    string `json:"plat"`
	TouchClaim  string `json:"touch"` // "true" / "false" — JS String(bool)
	MouseXStr   string `json:"mxs"`   // stringified mouseX captured inside VM
	MouseYStr   string `json:"mys"`   // stringified mouseY captured inside VM
	ColorDepth  string `json:"cd"`
	WebDriver   string `json:"wd"`  // "true"/"false"
	AutoSig     string `json:"ag"`  // "none" or signature tokens
	PluginsLen  string `json:"plg"` // navigator.plugins.length string
	Languages   string `json:"lgs"` // navigator.languages joined
	NotifCohere string `json:"nc"`  // "denied"/"granted"/"prompt"/"na"
	TZOffset    string `json:"tzo"` // minutes from UTC
	DevicePixel string `json:"dpr"` // window.devicePixelRatio
}

// FeatureVector holds the engineered features. Their order in
// ToSlice MUST match FEATURE_NAMES in ml/features.py.
type FeatureVector struct {
	MouseMoved        float64 // 0/1: any mouse movement?
	MouseX            float64 // raw X (pixels)
	MouseY            float64 // raw Y (pixels)
	MouseDistance     float64 // sqrt(x² + y²)
	TimingCount       float64 // #timing samples collected
	TimingMean        float64 // mean delta between samples
	TimingVariance    float64 // variance of deltas
	TimingMin         float64 // min delta
	TimingMax         float64 // max delta
	TimingRange       float64 // max - min
	ResponseLatencyMs float64 // submission_ts - issued_ts
	CanvasBlocked     float64 // 0/1
	WebGLBlocked      float64 // 0/1
	TouchClaimed      float64 // 0/1
	UALength          float64 // len(User-Agent)
	TokenValid        float64 // 0/1: VM produced a non-trivial token
	TimingJitterRatio float64 // variance / mean (KEY bot signal)
	SubmissionHour    float64 // hour of day (0-23)
	WebDriverTrue     float64 // 0/1: navigator.webdriver true
	AutomationGlobals float64 // 0/1: automation globals found
	PluginsEmpty      float64 // 0/1: plugin length is zero
	LanguagesMissing  float64 // 0/1: navigator.languages absent/empty
	NotifDenied       float64 // 0/1: Notification.permission denied
	UAPlatformMatch   float64 // 0/1: payload UA and platform coherent
	AcceptLangMatch   float64 // 0/1: Accept-Language aligns with payload
	TZConsistency     float64 // 0/1: timezone string and offset coherent
	DevicePixelValid  float64 // 0/1: reasonable DPR range
}

// ExtractFeatures computes the feature vector from a sensor payload
// plus contextual data drawn from the HTTP request.
//
// Inputs:
//
//	p          the decoded sensor payload (carries raw sensor values)
//	issuedAt   the unix-milliseconds the challenge was issued (Redis)
//	uaHeader   the raw User-Agent header from the incoming HTTP request
//
// Canvas / WebGL / touch signals are read straight from the payload:
// the VM now caches them and submits them verbatim. uaHeader is used
// ONLY for the UALength feature and the UA-vs-payload consistency check
// via the token (any mismatch would cause token verification to fail).
//
// The TimingFP string is parsed here so a sibling feature
// (timing_jitter_ratio) can see both halves even if the mousemove-based
// Timings slice is short.
func ExtractFeatures(
	p *SensorPayload,
	issuedAt int64,
	uaHeader string,
	acceptLanguage string,
) FeatureVector {
	f := FeatureVector{}

	// ── Mouse ───────────────────────────────────────────────────────
	f.MouseX = p.MouseX
	f.MouseY = p.MouseY
	f.MouseDistance = math.Sqrt(p.MouseX*p.MouseX + p.MouseY*p.MouseY)
	if p.MouseX != 0 || p.MouseY != 0 {
		f.MouseMoved = 1.0
	}

	// ── Timing samples ─────────────────────────────────────────────
	f.TimingCount = float64(len(p.Timings))
	if len(p.Timings) > 0 {
		minV, maxV := p.Timings[0], p.Timings[0]
		var sum float64
		for _, t := range p.Timings {
			sum += t
			if t < minV {
				minV = t
			}
			if t > maxV {
				maxV = t
			}
		}
		mean := sum / float64(len(p.Timings))
		var varSum float64
		for _, t := range p.Timings {
			diff := t - mean
			varSum += diff * diff
		}
		variance := varSum / float64(len(p.Timings))

		f.TimingMean = mean
		f.TimingMin = minV
		f.TimingMax = maxV
		f.TimingRange = maxV - minV
		f.TimingVariance = variance
		if mean > 0 {
			f.TimingJitterRatio = variance / mean
		}
	}

	// ── Timing fingerprint (takes priority if more precise) ────────
	// Format: "<mean>:<variance>" — the VM runs a tight 60-iteration
	// performance.now() loop which is more sensitive than mousemove.
	if fpMean, fpVar, ok := parseTimingFP(p.TimingFP); ok {
		// If we have no mousemove samples at all, fall back entirely
		// to the jitter FP. Otherwise merge by taking the MIN variance
		// between the two: this hurts bots that spoof one but not the other.
		if f.TimingCount == 0 {
			f.TimingMean = fpMean
			f.TimingVariance = fpVar
			if fpMean > 0 {
				f.TimingJitterRatio = fpVar / fpMean
			}
		} else if fpVar < f.TimingVariance {
			f.TimingVariance = fpVar
			if fpMean > 0 {
				f.TimingJitterRatio = fpVar / fpMean
			}
		}
	}

	// ── Latency from issuance to submission ────────────────────────
	f.ResponseLatencyMs = float64(p.Timestamp - issuedAt)

	// ── Environment signals (derived from VM-cached sensor values) ─
	// A blocked / absent API surfaces as a sentinel string
	// ("canvas_err", "webgl_err", "no_webgl", "no_ext") or as an empty
	// value if the VM never populated it.
	if p.CanvasFP == "" ||
		strings.Contains(p.CanvasFP, "err") ||
		strings.Contains(p.CanvasFP, "blocked") {
		f.CanvasBlocked = 1.0
	}
	if p.WebGLVendor == "" ||
		strings.Contains(p.WebGLVendor, "err") ||
		strings.Contains(p.WebGLVendor, "blocked") ||
		p.WebGLVendor == "no_webgl" || p.WebGLVendor == "no_ext" {
		f.WebGLBlocked = 1.0
	}
	if strings.EqualFold(p.TouchClaim, "true") {
		f.TouchClaimed = 1.0
	}

	// ── Token / UA / Hour ──────────────────────────────────────────
	// UALength uses the HTTP-header UA — the JS-reported one is part
	// of the token hash and thus already verified to match.
	f.UALength = float64(len(uaHeader))
	if len(p.Token) > 4 {
		f.TokenValid = 1.0
	}
	f.SubmissionHour = float64(time.Now().Hour())

	// ── Tier-1 automation probes ────────────────────────────────────
	if strings.EqualFold(p.WebDriver, "true") {
		f.WebDriverTrue = 1.0
	}
	if p.AutoSig != "" && p.AutoSig != "none" && !strings.Contains(p.AutoSig, "err") {
		f.AutomationGlobals = 1.0
	}
	if n, ok := parseFloat(p.PluginsLen); ok && n <= 0 {
		f.PluginsEmpty = 1.0
	} else if !ok {
		f.PluginsEmpty = 1.0
	}
	if strings.TrimSpace(p.Languages) == "" {
		f.LanguagesMissing = 1.0
	}
	if strings.EqualFold(p.NotifCohere, "denied") {
		f.NotifDenied = 1.0
	}

	// ── Tier-2 coherence checks ─────────────────────────────────────
	if uaPlatformLikelyMatch(p.UserAgent, p.Platform) {
		f.UAPlatformMatch = 1.0
	}
	if acceptLangLikelyMatch(acceptLanguage, p.Language, p.Languages) {
		f.AcceptLangMatch = 1.0
	}
	if timezoneLikelyCoherent(p.Timezone, p.TZOffset) {
		f.TZConsistency = 1.0
	}
	if dpr, ok := parseFloat(p.DevicePixel); ok && dpr >= 0.75 && dpr <= 5.0 {
		f.DevicePixelValid = 1.0
	}

	return f
}

func parseFloat(s string) (float64, bool) {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func uaPlatformLikelyMatch(ua, platform string) bool {
	ua = strings.ToLower(ua)
	platform = strings.ToLower(platform)
	switch {
	case strings.Contains(ua, "windows"):
		return strings.Contains(platform, "win")
	case strings.Contains(ua, "mac os x") || strings.Contains(ua, "macintosh"):
		return strings.Contains(platform, "mac")
	case strings.Contains(ua, "android"):
		return strings.Contains(platform, "linux") || strings.Contains(platform, "android")
	case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") || strings.Contains(ua, "ios"):
		return strings.Contains(platform, "iphone") || strings.Contains(platform, "ipad") || strings.Contains(platform, "ios") || strings.Contains(platform, "mac")
	case strings.Contains(ua, "linux"):
		return strings.Contains(platform, "linux") || strings.Contains(platform, "x11")
	default:
		return platform != ""
	}
}

func acceptLangLikelyMatch(acceptLanguage, language, languages string) bool {
	al := strings.ToLower(strings.TrimSpace(acceptLanguage))
	lang := strings.ToLower(strings.TrimSpace(language))
	langs := strings.ToLower(strings.TrimSpace(languages))
	if al == "" {
		return false
	}
	first := strings.Split(al, ",")[0]
	first = strings.TrimSpace(strings.Split(first, ";")[0])
	if first == "" {
		return false
	}
	if lang != "" && strings.HasPrefix(first, lang) || strings.HasPrefix(lang, first) {
		return true
	}
	if langs != "" {
		for _, x := range strings.Split(langs, ",") {
			x = strings.TrimSpace(x)
			if x != "" && (strings.HasPrefix(first, x) || strings.HasPrefix(x, first)) {
				return true
			}
		}
	}
	return false
}

func timezoneLikelyCoherent(timezone, offsetStr string) bool {
	offset, ok := parseFloat(offsetStr)
	if !ok {
		return false
	}
	// Broad bucketing by UTC offset to catch obvious contradictions with
	// minimal false positives. Date#getTimezoneOffset uses opposite sign:
	// UTC+5 => -300.
	tz := strings.ToLower(timezone)
	switch {
	case strings.Contains(tz, "utc"), strings.Contains(tz, "gmt"):
		return math.Abs(offset) <= 60
	case strings.Contains(tz, "new_york"), strings.Contains(tz, "toronto"):
		return offset >= 240 && offset <= 300
	case strings.Contains(tz, "los_angeles"), strings.Contains(tz, "vancouver"):
		return offset >= 420 && offset <= 480
	case strings.Contains(tz, "london"), strings.Contains(tz, "dublin"):
		return offset >= -60 && offset <= 60
	case strings.Contains(tz, "paris"), strings.Contains(tz, "berlin"), strings.Contains(tz, "madrid"):
		return offset >= -120 && offset <= -60
	case strings.Contains(tz, "tokyo"), strings.Contains(tz, "seoul"):
		return offset >= -600 && offset <= -480
	default:
		// Unknown IANA name: if present at all, assume coherent to avoid
		// over-penalizing uncommon zones.
		return timezone != ""
	}
}

// parseTimingFP accepts the "mean:variance" string produced by
// _timingFP() in the JS template. Returns ok=false on malformed input.
func parseTimingFP(s string) (mean, variance float64, ok bool) {
	if s == "" {
		return 0, 0, false
	}
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	mean, err1 := strconv.ParseFloat(parts[0], 64)
	variance, err2 := strconv.ParseFloat(parts[1], 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return mean, variance, true
}

// ToSlice flattens the feature vector for transport to the Python ML
// service. The index order MUST match FEATURE_NAMES in ml/features.py
// — a mismatch silently produces meaningless predictions.
func (f FeatureVector) ToSlice() []float64 {
	return []float64{
		f.MouseMoved,        // 0  mouse_moved
		f.MouseX,            // 1  mouse_x
		f.MouseY,            // 2  mouse_y
		f.MouseDistance,     // 3  mouse_distance
		f.TimingCount,       // 4  timing_count
		f.TimingMean,        // 5  timing_mean
		f.TimingVariance,    // 6  timing_variance
		f.TimingMin,         // 7  timing_min
		f.TimingMax,         // 8  timing_max
		f.TimingRange,       // 9  timing_range
		f.ResponseLatencyMs, // 10 response_latency_ms
		f.CanvasBlocked,     // 11 canvas_blocked
		f.WebGLBlocked,      // 12 webgl_blocked
		f.TouchClaimed,      // 13 touch_claimed
		f.UALength,          // 14 ua_length
		f.TokenValid,        // 15 token_valid
		f.TimingJitterRatio, // 16 timing_jitter_ratio
		f.SubmissionHour,    // 17 submission_hour
		f.WebDriverTrue,     // 18 webdriver_true
		f.AutomationGlobals, // 19 automation_globals
		f.PluginsEmpty,      // 20 plugins_empty
		f.LanguagesMissing,  // 21 languages_missing
		f.NotifDenied,       // 22 notif_denied
		f.UAPlatformMatch,   // 23 ua_platform_match
		f.AcceptLangMatch,   // 24 accept_lang_match
		f.TZConsistency,     // 25 tz_consistency
		f.DevicePixelValid,  // 26 device_pixel_valid
	}
}

// FeatureNames is the Go-side mirror of FEATURE_NAMES in ml/features.py.
// Kept here so tests can assert ordering.
var FeatureNames = []string{
	"mouse_moved",
	"mouse_x",
	"mouse_y",
	"mouse_distance",
	"timing_count",
	"timing_mean",
	"timing_variance",
	"timing_min",
	"timing_max",
	"timing_range",
	"response_latency_ms",
	"canvas_blocked",
	"webgl_blocked",
	"touch_claimed",
	"ua_length",
	"token_valid",
	"timing_jitter_ratio",
	"submission_hour",
	"webdriver_true",
	"automation_globals",
	"plugins_empty",
	"languages_missing",
	"notif_denied",
	"ua_platform_match",
	"accept_lang_match",
	"tz_consistency",
	"device_pixel_valid",
}
