"""
Feature name constants — the single source of truth for feature order.

The ordering here MUST match FeatureVector.ToSlice() in
validation/features.go. A mismatch silently produces meaningless
predictions with no runtime error, so do not reorder without
simultaneously updating the Go side.
"""

FEATURE_NAMES = [
    "mouse_moved",           # 0  0/1: any mouse movement detected
    "mouse_x",               # 1  last known X coordinate
    "mouse_y",               # 2  last known Y coordinate
    "mouse_distance",        # 3  Euclidean distance from origin
    "timing_count",          # 4  number of mousemove timing samples
    "timing_mean",           # 5  mean inter-event interval (ms)
    "timing_variance",       # 6  variance of intervals — KEY BOT SIGNAL
    "timing_min",            # 7  fastest interval
    "timing_max",            # 8  slowest interval
    "timing_range",          # 9  max - min
    "response_latency_ms",   # 10 time from challenge issue to submission
    "canvas_blocked",        # 11 0/1: canvas API returned error
    "webgl_blocked",         # 12 0/1: WebGL API returned error
    "touch_claimed",         # 13 0/1: touch events supported
    "ua_length",             # 14 length of User-Agent string
    "token_valid",           # 15 0/1: VM produced non-trivial output
    "timing_jitter_ratio",   # 16 variance / mean — near 0 = headless
    "submission_hour",       # 17 hour of day (0-23)
    "webdriver_true",        # 18 0/1: navigator.webdriver
    "automation_globals",    # 19 0/1: known automation globals present
    "plugins_empty",         # 20 0/1: navigator.plugins length == 0
    "languages_missing",     # 21 0/1: navigator.languages empty
    "notif_denied",          # 22 0/1: Notification.permission denied
    "ua_platform_match",     # 23 0/1: UA and platform coherent
    "accept_lang_match",     # 24 0/1: Accept-Language aligns
    "tz_consistency",        # 25 0/1: timezone and offset coherent
    "device_pixel_valid",    # 26 0/1: reasonable devicePixelRatio
]

N_FEATURES = len(FEATURE_NAMES)  # 27
