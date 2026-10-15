package challenge

// vmTemplate is the Go text/template source for the JavaScript runtime
// shipped to the browser. It is a single IIFE so that every identifier
// stays local to the challenge and cannot collide with host-page code.
//
// Template inputs (see generator.go for the wiring struct):
//
//	.SessionID   hex session ID
//	.EncBC       hex-encoded RC4-encrypted bytecode
//	.KeyP1       hex-encoded key part 1
//	.KeyP2       hex-encoded key part 2
//	.OpcodeCase  pre-rendered switch-case body (built by buildSwitchBlock)
//	.DeadCode    pre-rendered dead-code block
//	.V           VarSet — every runtime identifier
//
// IMPORTANT — the switch-case body (OpcodeCase) references identifiers
// by their mangled per-session names too. buildSwitchBlock is responsible
// for substituting VarSet.Regs, VarSet.EnvTable, VarSet.Push, VarSet.Pop,
// VarSet.Ops, and VarSet.PC into each case.
//
// ── Sensor caching contract ────────────────────────────────────────
// Every env_table entry is wrapped by a caching function that records
// the computed value into {{.V.Sensors}}[env_id]. When the bytecode
// executes, it populates the cache as a side-effect of each CALL_ENV.
// The final payload then ships the cached values verbatim so the
// server can reconstruct the exact string the VM hashed and
// cryptographically verify `tok`.
//
// Hash input order (matches BuildChallengeProgram register layout):
//
//	r0 = ua (0x01)
//	r1 = sw (0x02) ++ sh (0x03)
//	r2 = tz (0x04)
//	r3 = cfp (0x07)
//	r4 = wgl (0x08)
//	r5 = mx (0x0B) ++ my (0x0C)
//	r6 = tfp (0x0D)
//	r7 = plat (0x09)
//	r8 = cd  (0x0E)
//	r9 = sid (0x11) — server-issued session ID, binds token to request
//	rA = wd  (0x12) — navigator.webdriver flag
//	rB = ag  (0x13) — automation globals signature
//	rC = plg (0x14) — navigator.plugins.length
//	rD = lgs (0x15) — navigator.languages signature
//	rE = nc  (0x16) — notification coherence
//	rF = tzo (0x17) — timezone offset minutes
//	r10= dpr (0x18) — devicePixelRatio
//
// token = base64utf8( fnv1a32_hex_lower( r0..r10 concatenated ) ), with the
// concatenation order fixed per session by session.TokenRecipe.
//
// ── Anti-analysis posture ──────────────────────────────────────────
//   - Bytecode is encrypted with RC4 (not repeating XOR). An inline
//     KSA+PRGA decrypts it at runtime using the reconstructed master
//     key. If the master key has been tampered with, RC4 yields
//     nonsense bytes and the VM terminates at an unknown opcode,
//     silently returning null.
//   - Before RC4 runs we execute a `debugger;` trap and measure its
//     elapsed time. If DevTools is open and paused the measurement
//     exceeds the threshold and we corrupt the master key in place —
//     decryption then produces garbage, the VM aborts, and the server
//     eventually rejects the request with a 403. No visible exceptions
//     are thrown.
//   - We also time the VM execution itself. A human stepping through
//     the interpreter (even without pausing explicitly) cannot match
//     the sub-100ms baseline; if the threshold is exceeded we zero
//     the result so no valid token is submitted.
const vmTemplate = `(function(){
"use strict";

// ── Dead code (inflates & confuses static analyzers) ─────────────────
{{.DeadCode}}

// ── Hex decoder: string "a1b2..." → [0xa1, 0xb2, ...] ────────────────
var {{.V.Decode}} = function(h) {
    var b = [];
    for (var i = 0; i < h.length; i += 2) {
        b.push(parseInt(h.substr(i, 2), 16));
    }
    return b;
};

// ── Master key reconstruction (XOR of two shipped halves) ────────────
var {{.V.KeyP1}} = {{.V.Decode}}("{{.KeyP1}}");
var {{.V.KeyP2}} = {{.V.Decode}}("{{.KeyP2}}");
var {{.V.MasterKey}} = {{.V.KeyP1}}.map(function(b, i) {
    return b ^ {{.V.KeyP2}}[i];
});

// ── Anti-debug: timing-based DevTools detection ──────────────────────
// If DevTools is open AND execution is paused at the debugger; line,
// the elapsed wall-clock time will be large. A closed DevTools turns
// debugger; into a no-op (<1ms). We use a generous 100ms threshold so
// normal browsers (even under heavy GC pressure) never trip it.
//
// On detection we XOR the master key in place with 0xFF. RC4 with a
// wrong key produces garbage bytes, the VM parses garbage opcodes,
// hits the default arm of the switch, and returns null. The resulting
// tok === null payload fails server-side token verification (403).
(function() {
    try {
        var _dbgStart = (typeof performance !== 'undefined' && performance.now)
            ? performance.now() : Date.now();
        (function() { debugger; })();
        var _dbgEnd = (typeof performance !== 'undefined' && performance.now)
            ? performance.now() : Date.now();
        if ((_dbgEnd - _dbgStart) > 100) {
            for (var _kc = 0; _kc < {{.V.MasterKey}}.length; _kc++) {
                {{.V.MasterKey}}[_kc] = ({{.V.MasterKey}}[_kc] ^ 0xFF) & 0xFF;
            }
        }
    } catch(_e) { /* swallow */ }
})();

// ── Bytecode decryption (RC4 KSA + PRGA, inline) ─────────────────────
// Decrypts the RC4-encrypted bytecode with the (possibly tampered)
// master key. Using RC4 instead of repeating XOR means the ciphertext
// has no structural bias a static analyst can exploit.
var {{.V.EncBC}} = {{.V.Decode}}("{{.EncBC}}");
var {{.V.RawBC}} = (function(_ct, _key) {
    var _S = new Array(256);
    for (var _i = 0; _i < 256; _i++) _S[_i] = _i;
    var _j = 0;
    for (var _i = 0; _i < 256; _i++) {
        _j = (_j + _S[_i] + _key[_i % _key.length]) & 0xFF;
        var _tmp = _S[_i]; _S[_i] = _S[_j]; _S[_j] = _tmp;
    }
    var _out = new Array(_ct.length);
    var _a = 0, _b = 0;
    for (var _k = 0; _k < _ct.length; _k++) {
        _a = (_a + 1) & 0xFF;
        _b = (_b + _S[_a]) & 0xFF;
        var _t = _S[_a]; _S[_a] = _S[_b]; _S[_b] = _t;
        _out[_k] = _ct[_k] ^ _S[(_S[_a] + _S[_b]) & 0xFF];
    }
    return _out;
})({{.V.EncBC}}, {{.V.MasterKey}});

// ── Live sensor state ────────────────────────────────────────────────
var {{.V.MouseX}} = 0;
var {{.V.MouseY}} = 0;
var {{.V.Timings}} = [];
var {{.V.T0}} = (typeof performance !== 'undefined' && performance.now)
    ? performance.now() : Date.now();

if (typeof document !== 'undefined') {
    document.addEventListener('mousemove', function(e) {
        {{.V.MouseX}} = e.clientX;
        {{.V.MouseY}} = e.clientY;
        var _now = (typeof performance !== 'undefined' && performance.now)
            ? performance.now() : Date.now();
        {{.V.Timings}}.push(+(_now - {{.V.T0}}).toFixed(3));
    }, { passive: true });
}

// ── Canvas 2D fingerprinting ─────────────────────────────────────────
function _canvasFP() {
    try {
        var c = document.createElement('canvas');
        c.width = 200; c.height = 50;
        var ctx = c.getContext('2d');
        ctx.textBaseline = 'alphabetic';
        ctx.fillStyle = '#f0f';
        ctx.fillRect(0, 0, 200, 50);
        ctx.font = '15px Arial';
        ctx.fillStyle = '#069';
        ctx.fillText('\u6c49\u5b57 BotGuard \u00e9', 2, 30);
        ctx.fillStyle = 'rgba(102,204,0,0.6)';
        ctx.fillText('\u6c49\u5b57 BotGuard \u00e9', 4, 32);
        return c.toDataURL().slice(-32);
    } catch(e) { return 'canvas_err'; }
}

// ── WebGL vendor fingerprinting ─────────────────────────────────────
function _webglVendor() {
    try {
        var c = document.createElement('canvas');
        var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
        if (!gl) return 'no_webgl';
        var ext = gl.getExtension('WEBGL_debug_renderer_info');
        if (!ext) return 'no_ext';
        return String(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || '');
    } catch(e) { return 'webgl_err'; }
}

// ── performance.now() jitter fingerprint ────────────────────────────
// Real browsers: measurable variance from OS scheduler preemption.
// Headless / containerised runtimes: near-zero variance.
function _timingFP() {
    var d = [], prev = performance.now();
    for (var i = 0; i < 60; i++) {
        var n = performance.now();
        d.push(+(n - prev).toFixed(4));
        prev = n;
    }
    var mean = d.reduce(function(a,b){return a+b;}, 0) / d.length;
    var variance = d.reduce(function(a,b){return a + Math.pow(b-mean, 2);}, 0) / d.length;
    return mean.toFixed(5) + ':' + variance.toFixed(5);
}

function _automationSig() {
    try {
        var hits = [];
        if (typeof window.__webdriver_script_fn !== 'undefined') hits.push('wd_fn');
        if (typeof window.__webdriver_evaluate !== 'undefined') hits.push('wd_eval');
        if (typeof window.__selenium_unwrapped !== 'undefined') hits.push('sel_unwrapped');
        if (typeof window.__nightmare !== 'undefined') hits.push('nightmare');
        if (typeof window.callPhantom !== 'undefined') hits.push('phantom');
        if (typeof window._phantom !== 'undefined') hits.push('phantom_obj');
        if (typeof window.domAutomation !== 'undefined') hits.push('dom_auto');
        if (typeof window.domAutomationController !== 'undefined') hits.push('dom_auto_ctl');
        for (var k in window) {
            if (k.indexOf('cdc_') === 0 || k.indexOf('__webdriver') === 0 || k.indexOf('__selenium') === 0) {
                hits.push('k:' + k.slice(0, 20));
                if (hits.length > 6) break;
            }
        }
        return hits.length ? hits.join('|') : 'none';
    } catch(_e) { return 'sig_err'; }
}

function _notificationCoherence() {
    try {
        if (typeof Notification === 'undefined') return 'na';
        var p = Notification.permission;
        if (p === 'denied') return 'denied';
        if (p === 'granted') return 'granted';
        return 'prompt';
    } catch(_e) { return 'notif_err'; }
}

// ── Sensor cache ─────────────────────────────────────────────────────
// Populated as a side-effect of CALL_ENV executions so the payload can
// ship the exact values the VM hashed.
var {{.V.Sensors}} = {};
var {{.V.Cache}} = function(id, fn) {
    return function() {
        var v = fn();
        {{.V.Sensors}}[id] = v;
        return v;
    };
};

// ── Environment dispatch table (ENV_ID → cached getter) ─────────────
var {{.V.EnvTable}} = {
    0x01: {{.V.Cache}}(0x01, function() { return navigator.userAgent || ''; }),
    0x02: {{.V.Cache}}(0x02, function() { return String(screen.width); }),
    0x03: {{.V.Cache}}(0x03, function() { return String(screen.height); }),
    0x04: {{.V.Cache}}(0x04, function() {
        try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ''; }
        catch(e) { return ''; }
    }),
    0x05: {{.V.Cache}}(0x05, function() { return navigator.language || ''; }),
    0x06: {{.V.Cache}}(0x06, function() { return String(Date.now()); }),
    0x07: {{.V.Cache}}(0x07, function() { return _canvasFP(); }),
    0x08: {{.V.Cache}}(0x08, function() { return _webglVendor(); }),
    0x09: {{.V.Cache}}(0x09, function() { return navigator.platform || ''; }),
    0x0A: {{.V.Cache}}(0x0A, function() { return String('ontouchstart' in window); }),
    0x0B: {{.V.Cache}}(0x0B, function() { return String({{.V.MouseX}}); }),
    0x0C: {{.V.Cache}}(0x0C, function() { return String({{.V.MouseY}}); }),
    0x0D: {{.V.Cache}}(0x0D, function() { return _timingFP(); }),
    0x0E: {{.V.Cache}}(0x0E, function() { return String(screen.colorDepth); }),
    0x0F: {{.V.Cache}}(0x0F, function() { return String(navigator.deviceMemory || 0); }),
    0x10: {{.V.Cache}}(0x10, function() { return String(navigator.hardwareConcurrency || 0); }),
    // Server-bound-challenge anchor: returns the session ID the server
    // will also know. Hashing it into the token binds that token to
    // THIS request so farmed tokens cannot be replayed against a new
    // challenge.
    0x11: {{.V.Cache}}(0x11, function() { return "{{.SessionID}}"; }),
    0x12: {{.V.Cache}}(0x12, function() { return String(!!navigator.webdriver); }),
    0x13: {{.V.Cache}}(0x13, function() { return _automationSig(); }),
    0x14: {{.V.Cache}}(0x14, function() {
        try { return String((navigator.plugins && navigator.plugins.length) || 0); }
        catch(e) { return '0'; }
    }),
    0x15: {{.V.Cache}}(0x15, function() {
        try {
            if (!navigator.languages || !navigator.languages.length) return '';
            return navigator.languages.join(',');
        } catch(e) { return ''; }
    }),
    0x16: {{.V.Cache}}(0x16, function() { return _notificationCoherence(); }),
    0x17: {{.V.Cache}}(0x17, function() {
        try { return String(new Date().getTimezoneOffset()); }
        catch(e) { return '0'; }
    }),
    0x18: {{.V.Cache}}(0x18, function() {
        try { return String(window.devicePixelRatio || 1); }
        catch(e) { return '1'; }
    })
};

// ── VM interpreter loop ──────────────────────────────────────────────
var {{.V.VMFunc}} = function(bytecode) {
    var {{.V.Stack}} = [];
    var {{.V.Regs}}  = {};
    var {{.V.PC}}    = 0;

    function {{.V.Push}}(v) { {{.V.Stack}}.push(v); }
    function {{.V.Pop}}()   { return {{.V.Stack}}.pop(); }

    // Hard guard against pathological jumps: cap total iterations so a
    // runaway back-edge can never hang the browser. The real program
    // uses ~40 instructions plus a small counted loop; 4096 is well
    // above that and well below "infinite".
    var _steps = 0;
    var _MAX_STEPS = 4096;

    while ({{.V.PC}} < bytecode.length) {
        if (++_steps > _MAX_STEPS) return null;
        if ({{.V.PC}} < 0) return null;

        var {{.V.Op}}    = bytecode[{{.V.PC}}++];
        var {{.V.OpLen}} = bytecode[{{.V.PC}}++];
        var {{.V.Ops}}   = bytecode.slice({{.V.PC}}, {{.V.PC}} + {{.V.OpLen}});
        {{.V.PC}} += {{.V.OpLen}};

        switch({{.V.Op}}) {
{{.OpcodeCase}}
            default:
                // Unknown opcode — terminate silently so malformed
                // injection (or decryption with a corrupted key) does
                // not produce a loud JS error.
                return null;
        }
    }
    return null;
};

// ── Wait for sensor collection, execute VM, submit result ───────────
setTimeout(function() {
    var {{.V.Result}};
    // Anti-debug: measure total VM execution time. A human single-
    // stepping through the interpreter easily exceeds 500ms; a real
    // browser runs the program in well under 50ms. If the threshold
    // is exceeded we zero the result and the server rejects the token.
    var _vmStart = (typeof performance !== 'undefined' && performance.now)
        ? performance.now() : Date.now();
    try {
        {{.V.Result}} = {{.V.VMFunc}}({{.V.RawBC}});
    } catch(e) {
        {{.V.Result}} = null;
    }
    var _vmEnd = (typeof performance !== 'undefined' && performance.now)
        ? performance.now() : Date.now();
    if ((_vmEnd - _vmStart) > 500) {
        {{.V.Result}} = null;
    }

    var _S = {{.V.Sensors}};
    var {{.V.Payload}} = {
        sid:  "{{.SessionID}}",
        tok:  {{.V.Result}},
        mx:   {{.V.MouseX}},
        my:   {{.V.MouseY}},
        mt:   {{.V.Timings}}.slice(-30),
        ts:   Date.now(),

        // Raw cached sensor values — used by the server to recompute
        // the expected token and to surface env-level features.
        ua:   typeof _S[0x01] === 'string' ? _S[0x01] : '',
        sw:   typeof _S[0x02] === 'string' ? _S[0x02] : '',
        sh:   typeof _S[0x03] === 'string' ? _S[0x03] : '',
        tz:   typeof _S[0x04] === 'string' ? _S[0x04] : '',
        lang: typeof _S[0x05] === 'string' ? _S[0x05] : '',
        cfp:  typeof _S[0x07] === 'string' ? _S[0x07] : '',
        wgl:  typeof _S[0x08] === 'string' ? _S[0x08] : '',
        plat: typeof _S[0x09] === 'string' ? _S[0x09] : '',
        touch: typeof _S[0x0A] === 'string' ? _S[0x0A] : '',
        mxs:  typeof _S[0x0B] === 'string' ? _S[0x0B] : '',
        mys:  typeof _S[0x0C] === 'string' ? _S[0x0C] : '',
        tfp:  typeof _S[0x0D] === 'string' ? _S[0x0D] : _timingFP(),
        cd:   typeof _S[0x0E] === 'string' ? _S[0x0E] : '',
        wd:   typeof _S[0x12] === 'string' ? _S[0x12] : 'false',
        ag:   typeof _S[0x13] === 'string' ? _S[0x13] : 'none',
        plg:  typeof _S[0x14] === 'string' ? _S[0x14] : '0',
        lgs:  typeof _S[0x15] === 'string' ? _S[0x15] : '',
        nc:   typeof _S[0x16] === 'string' ? _S[0x16] : 'na',
        tzo:  typeof _S[0x17] === 'string' ? _S[0x17] : '0',
        dpr:  typeof _S[0x18] === 'string' ? _S[0x18] : '1'
    };

    fetch('/challenge/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({{.V.Payload}})
    }).then(function(r) {
        return r.json().catch(function(){ return {}; });
    }).then(function(d) {
        if (d && d.ok) {
            try {
                window.dispatchEvent(new CustomEvent('bd-cleared', { detail: d }));
            } catch(_e) {}
        } else {
            try {
                window.dispatchEvent(new CustomEvent('bd-blocked', { detail: d || {} }));
            } catch(_e) {}
        }
    }).catch(function() {
        // swallow network errors — nothing to do client-side
    });
}, 600);

})();`
