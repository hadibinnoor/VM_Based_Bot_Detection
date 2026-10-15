package challenge

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"text/template"
)

// ─── Variable name mangling ───────────────────────────────────────────────────
//
// Every JS variable exposed to the challenge script receives a fresh
// random identifier per request. Combined with the randomized opcode
// map this defeats static pattern matching: no two challenges share a
// single consistent symbol.

// RandVarName generates a random-looking JS identifier. The prefix is
// a short readability tag (e.g. "pc" for program counter) that helps
// humans read the output during development; it is NOT a security
// feature.
func RandVarName(prefix string) string {
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is unrecoverable; fall back to a stable
		// but unique-per-call name.
		return fmt.Sprintf("_%s%x", prefix, b)
	}
	return "_" + prefix + hex.EncodeToString(b)
}

// VarSet is a complete, consistent set of randomized variable names
// used throughout one rendered challenge script. Keep the field names
// in sync with the template placeholders in template.go.
type VarSet struct {
	VMFunc    string // main VM function
	Stack     string // operand stack
	Regs      string // register table
	PC        string // program counter
	Op        string // current opcode byte
	OpLen     string // operand length
	Ops       string // operands slice
	Decode    string // hex → []int helper
	KeyP1     string // first key half
	KeyP2     string // second key half
	MasterKey string // reconstructed master key
	EncBC     string // encrypted bytecode
	RawBC     string // decrypted bytecode
	EnvTable  string // environment dispatch table
	MouseX    string // running mouse X state
	MouseY    string // running mouse Y state
	Timings   string // mousemove performance.now() samples
	T0        string // timing baseline (performance.now() at load)
	Result    string // VM return value
	Payload   string // final fetch() body object
	Push      string // _push stack helper
	Pop       string // _pop stack helper
	Sensors   string // shared sensor-value cache object
	Cache     string // caching wrapper function
}

// NewVarSet produces a fresh set of random names.
func NewVarSet() VarSet {
	return VarSet{
		VMFunc:    RandVarName("vm"),
		Stack:     RandVarName("sk"),
		Regs:      RandVarName("rg"),
		PC:        RandVarName("pc"),
		Op:        RandVarName("op"),
		OpLen:     RandVarName("ol"),
		Ops:       RandVarName("os"),
		Decode:    RandVarName("dc"),
		KeyP1:     RandVarName("k1"),
		KeyP2:     RandVarName("k2"),
		MasterKey: RandVarName("mk"),
		EncBC:     RandVarName("eb"),
		RawBC:     RandVarName("rb"),
		EnvTable:  RandVarName("et"),
		MouseX:    RandVarName("mx"),
		MouseY:    RandVarName("my"),
		Timings:   RandVarName("tm"),
		T0:        RandVarName("t0"),
		Result:    RandVarName("rs"),
		Payload:   RandVarName("pl"),
		Push:      RandVarName("ph"),
		Pop:       RandVarName("pp"),
		Sensors:   RandVarName("sn"),
		Cache:     RandVarName("ca"),
	}
}

// ─── Dead code injection ─────────────────────────────────────────────────────
//
// Inserted before the real VM body, these snippets compile and execute
// without producing observable side effects. Purpose: inflate the
// script, exercise the JS engine's optimizer, and trip simple
// signature-based analyzers.

var deadCodeTemplates = []string{
	`var {{.A}} = (function(){ var _t = []; for(var _i=0;_i<3;_i++) _t.push(_i*2); return _t; })();`,
	`var {{.B}} = (typeof navigator!=='undefined' && navigator.appName) || 'unknown'; if(false){ console.log({{.B}}); }`,
	`try { var {{.C}} = null; {{.C}}.x; } catch(_e) { void 0; }`,
	`var {{.D}} = Math.random() > 2 ? 'a' : 'b';`,
	`(function(){ var {{.E}} = Date.now(); if({{.E}} < 0){ fetch('/noop'); } })();`,
	`var {{.F}} = [1,2,3].filter(function(x){ return x > 10; });`,
}

// GenerateDeadCode produces a block of random-named dead code suitable
// for pasting directly into the JS template.
func GenerateDeadCode() string {
	var sb strings.Builder
	for _, tmplStr := range deadCodeTemplates {
		vars := map[string]string{
			"A": RandVarName("d"),
			"B": RandVarName("d"),
			"C": RandVarName("d"),
			"D": RandVarName("d"),
			"E": RandVarName("d"),
			"F": RandVarName("d"),
		}
		tmpl, err := template.New("dc").Parse(tmplStr)
		if err != nil {
			continue
		}
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, vars); err != nil {
			continue
		}
		sb.WriteString(buf.String())
		sb.WriteString("\n")
	}
	return sb.String()
}

// ─── String encoding ─────────────────────────────────────────────────────────

// EncodeStringLiteral encodes a string as a char-code array expression.
// Example:
//
//	EncodeStringLiteral("ab") =>
//	  [97,98].map(function(c){return String.fromCharCode(c);}).join('')
//
// It produces JS that evaluates to the original string at runtime but
// never appears in the source as a plain text literal. Currently not
// used by the main template but provided for extensions (e.g. hiding
// the fetch URL or the cookie name).
func EncodeStringLiteral(s string) string {
	codes := make([]string, 0, len([]rune(s)))
	for _, c := range s {
		codes = append(codes, fmt.Sprintf("%d", c))
	}
	return "[" + strings.Join(codes, ",") + "].map(function(c){return String.fromCharCode(c);}).join('')"
}

// RandomInt returns a cryptographically random int in [min, max).
// Returns min if max <= min.
func RandomInt(min, max int) int {
	if max <= min {
		return min
	}
	delta := int64(max - min)
	n, err := rand.Int(rand.Reader, big.NewInt(delta))
	if err != nil {
		return min
	}
	return min + int(n.Int64())
}
