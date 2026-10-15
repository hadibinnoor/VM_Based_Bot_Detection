package challenge

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"text/template"
	"time"

	"bot-defense/session"
)

// ChallengePayload is what Generator.Generate returns. The HTTP
// handler stores SessionID / IssuedAt / TokenRecipe in Redis and writes
// VMScript to the response body with the correct Content-Type.
type ChallengePayload struct {
	SessionID   string              // echo into Redis & verify payload
	IssuedAt    int64               // unix milliseconds
	TokenRecipe session.TokenRecipe // per-session hash-input permutation
	VMScript    string              // JS source to ship to the browser
}

// Generator produces fresh challenges. It is stateless and safe for
// concurrent use by multiple request goroutines.
type Generator struct {
	tmpl *template.Template
}

// NewGenerator parses the JS VM template once. Returns an error if the
// template itself is malformed (which is a programmer bug).
func NewGenerator() (*Generator, error) {
	tmpl, err := template.New("vm").Parse(vmTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse vm template: %w", err)
	}
	return &Generator{tmpl: tmpl}, nil
}

// MustNewGenerator is the panic-on-error variant. Use this from main()
// where a template error is a fatal programmer mistake.
func MustNewGenerator() *Generator {
	g, err := NewGenerator()
	if err != nil {
		panic(err)
	}
	return g
}

// Generate builds a complete, unique challenge payload.
//
// Steps:
//  1. Create a fresh ChallengeSession (session ID, RC4 key, key split, opcode map).
//  2. Compile the standard sensor program using this session's opcode map.
//  3. RC4-encrypt the bytecode with the session's key.
//  4. Build the JS switch-case body using this session's opcode byte values
//     AND this session's mangled variable names.
//  5. Render the top-level template with all of the above.
func (g *Generator) Generate() (*ChallengePayload, error) {
	now := time.Now()

	sess, err := NewChallengeSession(now.UnixMilli())
	if err != nil {
		return nil, fmt.Errorf("new session: %w", err)
	}

	prog := BuildChallengeProgram(sess.TokenRecipe)
	rawBC, err := Compile(prog, sess.OpcodeMap)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}

	encBC := RC4Encrypt(rawBC, sess.XORKey)

	vars := NewVarSet()
	switchBlock := buildSwitchBlock(sess.OpcodeMap, vars)

	data := struct {
		SessionID  string
		EncBC      string
		KeyP1      string
		KeyP2      string
		OpcodeCase string
		DeadCode   string
		V          VarSet
	}{
		SessionID:  sess.SessionID,
		EncBC:      hex.EncodeToString(encBC),
		KeyP1:      hex.EncodeToString(sess.KeyPart1),
		KeyP2:      hex.EncodeToString(sess.KeyPart2),
		OpcodeCase: switchBlock,
		DeadCode:   GenerateDeadCode(),
		V:          vars,
	}

	var buf bytes.Buffer
	if err := g.tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("template execute: %w", err)
	}

	return &ChallengePayload{
		SessionID:   sess.SessionID,
		IssuedAt:    now.UnixMilli(),
		TokenRecipe: sess.TokenRecipe,
		VMScript:    buf.String(),
	}, nil
}

// buildSwitchBlock generates the JS `switch` body that forms the core
// of the VM. Each case uses the per-session opcode byte value AND the
// per-session mangled variable names.
//
// A small helper closure makes it easy to substitute names into the
// case bodies without an intermediate pass over the rendered JS.
func buildSwitchBlock(opcodes OpcodeMap, v VarSet) string {
	var sb strings.Builder

	// Helpers for short-hand name substitution inside case bodies.
	push := v.Push
	pop := v.Pop
	regs := v.Regs
	envTable := v.EnvTable
	ops := v.Ops
	pc := v.PC

	// emit writes one case header + body + break.
	emit := func(op, body string) {
		opByte, ok := opcodes[op]
		if !ok {
			return
		}
		fmt.Fprintf(&sb, "            case 0x%02X: { // %s\n", opByte, op)
		sb.WriteString(indentLines(body, "                "))
		if !strings.HasSuffix(strings.TrimRight(body, " \t\n"), "return") {
			sb.WriteString("                break;\n")
		}
		sb.WriteString("            }\n")
	}

	emit(OP_PUSH, fmt.Sprintf(`%s(%s[0]);`, push, ops))

	emit(OP_POP, fmt.Sprintf(`%s();`, pop))

	emit(OP_STORE, fmt.Sprintf(`%s[%s[0]] = %s();`, regs, ops, pop))

	emit(OP_LOAD, fmt.Sprintf(`%s(%s[%s[0]]);`, push, regs, ops))

	emit(OP_CALL_ENV, fmt.Sprintf(
		`var _fn = %s[%s[0]]; %s(_fn ? _fn() : '');`,
		envTable, ops, push,
	))

	emit(OP_CONCAT, fmt.Sprintf(
		`var _b = String(%s()); var _a = String(%s()); %s(_a + _b);`,
		pop, pop, push,
	))

	emit(OP_ADD, fmt.Sprintf(
		`var _b2 = Number(%s()); var _a2 = Number(%s()); %s(_a2 + _b2);`,
		pop, pop, push,
	))

	emit(OP_SUBSTR, fmt.Sprintf(
		`%s(String(%s()).slice(0, 8));`,
		push, pop,
	))

	// FNV-1a 32-bit string hash, returned as lowercase hex.
	emit(OP_HASH, fmt.Sprintf(
		`var _s = String(%s());
var _h = 0x811c9dc5 >>> 0;
for (var _ci = 0; _ci < _s.length; _ci++) {
    _h ^= _s.charCodeAt(_ci);
    _h = Math.imul(_h, 0x01000193);
}
%s((_h >>> 0).toString(16));`,
		pop, push,
	))

	emit(OP_ENCODE, fmt.Sprintf(
		`try { %s(btoa(unescape(encodeURIComponent(String(%s()))))); }
catch(_e) { %s('enc_err'); }`,
		push, pop, push,
	))

	// ── Control flow: JMP (unconditional relative jump) ─────────────
	// operand[0] is a signed int8 offset added to PC *after* the
	// instruction has been fully consumed. Sign-extension is done via
	// `(x << 24) >> 24` which is the idiomatic 8→32 sign extension
	// in JavaScript without resorting to DataView.
	emit(OP_JMP, fmt.Sprintf(
		`var _off = (%s[0] << 24) >> 24; %s += _off;`,
		ops, pc,
	))

	// ── Control flow: JEQ (pop two, jump if equal) ─────────────────
	// Used for opaque predicates in BuildChallengeProgram: we push a
	// constant twice and JEQ, which always succeeds, but a linear
	// disassembler has no way to know that statically and must parse
	// the decoy bytes between here and the jump target.
	emit(OP_JEQ, fmt.Sprintf(
		`var _jb = %s(); var _ja = %s();
if (String(_ja) === String(_jb)) {
    var _jo = (%s[0] << 24) >> 24;
    %s += _jo;
}`,
		pop, pop, ops, pc,
	))

	// RET: terminate the VM by returning the top of stack. Written
	// manually to omit the trailing break (unreachable after return).
	if retByte, ok := opcodes[OP_RET]; ok {
		fmt.Fprintf(&sb, "            case 0x%02X: { // RET\n", retByte)
		fmt.Fprintf(&sb, "                return %s();\n", pop)
		sb.WriteString("            }\n")
	}

	return sb.String()
}

// indentLines prefixes each line of s with prefix, preserving line
// breaks. Used so multi-line case bodies align in the rendered JS.
func indentLines(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if line == "" && i == len(lines)-1 {
			continue
		}
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n") + "\n"
}
