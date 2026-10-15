// Package challenge implements Module 2 of the bot-defense pipeline:
// per-request generation of a polymorphic JavaScript virtual machine
// that collects behavioral/environmental signals from the browser.
//
// The pipeline is:
//
//	BuildChallengeProgram()  →  Program          (list of logical instructions)
//	NewChallengeSession()    →  ChallengeSession (random RC4 key, opcode map)
//	Compile(prog, opcodes)   →  []byte           (bytecode using THIS session's opcodes)
//	RC4Encrypt(bc, key)      →  []byte           (encrypted bytecode)
//	Generator.Generate()     →  ChallengePayload (JS script with all of the above)
//
// Everything except the logical ENV_* IDs rotates per request.
package challenge

// ─── Base opcodes ─────────────────────────────────────────────────────────────
//
// These are LOGICAL operation names. The byte value assigned to each
// name is randomized per session (see GenerateOpcodeMap). The JS VM
// template is rendered with the session's specific byte values in its
// switch-case so a decompiler cannot rely on a fixed table.

const (
	// Stack operations.
	OP_PUSH  = "PUSH"  // operand: 1 byte — push literal byte onto stack
	OP_POP   = "POP"   // no operands — discard top of stack
	OP_STORE = "STORE" // operand: 1 byte reg_id — pop → regs[id]
	OP_LOAD  = "LOAD"  // operand: 1 byte reg_id — push regs[id]

	// Environment calls: dispatch into the envTable and push its result.
	OP_CALL_ENV = "CALL_ENV" // operand: 1 byte env_id

	// Arithmetic / string operations.
	OP_CONCAT = "CONCAT" // pop 2 strings, push joined
	OP_ADD    = "ADD"    // pop 2 numbers, push sum
	OP_SUBSTR = "SUBSTR" // pop string, push first 8 chars

	// Cryptographic / encoding primitives.
	OP_HASH   = "HASH"   // pop string, push FNV-1a 32-bit hex
	OP_ENCODE = "ENCODE" // pop string, push base64

	// Control flow.
	OP_RET = "RET" // return top of stack, terminate VM loop
	// OP_JMP: unconditional relative jump. Operand: 1 signed int8 byte.
	// The offset is added to PC AFTER the JMP instruction has been
	// consumed (i.e. PC already advanced past the operand).
	OP_JMP = "JMP"
	// OP_JEQ: pop two stack values, compare (string equality) and take
	// the jump iff equal. Operand: 1 signed int8 byte (same semantics
	// as OP_JMP). Used to build opaque predicates.
	OP_JEQ = "JEQ"
)

// AllOps enumerates every logical opcode name. Used by GenerateOpcodeMap
// so that a new opcode added above automatically gets a byte assignment.
var AllOps = []string{
	OP_PUSH, OP_POP, OP_STORE, OP_LOAD,
	OP_CALL_ENV, OP_CONCAT, OP_ADD, OP_SUBSTR,
	OP_HASH, OP_ENCODE, OP_RET,
	OP_JMP, OP_JEQ,
}

// ─── Environment IDs ──────────────────────────────────────────────────────────
//
// These are STABLE byte values that identify which browser sensor to
// invoke. They are operands to OP_CALL_ENV and are embedded plainly in
// the bytecode; stability is acceptable because they are only
// meaningful AFTER a CALL_ENV opcode is executed (whose byte itself
// rotates).

const (
	ENV_USER_AGENT    = byte(0x01) // navigator.userAgent
	ENV_SCREEN_W      = byte(0x02) // screen.width
	ENV_SCREEN_H      = byte(0x03) // screen.height
	ENV_TIMEZONE      = byte(0x04) // Intl.DateTimeFormat().resolvedOptions().timeZone
	ENV_LANGUAGE      = byte(0x05) // navigator.language
	ENV_TIMESTAMP     = byte(0x06) // Date.now()
	ENV_CANVAS_FP     = byte(0x07) // canvas 2D rendering fingerprint
	ENV_WEBGL_VENDOR  = byte(0x08) // WEBGL_debug_renderer_info UNMASKED_VENDOR
	ENV_PLATFORM      = byte(0x09) // navigator.platform
	ENV_TOUCH         = byte(0x0A) // 'ontouchstart' in window
	ENV_MOUSE_X       = byte(0x0B) // last mousemove clientX
	ENV_MOUSE_Y       = byte(0x0C) // last mousemove clientY
	ENV_TIMING_FP     = byte(0x0D) // performance.now() jitter fingerprint
	ENV_COLOR_DEPTH   = byte(0x0E) // screen.colorDepth
	ENV_DEVICE_MEMORY = byte(0x0F) // navigator.deviceMemory (hint only)
	ENV_CONCURRENCY   = byte(0x10) // navigator.hardwareConcurrency
	// ENV_SESSION_ID returns the per-request 32-hex-char challenge
	// session ID (the same value the server stores in Redis). Hashing
	// it into the final token binds the token to the specific issued
	// challenge and defeats token-farming / replay attacks — an
	// attacker who collects a (sensor, token) pair from session A
	// cannot replay token_A against a fresh session B, because the
	// server's reconstruction will hash SID_B and not SID_A.
	ENV_SESSION_ID = byte(0x11)
	// Tier-1 automation probes + Tier-2 coherence anchors.
	ENV_WEBDRIVER      = byte(0x12) // navigator.webdriver
	ENV_AUTOMATION_SIG = byte(0x13) // known automation globals found
	ENV_PLUGINS_LEN    = byte(0x14) // navigator.plugins.length
	ENV_LANGUAGES      = byte(0x15) // navigator.languages joined by ","
	ENV_NOTIF_COHER    = byte(0x16) // notification permission coherence check
	ENV_TZ_OFFSET      = byte(0x17) // Date#getTimezoneOffset
	ENV_DEVICE_PIXEL   = byte(0x18) // window.devicePixelRatio
)

// OpcodeMap maps logical op name → actual byte value for the session.
// Exactly one mapping exists per session; regenerated on every request.
type OpcodeMap map[string]byte

// OpcodeMapInverse is the reverse lookup (byte → logical name), used
// for debugging and potential disassembly during tests.
type OpcodeMapInverse map[byte]string

// Invert returns the reverse lookup of an OpcodeMap.
func (m OpcodeMap) Invert() OpcodeMapInverse {
	out := make(OpcodeMapInverse, len(m))
	for name, b := range m {
		out[b] = name
	}
	return out
}
