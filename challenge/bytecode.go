package challenge

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"bot-defense/session"
)

// Instruction is one logical VM instruction before serialization.
// Operands are raw bytes; their meaning depends on Op.
//
// jumpTarget is an assembly-time hint used by ProgramBuilder. When set,
// Compile treats the single operand byte as a label-resolution
// placeholder and the builder patches it with the computed signed
// offset before handing the Program off.
type Instruction struct {
	Op       string // logical op name, e.g. OP_CALL_ENV
	Operands []byte // zero or more operand bytes
}

// Program is an ordered sequence of instructions. Execution in the VM
// begins at index 0 and proceeds until OP_RET or end-of-bytecode.
type Program []Instruction

// ─── Label-based program builder ──────────────────────────────────────────────
//
// BuildChallengeProgram uses a small assembler so we can write opaque
// predicates and loops without hand-computing byte offsets across a
// variable-length instruction stream.
//
// Usage:
//
//	b := newProgramBuilder()
//	b.Emit(OP_PUSH, 0xAA)
//	b.Emit(OP_PUSH, 0xAA)
//	b.EmitJump(OP_JEQ, "skip")
//	b.Emit(OP_CALL_ENV, 0xFF) // junk — never reached
//	b.Label("skip")
//	... real work ...
//	prog, err := b.Build()
//
// Jump offsets are signed 8-bit (range -128..+127 bytes). Build()
// returns an error if any jump is out of range, or if a label referenced
// by a jump is undefined.

type jumpFixup struct {
	instrIdx int    // index of the jump Instruction in the builder list
	target   string // destination label name
}

type programBuilder struct {
	instrs []Instruction
	labels map[string]int // label name → NEXT instruction index (so "Label; Emit" lands AT the emitted instr)
	jumps  []jumpFixup
}

func newProgramBuilder() *programBuilder {
	return &programBuilder{labels: map[string]int{}}
}

// Emit appends a regular instruction with zero or more operand bytes.
func (b *programBuilder) Emit(op string, operands ...byte) {
	b.instrs = append(b.instrs, Instruction{Op: op, Operands: append([]byte(nil), operands...)})
}

// EmitJump appends a jump-class instruction (OP_JMP or OP_JEQ) whose
// operand byte will be patched in Build() to the correct signed offset.
func (b *programBuilder) EmitJump(op, targetLabel string) {
	b.jumps = append(b.jumps, jumpFixup{instrIdx: len(b.instrs), target: targetLabel})
	b.instrs = append(b.instrs, Instruction{Op: op, Operands: []byte{0x00}})
}

// Label declares that the next Emit/EmitJump lands at this label.
// A label may be referenced before it is declared (forward jump).
func (b *programBuilder) Label(name string) {
	if _, exists := b.labels[name]; exists {
		panic(fmt.Sprintf("duplicate label %q", name))
	}
	b.labels[name] = len(b.instrs)
}

// Build resolves all jump targets and returns a runnable Program.
//
// On-wire layout of each instruction is [op][len][operand_bytes], so a
// jump that sits at instruction index i has its "PC after consumed"
// byte position equal to offsets[i+1]. The landing byte for label L is
// offsets[labels[L]].
func (b *programBuilder) Build() (Program, error) {
	offsets := make([]int, len(b.instrs)+1)
	for i, ins := range b.instrs {
		offsets[i+1] = offsets[i] + 2 + len(ins.Operands)
	}

	for _, f := range b.jumps {
		dstIdx, ok := b.labels[f.target]
		if !ok {
			return nil, fmt.Errorf("undefined jump label %q", f.target)
		}
		srcByte := offsets[f.instrIdx+1]
		dstByte := offsets[dstIdx]
		delta := dstByte - srcByte
		if delta < -128 || delta > 127 {
			return nil, fmt.Errorf("jump to %q out of int8 range: %d", f.target, delta)
		}
		b.instrs[f.instrIdx].Operands[0] = byte(int8(delta))
	}

	return Program(append([]Instruction(nil), b.instrs...)), nil
}

// ─── BuildChallengeProgram ────────────────────────────────────────────────────

// BuildChallengeProgram returns the canonical sensor-collection routine.
//
// Register layout produced at runtime:
//
//	regs[0x00]  = userAgent
//	regs[0x01]  = screenW + screenH
//	regs[0x02]  = timezone
//	regs[0x03]  = canvasFingerprint
//	regs[0x04]  = webglVendor
//	regs[0x05]  = mouseX + mouseY
//	regs[0x06]  = timingFingerprint
//	regs[0x07]  = platform
//	regs[0x08]  = colorDepth
//	regs[0x09]  = sessionID       (binds the token to this request)
//	regs[0x0A]  = webdriver flag
//	regs[0x0B]  = automation globals signature
//	regs[0x0C]  = plugins length
//	regs[0x0D]  = navigator.languages signature
//	regs[0x0E]  = notification coherence status
//	regs[0x0F]  = timezone offset minutes
//	regs[0x10]  = device pixel ratio
//	regs[0x20]  = loop counter    (scratch, discarded)
//
// Final value returned: base64( FNV1a( concat of regs in recipe order ) ).
// The hash_stage emits LOAD/CONCAT in the order specified by recipe.
// Permutation, so the same 17 inputs are mixed in a session-specific
// order. The server persists the recipe in Redis so it can recompute
// the expected token.
//
// The program is polymorphic at the byte level because of three things:
//  1. Opcode remapping (see GenerateOpcodeMap).
//  2. Opaque predicates and a junk loop emitted by this builder.
//  3. Per-session permutation of the hash-stage register loads.
//
// Opaque predicates: we push identical bytes and use OP_JEQ to branch
// over a block of decoy bytecode. Because the decoys decode as valid
// instructions, a naive linear disassembler will "see" env-call IDs
// and arithmetic that never actually run.
//
// Junk loop: a short counter loop (stored in a scratch register) runs
// a handful of iterations before the real hash chain. Its observable
// effect is zero; its structural effect is a back-edge in the control
// flow graph, which defeats the assumption that the VM is purely
// linear.
func BuildChallengeProgram(recipe session.TokenRecipe) Program {
	if !recipe.IsValid() {
		panic("BuildChallengeProgram: invalid token recipe")
	}
	b := newProgramBuilder()

	// ── Opaque predicate #1 ─────────────────────────────────────────
	// push K; push K; JEQ real_start — always taken.
	// The decoy block between here and `real_start` contains plausible
	// but unreachable CALL_ENV / STORE / HASH bytes.
	junkByte1 := randomDecoyByte()
	b.Emit(OP_PUSH, junkByte1)
	b.Emit(OP_PUSH, junkByte1)
	b.EmitJump(OP_JEQ, "real_start")

	// ── Decoy block (never executed, parsed only by static tools) ──
	b.Emit(OP_CALL_ENV, 0xFE) // not defined in envTable → would return ''
	b.Emit(OP_STORE, 0x1F)
	b.Emit(OP_CALL_ENV, 0xFD)
	b.Emit(OP_PUSH, randomDecoyByte())
	b.Emit(OP_HASH)

	b.Label("real_start")

	// ── Junk loop: ~3 iterations, side-effect free ─────────────────
	// reg[0x20] = 0
	b.Emit(OP_PUSH, 0x00)
	b.Emit(OP_STORE, 0x20)

	b.Label("loop_head")
	b.Emit(OP_LOAD, 0x20)
	b.Emit(OP_PUSH, 0x03) // loop target
	b.EmitJump(OP_JEQ, "loop_end")

	// Body: increment reg[0x20] by 1. The ADD opcode coerces to Number
	// and pushes sum; we then STORE back.
	b.Emit(OP_LOAD, 0x20)
	b.Emit(OP_PUSH, 0x01)
	b.Emit(OP_ADD)
	b.Emit(OP_STORE, 0x20)
	b.EmitJump(OP_JMP, "loop_head")

	b.Label("loop_end")

	// ── Real sensor collection ─────────────────────────────────────
	// userAgent → regs[0x00]
	b.Emit(OP_CALL_ENV, ENV_USER_AGENT)
	b.Emit(OP_STORE, 0x00)

	// screenW ++ screenH → regs[0x01]
	b.Emit(OP_CALL_ENV, ENV_SCREEN_W)
	b.Emit(OP_CALL_ENV, ENV_SCREEN_H)
	b.Emit(OP_CONCAT)
	b.Emit(OP_STORE, 0x01)

	// timezone → regs[0x02]
	b.Emit(OP_CALL_ENV, ENV_TIMEZONE)
	b.Emit(OP_STORE, 0x02)

	// canvas fingerprint → regs[0x03]
	b.Emit(OP_CALL_ENV, ENV_CANVAS_FP)
	b.Emit(OP_STORE, 0x03)

	// webgl vendor → regs[0x04]
	b.Emit(OP_CALL_ENV, ENV_WEBGL_VENDOR)
	b.Emit(OP_STORE, 0x04)

	// mouseX ++ mouseY → regs[0x05]
	b.Emit(OP_CALL_ENV, ENV_MOUSE_X)
	b.Emit(OP_CALL_ENV, ENV_MOUSE_Y)
	b.Emit(OP_CONCAT)
	b.Emit(OP_STORE, 0x05)

	// timing fingerprint → regs[0x06]
	b.Emit(OP_CALL_ENV, ENV_TIMING_FP)
	b.Emit(OP_STORE, 0x06)

	// platform → regs[0x07]
	b.Emit(OP_CALL_ENV, ENV_PLATFORM)
	b.Emit(OP_STORE, 0x07)

	// colorDepth → regs[0x08]
	b.Emit(OP_CALL_ENV, ENV_COLOR_DEPTH)
	b.Emit(OP_STORE, 0x08)

	// sessionID → regs[0x09]   (server-bound challenge)
	b.Emit(OP_CALL_ENV, ENV_SESSION_ID)
	b.Emit(OP_STORE, 0x09)

	// webdriver flag → regs[0x0A]
	b.Emit(OP_CALL_ENV, ENV_WEBDRIVER)
	b.Emit(OP_STORE, 0x0A)

	// automation globals signature → regs[0x0B]
	b.Emit(OP_CALL_ENV, ENV_AUTOMATION_SIG)
	b.Emit(OP_STORE, 0x0B)

	// plugins length → regs[0x0C]
	b.Emit(OP_CALL_ENV, ENV_PLUGINS_LEN)
	b.Emit(OP_STORE, 0x0C)

	// navigator.languages signature → regs[0x0D]
	b.Emit(OP_CALL_ENV, ENV_LANGUAGES)
	b.Emit(OP_STORE, 0x0D)

	// notification API coherence → regs[0x0E]
	b.Emit(OP_CALL_ENV, ENV_NOTIF_COHER)
	b.Emit(OP_STORE, 0x0E)

	// timezone offset minutes → regs[0x0F]
	b.Emit(OP_CALL_ENV, ENV_TZ_OFFSET)
	b.Emit(OP_STORE, 0x0F)

	// devicePixelRatio → regs[0x10]
	b.Emit(OP_CALL_ENV, ENV_DEVICE_PIXEL)
	b.Emit(OP_STORE, 0x10)

	// ── Opaque predicate #2: skip a second junk block ──────────────
	junkByte2 := randomDecoyByte()
	b.Emit(OP_PUSH, junkByte2)
	b.Emit(OP_PUSH, junkByte2)
	b.EmitJump(OP_JEQ, "hash_stage")

	b.Emit(OP_CALL_ENV, 0xFC)
	b.Emit(OP_SUBSTR)
	b.Emit(OP_PUSH, randomDecoyByte())
	b.Emit(OP_ENCODE)

	b.Label("hash_stage")

	// Concatenate all sensor registers into a single string in the
	// session's recipe order, then hash. Segment index i in the recipe
	// corresponds to register byte i (the layout is documented in the
	// register table above and mirrored on the server side in
	// validation.ExpectedTokenWithRecipe).
	//
	// Stack discipline note: OP_CONCAT pops two values and pushes
	// String(a) + String(b) where a was pushed first (deeper on the
	// stack) and b was pushed second. So a `LOAD r0; LOAD r1; CONCAT`
	// produces "r0r1" on top of stack — the natural left-to-right
	// concatenation we want.
	b.Emit(OP_LOAD, recipe.Permutation[0])
	for i := 1; i < session.NumTokenSegments; i++ {
		b.Emit(OP_LOAD, recipe.Permutation[i])
		b.Emit(OP_CONCAT)
	}

	b.Emit(OP_HASH)
	b.Emit(OP_ENCODE)
	b.Emit(OP_RET)

	prog, err := b.Build()
	if err != nil {
		// Programmer error — fail loudly during development rather
		// than ship a silently broken challenge.
		panic(fmt.Sprintf("BuildChallengeProgram: %v", err))
	}
	return prog
}

// randomDecoyByte returns a non-zero byte that is unlikely to coincide
// with a common logical opcode value. Used to fill decoy blocks with
// plausible-looking operand data.
func randomDecoyByte() byte {
	n, err := rand.Int(rand.Reader, big.NewInt(254))
	if err != nil {
		return 0xA5
	}
	b := byte(n.Int64() + 1)
	if b == 0 {
		b = 0xA5
	}
	return b
}

// Compile serializes a Program into a byte slice using the provided
// OpcodeMap. The on-wire format for each instruction is:
//
//	[1 byte opcode] [1 byte operand_length] [operand_length bytes operands]
//
// A length-prefix makes the VM loop trivial and future-proof: we can
// introduce variable-width operand instructions without changing the
// parser.
func Compile(prog Program, opcodes OpcodeMap) ([]byte, error) {
	var out []byte
	for i, instr := range prog {
		opByte, ok := opcodes[instr.Op]
		if !ok {
			return nil, fmt.Errorf("compile: unknown opcode %q at index %d", instr.Op, i)
		}
		if len(instr.Operands) > 255 {
			return nil, fmt.Errorf("compile: operand too long (%d) at index %d", len(instr.Operands), i)
		}
		out = append(out, opByte)
		out = append(out, byte(len(instr.Operands)))
		out = append(out, instr.Operands...)
	}
	return out, nil
}

// Disassemble is a helper for tests: it walks bytecode produced by
// Compile and returns a human-readable list of "OPNAME [op1 op2 ...]"
// lines. Not called at runtime; present for unit tests and debugging.
func Disassemble(bc []byte, opcodes OpcodeMap) ([]string, error) {
	inv := opcodes.Invert()
	var out []string
	for pc := 0; pc < len(bc); {
		if pc+2 > len(bc) {
			return nil, fmt.Errorf("disassemble: truncated header at pc=%d", pc)
		}
		op := bc[pc]
		ln := int(bc[pc+1])
		pc += 2
		if pc+ln > len(bc) {
			return nil, fmt.Errorf("disassemble: truncated operands at pc=%d", pc)
		}
		name, ok := inv[op]
		if !ok {
			name = fmt.Sprintf("UNK_0x%02X", op)
		}
		out = append(out, fmt.Sprintf("%-10s % X", name, bc[pc:pc+ln]))
		pc += ln
	}
	return out, nil
}
