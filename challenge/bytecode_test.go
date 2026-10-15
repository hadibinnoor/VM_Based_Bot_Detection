package challenge

import (
	"encoding/hex"
	"strings"
	"testing"

	"bot-defense/session"
)

func TestBytecodeRoundTrip(t *testing.T) {
	opcodes, err := GenerateOpcodeMap()
	if err != nil {
		t.Fatalf("opcode map: %v", err)
	}
	recipe, err := session.NewTokenRecipe()
	if err != nil {
		t.Fatalf("token recipe: %v", err)
	}
	prog := BuildChallengeProgram(recipe)
	bc, err := Compile(prog, opcodes)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	if len(bc) == 0 {
		t.Fatal("empty bytecode")
	}
	t.Logf("bytecode (%d bytes): %s", len(bc), hex.EncodeToString(bc))

	// Round-trip via disassembler.
	lines, err := Disassemble(bc, opcodes)
	if err != nil {
		t.Fatalf("disassemble: %v", err)
	}
	if len(lines) != len(prog) {
		t.Fatalf("disassembled %d instructions, expected %d", len(lines), len(prog))
	}
	for i, l := range lines {
		if !strings.HasPrefix(strings.TrimSpace(l), prog[i].Op) {
			t.Errorf("line %d: %q does not start with op %q", i, l, prog[i].Op)
		}
	}
}

func TestXORRoundTrip(t *testing.T) {
	key := []byte{
		0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A,
		0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55,
	}
	data := []byte("hello world this is test bytecode data 1234")
	encrypted := XORBytes(data, key)
	if string(encrypted) == string(data) {
		t.Fatal("XOR is a no-op with non-zero key")
	}
	decrypted := XORBytes(encrypted, key)
	if string(decrypted) != string(data) {
		t.Fatalf("XOR round trip failed:\n got: %q\nwant: %q", string(decrypted), string(data))
	}
}

func TestKeySplit(t *testing.T) {
	sess, err := NewChallengeSession(12345)
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	if len(sess.XORKey) != 16 || len(sess.KeyPart1) != 16 || len(sess.KeyPart2) != 16 {
		t.Fatal("expected 16-byte key and halves")
	}
	for i := range sess.XORKey {
		recon := sess.KeyPart1[i] ^ sess.KeyPart2[i]
		if recon != sess.XORKey[i] {
			t.Fatalf("key split mismatch at byte %d: got 0x%02X want 0x%02X", i, recon, sess.XORKey[i])
		}
	}
}

func TestOpcodeMapUniqueness(t *testing.T) {
	opcodes, err := GenerateOpcodeMap()
	if err != nil {
		t.Fatalf("opcode map: %v", err)
	}
	if len(opcodes) != len(AllOps) {
		t.Fatalf("opcode map has %d entries, expected %d", len(opcodes), len(AllOps))
	}
	seen := map[byte]string{}
	for op, b := range opcodes {
		if b == 0x00 || b == 0xFE || b == 0xFF {
			t.Errorf("opcode %s assigned reserved byte 0x%02X", op, b)
		}
		if prev, ok := seen[b]; ok {
			t.Fatalf("duplicate byte value 0x%02X: %s and %s", b, prev, op)
		}
		seen[b] = op
	}
}

func TestSessionIsDifferentEachTime(t *testing.T) {
	s1, _ := NewChallengeSession(1)
	s2, _ := NewChallengeSession(2)
	if s1.SessionID == s2.SessionID {
		t.Error("expected different session IDs")
	}
	// Compare opcode assignments — it's astronomically unlikely they match.
	same := true
	for op := range s1.OpcodeMap {
		if s1.OpcodeMap[op] != s2.OpcodeMap[op] {
			same = false
			break
		}
	}
	if same {
		t.Error("opcode maps should differ across sessions")
	}
}
