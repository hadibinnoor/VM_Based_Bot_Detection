package challenge

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"

	"bot-defense/session"
)

// ChallengeSession carries all per-request cryptographic material.
// It is built fresh by NewChallengeSession every time /challenge/js is hit.
//
// Key splitting: rather than shipping the RC4 master key in the JS, we
// ship two random halves and let the VM reconstruct it by XOR at
// runtime. This prevents trivial grep-for-a-16-byte-string analysis and
// forces static analyzers to trace data flow through the runtime.
type ChallengeSession struct {
	SessionID   string              // 32-hex-char random identifier
	XORKey      []byte              // 16-byte RC4 master key (bytecode cipher)
	KeyPart1    []byte              // 16 random bytes
	KeyPart2    []byte              // XORKey XOR KeyPart1 (ships alongside KeyPart1)
	OpcodeMap   OpcodeMap           // logical-op → byte-value mapping for THIS session
	TokenRecipe session.TokenRecipe // per-session permutation for the hash input
	IssuedAt    int64               // unix milliseconds when the session was created
}

// NewChallengeSession generates the full set of cryptographic inputs
// for one challenge. The issuedAt argument is stored so the caller can
// persist it in Redis (and later compute response latency).
func NewChallengeSession(issuedAt int64) (*ChallengeSession, error) {
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("session id rand: %w", err)
	}

	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("master key rand: %w", err)
	}

	part1 := make([]byte, 16)
	if _, err := rand.Read(part1); err != nil {
		return nil, fmt.Errorf("key part rand: %w", err)
	}
	part2 := make([]byte, 16)
	for i := range key {
		part2[i] = key[i] ^ part1[i]
	}

	opcodes, err := GenerateOpcodeMap()
	if err != nil {
		return nil, fmt.Errorf("opcode map: %w", err)
	}

	recipe, err := session.NewTokenRecipe()
	if err != nil {
		return nil, fmt.Errorf("token recipe: %w", err)
	}

	return &ChallengeSession{
		SessionID:   hex.EncodeToString(idBytes),
		XORKey:      key,
		KeyPart1:    part1,
		KeyPart2:    part2,
		OpcodeMap:   opcodes,
		TokenRecipe: recipe,
		IssuedAt:    issuedAt,
	}, nil
}

// XORBytes encrypts (or decrypts — it's symmetric) data with a
// repeating key. The key MUST be non-empty or this panics.
// A fresh slice is allocated so the caller's input is never mutated.
//
// Deprecated: retained for tests and to keep the public surface stable.
// The live challenge pipeline uses RC4Encrypt — see Generate().
func XORBytes(data, key []byte) []byte {
	if len(key) == 0 {
		panic("XORBytes: empty key")
	}
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%len(key)]
	}
	return out
}

// RC4Encrypt encrypts data with the RC4 stream cipher using key.
// Decryption is the same operation (RC4 is symmetric), and the client
// runs an inline KSA + PRGA over the same 16-byte master key to recover
// the plaintext bytecode.
//
// Why RC4 instead of repeating XOR: a repeating XOR with a 16-byte key
// is defeated by any analyst who can observe two ciphertexts (or any
// known-plaintext structure like the per-instruction length byte being
// small). RC4 produces a non-repeating pseudo-random stream from a
// compact state (~256 bytes of S-box + 2 indices) that is trivially
// portable to a few hundred bytes of hand-written JS, so we get
// meaningful cryptographic opacity at essentially zero payload cost.
//
// This is obfuscation, not a keep-it-secret cipher — the key itself is
// still shipped (as two XOR halves) to the browser, so a determined
// reverse engineer can decrypt the bytecode. The goal is to break
// static pattern matching and raise the cost of automated analysis.
func RC4Encrypt(data, key []byte) []byte {
	if len(key) == 0 {
		panic("RC4Encrypt: empty key")
	}

	// Key-Scheduling Algorithm (KSA).
	var s [256]byte
	for i := 0; i < 256; i++ {
		s[i] = byte(i)
	}
	var j byte
	for i := 0; i < 256; i++ {
		j = j + s[i] + key[i%len(key)]
		s[i], s[j] = s[j], s[i]
	}

	// Pseudo-Random Generation Algorithm (PRGA).
	out := make([]byte, len(data))
	var a, b byte
	for k := 0; k < len(data); k++ {
		a++
		b += s[a]
		s[a], s[b] = s[b], s[a]
		out[k] = data[k] ^ s[(s[a]+s[b])&0xFF]
	}
	return out
}

// GenerateOpcodeMap randomly assigns a distinct byte value in
// [0x01, 0xFD] to every logical opcode. We reserve:
//
//	0x00 — avoided to keep a null byte from accidentally terminating
//	       any downstream string representation.
//	0xFE / 0xFF — kept free for potential future sentinel markers.
//
// rejection sampling ensures uniqueness without tracking state across
// retries.
func GenerateOpcodeMap() (OpcodeMap, error) {
	used := make(map[byte]bool)
	result := make(OpcodeMap, len(AllOps))

	// 253 possible values: 0x01..0xFD inclusive.
	const domain = 253

	for _, op := range AllOps {
		for attempt := 0; ; attempt++ {
			if attempt > 1024 {
				return nil, fmt.Errorf("opcode map: too many collisions")
			}
			n, err := rand.Int(rand.Reader, big.NewInt(domain))
			if err != nil {
				return nil, fmt.Errorf("opcode map rand: %w", err)
			}
			b := byte(n.Int64() + 1) // shift into 0x01..0xFD
			if !used[b] {
				result[op] = b
				used[b] = true
				break
			}
		}
	}
	return result, nil
}
