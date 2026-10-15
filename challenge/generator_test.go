package challenge

import (
	"strings"
	"testing"
)

func TestGenerateProducesValidJS(t *testing.T) {
	g, err := NewGenerator()
	if err != nil {
		t.Fatalf("new generator: %v", err)
	}
	p, err := g.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if len(p.SessionID) != 32 {
		t.Errorf("session id length = %d, want 32", len(p.SessionID))
	}
	if p.IssuedAt == 0 {
		t.Error("IssuedAt should be set")
	}
	js := p.VMScript
	if !strings.HasPrefix(strings.TrimSpace(js), "(function()") {
		t.Error("script is not wrapped in IIFE")
	}
	for _, want := range []string{
		"fetch('/challenge/verify'",
		"sid:",
		"performance.now",
		"navigator.userAgent",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("script missing substring %q", want)
		}
	}
	// Session ID must appear literally in the payload body.
	if !strings.Contains(js, p.SessionID) {
		t.Error("session ID should appear in rendered script")
	}
}

func TestGeneratePolymorphism(t *testing.T) {
	g := MustNewGenerator()
	a, _ := g.Generate()
	b, _ := g.Generate()
	if a.VMScript == b.VMScript {
		t.Fatal("two challenges produced identical bytes")
	}
	// Sanity: challenges differ in at least half their length.
	diff := 0
	for i := 0; i < len(a.VMScript) && i < len(b.VMScript); i++ {
		if a.VMScript[i] != b.VMScript[i] {
			diff++
		}
	}
	if diff == 0 {
		t.Error("challenges should differ at many positions")
	}
}

func TestSwitchBlockContainsAllOps(t *testing.T) {
	opcodes, _ := GenerateOpcodeMap()
	vars := NewVarSet()
	block := buildSwitchBlock(opcodes, vars)
	for _, op := range AllOps {
		if !strings.Contains(block, "// "+op) {
			t.Errorf("switch block missing case for %s", op)
		}
	}
}
