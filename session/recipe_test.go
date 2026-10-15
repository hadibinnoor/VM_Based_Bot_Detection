package session

import "testing"

// TestNewTokenRecipeIsValid asserts the recipe constructor produces a
// permutation containing exactly the indices 0..NumTokenSegments-1
// once each. Repeated runs should also produce different recipes
// (otherwise the per-session randomization is broken).
func TestNewTokenRecipeIsValid(t *testing.T) {
	r, err := NewTokenRecipe()
	if err != nil {
		t.Fatalf("NewTokenRecipe: %v", err)
	}
	if !r.IsValid() {
		t.Fatalf("recipe failed IsValid: %v", r.Permutation)
	}

	r2, err := NewTokenRecipe()
	if err != nil {
		t.Fatalf("NewTokenRecipe (2): %v", err)
	}
	if r.Permutation == r2.Permutation {
		// 17! ≈ 3.5e14 — the probability of collision is astronomical.
		t.Errorf("two consecutive recipes are identical: %v", r.Permutation)
	}
}

// TestIsValidRejectsMalformed exercises the IsValid guard so we know
// regressions in the verification path will be caught.
func TestIsValidRejectsMalformed(t *testing.T) {
	var zero TokenRecipe
	if zero.IsValid() {
		t.Error("zero-value recipe should be invalid")
	}

	var dup TokenRecipe
	for i := 0; i < NumTokenSegments; i++ {
		dup.Permutation[i] = byte(i)
	}
	dup.Permutation[3] = dup.Permutation[2]
	if dup.IsValid() {
		t.Error("recipe with duplicate index should be invalid")
	}

	var oob TokenRecipe
	for i := 0; i < NumTokenSegments; i++ {
		oob.Permutation[i] = byte(i)
	}
	oob.Permutation[0] = byte(NumTokenSegments) // out of range
	if oob.IsValid() {
		t.Error("recipe with out-of-range index should be invalid")
	}
}
