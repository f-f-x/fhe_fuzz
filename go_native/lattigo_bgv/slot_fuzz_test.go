package lattigobgv

// This file is deliberately separate from the polynomial-expression fuzzers.
// A BGV batch is a 2 x (MaxSlots/2) matrix: slot permutations, row swaps and
// partial sums have vector semantics that cannot be represented faithfully by
// ExprSpec's one-variable polynomial model.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

type slotProgram struct {
	Operation int
	Pattern   int
	Rotation  int
	BatchSize int
	Count     int
	Active    int
	Data      []byte
}

type slotSchedule struct {
	batchSize int
	count     int
}

var rotateAndAddSchedules = []slotSchedule{
	{1, 2}, {3, 7}, {8, 32},
}

var rotations = []int{-7, -2, -1, 1, 2, 7}

func byteAt(data []byte, i int) byte {
	if len(data) == 0 {
		return 0
	}
	return data[i%len(data)]
}

func activeSlots(data []byte, slots int) int {
	// Exact length boundaries are part of the public batched encoder contract.
	// The encoder implementation clears the unmapped slots; keeping these
	// representatives in the corpus catches stale-buffer and prefix errors.
	lengths := []int{0, 1, 2, 7, 8, 16, slots/2 - 1, slots / 2, slots - 1, slots}
	return lengths[int(byteAt(data, 1))%len(lengths)]
}

func innerSumSchedules(slots int) []slotSchedule {
	return []slotSchedule{{1, 2}, {2, 4}, {8, 8}, {1, slots}}
}

func decodeSlotProgram(data []byte, slots int) slotProgram {
	schedules := innerSumSchedules(slots)
	schedule := schedules[int(byteAt(data, 3))%len(schedules)]
	return slotProgram{
		Operation: int(byteAt(data, 0)) % 6,
		Pattern:   int(byteAt(data, 2)) % 7,
		Rotation:  rotations[int(byteAt(data, 4))%len(rotations)],
		BatchSize: schedule.batchSize,
		Count:     schedule.count,
		Active:    activeSlots(data, slots),
		Data:      data,
	}
}

func centeredByte(b byte) int64 {
	return int64(int(b) - 128)
}

func boundaryValue(data []byte, i int) int64 {
	boundaries := []int64{0, 1, -1, 2, -2, 127, -127, 128, -128, 256, -256, 257, -257}
	return boundaries[int(byteAt(data, i))%len(boundaries)]
}

// makeSlotVector uses spatially distinctive patterns. Random values alone are
// weak at detecting a rotation, because accidental repeated values can mask a
// misplaced slot.
func makeSlotVector(p slotProgram, slots int) []int64 {
	values := make([]int64, slots)
	half := slots / 2
	switch p.Pattern {
	case 0: // one-hot, including a selectable tail slot
		values[int(byteAt(p.Data, 5))%slots] = boundaryValue(p.Data, 6)
	case 1: // first/last sentinels, catches prefix and tail truncation
		values[0] = 127
		values[half-1] = -128
		values[half] = 128
		values[slots-1] = -127
	case 2: // alternating signs, catches a one-slot rotation immediately
		for i := range values {
			if i%2 == 0 {
				values[i] = 127
			} else {
				values[i] = -128
			}
		}
	case 3: // periodic boundary pattern
		for i := range values {
			values[i] = boundaryValue(p.Data, 5+i)
		}
	case 4: // sparse sentinels in both rows
		for _, off := range []int{0, 1, half - 1, half, half + 1, slots - 1} {
			values[off] = boundaryValue(p.Data, 5+off)
		}
	case 5: // dense byte-derived values
		for i := range values {
			values[i] = centeredByte(byteAt(p.Data, 5+i))
		}
	case 6: // row-distinct ramp; a row swap cannot hide in a uniform vector
		for i := 0; i < half; i++ {
			values[i] = center(int64(i) - 128)
			values[half+i] = center(int64(i) + 17)
		}
	}
	return values
}

func paddedPrefix(values []int64, active int) []int64 {
	result := make([]int64, len(values))
	copy(result, values[:active])
	return result
}

func decodeAll(t testing.TB, c *testContext, ct *rlwe.Ciphertext) []int64 {
	t.Helper()
	got := make([]int64, c.params.MaxSlots())
	if err := c.eval.Decode(c.dec.DecryptNew(ct), got); err != nil {
		t.Fatal(err)
	}
	return got
}

func firstMismatch(got, want []int64) int {
	if len(got) != len(want) {
		return -2
	}
	for i := range want {
		if !sameResidue(got[i], want[i]) {
			return i
		}
	}
	return -1
}

func rotateColumnsExpected(values []int64, k int) []int64 {
	result := make([]int64, len(values))
	half := len(values) / 2
	for row := 0; row < 2; row++ {
		start := row * half
		copy(result[start:start+half], rotateSliceExpected(values[start:start+half], k))
	}
	return result
}

func rotateSliceExpected(values []int64, k int) []int64 {
	result := make([]int64, len(values))
	for i := range values {
		j := (i + k) % len(values)
		if j < 0 {
			j += len(values)
		}
		result[i] = values[j]
	}
	return result
}

func rotateRowsExpected(values []int64) []int64 {
	result := make([]int64, len(values))
	half := len(values) / 2
	copy(result[:half], values[half:])
	copy(result[half:], values[:half])
	return result
}

func rotateAndAddExpected(values []int64, batchSize, n int) []int64 {
	result := append([]int64(nil), values...)
	for i := 1; i < n; i++ {
		rotated := rotateColumnsExpected(values, i*batchSize)
		for j := range result {
			result[j] = center(result[j] + rotated[j])
		}
	}
	return result
}

// innerSumExpected is intentionally the same reference construction used by
// Lattigo's BGV test suite. InnerSum leaves non-leading slots unspecified; the
// caller checks exactly the documented leading batch in every block.
func innerSumExpected(values []int64, batchSize, n int) []int64 {
	result := append([]int64(nil), values...)
	if n == 1 {
		return result
	}
	length := n * batchSize
	aggregate := length == len(values)
	partialN := n
	if aggregate {
		partialN /= 2
	}
	half := len(values) / 2
	row0 := append([]int64(nil), values[:half]...)
	row1 := append([]int64(nil), values[half:]...)
	for i := 1; i < partialN; i++ {
		rot0 := rotateSliceExpected(row0, i*batchSize)
		rot1 := rotateSliceExpected(row1, i*batchSize)
		for j := 0; j < half; j++ {
			result[j] = center(result[j] + rot0[j])
			result[j+half] = center(result[j+half] + rot1[j])
		}
	}
	if aggregate {
		for j := 0; j < half; j++ {
			result[j] = center(result[j] + result[j+half])
		}
	}
	return result
}

func galoisCacheKey(galEls []uint64) string {
	return fmt.Sprint(galEls)
}

func (c *testContext) evaluatorWithGalois(t testing.TB, galEls []uint64) *bgv.Evaluator {
	t.Helper()
	key := galoisCacheKey(galEls)
	if evaluator, ok := c.evalByGalois[key]; ok {
		return evaluator
	}
	gks := c.kgen.GenGaloisKeysNew(galEls, c.sk)
	evaluator := bgv.NewEvaluator(c.params, rlwe.NewMemEvaluationKeySet(c.relin, gks...), false)
	c.evalByGalois[key] = evaluator
	return evaluator
}

func slotMismatch(t *testing.T, source string, p slotProgram, input, got, want []int64) {
	t.Helper()
	slot := firstMismatch(got, want)
	if slot >= 0 {
		writeSlotArtifact(t, source, p, input)
		t.Fatalf("%s: slot %d: got %d want %d", source, slot, got[slot], want[slot])
	}
	if slot == -2 {
		writeSlotArtifact(t, source, p, input)
		t.Fatalf("%s: output length %d want %d", source, len(got), len(want))
	}
}

func slotInnerSumMismatch(t *testing.T, source string, p slotProgram, input, got, want []int64) {
	t.Helper()
	block := p.BatchSize * p.Count
	for start := 0; start < len(want); start += block {
		for j := 0; j < p.BatchSize; j++ {
			idx := start + j
			if !sameResidue(got[idx], want[idx]) {
				writeSlotArtifact(t, source, p, input)
				t.Fatalf("%s: slot %d: got %d want %d", source, idx, got[idx], want[idx])
			}
		}
	}
}

func injectedSlotFault(got []int64, p slotProgram) []int64 {
	if os.Getenv("FHE_FUZZ_SLOT_FAULT") != "rotation-plus-one" || p.Operation != 1 {
		return got
	}
	// Opt-in oracle gate: model an evaluator that rotates one extra slot. This
	// is never active in normal testing and is deliberately tied to the actual
	// rotation semantic oracle rather than a generic output+1 mutation.
	return rotateColumnsExpected(got, 1)
}

// FuzzBGVSlotProgram covers the BGV SIMD-specific operations absent from the
// polynomial oracle: full-slot round trips, column/row rotations,
// RotateAndAdd and InnerSum. It compares to exact modular vector semantics.
func FuzzBGVSlotProgram(f *testing.F) {
	c := newTestContext(f)
	// One seed per operation plus distinctive spatial patterns. Keep them in
	// code as well as testdata/fuzz so `go test` exercises the same contracts.
	f.Add([]byte{0, 0, 0, 0, 0, 0, 1})
	f.Add([]byte{1, 0, 0, 0, 3, 0, 1})
	f.Add([]byte{2, 0, 1, 0, 0, 0, 1})
	f.Add([]byte{3, 0, 2, 1, 0, 0, 1})
	f.Add([]byte{4, 0, 4, 2, 0, 0, 1})
	f.Add([]byte{5, 0, 6, 0, 5, 0, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		p := decodeSlotProgram(data, c.params.MaxSlots())
		values := makeSlotVector(p, c.params.MaxSlots())
		ct := c.encrypt(t, values)

		switch p.Operation {
		case 0: // full-vector encode/decode; prefix handling is covered separately
			slotMismatch(t, "slot-roundtrip", p, values, decodeAll(t, c, ct), values)
		case 1:
			evaluator := c.evaluatorWithGalois(t, []uint64{c.params.GaloisElement(p.Rotation)})
			rotated, err := evaluator.RotateColumnsNew(ct, p.Rotation)
			if err != nil {
				t.Fatal(err)
			}
			got := injectedSlotFault(decodeAll(t, c, rotated), p)
			slotMismatch(t, "rotate-columns", p, values, got, rotateColumnsExpected(values, p.Rotation))
		case 2:
			evaluator := c.evaluatorWithGalois(t, []uint64{c.params.GaloisElementForRowRotation()})
			rotated, err := evaluator.RotateRowsNew(ct)
			if err != nil {
				t.Fatal(err)
			}
			slotMismatch(t, "rotate-rows", p, values, decodeAll(t, c, rotated), rotateRowsExpected(values))
		case 3:
			schedule := rotateAndAddSchedules[int(byteAt(data, 3))%len(rotateAndAddSchedules)]
			p.BatchSize, p.Count = schedule.batchSize, schedule.count
			galEls := c.params.GaloisElementsForInnerSum(p.BatchSize, p.Count)
			evaluator := c.evaluatorWithGalois(t, galEls)
			out := bgv.NewCiphertext(c.params, 1, ct.Level())
			if err := evaluator.RotateAndAdd(ct, p.BatchSize, p.Count, out); err != nil {
				t.Fatal(err)
			}
			slotMismatch(t, "rotate-and-add", p, values, decodeAll(t, c, out), rotateAndAddExpected(values, p.BatchSize, p.Count))
		case 4:
			galEls := c.params.GaloisElementsForInnerSum(p.BatchSize, p.Count)
			evaluator := c.evaluatorWithGalois(t, galEls)
			out := bgv.NewCiphertext(c.params, 1, ct.Level())
			if err := evaluator.InnerSum(ct, p.BatchSize, p.Count, out); err != nil {
				t.Fatal(err)
			}
			slotInnerSumMismatch(t, "inner-sum", p, values, decodeAll(t, c, out), innerSumExpected(values, p.BatchSize, p.Count))
		case 5:
			galEls := []uint64{c.params.GaloisElement(p.Rotation), c.params.GaloisElement(-p.Rotation)}
			evaluator := c.evaluatorWithGalois(t, galEls)
			forward, err := evaluator.RotateColumnsNew(ct, p.Rotation)
			if err != nil {
				t.Fatal(err)
			}
			back, err := evaluator.RotateColumnsNew(forward, -p.Rotation)
			if err != nil {
				t.Fatal(err)
			}
			slotMismatch(t, "rotate-inverse", p, values, decodeAll(t, c, back), values)
		}
	})
}

// FuzzBGVBatchPrefix specifically checks encoder length boundaries and the
// required zeroing of unprovided slots. It stays separate from the full-vector
// program fuzzer so a failure has a minimal, directly reportable cause.
func FuzzBGVBatchPrefix(f *testing.F) {
	c := newTestContext(f)
	f.Add([]byte{0, 0, 0, 0, 0})
	f.Add([]byte{9, 1, 2, 3, 4, 5})
	f.Add([]byte{8, 255, 128, 127, 0, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		p := decodeSlotProgram(data, c.params.MaxSlots())
		values := makeSlotVector(p, c.params.MaxSlots())
		want := paddedPrefix(values, p.Active)
		ct := c.encrypt(t, values[:p.Active])
		slotMismatch(t, "batched-prefix", p, values[:p.Active], decodeAll(t, c, ct), want)
	})
}

func writeSlotArtifact(t *testing.T, source string, p slotProgram, values []int64) {
	dir := os.Getenv("FHE_FUZZ_ARTIFACT_DIR")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	payload := map[string]any{
		"source": source,
		"slot_program": map[string]any{
			"operation":    p.Operation,
			"pattern":      p.Pattern,
			"rotation":     p.Rotation,
			"batch_size":   p.BatchSize,
			"count":        p.Count,
			"active_slots": p.Active,
		},
		"values": values,
	}
	b, err := json.MarshalIndent(payload, "", "  ")
	if err == nil {
		_ = os.WriteFile(filepath.Join(dir, source+".json"), b, 0o644)
	}
}
