package domain_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/laenenai/keyring/internal/domain"
)

func TestNewDEKIsFullLengthAndUnpredictable(t *testing.T) {
	t.Parallel()

	first, err := domain.NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	t.Cleanup(first.Destroy)

	if got := len(first.Bytes()); got != domain.DEKSize {
		t.Fatalf("len(NewDEK().Bytes()) = %d, want %d", got, domain.DEKSize)
	}
	if err := first.Validate(); err != nil {
		t.Fatalf("NewDEK().Validate(): %v", err)
	}

	second, err := domain.NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	t.Cleanup(second.Destroy)

	if first.Equal(second) {
		t.Fatal("two NewDEK calls returned equal key material")
	}
}

func TestDEKFromCopiesAndValidates(t *testing.T) {
	t.Parallel()

	t.Run("CopiesTheCallersBuffer", func(t *testing.T) {
		t.Parallel()

		raw := bytes.Repeat([]byte{0xA7}, domain.DEKSize)
		dek, err := domain.DEKFrom(raw)
		if err != nil {
			t.Fatalf("DEKFrom: %v", err)
		}
		t.Cleanup(dek.Destroy)

		// Mutating the caller's buffer must not reach inside the DEK, and
		// zeroizing the DEK must not reach back out into the caller's
		// buffer: ownership of each is separate.
		clear(raw)
		if !bytes.Equal(dek.Bytes(), bytes.Repeat([]byte{0xA7}, domain.DEKSize)) {
			t.Fatal("DEKFrom aliased the caller's buffer instead of copying it")
		}
	})

	t.Run("RejectsBadMaterial", func(t *testing.T) {
		t.Parallel()

		cases := []struct {
			name string
			in   []byte
		}{
			{"nil", nil},
			{"empty", []byte{}},
			{"too_short", bytes.Repeat([]byte{1}, domain.DEKSize-1)},
			{"too_long", bytes.Repeat([]byte{1}, domain.DEKSize+1)},
			{"all_zero", make([]byte, domain.DEKSize)},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				if _, err := domain.DEKFrom(tc.in); !errors.Is(err, domain.ErrInvalidKeyMaterial) {
					t.Fatalf("DEKFrom(%s) error = %v, want ErrInvalidKeyMaterial", tc.name, err)
				}
			})
		}
	})
}

// All-zero key material is rejected rather than accepted as a legitimate
// (if astronomically unlikely) random key, because in practice every
// all-zero buffer that reaches this constructor is either a zeroized DEK
// being reused after Destroy or an uninitialized make([]byte, 32). Failing
// closed on it turns a silent "everything is encrypted under a known key"
// bug into an error at the boundary.
func TestDestroyedDEKFailsValidationAndRendersEmpty(t *testing.T) {
	t.Parallel()

	dek, err := domain.NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}

	copied := dek // a value copy shares the backing array, deliberately
	dek.Destroy()

	if dek.Bytes() != nil {
		t.Fatalf("Bytes() after Destroy = %v, want nil", dek.Bytes())
	}
	if !dek.IsZero() {
		t.Fatal("IsZero() after Destroy = false, want true")
	}
	if err := dek.Validate(); !errors.Is(err, domain.ErrInvalidKeyMaterial) {
		t.Fatalf("Validate() after Destroy = %v, want ErrInvalidKeyMaterial", err)
	}

	// Destroy zeroizes the shared backing array, so a copy taken before
	// Destroy holds zeros rather than the live key — and is therefore
	// rejected by Validate too, which is what stops a zeroized key from
	// being wrapped as if it were real material.
	if err := copied.Validate(); !errors.Is(err, domain.ErrInvalidKeyMaterial) {
		t.Fatalf("copy taken before Destroy: Validate() = %v, want ErrInvalidKeyMaterial", err)
	}

	// Destroy is idempotent: an adapter that defers Destroy and a caller
	// that also calls it must not need to coordinate.
	dek.Destroy()
}

func TestDEKEqualIsContentEquality(t *testing.T) {
	t.Parallel()

	raw := bytes.Repeat([]byte{0x11}, domain.DEKSize)
	a, err := domain.DEKFrom(raw)
	if err != nil {
		t.Fatalf("DEKFrom: %v", err)
	}
	t.Cleanup(a.Destroy)
	b, err := domain.DEKFrom(raw)
	if err != nil {
		t.Fatalf("DEKFrom: %v", err)
	}
	t.Cleanup(b.Destroy)

	if !a.Equal(b) {
		t.Fatal("DEKs with identical material compared unequal")
	}

	other, err := domain.NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	t.Cleanup(other.Destroy)
	if a.Equal(other) {
		t.Fatal("DEKs with different material compared equal")
	}

	var zero domain.DEK
	if zero.Equal(a) || a.Equal(zero) {
		t.Fatal("a zero DEK compared equal to live key material")
	}
}

// TestDEKNeverRendersItsMaterial is the type-level half of the
// "no key material in errors or logs" invariant: every rendering path the
// standard library reaches for — fmt, encoding/json, encoding.TextMarshaler,
// log/slog — must yield a redacted placeholder. The conformance suite's
// NoKeyMaterialLeaksInErrors subtest covers the adapter-level half.
func TestDEKNeverRendersItsMaterial(t *testing.T) {
	t.Parallel()

	dek, err := domain.NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	t.Cleanup(dek.Destroy)
	material := dek.Bytes()

	jsonDEK, err := json.Marshal(dek)
	if err != nil {
		t.Fatalf("json.Marshal(DEK): %v", err)
	}
	text, err := dek.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}

	var logged bytes.Buffer
	slog.New(slog.NewTextHandler(&logged, nil)).Info("wrapped", "dek", dek)

	type holder struct {
		Note string
		DEK  domain.DEK
	}

	// The verbs are variables rather than literals so that a linter which
	// rewrites fmt.Sprintf("%s", x) into x.String() cannot quietly remove
	// the thing under test, which is the fmt path itself.
	vVerb, sVerb := "%v", "%s"

	renderings := map[string]string{
		"String":            dek.String(),
		"GoString":          dek.GoString(),
		"fmt %v":            fmt.Sprintf(vVerb, dek),
		"fmt %s":            fmt.Sprintf(sVerb, dek),
		"fmt %+v":           fmt.Sprintf("%+v", dek),
		"fmt %#v":           fmt.Sprintf("%#v", dek),
		"fmt %v pointer":    fmt.Sprintf("%v", &dek),
		"fmt %v in struct":  fmt.Sprintf("%v", holder{Note: "n", DEK: dek}),
		"fmt %+v in struct": fmt.Sprintf("%+v", holder{Note: "n", DEK: dek}),
		"MarshalText":       string(text),
		"MarshalJSON":       string(jsonDEK),
		"json in struct":    mustJSON(t, holder{Note: "n", DEK: dek}),
		"slog":              logged.String(),
	}
	for name, rendering := range renderings {
		for _, encoded := range encodingsOf(material) {
			if strings.Contains(rendering, encoded.value) {
				t.Errorf("%s leaked key material as %s: %q", name, encoded.name, rendering)
			}
		}
		if !strings.Contains(rendering, domain.Redacted) {
			t.Errorf("%s = %q, want it to contain the redaction marker %q", name, rendering, domain.Redacted)
		}
	}
}

func TestKEKIDAndKeyIDValidation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		ok   bool
	}{
		{"ulid", "01K8ABCD1234567890ABCDEFGH", true},
		{"dotted", "tenant.blob-key_1", true},
		{"single_char", "a", true},
		{"max_length", strings.Repeat("a", 256), true},
		{"empty", "", false},
		{"over_max_length", strings.Repeat("a", 257), false},
		{"null_byte", "ten\x00ant", false},
		{"forward_slash", "tenant/kek", false},
		{"backslash", `tenant\kek`, false},
		{"dot", ".", false},
		{"dot_dot", "..", false},
		{"traversal", "a/../b", false},
		{"newline", "tenant\nkek", false},
		{"tab", "tenant\tkek", false},
		{"invalid_utf8", "tenant\xff", false},
		{"leading_space", " tenant", false},
		{"trailing_space", "tenant ", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			kekErr := domain.KEKID(tc.in).Validate()
			keyErr := domain.KeyID(tc.in).Validate()
			switch {
			case tc.ok && (kekErr != nil || keyErr != nil):
				t.Fatalf("Validate(%q): KEKID = %v, KeyID = %v, want both nil", tc.in, kekErr, keyErr)
			case !tc.ok && !errors.Is(kekErr, domain.ErrInvalidIdentifier):
				t.Fatalf("KEKID(%q).Validate() = %v, want ErrInvalidIdentifier", tc.in, kekErr)
			case !tc.ok && !errors.Is(keyErr, domain.ErrInvalidIdentifier):
				t.Fatalf("KeyID(%q).Validate() = %v, want ErrInvalidIdentifier", tc.in, keyErr)
			}
		})
	}
}

func TestIdentifierValidationErrorsNameTheField(t *testing.T) {
	t.Parallel()

	kekErr := domain.KEKID("").Validate()
	if kekErr == nil || !strings.Contains(kekErr.Error(), "KEK id") {
		t.Fatalf("KEKID(\"\").Validate() = %v, want an error naming the KEK id", kekErr)
	}
	keyErr := domain.KeyID("").Validate()
	if keyErr == nil || !strings.Contains(keyErr.Error(), "key id") {
		t.Fatalf("KeyID(\"\").Validate() = %v, want an error naming the key id", keyErr)
	}
}

func TestKEKVersion(t *testing.T) {
	t.Parallel()

	if domain.FirstKEKVersion != 1 {
		t.Fatalf("FirstKEKVersion = %d, want 1", domain.FirstKEKVersion)
	}
	if err := domain.KEKVersion(0).Validate(); !errors.Is(err, domain.ErrInvalidIdentifier) {
		t.Fatalf("KEKVersion(0).Validate() = %v, want ErrInvalidIdentifier (version numbering starts at 1)", err)
	}
	if err := domain.FirstKEKVersion.Validate(); err != nil {
		t.Fatalf("FirstKEKVersion.Validate(): %v", err)
	}
	if got, want := domain.FirstKEKVersion.Next(), domain.KEKVersion(2); got != want {
		t.Fatalf("FirstKEKVersion.Next() = %d, want %d", got, want)
	}
	if got, want := domain.KEKVersion(7).String(), "v7"; got != want {
		t.Fatalf("KEKVersion(7).String() = %q, want %q", got, want)
	}
}

func TestWrappedDEKValidation(t *testing.T) {
	t.Parallel()

	valid := domain.WrappedDEK{
		KEKID:      "kek-1",
		KEKVersion: domain.FirstKEKVersion,
		KeyID:      "blob-1",
		Ciphertext: []byte{1, 2, 3, 4},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() of a well-formed WrappedDEK: %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(w *domain.WrappedDEK)
		wantErr error
	}{
		{"empty_kek_id", func(w *domain.WrappedDEK) { w.KEKID = "" }, domain.ErrInvalidIdentifier},
		{"unsafe_kek_id", func(w *domain.WrappedDEK) { w.KEKID = "a/b" }, domain.ErrInvalidIdentifier},
		{"empty_key_id", func(w *domain.WrappedDEK) { w.KeyID = "" }, domain.ErrInvalidIdentifier},
		{"zero_kek_version", func(w *domain.WrappedDEK) { w.KEKVersion = 0 }, domain.ErrInvalidIdentifier},
		{"nil_ciphertext", func(w *domain.WrappedDEK) { w.Ciphertext = nil }, domain.ErrInvalidWrappedDEK},
		{"empty_ciphertext", func(w *domain.WrappedDEK) { w.Ciphertext = []byte{} }, domain.ErrInvalidWrappedDEK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := valid
			w.Ciphertext = bytes.Clone(valid.Ciphertext)
			tc.mutate(&w)
			if err := w.Validate(); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Validate() = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// A wrapped DEK is ciphertext, not key material, but it is still the one
// value an adapter is most likely to log while debugging a failed unwrap.
// Rendering it must name the KEK and version that can open it — the whole
// point of recording them — and must not dump the ciphertext.
func TestWrappedDEKRendersIdentifiersWithoutCiphertext(t *testing.T) {
	t.Parallel()

	w := domain.WrappedDEK{
		KEKID:      "kek-1",
		KEKVersion: domain.KEKVersion(3),
		KeyID:      "blob-1",
		Ciphertext: []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}
	rendered := fmt.Sprintf("%v", w)
	for _, want := range []string{"kek-1", "v3", "blob-1"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("WrappedDEK rendering %q does not name %q", rendered, want)
		}
	}
	for _, encoded := range encodingsOf(w.Ciphertext) {
		if strings.Contains(rendered, encoded.value) {
			t.Errorf("WrappedDEK rendering leaked ciphertext as %s: %q", encoded.name, rendered)
		}
	}
}

type encoding struct {
	name  string
	value string
}

// encodingsOf returns the renderings of b that a leak would plausibly take:
// the raw bytes, lower and upper hex, standard and URL base64 (padded and
// raw), and Go's own byte-slice formatting. A single substring check against
// each catches an adapter that formats key material with %v, %x, %q or
// base64 alike.
func encodingsOf(b []byte) []encoding {
	if len(b) == 0 {
		return nil
	}
	return []encoding{
		{"raw bytes", string(b)},
		{"lower hex", hex.EncodeToString(b)},
		{"upper hex", strings.ToUpper(hex.EncodeToString(b))},
		{"base64 std", base64.StdEncoding.EncodeToString(b)},
		{"base64 raw std", base64.RawStdEncoding.EncodeToString(b)},
		{"base64 url", base64.URLEncoding.EncodeToString(b)},
		{"base64 raw url", base64.RawURLEncoding.EncodeToString(b)},
		{"go byte slice", fmt.Sprintf("%v", b)},
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return string(b)
}

func TestWrappedDEKRoundTripsThroughBinary(t *testing.T) {
	t.Parallel()

	w := domain.WrappedDEK{
		KEKID:      "kek-1",
		KEKVersion: domain.KEKVersion(4),
		KeyID:      "blob-1",
		Format:     domain.WrappedDEKFormatLocal,
		Ciphertext: []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}
	encoded, err := w.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	var got domain.WrappedDEK
	if err := got.UnmarshalBinary(encoded); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	if got.KEKID != w.KEKID || got.KEKVersion != w.KEKVersion || got.KeyID != w.KeyID || got.Format != w.Format || !bytes.Equal(got.Ciphertext, w.Ciphertext) {
		t.Fatalf("round trip = %+v, want %+v", got, w)
	}
}

func TestWrappedDEKBinaryRejectsUnknownVersionAndTrailingBytes(t *testing.T) {
	t.Parallel()

	w := domain.WrappedDEK{
		KEKID:      "kek-1",
		KEKVersion: domain.FirstKEKVersion,
		KeyID:      "blob-1",
		Format:     domain.WrappedDEKFormatLocal,
		Ciphertext: []byte{1, 2, 3},
	}
	encoded, err := w.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	unknown := bytes.Clone(encoded)
	unknown[0] = 0xff
	var got domain.WrappedDEK
	if err := got.UnmarshalBinary(unknown); !errors.Is(err, domain.ErrInvalidWrappedDEK) {
		t.Fatalf("UnmarshalBinary(unknown version) = %v, want ErrInvalidWrappedDEK", err)
	}
	if err := got.UnmarshalBinary(append(encoded, 0)); !errors.Is(err, domain.ErrInvalidWrappedDEK) {
		t.Fatalf("UnmarshalBinary(trailing bytes) = %v, want ErrInvalidWrappedDEK", err)
	}
}

func TestWrappedDEKUsesStableJSONFieldNames(t *testing.T) {
	t.Parallel()

	w := domain.WrappedDEK{
		KEKID:      "kek-1",
		KEKVersion: domain.FirstKEKVersion,
		KeyID:      "blob-1",
		Format:     domain.WrappedDEKFormatLocal,
		Ciphertext: []byte{1, 2, 3},
	}
	rendered := mustJSON(t, w)
	for _, field := range []string{`"kek_id"`, `"kek_version"`, `"key_id"`, `"format"`, `"ciphertext"`} {
		if !strings.Contains(rendered, field) {
			t.Errorf("JSON %s does not contain stable field %s", rendered, field)
		}
	}
	for _, oldField := range []string{`"KEKID"`, `"KEKVersion"`, `"KeyID"`, `"Format"`, `"Ciphertext"`} {
		if strings.Contains(rendered, oldField) {
			t.Errorf("JSON %s still contains Go field name %s", rendered, oldField)
		}
	}
}

func TestWrappedDEKRendersTheAdapterFormat(t *testing.T) {
	t.Parallel()

	w := domain.WrappedDEK{
		KEKID:      "kek-1",
		KEKVersion: domain.FirstKEKVersion,
		KeyID:      "blob-1",
		Format:     domain.WrappedDEKFormatOpenBaoTransit,
		Ciphertext: []byte{1, 2, 3},
	}
	if rendered := fmt.Sprint(w); !strings.Contains(rendered, string(domain.WrappedDEKFormatOpenBaoTransit)) {
		t.Fatalf("WrappedDEK rendering %q does not name its format", rendered)
	}
}

func TestWrappedDEKUnmarshalJSONAcceptsLegacyFieldNames(t *testing.T) {
	t.Parallel()

	const legacy = `{"KEKID":"kek-1","KEKVersion":3,"KeyID":"blob-1","Ciphertext":"AQID"}`
	var w domain.WrappedDEK
	if err := json.Unmarshal([]byte(legacy), &w); err != nil {
		t.Fatalf("unmarshal legacy WrappedDEK: %v", err)
	}
	if err := w.Validate(); err != nil {
		t.Fatalf("legacy WrappedDEK did not validate: %v", err)
	}
	if w.KEKID != "kek-1" || w.KEKVersion != 3 || w.KeyID != "blob-1" || !bytes.Equal(w.Ciphertext, []byte{1, 2, 3}) {
		t.Fatalf("legacy WrappedDEK = %+v", w)
	}
}
