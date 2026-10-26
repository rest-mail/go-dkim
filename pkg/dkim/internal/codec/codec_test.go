package codec

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// TestDecodeBase64Tag exercises the tolerant decoder that all three verification
// base64 sites (bh=, b=, key p=) share, over the shapes RFC 6376 §2.10 / §3.5
// permit: padded and unpadded (length ≡ 2 and ≡ 3 mod 4), values carrying folding
// whitespace, and genuinely invalid input that must still be rejected.
//
// checklist: DKIM-TAG-07 DKIM-SIG-04
func TestDecodeBase64Tag(t *testing.T) {
	// Inputs chosen so the canonical encoding needs padding: 4 bytes ≡ 1 (mod 3)
	// → 2 pad chars (encoded length ≡ 3 mod 4); 5 bytes ≡ 2 (mod 3) → 1 pad char
	// (encoded length ≡ 2 mod 4). 3 bytes needs none (length ≡ 0 mod 4).
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"one pad char (len%4==2)", []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01}},
		{"two pad chars (len%4==3)", []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		{"no pad needed (len%4==0)", []byte{0xDE, 0xAD, 0xBE}},
		{"empty", []byte{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			padded := base64.StdEncoding.EncodeToString(tc.raw)
			unpadded := strings.TrimRight(padded, "=")

			for label, in := range map[string]string{
				"padded":              padded,
				"unpadded":            unpadded,
				"unpadded + FWS fold": insertFWS(unpadded),
				"padded + FWS fold":   insertFWS(padded),
			} {
				got, err := DecodeTag(in)
				if err != nil {
					t.Fatalf("%s: unexpected error: %v", label, err)
				}
				if !bytes.Equal(got, tc.raw) {
					t.Fatalf("%s: decoded %x, want %x", label, got, tc.raw)
				}
			}
		})
	}

	// Genuinely invalid base64 must still be rejected (not silently accepted).
	for _, bad := range []string{"!!!!", "AB=C", "ABCDE"} { // last is length ≡ 1 mod 4
		if _, err := DecodeTag(bad); err == nil {
			t.Errorf("DecodeTag(%q) accepted invalid input, want error", bad)
		}
	}
}

// insertFWS splices a CRLF+space fold into the middle of a base64 string to model
// a value folded across lines (RFC 6376 permits FWS within base64string).
func insertFWS(s string) string {
	if len(s) < 2 {
		return s
	}
	mid := len(s) / 2
	return s[:mid] + "\r\n " + s[mid:]
}
