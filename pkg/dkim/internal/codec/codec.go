package codec

import (
	"encoding/base64"
	"strings"
)

// StripWSP removes all whitespace (SP, TAB, CR, LF) — used on base64 tag values
// (b=, bh=, p=) that may be folded across lines.
func StripWSP(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, s)
}

// DecodeTag decodes a DKIM base64 tag value (b=, bh=, key p=) tolerantly,
// per RFC 6376 §2.10 / §3.5. Two allowances of the base64string ABNF are honored
// that strict base64.StdEncoding does not:
//
//   - Folding whitespace (FWS) may appear within the value (it is commonly folded
//     across lines), so all embedded SP/TAB/CR/LF are stripped first.
//   - The trailing "=" padding is OPTIONAL, and some conformant signers and key
//     records emit unpadded base64. StdEncoding rejects any input whose length is
//     not a multiple of four, so an unpadded value is spuriously rejected.
//
// Standard (padded) decoding is tried first so canonical inputs take the exact
// prior path; only on failure is the value normalized — any stray padding removed
// — and retried with the raw (unpadded) alphabet. A value that decodes under
// either form is accepted; one that decodes under neither (genuinely invalid
// base64) still returns an error and is rejected by the caller.
func DecodeTag(s string) ([]byte, error) {
	s = StripWSP(s)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
}
