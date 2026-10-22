package dkim

import (
	"math"
	"strings"
	"unicode/utf8"
)

// toALabels converts every U-label of domain to its A-label (xn-- punycode)
// form. RFC 8616 §5 lets an internationalized message carry d=, s= and the i=
// domain as U-labels; the key record is still looked up, and the names still
// compared, in A-label form. An all-ASCII label is returned as it is; a label
// with non-ASCII runes is lower-cased (Unicode simple folding) and
// punycode-encoded. A name that is not valid UTF-8 is returned unchanged, so it
// stays an invalid DNS name.
//
// The full IDNA2008 mapping (NFC normalization, special folds such as ß, and
// label validation) is out of scope for a dependency-free verifier; only
// deliberately unusual spellings differ.
func toALabels(domain string) string {
	if isASCII(domain) || !utf8.ValidString(domain) {
		return domain
	}
	labels := strings.Split(domain, ".")
	for i, label := range labels {
		labels[i] = labelToASCII(label)
	}
	return strings.Join(labels, ".")
}

// labelToASCII returns the A-label form of one DNS label. An all-ASCII label
// (an existing xn-- label included) is returned unchanged.
func labelToASCII(label string) string {
	// An A-label has at most 63 characters, at least one per code point, so a
	// longer label is left as it is (and is then no valid domain); this also
	// bounds the quadratic encoder.
	if isASCII(label) || utf8.RuneCountInString(label) > 63 {
		return label
	}
	return "xn--" + punycodeEncode(strings.ToLower(label))
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// Punycode (RFC 3492) bootstring parameters for IDNA.
const (
	punyBase        = 36
	punyTMin        = 1
	punyTMax        = 26
	punySkew        = 38
	punyDamp        = 700
	punyInitialBias = 72
	punyInitialN    = 128 // first non-ASCII code point
	punyDelimiter   = '-'
)

// punycodeEncode encodes a string of Unicode code points into its punycode
// (RFC 3492) basic-string form, i.e. the part that follows the xn-- prefix in an
// IDNA A-label. This is the RFC 3492 reference "Encoding procedure" adapted to
// Go. Its input is at most 63 code points (see labelToASCII), so delta stays
// below 64 * 0x110000 and cannot overflow, which the reference code checks.
func punycodeEncode(input string) string {
	runes := []rune(input)
	var out strings.Builder

	// Copy all basic (ASCII) code points first, in order.
	basic := 0
	for _, r := range runes {
		if r < punyInitialN {
			out.WriteByte(byte(r))
			basic++
		}
	}
	handled := basic
	if basic > 0 {
		out.WriteByte(punyDelimiter)
	}

	n := punyInitialN
	delta := 0
	bias := punyInitialBias
	for handled < len(runes) {
		// Find the next-smallest code point not yet handled.
		m := math.MaxInt32
		for _, r := range runes {
			if int(r) >= n && int(r) < m {
				m = int(r)
			}
		}
		delta += (m - n) * (handled + 1)
		n = m
		for _, r := range runes {
			c := int(r)
			if c < n {
				delta++
			}
			if c == n {
				q := delta
				for k := punyBase; ; k += punyBase {
					t := punyThreshold(k, bias)
					if q < t {
						break
					}
					out.WriteByte(punyDigit(t + (q-t)%(punyBase-t)))
					q = (q - t) / (punyBase - t)
				}
				out.WriteByte(punyDigit(q))
				bias = punyAdapt(delta, handled+1, handled == basic)
				delta = 0
				handled++
			}
		}
		delta++
		n++
	}
	return out.String()
}

func punyThreshold(k, bias int) int {
	switch {
	case k <= bias+punyTMin:
		return punyTMin
	case k >= bias+punyTMax:
		return punyTMax
	default:
		return k - bias
	}
}

func punyAdapt(delta, numPoints int, firstTime bool) int {
	if firstTime {
		delta /= punyDamp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := 0
	for delta > ((punyBase-punyTMin)*punyTMax)/2 {
		delta /= punyBase - punyTMin
		k += punyBase
	}
	return k + (punyBase-punyTMin+1)*delta/(delta+punySkew)
}

// punyDigit maps a value 0..35 to its punycode digit: 0..25 -> 'a'..'z',
// 26..35 -> '0'..'9'.
func punyDigit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}
