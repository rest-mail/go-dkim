// Package idna converts internationalized domain names to their A-label
// (xn-- punycode, RFC 3492) form, so that a DKIM verifier can look up a key
// record and compare d=, s= and i= domains in one form (RFC 8616 §5).
//
// It implements only what DKIM needs, with no dependency beyond the standard
// library: it lower-cases a U-label and punycode-encodes it. The full IDNA2008
// mapping and label validation are out of scope.
package idna
