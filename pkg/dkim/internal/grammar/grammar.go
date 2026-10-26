package grammar

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/rest-mail/go-dkim/pkg/dkim/internal/idna"
)

// ParseTagList parses a DKIM tag=value list ("k=v; k2=v2") into a map. Keys and
// the ends of values are trimmed of folding whitespace (see TrimFWS) and
// nothing else; internal FWS in values is preserved (callers strip it via
// the codec package where it is insignificant, e.g. b=, bh=, p=). It parses
// DKIM-Signature, DKIM key records, and ARC header (i=, cv=, …) tag lists alike.
func ParseTagList(s string) map[string]string {
	out := map[string]string{}
	for _, seg := range strings.Split(s, ";") {
		eq := strings.IndexByte(seg, '=')
		if eq < 0 {
			continue
		}
		key := TrimFWS(seg[:eq])
		if key == "" {
			continue
		}
		out[key] = TrimFWS(seg[eq+1:])
	}
	return out
}

// ParseTagListStrict parses a DKIM tag=value list like ParseTagList but enforces
// the RFC 6376 §3.2 well-formedness rules the verification paths require:
//
//   - "Tags with duplicate names MUST NOT occur within a single tag-list; if a
//     tag name does occur more than once, the entire tag-list is invalid."
//     Silently taking one of the values (as a last-wins parse does) lets two
//     verifiers reach different verdicts about the same message, so a repeated
//     tag name is an error.
//   - A non-empty segment that lacks "=" is a malformed tag-spec and is an
//     error (§6.1.1 cautions against being liberal in what is accepted). An
//     empty segment — e.g. from the optional trailing ";" the ABNF allows, or
//     surrounding folding whitespace — is ignored, not rejected.
//   - A tag name that is not ALPHA *ALNUMPUNC (an empty one, say), or a value
//     with a character outside VALCHAR and folding whitespace, is malformed and
//     is an error.
//   - The only whitespace is FWS: SP, HTAB and CRLF folding (RFC 5322 §3.2.2).
//     Any other whitespace — a form feed, a vertical tab, U+0085, U+00A0 — is
//     an error wherever it appears, so "i\f=1" is not read as "i=1".
//
// On any violation it returns a nil map and an error, so a caller verifying a
// DKIM-Signature or a DNS key record can PERMFAIL (or skip the record) rather
// than resolve a malformed list to an arbitrary value.
func ParseTagListStrict(s string) (map[string]string, error) {
	if r, ok := nonFWSSpace(s); ok {
		return nil, fmt.Errorf("tag-list contains %q (%U), whitespace that is not folding whitespace", r, r)
	}
	out := map[string]string{}
	for _, seg := range strings.Split(s, ";") {
		eq := strings.IndexByte(seg, '=')
		if eq < 0 {
			if TrimFWS(seg) == "" {
				continue // empty segment: trailing ";" or surrounding FWS
			}
			return nil, fmt.Errorf("malformed tag-list segment %q (missing '=')", TrimFWS(seg))
		}
		key := TrimFWS(seg[:eq])
		if !validTagName(key) {
			return nil, fmt.Errorf("malformed tag name %q in tag-list", key)
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("duplicate tag %q in tag-list", key)
		}
		val := TrimFWS(seg[eq+1:])
		if !validTagValue(val) {
			return nil, fmt.Errorf("malformed value for tag %q in tag-list", key)
		}
		out[key] = val
	}
	return out, nil
}

// fws holds the characters of folding whitespace, the only whitespace RFC 6376
// allows around tag names, "=", values, ";" (§3.2) and the ":" of a list such
// as h= (§3.5, §3.6.1): the SP and HTAB of WSP and the CR and LF of a fold (RFC
// 5322 §3.2.2). strings.TrimSpace is wrong for wire data: it also strips a form
// feed, a vertical tab, U+0085 and U+00A0, which are not whitespace there.
const fws = " \t\r\n"

// TrimFWS removes the folding whitespace around s, and nothing else.
func TrimFWS(s string) string { return strings.Trim(s, fws) }

// nonFWSSpace returns the first rune in s that Unicode counts as whitespace but
// folding whitespace does not ("\f", "\v", U+0085, U+00A0, ...), and whether
// there is one.
func nonFWSSpace(s string) (rune, bool) {
	for _, r := range s {
		if unicode.IsSpace(r) && !strings.ContainsRune(fws, r) {
			return r, true
		}
	}
	return 0, false
}

// validTagName reports whether name matches the RFC 6376 §3.2 tag-name ABNF,
// ALPHA *ALNUMPUNC, where ALNUMPUNC is a letter, a digit or "_".
func validTagName(name string) bool {
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !isAlpha(c) && (i == 0 || !isDigit(c) && c != '_') {
			return false
		}
	}
	return name != ""
}

func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// validTagValue reports whether a trimmed tag value holds only the RFC 6376
// §3.2 tag-value characters: VALCHAR (printable US-ASCII except ";") and the
// whitespace of FWS between them. RFC 8616 §5 adds UTF-8 for internationalized
// headers (U-labels in d=, s= and i=, UTF-8 in the i= local-part and
// dkim-safe-char), so well-formed non-ASCII UTF-8 is accepted too; invalid
// UTF-8 is not.
func validTagValue(val string) bool {
	for i := 0; i < len(val); i++ {
		c := val[i]
		if (c < 0x21 || c > 0x7e) && c != ' ' && c != '\t' && c != '\r' && c != '\n' && c < 0x80 {
			return false
		}
	}
	return utf8.ValidString(val)
}

// ParseUint parses a DKIM tag value that RFC 6376 defines as digits only (e.g.
// the l= body-length tag, sig-l-tag = ... 1*76DIGIT — §3.5). It rejects any
// value that is not composed solely of ASCII digits, including a leading "+" or
// "-" sign. This matters: strconv.Atoi accepts a sign, so without this guard a
// negative l= would parse cleanly and then slice the body with a negative bound
// (canonBody[:-1]), panicking — a remotely triggerable crash since the
// signature header is attacker-controlled. strconv.Atoi still rejects values
// that overflow int; the grammar also limits the value to 1–76 digits.
func ParseUint(s string) (int, error) {
	if len(s) == 0 || len(s) > 76 {
		return 0, strconv.ErrSyntax
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, strconv.ErrSyntax
		}
	}
	return strconv.Atoi(s)
}

// ParseTimeTag parses a DKIM timestamp tag (t= or x=), whose RFC 6376 §3.5 ABNF
// is 1*12DIGIT — an unsigned decimal count of seconds since the Unix epoch. It
// rejects an empty value, any non-digit (including a leading "+" or "-" sign),
// and a value longer than 12 digits, so a syntactically invalid expiration is a
// clean error rather than being silently ignored. The result is returned as
// int64 so the epoch-second comparison against the current time is correct on a
// 32-bit platform (where int would overflow beyond year 2038).
func ParseTimeTag(s string) (int64, error) {
	s = TrimFWS(s)
	if s == "" || len(s) > 12 {
		return 0, strconv.ErrSyntax
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, strconv.ErrSyntax
		}
	}
	return strconv.ParseInt(s, 10, 64)
}

// ValidFieldName reports whether name is an RFC 5322 field-name: one or more
// printable US-ASCII characters other than the colon.
func ValidFieldName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		if name[i] < 33 || name[i] > 126 || name[i] == ':' {
			return false
		}
	}
	return true
}

// ValidDNSName reports whether name is a plausible DNS name in A-label form:
// dot-separated labels of 1 to 63 letters, digits, hyphens or underscores, 253
// characters at most. It rejects U-labels (RFC 6376 §3.5 requires A-labels),
// whitespace, control characters and empty labels.
func ValidDNSName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !isAlpha(c) && !isDigit(c) && c != '-' && c != '_' {
				return false
			}
		}
	}
	return true
}

// HeaderListCoversFrom reports whether a signature's h= tag (a colon-separated
// list of header field names) includes the From field, matched
// case-insensitively and ignoring whitespace around each name. RFC 6376 §5.4
// makes From mandatory in h=; §6.1.1 requires PERMFAIL when it is absent.
func HeaderListCoversFrom(hTag string) bool {
	for _, name := range strings.Split(hTag, ":") {
		if strings.EqualFold(TrimFWS(name), "from") {
			return true
		}
	}
	return false
}

// ALabelTags rewrites the U-labels of d=, s= and the i= domain in tags to
// A-labels (RFC 8616 §5). Every later check, the alignment comparisons and the
// key record name then see one form, while the header hash still covers the
// field text exactly as it occurs in sig. The i= local-part, which RFC 8616
// lets carry UTF-8, is kept as it is.
func ALabelTags(tags map[string]string) {
	for _, k := range []string{"d", "s"} {
		if v, ok := tags[k]; ok {
			tags[k] = idna.ToALabels(v)
		}
	}
	if iTag, ok := tags["i"]; ok {
		if at := strings.LastIndexByte(iTag, '@'); at >= 0 {
			tags["i"] = iTag[:at+1] + idna.ToALabels(iTag[at+1:])
		}
	}
}

// IdentityDomain returns the domain part of a DKIM i= (AUID) tag value: the
// text after the LAST "@". RFC 6376 §3.5 defines i= as [ Local-part ] "@"
// domain-name, and the local part may be a quoted string that itself contains
// "@", so the split is on the last "@". A value with no "@" is malformed and
// yields ("", false).
func IdentityDomain(iTag string) (string, bool) {
	at := strings.LastIndexByte(iTag, '@')
	if at < 0 {
		return "", false
	}
	return iTag[at+1:], true
}

// DomainAligned reports whether the i= domain idomain is the same as, or a
// subdomain of, the signing domain d (RFC 6376 §6.1.1), compared
// case-insensitively. An empty idomain or d is never aligned.
func DomainAligned(idomain, d string) bool {
	idomain = strings.ToLower(TrimFWS(idomain))
	d = strings.ToLower(TrimFWS(d))
	if idomain == "" || d == "" {
		return false
	}
	return idomain == d || strings.HasSuffix(idomain, "."+d)
}

// FirstTagName returns the name of the first tag in a DKIM tag-list record (the
// text before the first "="), ignoring the ABNF's optional leading folding
// whitespace and any empty leading segments (a stray leading ";" or surrounding
// FWS). It returns "" for a record with no tag. It is used to enforce RFC 6376
// §3.6.1's requirement that a key record's v= tag, when present, be the FIRST
// tag in the record.
func FirstTagName(rec string) string {
	for _, seg := range strings.Split(rec, ";") {
		if TrimFWS(seg) == "" {
			continue
		}
		eq := strings.IndexByte(seg, '=')
		if eq < 0 {
			return ""
		}
		return TrimFWS(seg[:eq])
	}
	return ""
}

// ListContains reports whether the colon-separated tag value list has an
// element equal to want, ignoring the folding whitespace allowed around each
// ":". Values are case-sensitive (RFC 6376 §3.2).
func ListContains(list, want string) bool {
	for _, v := range strings.Split(list, ":") {
		if TrimFWS(v) == want {
			return true
		}
	}
	return false
}
