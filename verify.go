package dkim

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"
)

// timeNow is the clock VerifySignature reads to decide whether a signature's x=
// expiration has passed. It is a package variable, defaulting to time.Now, so
// tests can pin "now" to a fixed instant and exercise the expiry boundary
// deterministically without waiting on or depending on the wall clock.
var timeNow = time.Now

// Verify performs RFC 6376 DKIM verification against a raw RFC 5322 message.
//
// Verification MUST run over the exact bytes that were signed — the header and
// body as transmitted — so this operates on the raw message, never on a parsed
// or reconstructed representation (reconstructing headers/body from structured
// fields would not reproduce the signer's canonicalization for anything but the
// simplest messages).
//
// It returns one VerifyResult per DKIM-Signature header found, in header order.
// An empty slice means the message carried no DKIM-Signature. A nil resolver
// uses the system DNS resolver.
func Verify(ctx context.Context, rawMessage []byte, resolver TXTResolver) []VerifyResult {
	if resolver == nil {
		resolver = net.DefaultResolver.LookupTXT
	}
	headers, body := SplitMessage(rawMessage)

	var results []VerifyResult
	for _, h := range headers {
		if !strings.EqualFold(h.Name, "DKIM-Signature") {
			continue
		}
		results = append(results, VerifySignature(ctx, h, headers, body, resolver))
	}
	return results
}

// TXTResolver looks up DNS TXT records for a name. It matches the signature of
// net.Resolver.LookupTXT so the default resolver can be used directly, and a
// stub can be injected in tests.
type TXTResolver func(ctx context.Context, name string) ([]string, error)

// Verification result strings, mirroring RFC 8601 dkim= values.
const (
	ResultPass      = "pass"
	ResultFail      = "fail"
	ResultNeutral   = "neutral"
	ResultNone      = "none"
	ResultTempError = "temperror"
	ResultPermError = "permerror"
)

// VerifyResult is the outcome of verifying a single DKIM-Signature.
type VerifyResult struct {
	Domain   string // d= signing domain
	Selector string // s= selector
	Result   string // one of the Result* constants
	Reason   string // human-readable detail
}

// Header is one parsed header field of an RFC 5322 message: its name, its value
// (everything after the colon, folding CRLFs preserved, trailing CRLF stripped)
// and the full raw field. It is the unit SplitMessage produces and that
// CanonicalizeHeader / VerifySignature / BuildSignedHeaders consume.
type Header struct {
	// Name is the field name, e.g. "From" (whitespace-trimmed, original case).
	Name string
	// Value is everything after the colon, with folding CRLFs preserved and the
	// trailing CRLF stripped.
	Value string
	// Raw is the full field exactly as it appeared (name, colon, value, folds),
	// with no trailing CRLF — used by simple header canonicalization.
	Raw string
}

// VerifySignature verifies a single DKIM-Signature header (sig) against the
// message it covers: allHeaders is the full ordered header block the signature's
// h= tag selects from, and body is the CRLF-normalized body (both as returned by
// SplitMessage). It performs body-hash, header-hash and public key checks and
// returns a VerifyResult.
//
// It is the per-signature verification primitive underneath Verify and applies
// the FULL RFC 6376 DKIM-Signature policy: v= is required and must be 1, From
// must be signed, an i= (AUID) must be aligned with d=, timing (t=/x=) is
// enforced, and the key record's t=s / s= policy flags are applied.
//
// A layered scheme (e.g. ARC) whose signature is structurally a DKIM-Signature
// but versionless and governed by its own rules should NOT call this — it would
// inherit DKIM policy that does not apply. Call VerifySignatureBare instead: the
// same canonicalization and crypto path with none of the DKIM policy, and apply
// the scheme's own policy on top.
func VerifySignature(ctx context.Context, sig Header, allHeaders []Header, body string, resolver TXTResolver) VerifyResult {
	// Parse strictly: a DKIM-Signature whose tag-list repeats a tag name (or
	// carries a malformed segment) is invalid per RFC 6376 §3.2 and must PERMFAIL
	// rather than resolve to an arbitrary value — otherwise verifiers that pick a
	// different value for the duplicate reach different verdicts about the same
	// message.
	tags, err := ParseTagListStrict(sig.Value)
	if err != nil {
		return VerifyResult{Result: ResultPermError, Reason: err.Error()}
	}
	aLabelTags(tags)

	res := VerifyResult{Domain: tags["d"], Selector: tags["s"]}
	permfail := func(reason string) VerifyResult { res.Result = ResultPermError; res.Reason = reason; return res }

	// Version (RFC 6376 §3.5): v= is REQUIRED and MUST be "1". A signature that is
	// present-but-wrong (v= != 1) is an unsupported version; a signature that
	// omits v= entirely is malformed. Both PERMFAIL — an absent v= must NOT slip
	// through the wrong-version guard's `!= ""` short-circuit and be accepted, so
	// v= is also carried in the required-tag loop below. (This is the signature
	// header's v=, distinct from the key record's v=DKIM1.)
	if tags["v"] != "" && tags["v"] != "1" {
		return permfail("unsupported DKIM version " + tags["v"])
	}
	for _, req := range []string{"v", "a", "b", "bh", "d", "s", "h"} {
		if tags[req] == "" {
			return permfail("missing required tag " + req)
		}
	}

	// From MUST be signed (RFC 6376 §5.4, §6.1.1): the h= list MUST include the
	// From header field. If it does not, the displayed author identity sits
	// outside the signature's hash, so From can be altered — or the message
	// replayed under a new author — without breaking the signature, defeating
	// DKIM's core guarantee. Per §6.1.1 the Verifier MUST ignore such a
	// signature and return PERMFAIL (From field not signed).
	if !headerListCoversFrom(tags["h"]) {
		return permfail("From field not signed (h= does not cover from)")
	}

	// Identity alignment (RFC 6376 §6.1.1): when an Agent or User Identifier
	// (i=) is present, its domain MUST be the same as, or a subdomain of, the
	// signing domain (d=). An unaligned i= lets a signature valid for one domain
	// assert an identity in an arbitrary domain, misleading any assessor that
	// reads i= to attribute responsibility — so it is a PERMFAIL (domain
	// mismatch). Its domain, like d=, must be in A-label form (§3.5). When i= is
	// absent its default is "@"+d (§3.5), trivially aligned, so no check is
	// needed.
	if iTag, present := tags["i"]; present {
		idomain, ok := identityDomain(iTag)
		if !ok || !validDNSName(idomain) || !domainAligned(idomain, tags["d"]) {
			return permfail(fmt.Sprintf("i= domain %q not aligned with d= domain %q", idomain, tags["d"]))
		}
	}

	// Signature timing (RFC 6376 §3.5): t= (signature timestamp) and x=
	// (signature expiration) are counts of seconds since the Unix epoch. These
	// checks run before the crypto so an expired or malformed signature is
	// rejected without spending a DNS key lookup or an RSA verification.
	//
	//   - A syntactically invalid t= or x= (non-digit, or over 12 digits) is a
	//     PERMFAIL rather than being silently accepted.
	//   - When both are present, x= MUST be greater than t=; a value that is not
	//     is malformed and PERMFAILs.
	//   - When now is at or after x=, the signature has expired. §6.1.1 lets a
	//     verifier treat an expired signature as invalid; we do — an expired
	//     signature is a replay of a message the signer explicitly time-boxed —
	//     so it PERMFAILs rather than passing.
	var (
		tVal  int64
		haveT bool
	)
	if tTag, present := tags["t"]; present {
		tv, terr := parseTimeTag(tTag)
		if terr != nil {
			return permfail("invalid t= tag")
		}
		tVal, haveT = tv, true
	}
	if xTag, present := tags["x"]; present {
		xVal, xerr := parseTimeTag(xTag)
		if xerr != nil {
			return permfail("invalid x= tag")
		}
		if haveT && xVal <= tVal {
			return permfail("x= expiration not greater than t= timestamp")
		}
		if !timeNow().Before(time.Unix(xVal, 0)) {
			return permfail(fmt.Sprintf("signature expired (x=%s)", xTag))
		}
	}

	// ── Cryptographic mechanism ──────────────────────────────────────
	// Everything above is DKIM-Signature POLICY (RFC 6376). The actual
	// verification — select h= headers, canonicalize, hash, RSA-check b= against
	// the d=/s= key — is the policy-free primitive VerifySignatureBare, shared
	// here so DKIM and a layered scheme run byte-identical crypto. It also returns
	// the selected key record's policy flags for the two remaining DKIM checks.
	result, flags := verifyMechanism(ctx, tags, sig, allHeaders, body, resolver)
	if result.Result != ResultPass {
		return result
	}

	// Key-record s= service type (RFC 6376 §3.6.1): s= is a colon-separated list
	// of the service types the key may be used for, defaulting to "*" (all). We
	// are verifying an email signature, so a key whose published list names
	// neither "email" nor the wildcard "*" MUST NOT be used here — the domain
	// restricted this key to other services (e.g. s=tlsa), and honoring an email
	// signature under it would defy that restriction. PERMFAIL. Absent s= (the
	// default "*") imposes no restriction, so FetchKey leaves the flag unset.
	if flags.NotForEmail {
		return permfail("key record service type (s=) does not permit email")
	}

	// Key-record t=s flag (RFC 6376 §3.6.1): the "s" flag forbids subdomaining —
	// any signature carrying an i= (AUID) tag MUST have the same domain on the
	// right of the "@" as the value of d=; a subdomain is NOT permitted. The
	// general d=/i= alignment check above admits a subdomain i=, but when the key
	// the signer published sets t=s that admission is withdrawn: a subdomain AUID
	// PERMFAILs. When i= is absent its default is "@"+d (§3.5), whose domain
	// equals d exactly, so t=s is trivially satisfied and no check is needed.
	if flags.NoSubdomain {
		if iTag, present := tags["i"]; present {
			idomain, _ := identityDomain(iTag)
			if !strings.EqualFold(trimFWS(idomain), trimFWS(tags["d"])) {
				return permfail(fmt.Sprintf("i= domain %q must equal d= domain %q exactly: key record forbids subdomaining (t=s)", idomain, tags["d"]))
			}
		}
	}

	return result
}

// VerifySignatureBare verifies ONLY the cryptographic mechanism of a DKIM-shaped
// signature and applies NONE of the RFC 6376 DKIM-Signature policy. It selects
// the h= headers, canonicalizes header and body per c= (honoring l=), hashes per
// a=, resolves the signer's public key from d=/s= via DNS, and checks the b=
// signature. It does NOT require a v= version tag, does NOT require From to be
// signed, does NOT check i= (AUID) alignment to d=, does NOT apply signature
// timing (t=/x=), and does NOT enforce the key record's t=s / s= policy flags.
//
// It exists so a layered scheme can verify a signature that is structurally a
// DKIM-Signature but governed by its OWN policy, then apply that policy itself.
// The canonical case is ARC: an ARC-Message-Signature is versionless by design
// (RFC 8617 §4.1.2) and carries no author-alignment semantics, so verifying it
// under full DKIM policy is wrong. An ARC verifier calls VerifySignatureBare to
// check the AMS mechanism and then enforces RFC 8617 itself. Selecting the right
// key (the key record's own v=DKIM1 / h= constraints) is part of the mechanism
// and still applies.
//
// For standalone DKIM use Verify or VerifySignature — which is exactly this
// primitive plus the full RFC 6376 policy — NOT this function.
func VerifySignatureBare(ctx context.Context, sig Header, allHeaders []Header, body string, resolver TXTResolver) VerifyResult {
	// Parse strictly (RFC 6376 §3.2): a tag-list repeating a tag name is invalid
	// and must PERMFAIL rather than resolve to an arbitrary value — the same rule
	// VerifySignature applies, since this is the primitive underneath it.
	tags, err := ParseTagListStrict(sig.Value)
	if err != nil {
		return VerifyResult{Result: ResultPermError, Reason: err.Error()}
	}
	aLabelTags(tags)
	res, _ := verifyMechanism(ctx, tags, sig, allHeaders, body, resolver)
	return res
}

// VerifySignatureBareTags is VerifySignatureBare for a caller that has already
// parsed the signature's tag-list itself. A layered scheme whose grammar is wider
// than RFC 6376 §3.2 needs it: RFC 8617 §3.9 lets the leading i= instance of an
// ARC-Message-Signature carry CFWS comments ("i (hop) = 1;"), which the DKIM
// tag-list grammar refuses, so an ARC verifier parses the instance itself and
// passes the resulting tags here.
//
// tags drives the mechanism (a=, b=, bh=, c=, d=, h=, l=, s=); sig is still the
// header exactly as it occurs, because the header hash covers it with only the
// b= value emptied. The caller owns the tag-list's strictness, duplicate names
// included. tags is not modified; U-labels in d=, s= and the i= domain are
// converted to A-labels on a copy (RFC 8616 §5), as VerifySignatureBare does.
func VerifySignatureBareTags(ctx context.Context, tags map[string]string, sig Header, allHeaders []Header, body string, resolver TXTResolver) VerifyResult {
	own := make(map[string]string, len(tags))
	for k, v := range tags {
		own[k] = v
	}
	aLabelTags(own)
	res, _ := verifyMechanism(ctx, own, sig, allHeaders, body, resolver)
	return res
}

// verifyMechanism is the shared policy-free core beneath VerifySignatureBare,
// VerifySignatureBareTags and VerifySignature. Given the already-parsed tags it
// runs the pure verification mechanism and returns the VerifyResult plus, on a
// Pass, the selected key record's KeyFlags (the t=s / s= policy tags) so a DKIM
// caller can enforce them. On any non-Pass outcome the returned KeyFlags is the zero value.
func verifyMechanism(ctx context.Context, tags map[string]string, sig Header, allHeaders []Header, body string, resolver TXTResolver) (VerifyResult, KeyFlags) {
	res := VerifyResult{Domain: tags["d"], Selector: tags["s"]}
	permfail := func(reason string) (VerifyResult, KeyFlags) {
		res.Result = ResultPermError
		res.Reason = reason
		return res, KeyFlags{}
	}

	// Mechanism-required tags (RFC 6376 §3.5): without a=, b=, bh=, d=, s= and h=
	// the signature simply cannot be verified — they name the algorithm, the
	// signature bytes, the body hash, the key location and the covered headers.
	// v= is deliberately NOT required here: it is a DKIM POLICY tag enforced by
	// VerifySignature, and a versionless ARC-Message-Signature (RFC 8617 §4.1.2)
	// must verify through this primitive.
	for _, req := range []string{"a", "b", "bh", "d", "s", "h"} {
		if tags[req] == "" {
			return permfail("missing required tag " + req)
		}
	}

	// Algorithm (RFC 6376 §3.3, RFC 8301 §3.1, RFC 8463 §4.1). The key type is
	// threaded into key selection, which must find a key record of the same
	// type, and hashAlg into the key record's h= check (RFC 6376 §3.6.1 /
	// §6.1.2). Tag values are case-sensitive (§3.2), so "RSA-SHA256" is not
	// recognized. rsa-sha1 is historic: RFC 8301 forbids verifying with it.
	var keyType string
	const hashType, hashAlg = crypto.SHA256, "sha256"
	switch tags["a"] {
	case "rsa-sha256":
		keyType = "rsa"
	case "ed25519-sha256":
		keyType = "ed25519"
	case "rsa-sha1":
		return permfail("rsa-sha1 is historic and no longer verified (RFC 8301)")
	default:
		return permfail("unsupported algorithm " + tags["a"])
	}

	// Signing domain and selector (RFC 6376 §3.5): DNS names, internationalized
	// ones as A-labels. U-labels, which RFC 8616 §5 allows, were converted by
	// aLabelTags. Anything else cannot name a key record, and is not sent to the
	// resolver.
	if !validDNSName(tags["d"]) {
		return permfail("d= is not a DNS name in A-label form")
	}
	if !validDNSName(tags["s"]) {
		return permfail("s= is not a DNS name in A-label form")
	}

	// Query method (RFC 6376 §3.5): q= defaults to dns/txt, the only defined
	// method. Unrecognized methods are ignored, so a q= listing no dns/txt
	// leaves no way to fetch the key.
	if q, ok := tags["q"]; ok && !listContains(q, "dns/txt") {
		return permfail("no supported key query method in q=" + q)
	}

	// Canonicalization: c=header/body, default simple/simple.
	headerCanon, bodyCanon := "simple", "simple"
	if c, present := tags["c"]; present {
		parts := strings.SplitN(c, "/", 2)
		headerCanon = parts[0]
		if len(parts) == 2 {
			bodyCanon = parts[1]
		} else {
			bodyCanon = "simple" // "c=relaxed" means relaxed header, simple body
		}
	}
	if headerCanon != "simple" && headerCanon != "relaxed" {
		return permfail("unsupported header canonicalization " + headerCanon)
	}
	if bodyCanon != "simple" && bodyCanon != "relaxed" {
		return permfail("unsupported body canonicalization " + bodyCanon)
	}

	// ── Body hash ────────────────────────────────────────────────────
	canonBody := CanonicalizeBody(body, bodyCanon)
	if l, present := tags["l"]; present {
		n, err := parseUint(l)
		if err != nil {
			return permfail("invalid l= tag")
		}
		if n > len(canonBody) {
			return permfail("l= exceeds canonicalized body length")
		}
		canonBody = canonBody[:n]
	}
	computedBH := HashBytes(hashType, []byte(canonBody))
	expectedBH, err := decodeBase64Tag(tags["bh"])
	if err != nil {
		return permfail("invalid bh= base64")
	}
	if !bytesEqual(computedBH, expectedBH) {
		res.Result = ResultFail
		res.Reason = "body hash mismatch"
		return res, KeyFlags{}
	}

	// ── Header hash / signature ──────────────────────────────────────
	signedData := BuildSignedHeaders(tags["h"], allHeaders, sig, headerCanon)

	sigBytes, err := decodeBase64Tag(tags["b"])
	if err != nil {
		return permfail("invalid b= base64")
	}

	// ── Public key via DNS ───────────────────────────────────────────
	pub, flags, kres := fetchKey(ctx, tags["s"], tags["d"], keyType, hashAlg, resolver)
	if kres != "" {
		res.Result = kres
		if kres == ResultTempError {
			res.Reason = "temporary DNS failure for " + RecordName(tags["s"], tags["d"])
		} else {
			res.Reason = "no valid " + keyType + " key at " + RecordName(tags["s"], tags["d"])
		}
		return res, KeyFlags{}
	}

	hashed := HashBytes(hashType, []byte(signedData))
	if !verifyHash(pub, hashed, sigBytes) {
		res.Result = ResultFail
		res.Reason = "signature verification failed"
		return res, KeyFlags{}
	}

	res.Result = ResultPass
	res.Reason = fmt.Sprintf("signature ok (d=%s s=%s)", tags["d"], tags["s"])
	return res, flags
}

// headerListCoversFrom reports whether a signature's h= tag (a colon-separated
// list of header field names) includes the From field, matched
// case-insensitively and ignoring whitespace around each name. RFC 6376 §5.4
// makes From mandatory in h=; §6.1.1 requires PERMFAIL when it is absent.
func headerListCoversFrom(hTag string) bool {
	for _, name := range strings.Split(hTag, ":") {
		if strings.EqualFold(trimFWS(name), "from") {
			return true
		}
	}
	return false
}

// aLabelTags rewrites the U-labels of d=, s= and the i= domain in tags to
// A-labels (RFC 8616 §5). Every later check, the alignment comparisons and the
// key record name then see one form, while the header hash still covers the
// field text exactly as it occurs in sig. The i= local-part, which RFC 8616
// lets carry UTF-8, is kept as it is.
func aLabelTags(tags map[string]string) {
	for _, k := range []string{"d", "s"} {
		if v, ok := tags[k]; ok {
			tags[k] = toALabels(v)
		}
	}
	if iTag, ok := tags["i"]; ok {
		if at := strings.LastIndexByte(iTag, '@'); at >= 0 {
			tags["i"] = iTag[:at+1] + toALabels(iTag[at+1:])
		}
	}
}

// identityDomain returns the domain part of a DKIM i= (AUID) tag value: the
// text after the LAST "@". RFC 6376 §3.5 defines i= as [ Local-part ] "@"
// domain-name, and the local part may be a quoted string that itself contains
// "@", so the split is on the last "@". A value with no "@" is malformed and
// yields ("", false).
func identityDomain(iTag string) (string, bool) {
	at := strings.LastIndexByte(iTag, '@')
	if at < 0 {
		return "", false
	}
	return iTag[at+1:], true
}

// domainAligned reports whether the i= domain idomain is the same as, or a
// subdomain of, the signing domain d (RFC 6376 §6.1.1), compared
// case-insensitively. An empty idomain or d is never aligned.
func domainAligned(idomain, d string) bool {
	idomain = strings.ToLower(trimFWS(idomain))
	d = strings.ToLower(trimFWS(d))
	if idomain == "" || d == "" {
		return false
	}
	return idomain == d || strings.HasSuffix(idomain, "."+d)
}

// KeyFlags carries the policy-bearing tags of the DKIM key record the verifier
// selected — the flags it must apply against the signature after the key itself
// resolves, as distinct from the record fields (p=, k=, h=) FetchKey consumes to
// produce the key. It is returned by FetchKey so a caller (VerifySignature, or a
// layered scheme reusing the same key path) can enforce them.
type KeyFlags struct {
	// NoSubdomain reflects the key record's t=s flag (RFC 6376 §3.6.1): when set,
	// any signature carrying an i= (AUID) tag MUST have its domain equal to d=
	// exactly — subdomain AUIDs are not permitted. Absent the flag (the default),
	// a subdomain i= is allowed.
	NoSubdomain bool

	// NotForEmail reflects the key record's s= service-type tag (RFC 6376
	// §3.6.1): s= is a colon-separated list of the service types the key may be
	// used for, defaulting to "*" (all). When set — meaning s= was present and
	// listed neither "email" nor the wildcard "*" — the key MUST NOT be used to
	// verify an email signature. Absent the tag (default "*"), or a list that
	// includes "email" or "*", leaves it unset and the key usable for email.
	NotForEmail bool
}

// parseKeyFlags reads a DKIM key record's t= tag — a colon-separated list of
// flags, RFC 6376 §3.6.1, e.g. "y:s" — into a KeyFlags. Flag names are matched
// case-sensitively (§3.2) with the folding whitespace the ABNF permits around
// each ":" ignored; unrecognized flags (e.g. "y", testing mode, which the verifier
// does not act on here) are ignored per §3.6.1.
func parseKeyFlags(tTag string) KeyFlags {
	var f KeyFlags
	f.NoSubdomain = listContains(tTag, "s")
	return f
}

// FetchKey resolves and parses a signer's RSA public key from its DKIM key
// record at <selector>._domainkey.<domain>, for an rsa-sha256 signature such as
// an ARC-Seal. hashAlg is the hash half of the verifying signature's a= tag
// ("sha256"); a key record whose h= tag is present but does not list hashAlg is
// ignored (RFC 6376 §3.6.1 / §6.1.2), as is one whose key is not RSA or is
// shorter than 1024 bits (RFC 8301 §3.2). On success it returns (key, flags,
// "") where flags carries the selected key record's policy tags (the t= flags,
// §3.6.1) for the caller to enforce against the signature; on failure it
// returns (nil, KeyFlags{}, result) where result is ResultTempError (transient
// DNS failure) or ResultPermError (missing, revoked, malformed, or
// hash-algorithm-disallowed key).
func FetchKey(ctx context.Context, selector, domain, hashAlg string, resolver TXTResolver) (*rsa.PublicKey, KeyFlags, string) {
	pub, flags, res := fetchKey(ctx, selector, domain, "rsa", hashAlg, resolver)
	if res != "" {
		return nil, flags, res
	}
	return pub.(*rsa.PublicKey), flags, ""
}

// fetchKey resolves the key record at <selector>._domainkey.<domain> and
// returns the first usable key of keyType ("rsa" or "ed25519"): an
// *rsa.PublicKey of at least 1024 bits or an ed25519.PublicKey.
func fetchKey(ctx context.Context, selector, domain, keyType, hashAlg string, resolver TXTResolver) (crypto.PublicKey, KeyFlags, string) {
	name := RecordName(selector, domain)
	records, err := resolver(ctx, name)
	if err != nil {
		var dnsErr *net.DNSError
		if ok := asDNSError(err, &dnsErr); ok && dnsErr.IsNotFound {
			return nil, KeyFlags{}, ResultPermError
		}
		return nil, KeyFlags{}, ResultTempError
	}
	for _, rec := range records {
		// A key record whose tag-list repeats a tag name (or carries a malformed
		// segment) is invalid per RFC 6376 §3.2; skip it rather than resolve, say,
		// a duplicate p= to one of its values. If no valid record remains, the
		// caller returns PERMFAIL (no usable key).
		kt, err := ParseTagListStrict(rec)
		if err != nil {
			continue
		}
		// RFC 6376 §3.6.1 / §6.1.2: the key record's v= tag is the key-record
		// version (default "DKIM1"). When present it MUST equal "DKIM1"
		// (case-sensitive) AND MUST be the first tag in the record; a record
		// advertising any other version (e.g. v=DKIM2) or one whose v= is present
		// but not first MUST be treated as though it does not exist — skip it so the
		// caller PERMFAILs when no other record is usable. This blocks a domain's
		// future or parallel key scheme from being silently honored under DKIM1
		// rules. An ABSENT v= is permitted and defaults to DKIM1, so its absence
		// must NOT reject the record. (This is the DNS KEY record's v=, distinct
		// from the DKIM-Signature header's v= enforced at §3.5.)
		if v, ok := kt["v"]; ok && (v != "DKIM1" || firstTagName(rec) != "v") {
			continue
		}
		// RFC 6376 §3.6.1 / §6.1.2: the key record's h= tag, when present, lists
		// the hash algorithms the domain permits with this key. If the signature's
		// hash algorithm (hashAlg, the hash half of its a= tag) is not among them,
		// this record MUST be ignored — skip it so the caller PERMFAILs when no
		// other record permits the algorithm. This closes an algorithm-downgrade
		// acceptance avenue whereby a key the domain published for one hash is used
		// to accept a signature under an algorithm it never authorized. An h= tag
		// present but empty lists nothing acceptable, so it too excludes the key.
		if _, ok := kt["h"]; ok && !keyRecordAllowsHash(kt["h"], hashAlg) {
			continue
		}
		if kt["p"] == "" {
			continue // revoked or malformed
		}
		// k= defaults to "rsa" (§3.6.1). A key of another type than the
		// signature's a= names is not suitable for it (§6.1.2), and an
		// unrecognized type is ignored; either way the record is skipped.
		k, ok := kt["k"]
		if !ok {
			k = "rsa"
		}
		if k != keyType {
			continue
		}
		der, derr := decodeBase64Tag(kt["p"])
		if derr != nil {
			continue
		}
		pub := parsePublicKey(k, der)
		if pub == nil {
			continue
		}
		flags := parseKeyFlags(kt["t"])
		// RFC 6376 §3.6.1: the key record's s= tag, when present, lists the
		// service types this key may be used for (default "*", all services). A
		// list naming neither "email" nor the wildcard "*" bars the key from
		// verifying an email signature; record that so VerifySignature PERMFAILs.
		// Absent s= leaves the default (all services), so the key stays usable.
		if s, ok := kt["s"]; ok && !keyRecordAllowsService(s) {
			flags.NotForEmail = true
		}
		return pub, flags, ""
	}
	return nil, KeyFlags{}, ResultPermError
}

// parsePublicKey decodes the p= data of a key record of type k, or returns nil
// when it is not a usable key of that type.
//
// For "rsa", RFC 6376 §3.6.1 names an RSAPublicKey, but its own example
// (Appendix C) and nearly every published record carry a SubjectPublicKeyInfo,
// so both are accepted. A key shorter than 1024 bits is not usable (RFC 8301
// §3.2). For "ed25519", p= is the raw 32-byte public key (RFC 8463 §4.2).
func parsePublicKey(k string, der []byte) crypto.PublicKey {
	if k == "ed25519" {
		if len(der) != ed25519.PublicKeySize {
			return nil
		}
		return ed25519.PublicKey(der)
	}
	var key *rsa.PublicKey
	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		key, _ = pub.(*rsa.PublicKey)
	} else if pub, err := x509.ParsePKCS1PublicKey(der); err == nil {
		key = pub
	}
	if key == nil || key.N.BitLen() < minRSABits {
		return nil
	}
	return key
}

// verifyHash checks sig over the SHA-256 hash of the signed data with pub, an
// RSA key (PKCS#1 v1.5, RFC 6376 §3.3.2) or an Ed25519 key (PureEdDSA over the
// hash, RFC 8463 §3).
func verifyHash(pub crypto.PublicKey, hashed, sig []byte) bool {
	if k, ok := pub.(ed25519.PublicKey); ok {
		return ed25519.Verify(k, hashed, sig)
	}
	return rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), crypto.SHA256, hashed, sig) == nil
}

// firstTagName returns the name of the first tag in a DKIM tag-list record (the
// text before the first "="), ignoring the ABNF's optional leading folding
// whitespace and any empty leading segments (a stray leading ";" or surrounding
// FWS). It returns "" for a record with no tag. It is used to enforce RFC 6376
// §3.6.1's requirement that a key record's v= tag, when present, be the FIRST
// tag in the record.
func firstTagName(rec string) string {
	for _, seg := range strings.Split(rec, ";") {
		if trimFWS(seg) == "" {
			continue
		}
		eq := strings.IndexByte(seg, '=')
		if eq < 0 {
			return ""
		}
		return trimFWS(seg[:eq])
	}
	return ""
}

// keyRecordAllowsHash reports whether a DKIM key record's h= tag value (hTag) —
// a colon-separated list of acceptable hash algorithm names, RFC 6376 §3.6.1 —
// permits the hash algorithm named hashAlg ("sha256", the hash half of the
// signature's a= tag). Names are matched case-sensitively (§3.2) with the
// folding whitespace §3.6.1 allows around each ":" ignored; an unrecognized
// name in the list simply does not match (§3.6.1: "Unrecognized algorithms MUST
// be ignored"). It reports only list membership: whether the h= tag is present
// at all (absent = no restriction) is the caller's decision, so an empty hTag —
// a list with no members — returns false here.
func keyRecordAllowsHash(hTag, hashAlg string) bool {
	return listContains(hTag, hashAlg)
}

// listContains reports whether the colon-separated tag value list has an
// element equal to want, ignoring the folding whitespace allowed around each
// ":". Values are case-sensitive (RFC 6376 §3.2).
func listContains(list, want string) bool {
	for _, v := range strings.Split(list, ":") {
		if trimFWS(v) == want {
			return true
		}
	}
	return false
}

// keyRecordAllowsService reports whether a DKIM key record's s= tag value (sTag)
// — a colon-separated list of the service types the key may be used for, RFC 6376
// §3.6.1 — permits the "email" service: the list contains either "email" or the
// wildcard "*". Names are matched case-sensitively (§3.2) with the folding
// whitespace §3.6.1 allows around each ":" ignored; any other service type in the list is
// simply not a match (§3.6.1: unrecognized service types are ignored, not an
// error), so a list like "email:tlsa" permits email on the strength of its
// "email" entry. It reports only list membership: whether the s= tag is present
// at all (absent = default "*", all services) is the caller's decision, so an
// empty sTag — a list with no members — returns false here.
func keyRecordAllowsService(sTag string) bool {
	return listContains(sTag, "email") || listContains(sTag, "*")
}

// BuildSignedHeaders assembles the canonicalized header block that a signature's
// b= tag signs: each header named in hTag (a colon-separated list, matched
// bottom-up per RFC 6376 §5.4.2), followed by the signature header (sig) itself
// with its b= value emptied and NO trailing CRLF.
//
// It is exported so a signer or a layered scheme (ARC's ARC-Message-Signature)
// can produce the exact bytes VerifySignature will hash.
func BuildSignedHeaders(hTag string, allHeaders []Header, sig Header, canon string) string {
	// The field being verified is added implicitly below, never selected by
	// h=. Other signature fields retain their complete b= values (§3.5).
	// Copy only when sig occurs in the input; never alter the caller's slice.
	for i, h := range allHeaders {
		if h == sig {
			headers := make([]Header, 0, len(allHeaders)-1)
			headers = append(headers, allHeaders[:i]...)
			allHeaders = append(headers, allHeaders[i+1:]...)
			break
		}
	}
	// Track, per lowercased name, how many instances we've already consumed so
	// repeated names match from the bottom of the header block upward (RFC 6376
	// §5.4.2).
	consumed := map[string]int{}
	var b strings.Builder
	for _, name := range strings.Split(hTag, ":") {
		name = trimFWS(name)
		if name == "" {
			continue
		}
		lname := strings.ToLower(name)
		h := nthFromBottom(allHeaders, lname, consumed[lname])
		consumed[lname]++
		if h == nil {
			continue // absent header contributes nothing
		}
		b.WriteString(CanonicalizeHeader(*h, canon))
		b.WriteString("\r\n")
	}
	// The signature header being verified, b= emptied, no trailing CRLF.
	stripped := sig
	stripped.Value = RemoveBValue(sig.Value)
	// The raw field is name, colon, value; blank b= in the value only, so a b=
	// that is the first tag is found even though the name precedes it.
	if colon := strings.IndexByte(sig.Raw, ':'); colon >= 0 {
		stripped.Raw = sig.Raw[:colon+1] + RemoveBValue(sig.Raw[colon+1:])
	}
	b.WriteString(CanonicalizeHeader(stripped, canon))
	return b.String()
}

// decodeBase64Tag decodes a DKIM base64 tag value (b=, bh=, key p=) tolerantly,
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
func decodeBase64Tag(s string) ([]byte, error) {
	s = StripWSP(s)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
}

// nthFromBottom returns the nth (0-based) instance of the named header counting
// from the bottom of the header block, or nil if there are fewer than n+1.
func nthFromBottom(headers []Header, lname string, n int) *Header {
	count := 0
	for i := len(headers) - 1; i >= 0; i-- {
		if strings.ToLower(headers[i].Name) == lname {
			if count == n {
				return &headers[i]
			}
			count++
		}
	}
	return nil
}
