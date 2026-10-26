package dkim

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/rest-mail/go-dkim/pkg/dkim/internal/folding"
	"github.com/rest-mail/go-dkim/pkg/dkim/internal/grammar"
)

// ParsePrivateKey parses a PEM-encoded RSA private key in PKCS#1 or PKCS#8 form.
// An Ed25519 signing key needs no helper: x509.ParsePKCS8PrivateKey returns an
// ed25519.PrivateKey, which SignOptions.PrivateKey accepts.
func ParsePrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("dkim: invalid private key PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k8, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("dkim: parse private key: %w", err)
	}
	rk, ok := k8.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("dkim: private key is not RSA")
	}
	return rk, nil
}

// SignOptions configures DKIM signing. Zero-value fields fall back to the
// documented defaults.
type SignOptions struct {
	Domain   string // d= signing domain (required)
	Selector string // s= selector (required)

	// PrivateKey signs the message (required). An RSA key of at least 1024
	// bits signs with rsa-sha256 (RFC 8301); an ed25519.PrivateKey signs with
	// ed25519-sha256 (RFC 8463). Any crypto.Signer whose public key is one of
	// those two types works, so the key can live in an HSM.
	PrivateKey crypto.Signer

	// Headers names the header fields to sign. Every instance of each that the
	// message carries is signed; a name the message lacks is left out.
	//
	// Oversign names header fields to sign once more than they appear, so a
	// copy added after signing breaks the signature (RFC 6376 §5.4.2). A name
	// in Oversign is signed even when the message lacks it, which asserts the
	// field's absence, and need not also be in Headers.
	//
	// When both are empty, Sign signs DefaultSignedHeaders and oversigns
	// DefaultOversignedHeaders. Otherwise each is taken as given: Headers set
	// and Oversign empty oversigns nothing. From must be in one of them.
	Headers  []string
	Oversign []string

	HeaderCanon string // "relaxed" (default) or "simple"
	BodyCanon   string // "relaxed" (default) or "simple"
	Time        int64  // t= value; 0 omits the tag

	// Expiration is the x= absolute expiration time, in seconds since the
	// epoch (RFC 6376 §3.5); 0 omits the tag. When Time is also set,
	// Expiration must be greater than it. Verifiers treat the signature as
	// invalid from that moment on.
	Expiration int64
}

// DefaultSignedHeaders is the header set Sign signs when SignOptions names
// none: the fields RFC 6376 §5.4.1 recommends, plus Message-ID, Sender and the
// top-level MIME fields, which §5.4 advises signing. Return-Path, Received,
// Comments and Keywords are left out, as §5.4.1 advises, because they are
// added or changed in transit.
var DefaultSignedHeaders = []string{
	"from", "reply-to", "subject", "date", "to", "cc",
	"resent-date", "resent-from", "resent-to", "resent-cc",
	"in-reply-to", "references",
	"list-id", "list-help", "list-unsubscribe", "list-subscribe", "list-post", "list-owner", "list-archive",
	"message-id", "sender", "mime-version", "content-type", "content-transfer-encoding",
}

// DefaultOversignedHeaders is the set Sign oversigns when SignOptions names
// no headers: the fields a reader sees or that decide how the body is shown,
// none of which a relay has reason to add.
var DefaultOversignedHeaders = []string{
	"from", "to", "cc", "subject", "reply-to", "date", "message-id", "content-type", "mime-version",
}

// maxTimestamp is the largest t= or x= value: RFC 6376 §3.5 allows 1*12DIGIT.
const maxTimestamp = 999999999999

// minRSABits is the smallest RSA key RFC 8301 §3.2 lets a signer use or a
// verifier accept.
const minRSABits = 1024

// Sign computes a DKIM-Signature header field VALUE (everything after
// "DKIM-Signature:") over the given raw RFC 5322 message. The caller prepends it
// as "DKIM-Signature: " + value + "\r\n", above any other DKIM-Signature.
//
// Signing operates on the message's ACTUAL header/body bytes and shares its
// canonicalization with Verify (via BuildSignedHeaders and CanonicalizeBody), so
// a message signed here verifies here — and, because it signs the real
// transmitted bytes rather than a reconstruction, at any RFC 6376 verifier.
//
// The value is folded into lines of at most 78 characters, counting the
// "DKIM-Signature: " the caller prepends, so the field stays within RFC 5322's
// line limits whatever the key size.
func Sign(rawMessage []byte, opt SignOptions) (string, error) {
	if opt.Domain == "" || opt.Selector == "" || opt.PrivateKey == nil {
		return "", fmt.Errorf("dkim.Sign: domain, selector and private key are required")
	}
	// RFC 6376 §3.5: d= and s= are DNS names, internationalized ones as
	// A-labels; anything else names no key record a verifier could find.
	if !grammar.ValidDNSName(opt.Domain) {
		return "", fmt.Errorf("dkim.Sign: domain %q is not a DNS name in A-label form", opt.Domain)
	}
	if !grammar.ValidDNSName(opt.Selector) {
		return "", fmt.Errorf("dkim.Sign: selector %q is not a DNS name in A-label form", opt.Selector)
	}

	var (
		algorithm string
		signOpts  crypto.SignerOpts
	)
	switch pub := opt.PrivateKey.Public().(type) {
	case *rsa.PublicKey:
		// RFC 8301 §3.2: signers MUST use RSA keys of at least 1024 bits.
		if pub.N.BitLen() < minRSABits {
			return "", fmt.Errorf("dkim.Sign: RSA key has %d bits, RFC 8301 requires at least %d", pub.N.BitLen(), minRSABits)
		}
		algorithm, signOpts = "rsa-sha256", crypto.SHA256
	case ed25519.PublicKey:
		// RFC 8463 §3: PureEdDSA over the SHA-256 hash, so no prehash option.
		algorithm, signOpts = "ed25519-sha256", crypto.Hash(0)
	default:
		return "", fmt.Errorf("dkim.Sign: unsupported key type %T (want RSA or Ed25519)", pub)
	}

	// RFC 6376 §3.5: t= and x= are 1*12DIGIT, and x= MUST be greater than
	// t=. A signature breaking either would fail at every verifier.
	if opt.Time > maxTimestamp || opt.Expiration > maxTimestamp {
		return "", fmt.Errorf("dkim.Sign: Time and Expiration must fit in 12 digits (RFC 6376 §3.5)")
	}
	if opt.Expiration < 0 {
		return "", fmt.Errorf("dkim.Sign: Expiration %d is negative", opt.Expiration)
	}
	if opt.Expiration > 0 && opt.Time > 0 && opt.Expiration <= opt.Time {
		return "", fmt.Errorf("dkim.Sign: Expiration %d is not after Time %d (RFC 6376 §3.5)", opt.Expiration, opt.Time)
	}

	headerCanon := opt.HeaderCanon
	if headerCanon == "" {
		headerCanon = "relaxed"
	}
	bodyCanon := opt.BodyCanon
	if bodyCanon == "" {
		bodyCanon = "relaxed"
	}
	for _, c := range []string{headerCanon, bodyCanon} {
		if c != "simple" && c != "relaxed" {
			return "", fmt.Errorf("dkim.Sign: unknown canonicalization %q (want simple or relaxed)", c)
		}
	}
	wantHeaders, oversign := opt.Headers, opt.Oversign
	if len(wantHeaders) == 0 && len(oversign) == 0 {
		wantHeaders, oversign = DefaultSignedHeaders, DefaultOversignedHeaders
	}

	allHeaders, body := SplitMessage(rawMessage)
	hTag, err := signedHeaderList(allHeaders, wantHeaders, oversign)
	if err != nil {
		return "", err
	}

	// Body hash.
	bodyHash := HashBytes(crypto.SHA256, []byte(CanonicalizeBody(body, bodyCanon)))
	bh := base64.StdEncoding.EncodeToString(bodyHash)

	// DKIM-Signature value with an empty b=.
	tags := []string{"v=1", "a=" + algorithm, "c=" + headerCanon + "/" + bodyCanon, "d=" + opt.Domain, "s=" + opt.Selector}
	if opt.Time > 0 {
		tags = append(tags, fmt.Sprintf("t=%d", opt.Time))
	}
	if opt.Expiration > 0 {
		tags = append(tags, fmt.Sprintf("x=%d", opt.Expiration))
	}
	tags = append(tags, "h="+strings.Join(hTag, ":"), "bh="+bh)
	f := folding.New()
	for _, tag := range tags {
		f.Tag(tag)
	}
	f.Tag("b=")
	valueNoB := f.String()

	// Build the signed data exactly as Verify does: the signed headers, then the
	// DKIM-Signature header itself (b= empty, no trailing CRLF). Reusing
	// BuildSignedHeaders is what guarantees sign/verify canonicalization parity.
	sigHeader := Header{Name: "DKIM-Signature", Value: " " + valueNoB, Raw: "DKIM-Signature: " + valueNoB}
	signedData := BuildSignedHeaders(strings.Join(hTag, ":"), allHeaders, sigHeader, headerCanon)

	hashed := HashBytes(crypto.SHA256, []byte(signedData))
	sig, err := opt.PrivateKey.Sign(rand.Reader, hashed, signOpts)
	if err != nil {
		return "", fmt.Errorf("dkim.Sign: %w", err)
	}
	f.Base64(base64.StdEncoding.EncodeToString(sig))
	return f.String(), nil
}

// signedHeaderList builds the h= list: each name in want once per instance the
// message carries, each name in oversign once more than that (RFC 6376
// §5.4.2), in the order first named. Names are lowercased and must be valid
// field names, and From must be among them (§5.4).
func signedHeaderList(headers []Header, want, oversign []string) ([]string, error) {
	count := map[string]int{}
	for _, h := range headers {
		count[strings.ToLower(h.Name)]++
	}
	extra := map[string]int{}
	var order []string
	add := func(names []string, more int) error {
		for _, name := range names {
			name = strings.ToLower(strings.TrimSpace(name))
			if !grammar.ValidFieldName(name) {
				return fmt.Errorf("dkim.Sign: %q is not a header field name", name)
			}
			if _, seen := extra[name]; !seen {
				order = append(order, name)
			}
			extra[name] = max(extra[name], more)
		}
		return nil
	}
	if err := add(want, 0); err != nil {
		return nil, err
	}
	if err := add(oversign, 1); err != nil {
		return nil, err
	}
	// RFC 6376 §5.4: the From header field MUST be signed. Refuse a header list
	// that omits it, or a message that has none, rather than emit a signature no
	// conforming verifier will accept.
	if _, ok := extra["from"]; !ok {
		return nil, fmt.Errorf("dkim.Sign: the From header must be signed (RFC 6376 §5.4); include \"from\" in SignOptions.Headers")
	}
	if count["from"] == 0 {
		return nil, fmt.Errorf("dkim.Sign: message has no From header to sign (RFC 6376 §5.4)")
	}
	var list []string
	for _, name := range order {
		for range count[name] + extra[name] {
			list = append(list, name)
		}
	}
	return list, nil
}
