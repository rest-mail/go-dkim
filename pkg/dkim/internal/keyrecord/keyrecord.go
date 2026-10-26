package keyrecord

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"net"

	"github.com/rest-mail/go-dkim/pkg/dkim/internal/codec"
	"github.com/rest-mail/go-dkim/pkg/dkim/internal/grammar"
)

// Flags carries the selected key record's policy.
type Flags struct {
	NoSubdomain bool
	NotForEmail bool
}

const minRSABits = 1024
const resultPermError = "permerror"
const resultTempError = "temperror"

// RecordName returns the selector's DNS name, defaulting an empty selector.
func RecordName(selector, domain string) string {
	if selector == "" {
		selector = "default"
	}
	return selector + "._domainkey." + domain
}

// parseKeyFlags reads a DKIM key record's t= tag — a colon-separated list of
// flags, RFC 6376 §3.6.1, e.g. "y:s" — into a Flags. Flag names are matched
// case-sensitively (§3.2) with the folding whitespace the ABNF permits around
// each ":" ignored; unrecognized flags (e.g. "y", testing mode, which the verifier
// does not act on here) are ignored per §3.6.1.
func parseKeyFlags(tTag string) Flags {
	var f Flags
	f.NoSubdomain = grammar.ListContains(tTag, "s")
	return f
}

// Fetch resolves the key record at <selector>._domainkey.<domain> and
// returns the first usable key of keyType ("rsa" or "ed25519"): an
// *rsa.PublicKey of at least 1024 bits or an ed25519.PublicKey.
func Fetch(ctx context.Context, selector, domain, keyType, hashAlg string, resolver func(context.Context, string) ([]string, error)) (crypto.PublicKey, Flags, string) {
	name := RecordName(selector, domain)
	records, err := resolver(ctx, name)
	if err != nil {
		var dnsErr *net.DNSError
		if ok := errors.As(err, &dnsErr); ok && dnsErr.IsNotFound {
			return nil, Flags{}, resultPermError
		}
		return nil, Flags{}, resultTempError
	}
	for _, rec := range records {
		// A key record whose tag-list repeats a tag name (or carries a malformed
		// segment) is invalid per RFC 6376 §3.2; skip it rather than resolve, say,
		// a duplicate p= to one of its values. If no valid record remains, the
		// caller returns PERMFAIL (no usable key).
		kt, err := grammar.ParseTagListStrict(rec)
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
		if v, ok := kt["v"]; ok && (v != "DKIM1" || grammar.FirstTagName(rec) != "v") {
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
		der, derr := codec.DecodeTag(kt["p"])
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
	return nil, Flags{}, resultPermError
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

// VerifyHash checks sig over the SHA-256 hash of the signed data with pub, an
// RSA key (PKCS#1 v1.5, RFC 6376 §3.3.2) or an Ed25519 key (PureEdDSA over the
// hash, RFC 8463 §3).
func VerifyHash(pub crypto.PublicKey, hashed, sig []byte) bool {
	if k, ok := pub.(ed25519.PublicKey); ok {
		return ed25519.Verify(k, hashed, sig)
	}
	return rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), crypto.SHA256, hashed, sig) == nil
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
	return grammar.ListContains(hTag, hashAlg)
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
	return grammar.ListContains(sTag, "email") || grammar.ListContains(sTag, "*")
}
