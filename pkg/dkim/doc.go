// Package dkim signs and verifies email messages with DomainKeys Identified
// Mail (DKIM, RFC 6376).
//
// DKIM lets a domain take responsibility for a message by attaching a
// cryptographic signature over selected header fields and the body. A verifier
// fetches the signer's public key from DNS (at <selector>._domainkey.<domain>)
// and confirms the message was not altered in transit.
//
// Signing and verification both operate on the raw RFC 5322 message bytes —
// never on a parsed or reconstructed representation — so a signature is checked
// against exactly what was transmitted. Both "simple" and "relaxed" header and
// body canonicalization are supported, with the rsa-sha256 and ed25519-sha256
// algorithms (RFC 8301, RFC 8463); the historic rsa-sha1 is refused. The
// package depends only on the Go standard library.
//
// # Signing
//
// Sign returns a DKIM-Signature field value over a raw message; the caller
// prepends the header field name and a trailing CRLF:
//
//	value, err := dkim.Sign(raw, dkim.SignOptions{
//		Domain:     "example.com",
//		Selector:   "default",
//		PrivateKey: key,
//	})
//	signed := append([]byte("DKIM-Signature: "+value+"\r\n"), raw...)
//
// By default Sign signs the header fields RFC 6376 §5.4.1 recommends
// (DefaultSignedHeaders) and oversigns the ones a reader sees
// (DefaultOversignedHeaders), so a From, To or Subject added after signing
// breaks the signature. SignOptions.Headers and SignOptions.Oversign choose
// others.
//
// GenerateKey, RecordName, RecordValue and RecordFragment produce a keypair and
// render the public half as the DNS TXT record verifiers look up.
//
// # Verifying
//
// Verify returns one VerifyResult per DKIM-Signature header, in header order. A
// nil resolver uses the system DNS resolver:
//
//	for _, r := range dkim.Verify(ctx, raw, nil) {
//		fmt.Println(r.Domain, r.Result)
//	}
//
// # Primitives
//
// The canonicalization and single-signature primitives (SplitMessage,
// CanonicalizeHeader, CanonicalizeBody, BuildSignedHeaders, VerifySignature,
// FetchKey, ParseTagList, RemoveBValue, StripWSP, HashBytes) are exported so
// that layered schemes such as ARC — whose ARC-Message-Signature is
// structurally a DKIM-Signature — can reuse the exact same code path.
package dkim
