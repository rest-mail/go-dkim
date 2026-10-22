# go-dkim

[![CI](https://github.com/rest-mail/go-dkim/actions/workflows/ci.yml/badge.svg)](https://github.com/rest-mail/go-dkim/actions/workflows/ci.yml)
[![Coverage gate: ≥95%](https://img.shields.io/badge/coverage%20gate-%E2%89%A595%25-brightgreen)](COVERAGE.md)
[![Checklist: 110/134 mapped](https://img.shields.io/badge/checklist-110%2F134%20mapped-blue)](CHECKLIST.md)
[![Go Reference](https://pkg.go.dev/badge/github.com/rest-mail/go-dkim.svg)](https://pkg.go.dev/github.com/rest-mail/go-dkim)
[![Go Report Card](https://goreportcard.com/badge/github.com/rest-mail/go-dkim)](https://goreportcard.com/report/github.com/rest-mail/go-dkim)

DKIM ([RFC 6376](https://www.rfc-editor.org/rfc/rfc6376)) message signing and
verification for Go, with the algorithm updates of
[RFC 8301](https://www.rfc-editor.org/rfc/rfc8301) and
[RFC 8463](https://www.rfc-editor.org/rfc/rfc8463) (Ed25519), from the
[REST Mail](https://rest-mail.com) project. Standard library only, no external
dependencies.

## About

DomainKeys Identified Mail lets a domain take responsibility for a message by
attaching a cryptographic signature over selected header fields and the body. A
verifier fetches the signer's public key from DNS (at
`<selector>._domainkey.<domain>`) and confirms the message was not altered in
transit.

This package signs and verifies over the **raw** RFC 5322 message bytes — never
a parsed or reconstructed representation — so a signature is checked against
exactly what was transmitted. That is the difference between a signature that
survives real-world relays and one that only verifies against your own
serializer.

The requirement inventory and section audit are in [CHECKLIST.md](CHECKLIST.md).
Mapped rows provide executable evidence; the documented `n/a` rows include
caller duties and explicit limitations, including omitted timestamp/expiry
recommendations at the signing defaults.

## Features

- Sign and verify with `rsa-sha256` and `ed25519-sha256`. The historic
  `rsa-sha1`, and RSA keys under 1024 bits, are refused, as RFC 8301 requires.
- Signs the header fields RFC 6376 §5.4.1 recommends by default, and
  **oversigns** the ones a reader sees, so a `From`, `To` or `Subject` added
  after signing breaks the signature.
- Both **simple** and **relaxed** header and body canonicalization.
- Operates on raw message bytes; the sign and verify paths share one canonicalizer.
- Keypair generation and DNS TXT record rendering (`GenerateKey`, `RecordValue`, `RecordFragment`).
- RFC 8601 result values (`pass`, `fail`, `neutral`, `none`, `temperror`, `permerror`).
- Pluggable DNS resolver (`TXTResolver`) for tests and custom lookups.
- Exported canonicalization primitives, so layered schemes such as ARC reuse the exact same code path.
- No external dependencies (the tests use go-msgauth; the library does not).

## Install

```sh
go get github.com/rest-mail/go-dkim
```

## Quickstart

A full sign-then-verify round trip. In production you generate the keypair once,
sign with the private half, and publish the public half as the DNS TXT record;
verifiers then resolve it over real DNS (pass `nil` for the resolver). Here an
in-memory resolver keeps the example self-contained.

```go
package main

import (
	"context"
	"fmt"

	"github.com/rest-mail/go-dkim"
)

func main() {
	// Generate a keypair (do this once; keep the private key, publish the public).
	privPEM, pubPEM, err := dkim.GenerateKey(2048)
	if err != nil {
		panic(err)
	}
	key, err := dkim.ParsePrivateKey(privPEM)
	if err != nil {
		panic(err)
	}

	raw := []byte("From: alice@example.com\r\n" +
		"To: bob@example.net\r\n" +
		"Subject: hello\r\n" +
		"Date: Thu, 23 Jul 2026 10:00:00 +0000\r\n" +
		"Message-ID: <1@example.com>\r\n" +
		"\r\n" +
		"Hello, world!\r\n")

	// Sign returns the DKIM-Signature field VALUE; prepend the header yourself.
	value, err := dkim.Sign(raw, dkim.SignOptions{
		Domain:     "example.com",
		Selector:   "default",
		PrivateKey: key,
	})
	if err != nil {
		panic(err)
	}
	signed := append([]byte("DKIM-Signature: "+value+"\r\n"), raw...)

	// Verify. Pass nil for the resolver to use system DNS; here we serve the
	// public key we just generated from memory.
	txt, _ := dkim.RecordValue(pubPEM)
	resolver := func(_ context.Context, _ string) ([]string, error) {
		return []string{txt}, nil
	}
	for _, r := range dkim.Verify(context.Background(), signed, resolver) {
		fmt.Printf("d=%s s=%s -> %s\n", r.Domain, r.Selector, r.Result)
	}
	// Prints: d=example.com s=default -> pass
}
```

## Signing

`Sign` computes a DKIM-Signature field value over a raw message and returns it;
the caller prepends `DKIM-Signature: ` and a trailing CRLF, above any other
DKIM-Signature field. The value is folded into lines of at most 78 characters.
Unset `SignOptions` fields fall back to documented defaults: `relaxed/relaxed`
canonicalization and the header sets below.

`SignOptions.PrivateKey` is a `crypto.Signer`: an `*rsa.PrivateKey` of at least
1024 bits signs with `rsa-sha256`, an `ed25519.PrivateKey` with
`ed25519-sha256`. `ParsePrivateKey` reads an RSA key; `x509.ParsePKCS8PrivateKey`
reads an Ed25519 one.

Which header fields are signed:

- `SignOptions.Headers` names fields to sign. Every instance the message
  carries is signed; a name the message lacks is left out.
- `SignOptions.Oversign` names fields to sign **once more than they appear**
  (RFC 6376 §5.4.2). The extra entry hashes as an empty field, so a copy added
  anywhere after signing breaks the signature. A name in `Oversign` is signed
  even when the message lacks it, which asserts its absence.
- With both empty, `Sign` signs `DefaultSignedHeaders` (the §5.4.1 list:
  From, Reply-To, Subject, Date, To, Cc, the Resent-\* and List-\* fields,
  In-Reply-To and References, plus Message-ID, Sender, MIME-Version,
  Content-Type and Content-Transfer-Encoding) and oversigns
  `DefaultOversignedHeaders` (From, To, Cc, Subject, Reply-To, Date,
  Message-ID, Content-Type and MIME-Version). Set either and each is taken as
  given: `Headers` alone oversigns nothing. `From` must be among them.

Generate a keypair and render its DNS TXT record with `GenerateKey`,
`RecordName`, `RecordValue` and `RecordFragment` (the last splits values over
255 characters into multiple quoted strings so 2048-bit records stay valid).

## Verifying

`Verify` returns one `VerifyResult` per DKIM-Signature header, in header order;
an empty slice means the message carried no signature. Pass `nil` for the
resolver to use system DNS, or inject a `TXTResolver` (its signature matches
`net.Resolver.LookupTXT`) in tests. Each result's `Result` field is one of
`dkim.ResultPass`, `ResultFail`, `ResultNeutral`, `ResultNone`,
`ResultTempError` or `ResultPermError` (RFC 8601 `dkim=` values). RFC 6376's
PERMFAILs for a body hash or signature that does not verify are reported as
`fail`; every other PERMFAIL (a malformed signature, a missing or unusable key)
as `permerror`; a DNS failure as `temperror`.

Empty optional `c=`, `i=`, `t=`, `x=`, `l=` and `q=` tags are malformed;
defaults apply only when those tags are absent. A signature may cover another
DKIM-Signature field, including that field's complete `b=` value; it never
selects itself through `h=`. An `l=` larger than the canonicalized body or
longer than 76 digits is a `permerror`.

A resolver returns one string per TXT record, with the record's
character-strings joined without spaces, as `net.Resolver.LookupTXT` does. A
name that does not exist is a `*net.DNSError` whose `IsNotFound` is true; any
other error is transient.

## Primitives

The canonicalization and single-signature building blocks are exported —
`SplitMessage`, `CanonicalizeHeader`, `CanonicalizeBody`, `BuildSignedHeaders`,
`VerifySignature`, `VerifySignatureBare`, `FetchKey`, `ParseTagList`,
`ParseTagListStrict`, `RemoveBValue`, `StripWSP` and `HashBytes` — so a layered
scheme whose signature is structurally a DKIM-Signature (such as ARC's
ARC-Message-Signature) can reuse the exact same canonicalization and crypto path.
`FetchKey` returns the RSA key at a selector, for an `rsa-sha256` signature such
as an ARC-Seal, and refuses keys under 1024 bits.

For such a scheme, prefer `VerifySignatureBare`: it runs only the cryptographic
mechanism (header/body canonicalization, hashing, and the signature check against the
`d=`/`s=` DNS key) and applies none of the RFC 6376 DKIM-Signature policy — no
`v=` requirement, no From-signed rule, no `i=` alignment, no timing, no key-record
`t=s` / `s=` flags — so a versionless ARC-Message-Signature (RFC 8617 §4.1.2)
verifies and the scheme applies its own policy on top. `VerifySignature` is that
same primitive plus the full DKIM policy, for standalone DKIM.

## Choices the RFCs leave open

Where the RFCs leave a detail to the implementation, this package takes the
simplest secure option:

- **An expired signature** (`x=` in the past) is a `permerror`, which
  RFC 6376 §6.1.1 allows but does not require.
- **Several key records** at one selector are tried in turn; the first usable
  one is used.
- **An RSA `p=`** may be the RSAPublicKey RFC 6376 §3.6.1 names or the
  SubjectPublicKeyInfo its Appendix C (and nearly every publisher) uses.
- **`d=`, `s=` and the domain of `i=`** may be U-labels (RFC 8616 §5); they
  are converted to A-labels (lower-cased, punycode; not the full IDNA2008
  mapping) before any check or DNS query, and the result reports them so.
  After that they must be dot-separated labels of 1 to 63 letters, digits,
  hyphens or underscores; anything else (invalid UTF-8, say) is a `permerror`
  and no DNS query is sent.
- **A line in the header that is not a header field** (no colon, or a name
  with whitespace in it) is skipped together with its continuation lines.

## Testing

```sh
go test -race ./...                 # all tests, no network
go run ./internal/checklist         # CHECKLIST.md and the tests agree
go test -run='^$' -fuzz='^FuzzSignVerify$' -fuzztime=30s .
python3 -m unittest discover -s .github/tests   # what CI passes the shared proof
```

CI runs these through go-spf's reusable
[`rfc-verification.yml`](https://github.com/rest-mail/go-spf/blob/7d291c08d310b9c62afc287e75a534a39150fafb/.github/workflows/rfc-verification.yml),
pinned to that commit; the required `Build & Test` check passes only when it
and the workflow fixtures in [`.github/tests`](.github/tests) both succeed.
CI also fails below 95% statement coverage; the lines left uncovered on
purpose are listed, each with a reason, in [COVERAGE.md](COVERAGE.md). The
coverage badge states this enforced minimum; the measured percentage is in
each CI run's `RFC proof` log. The checklist badge counts requirements mapped
to tests over all requirements, including the 23 `n/a` rows, each with its
reason, in the total. CI validates the mappings and rejects a stale badge
count. These badges describe the checked-in contract; the CI badge shows
whether verification passed.

The fuzz targets are `FuzzParseTagList` (tag-lists), `FuzzSignatureHeader` (verifying
any DKIM-Signature field), `FuzzKeyRecord` (key records), `FuzzCanonicalization`
(properties such as relaxed canonicalization being idempotent) and
`FuzzSignVerify` (anything signed verifies); CI runs each for 30 seconds. Their
seeds are in the targets, and inputs that once failed are kept in
`testdata/fuzz`.

The RFCs' own examples are tests: RFC 8463's Appendix A message, whose
Ed25519 and RSA signatures verify against its published keys; the body hash and
key record of RFC 6376's Appendix A and C; and the canonicalization examples of
RFC 6376 §3.4.5. Differential tests check this package against
[go-msgauth](https://github.com/emersion/go-msgauth) (MIT): messages one signs
must verify with the other, both ways, in every canonicalization and with both
key types. go-msgauth is a test-only dependency; the library does not import
it.

### The RFC checklist

[CHECKLIST.md](CHECKLIST.md) lists the RFCs' requirements item by item, and a
small program, [`internal/checklist`](internal/checklist/main.go), checks it
against the tests in CI. It is the same program as
[go-spf](https://github.com/rest-mail/go-spf)'s; other `go-*` libraries can
copy both.

The checklist is a Markdown file holding one or more tables whose header is
exactly:

```markdown
| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DKIM-SIG-02 | 3.5, 6.1.1 | MUST | v= is required and is 1. | `TestVerify_WrongVersionRejected` |
| DKIM-VER-12 | 6.2 | SHOULD | Insert the verification result above the DKIM-Signature fields. | n/a: the library writes no header fields. |
```

- **ID** is unique, upper case, and ends in a number: a prefix for the RFC, an
  area, and a sequence number (`DKIM-SIG-02`).
- **Section** is the RFC section (or sections) the requirement comes from.
- **Level** is the RFC 2119 keyword it carries (`MUST`, `MUST NOT`, `SHOULD`,
  `SHOULD NOT`, `RECOMMENDED`, `NOT RECOMMENDED`, `MAY`, ...), or `Normative`
  for normative text without a keyword.
- **Requirement** says what is required, in one line (no `|`).
- **Tests** lists the test functions that cover it, separated by commas, or
  says `n/a:` and why it does not apply.

Each test names the items it covers in its doc comment:

```go
// TestRSASHA1Refused checks that an rsa-sha1 signature, historic since RFC
// 8301, is a permanent error.
//
// checklist: DKIM-ALG-03
func TestRSASHA1Refused(t *testing.T) {
```

`go run ./internal/checklist [-file CHECKLIST.md] [package dir ...]` scans the
`_test.go` files of the given package directories (default `.`) and fails when:

- an ID is used twice, or a row is malformed;
- an item names no test and is not marked `n/a`;
- an item lists a test that does not exist, or that does not name the item;
- a test names an item that does not exist, is `n/a`, or does not list it;
- a `Test` or `Fuzz` function names no item (`Example` functions may).

## Documentation

Full API reference:
[pkg.go.dev/github.com/rest-mail/go-dkim](https://pkg.go.dev/github.com/rest-mail/go-dkim).

## Changelog

Recent releases (full history and detail in [CHANGELOG.md](CHANGELOG.md)):

- **Unreleased** — Ed25519 (RFC 8463); RFC 8301 (no `rsa-sha1`, RSA keys of at least 1024 bits); the RFC 6376 §5.4.1 default header set with oversigning; a folded signature field; an RFC checklist, a 95% coverage gate, fuzzing and differential tests. (`SignOptions.PrivateKey` is now a `crypto.Signer`.)
- **0.2.1** — add `VerifySignatureBare`, a policy-free verification primitive, restoring ARC compatibility (a versionless ARC-Message-Signature can be verified without inheriting DKIM policy).
- **0.2.0** — enforce the key record's `v=`, `s=` service-type, `t=s` no-subdomain and `h=` hash-algorithm policy; require the signature `v=` tag; require `From` in `h=` when signing; accept unpadded base64. (`FetchKey` signature changed.)
- **0.1.3** — reject `From` not signed, unaligned `i=`, duplicate tags, and expired/malformed signature timing; export `ParseTagListStrict`.
- **0.1.2** — reject a non-digit `l=` body-length tag, fixing a remotely triggerable panic.
- **0.1.1** — rename the module path to `github.com/rest-mail/go-dkim`.
- **0.1.0** — initial release: RFC 6376 signing and verification, standard library only.

## License

[MIT](LICENSE) © 2026 rest-mail
