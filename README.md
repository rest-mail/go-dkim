# go-dkim

[![CI](https://github.com/rest-mail/go-dkim/actions/workflows/ci.yml/badge.svg)](https://github.com/rest-mail/go-dkim/actions/workflows/ci.yml)
[![Coverage gate: ≥95%](https://img.shields.io/badge/coverage%20gate-%E2%89%A595%25-brightgreen)](COVERAGE.md)
[![Checklist: 110/134 mapped](https://img.shields.io/badge/checklist-110%2F134%20mapped-blue)](CHECKLIST.md)
[![Go Reference](https://pkg.go.dev/badge/github.com/rest-mail/go-dkim.svg)](https://pkg.go.dev/github.com/rest-mail/go-dkim/pkg/dkim)
[![Go Report Card](https://goreportcard.com/badge/github.com/rest-mail/go-dkim)](https://goreportcard.com/report/github.com/rest-mail/go-dkim)

DKIM ([RFC 6376]) message signing and verification for Go, with the algorithm
updates of [RFC 8301] and [RFC 8463] (Ed25519) and the internationalized names
of [RFC 8616], from the [REST Mail](https://rest-mail.com) project. Standard
library only: no external dependencies.

DomainKeys Identified Mail lets a domain take responsibility for a message by
attaching a cryptographic signature over selected header fields and the body. A
verifier fetches the signer's public key from DNS (at
`<selector>._domainkey.<domain>`) and confirms the message was not altered in
transit.

go-dkim signs and verifies over the **raw** RFC 5322 message bytes, never a
parsed or reconstructed representation, so a signature is checked against
exactly what was transmitted. That is the difference between a signature that
survives real-world relays and one that only verifies against your own
serializer.

## Contents

- [Install](#install)
- [Packages](#packages)
- [Quick start](#quick-start): [sign and verify](#sign-and-verify), [one signature at a time](#one-signature-at-a-time)
- [Features](#features)
- [What the library does and what the host must do](#what-the-library-does-and-what-the-host-must-do)
- [RFC conformance](#rfc-conformance): [the checklist](#the-rfc-checklist), [what it does not do](#what-it-does-not-do), [badges and coverage](#badges-and-coverage)
- [Changelog](#changelog)
- [Licence](#licence)

## Install

```sh
go get github.com/rest-mail/go-dkim@latest
```

The module declares go 1.25.

## Packages

| Import path | What it holds |
|-------------|---------------|
| `github.com/rest-mail/go-dkim/pkg/dkim` | Signing and verifying: `Sign`, `SignOptions`, `DefaultSignedHeaders`, `DefaultOversignedHeaders`, `ParsePrivateKey`, `Verify`, `VerifyResult`, the `Result*` values and `TXTResolver`; the single-signature and canonicalization primitives (`Header`, `SplitMessage`, `CanonicalizeHeader`, `CanonicalizeBody`, `BuildSignedHeaders`, `VerifySignature`, `VerifySignatureBare`, `VerifySignatureBareTags`, `FetchKey`, `KeyFlags`, `ParseTagList`, `ParseTagListStrict`, `RemoveBValue`, `StripWSP`, `HashBytes`); and the key helpers `GenerateKey`, `RecordName`, `RecordValue`, `RecordFragment` and `DefaultSelector`. |
| `pkg/dkim/internal/grammar` | Tag-list and numeric grammar, field/DNS names and identity alignment. Internal: not importable by callers. |
| `pkg/dkim/internal/codec` | Folding-whitespace and base64 codecs. Internal: not importable by callers. |
| `pkg/dkim/internal/folding` | DKIM signature value folding. Internal: not importable by callers. |
| `pkg/dkim/internal/keyrecord` | DNS key-record parsing, policy flags and signature crypto. Internal: not importable by callers. |
| `pkg/dkim/internal/idna` | Converts U-labels to A-labels (lower-casing and RFC 3492 punycode) for RFC 8616 names. Internal: not importable. |

Upgrading from v0.4 or earlier: the root package is gone. Import
`github.com/rest-mail/go-dkim/pkg/dkim`; every name is unchanged.
[CHANGELOG.md](CHANGELOG.md#050---2026-10-26) has the old-to-new table.

## Quick start

### Sign and verify

A full sign-then-verify round trip. In production you generate the keypair once,
sign with the private half, and publish the public half as the DNS TXT record;
verifiers then resolve it over real DNS (pass `nil` for the resolver). Here an
in-memory resolver keeps the example self-contained.

```go
package main

import (
	"context"
	"fmt"

	"github.com/rest-mail/go-dkim/pkg/dkim"
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

`Example` in [`pkg/dkim/example_test.go`](pkg/dkim/example_test.go) runs the
same round trip as a test.

### One signature at a time

A scheme whose signature is structurally a DKIM-Signature, such as ARC's
ARC-Message-Signature, splits the message once and verifies one field:

```go
headers, body := dkim.SplitMessage(raw)
res := dkim.VerifySignatureBare(ctx, sigHeader, headers, body, resolver)
```

`VerifySignatureBare` runs only the cryptographic mechanism; the scheme applies
its own policy on top. See [primitives](#primitives).

## Features

| Feature | RFC | Notes |
|---------|-----|-------|
| `rsa-sha256` signing and verification | [RFC 6376], [RFC 8301] | RSA keys of at least 1024 bits; `GenerateKey` makes keys of at least 2048. |
| `ed25519-sha256` signing and verification | [RFC 8463] | Sign with an `ed25519.PrivateKey`; verify against a `k=ed25519` key record. |
| `simple` and `relaxed` canonicalization | RFC 6376 §3.4 | For the header and the body independently; `relaxed/relaxed` by default. One canonicalizer serves both signing and verifying. |
| Default signed header set, with oversigning | RFC 6376 §5.4 | `DefaultSignedHeaders` and `DefaultOversignedHeaders`; `SignOptions.Headers` and `Oversign` choose others. |
| `t=` and `x=` timestamps | RFC 6376 §3.5 | `SignOptions.Time` and `Expiration`; the verifier refuses an expired signature. |
| `l=` body length | RFC 6376 §3.5 | Verified when present; `Sign` never emits it. |
| Internationalized names | [RFC 8616] §5 | The verifier accepts U-labels in `d=`, `s=` and the `i=` domain, and UTF-8 in tag values. |
| Key records | RFC 6376 §3.6 | `v=`, `k=`, `h=`, `s=` and the `t=s` flag are enforced; `p=` may be an RSAPublicKey or a SubjectPublicKeyInfo. `RecordValue` and `RecordFragment` render them. |
| Results | RFC 8601 | `pass`, `fail`, `neutral`, `none`, `temperror` and `permerror`, one per signature. |
| Pluggable DNS | | `TXTResolver` matches `net.Resolver.LookupTXT`; `nil` uses the system resolver. |
| Exported primitives | RFC 8617 | Canonicalization and single-signature verification for layered schemes such as ARC. |

### Signing

`Sign` computes a DKIM-Signature field value over a raw message and returns it;
the caller prepends `DKIM-Signature: ` and a trailing CRLF, above any other
DKIM-Signature field. The value is folded into lines of at most 78 characters.
Unset `SignOptions` fields fall back to documented defaults: `relaxed/relaxed`
canonicalization and the header sets below.

`SignOptions.PrivateKey` is a `crypto.Signer`, so the key can live in an HSM:
an `*rsa.PrivateKey` of at least 1024 bits signs with `rsa-sha256`, an
`ed25519.PrivateKey` with `ed25519-sha256`. `ParsePrivateKey` reads an RSA key;
`x509.ParsePKCS8PrivateKey` reads an Ed25519 one.

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

`GenerateKey`, `RecordName`, `RecordValue` and `RecordFragment` produce a
keypair and render its public half as the DNS TXT record. `RecordFragment`
splits values over 255 characters into several quoted strings, so 2048-bit
records stay valid.

### Verifying

`Verify` returns one `VerifyResult` per DKIM-Signature header, in header order;
an empty slice means the message carried no signature. Each result's `Result`
field is one of `dkim.ResultPass`, `ResultFail`, `ResultNeutral`, `ResultNone`,
`ResultTempError` or `ResultPermError` (RFC 8601 `dkim=` values). RFC 6376's
PERMFAILs for a body hash or signature that does not verify are reported as
`fail`; every other PERMFAIL (a malformed signature, a missing or unusable key)
as `permerror`; a DNS failure as `temperror`.

A resolver returns one string per TXT record, with the record's
character-strings joined without spaces, as `net.Resolver.LookupTXT` does. A
name that does not exist is a `*net.DNSError` whose `IsNotFound` is true; any
other error is transient.

### Primitives

The canonicalization and single-signature building blocks are exported
(`SplitMessage`, `CanonicalizeHeader`, `CanonicalizeBody`, `BuildSignedHeaders`,
`VerifySignature`, `VerifySignatureBare`, `VerifySignatureBareTags`, `FetchKey`,
`ParseTagList`, `ParseTagListStrict`, `RemoveBValue`, `StripWSP` and
`HashBytes`), so a layered scheme whose signature is structurally a
DKIM-Signature can reuse the exact same canonicalization and crypto path.
`FetchKey` returns the RSA key at a selector, for an `rsa-sha256` signature such
as an ARC-Seal, and refuses keys under 1024 bits.

For such a scheme, prefer `VerifySignatureBare`: it runs only the cryptographic
mechanism (header and body canonicalization, hashing, and the signature check
against the `d=`/`s=` DNS key) and applies none of the RFC 6376 DKIM-Signature
policy: no `v=` requirement, no From-signed rule, no `i=` alignment, no timing,
no key-record `t=s` or `s=` flags. A versionless ARC-Message-Signature (RFC 8617
§4.1.2) then verifies, and the scheme applies its own policy on top.
`VerifySignature` is that same primitive plus the full DKIM policy, for
standalone DKIM.

A scheme whose tag-list grammar is wider than RFC 6376 §3.2 parses the signature
itself and calls `VerifySignatureBareTags` with the result. ARC needs this for
the CFWS comments RFC 8617 §3.9 allows around a leading `i=` instance, which the
DKIM grammar refuses. The tags drive the mechanism, while the header hash still
covers the signature field exactly as it occurs.

## What the library does and what the host must do

Each area below says what go-dkim handles and what stays with the host, the
mail system that calls it. The [checklist](CHECKLIST.md) records these
boundaries row by row.

### Signing

The library:

- Signs the bytes it is given, after normalizing line endings to CRLF for the
  hash, and returns the field value. It never rewrites the message.
- Refuses what would make a signature invalid everywhere: a `Domain` or
  `Selector` that is not an A-label DNS name, a header name that is not an
  RFC 5322 field name, a canonicalization other than `simple` or `relaxed`, an
  RSA key under 1024 bits, a missing From, an `Expiration` at or before `Time`,
  and a timestamp of more than 12 digits.
- Emits `t=` and `x=` only when `SignOptions.Time` and `Expiration` are set, and
  no `i=`, `l=` or `z=`.

The host:

- Builds the MIME message, converting 8-bit content to a transfer encoding
  that survives transit before signing (RFC 6376 §5.3).
- Transmits the CRLF form it signed, prepends the returned field above any
  other DKIM-Signature, and keeps that order.
- Makes any changes to a message before signing it, and checks existing
  signatures first if it re-signs mail it relays (RFC 6376 §5.5).
- Sets `SignOptions.Time` (`time.Now().Unix()`) to record when it signed.

### Verifying

The library:

- Checks each signature on its own and reports it in header order; no result
  depends on the others or on their order.
- Requires `v=1`, From among the signed fields, an `i=` aligned with `d=`, and
  a signature that has not expired. An expired signature is a `permerror`,
  which RFC 6376 §6.1.1 allows but does not require.
- Treats an empty optional tag (`c=`, `i=`, `t=`, `x=`, `l=`, `q=`) as
  malformed; defaults apply only when a tag is absent. An `l=` larger than the
  canonicalized body, or longer than 76 digits, is a `permerror`.
- Lets a signature cover another DKIM-Signature field, that field's whole `b=`
  value included; a signature never selects itself through `h=`.
- Converts U-labels in `d=`, `s=` and the `i=` domain to A-labels before any
  check or DNS query, and reports them so. After that they must be
  dot-separated labels of 1 to 63 letters, digits, hyphens or underscores;
  anything else (invalid UTF-8, say) is a `permerror`, and no query is sent.
- Tries several key records at one selector in turn and uses the first usable
  one. It reads an RSA `p=` as the RSAPublicKey RFC 6376 §3.6.1 names or the
  SubjectPublicKeyInfo its Appendix C (and nearly every publisher) uses.
- Skips a header line that is not a header field (no colon, or a name with
  whitespace in it) together with its continuation lines.

The host:

- Decides what a result means for delivery: a message with only failed
  signatures is treated like an unsigned one, testing-mode (`t=y`) keys change
  nothing, and a rejection uses a 5.7.x reply, or 4xx only for `temperror`
  (RFC 6376 §§6.1, 6.3).
- Writes the Authentication-Results field, with its own authserv-id, and shows
  the reader the signing domain (`VerifyResult.Domain`) when it differs from
  From.
- Filters signing domains it does not accept, from `VerifyResult.Domain`.

### Keys and DNS

The library:

- Generates RSA keys of at least 2048 bits with exponent 65537, and renders RSA
  and Ed25519 public keys as `v=DKIM1` records.

The host:

- Publishes one TXT record per selector, chooses whether to set `t=s`, and
  rotates keys. The library renders records but does not provision DNS.

## RFC conformance

### The RFC checklist

[CHECKLIST.md](CHECKLIST.md) lists the requirements RFC 6376, RFC 8301, RFC 8463
and RFC 8616 §5 place on a signer and a verifier, item by item, each mapped to
the tests that prove it. Rows the library does not meet, or that belong to the
host or the DNS publisher, are `n/a` with the reason. The tests sit beside the
code in [`pkg/dkim`](pkg/dkim) and its focused `internal` packages listed above.

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

[`internal/checklist`](internal/checklist/main.go) checks one against the other
in CI. It is the same program as the other `go-*` libraries'.
`go run ./internal/checklist [-file CHECKLIST.md] [package dir ...]` scans the
`_test.go` files of the given package directories (default `.`) and fails when:

- an ID is used twice, or a row is malformed;
- an item names no test and is not marked `n/a`;
- an item lists a test that does not exist, or that does not name the item;
- a test names an item that does not exist, is `n/a`, or does not list it;
- a `Test` or `Fuzz` function names no item (`Example` functions may).

```sh
go run ./internal/checklist ./pkg/dkim ./pkg/dkim/internal/codec \
  ./pkg/dkim/internal/folding ./pkg/dkim/internal/grammar \
  ./pkg/dkim/internal/idna ./pkg/dkim/internal/keyrecord
```

The RFCs' own examples are tests: RFC 8463's Appendix A message, whose Ed25519
and RSA signatures verify against its published keys; the body hash and key
record of RFC 6376's Appendix A and C; and the canonicalization examples of
RFC 6376 §3.4.5. Differential tests check go-dkim against
[go-msgauth](https://github.com/emersion/go-msgauth) (MIT): messages one signs
must verify with the other, both ways, in every canonicalization and with both
key types. go-msgauth is a test-only dependency; the library does not import
it.

### What it does not do

Some gaps are deliberate, and go-dkim will not fill them. Others are planned,
each with an issue. The checklist records every one as an `n/a` row with its
reason, except the signature limit, which has no row yet.

#### Not supported, by design

| Area | What go-dkim does | Why |
|------|-------------------|-----|
| Historic algorithms | `rsa-sha1` signatures and RSA keys under 1024 bits are a `permerror`. | RFC 8301 forbids them; RFC 6376's requirement to verify them is superseded. |
| Writing header fields | `Sign` returns a field value and `Verify` returns results; neither adds Authentication-Results or rewrites the message. | The host owns the message bytes it transmits and its own authserv-id. |
| Default `t=` | `Sign` emits `t=` only when `SignOptions.Time` is set. | `Sign` reads no clock, so its output depends only on its inputs; the host passes the time. |
| U-labels when signing | `Sign` takes A-label `Domain` and `Selector` only. | A-labels stay valid under RFC 8616 and every verifier reads them; `Sign` cannot tell whether a message is internationalized. |
| `l=` when signing | `Sign` never emits `l=`. | A body length lets anyone append content below the signed part (RFC 6376 §8.2). |
| IDNA2008 | U-labels are lower-cased and punycode-encoded, without the full IDNA2008 mapping (NFC, special folds such as ß, label validation). | It would need Unicode tables beyond the standard library; only deliberately unusual spellings differ. |

#### Not planned

| Area | What go-dkim does |
|------|-------------------|
| DKIM-quoted-printable | No encoder or decoder: `Sign` emits no `i=` or `z=`, and `Verify` does not decode `z=` copied headers or `n=` notes. |
| Unacceptable signing domains | No built-in list of refused `d=` domains; the host filters `VerifyResult.Domain`. |

#### Planned

| Gap | Issue |
|-----|-------|
| `Verify` requires only From among the signed fields; a host cannot require more (RFC 6376 §6.1.1). | [#47](https://github.com/rest-mail/go-dkim/issues/47) |
| `Verify` checks every DKIM-Signature in a message, however many there are (RFC 6376 §§6.1, 8.4). | [#48](https://github.com/rest-mail/go-dkim/issues/48) |

### Badges and coverage

The badges at the top are checked in CI. `TestReadmeChecklistBadge` in
`internal/checklist` checks the checklist badge: it counts mapped rows over all
rows, and the 24 `n/a` rows are in the denominator, so the badge never claims
more than the tests prove. The workflow fixtures in
[`.github/tests`](.github/tests) check the coverage badge. It shows the floor CI
enforces, not a measured figure; each CI run prints the measured statement
coverage in its `RFC proof` log. Lines left uncovered on purpose are listed,
each with a reason, in [COVERAGE.md](COVERAGE.md).

CI runs go-spf's reusable
[`rfc-verification.yml`](https://github.com/rest-mail/go-spf/blob/2409e76ef1e501e0222e6c25a0c7a6202de1051b/.github/workflows/rfc-verification.yml),
pinned to that commit: build, vet, golangci-lint, race tests with at least 95%
statement coverage measured across packages with `-coverpkg=./...`, the checklist
and 30 seconds of each fuzz target. The required `Build & Test` check passes
only when it and the workflow fixtures
both succeed. Locally:

```sh
go test -race -coverpkg=./... ./...                      # all tests, no network
go run ./internal/checklist ./pkg/dkim ./pkg/dkim/internal/codec \
  ./pkg/dkim/internal/folding ./pkg/dkim/internal/grammar \
  ./pkg/dkim/internal/idna ./pkg/dkim/internal/keyrecord
go test -run='^$' -fuzz='^FuzzSignVerify$' -fuzztime=30s ./pkg/dkim
python3 -m unittest discover -s .github/tests            # what CI passes the shared proof
```

Five fuzz targets run in CI: `FuzzParseTagList` in `pkg/dkim/internal/grammar`
(tag-lists), `FuzzKeyRecord` in `pkg/dkim/internal/keyrecord` (key records), and
three in `pkg/dkim`: `FuzzSignatureHeader` (verifying any DKIM-Signature field),
`FuzzCanonicalization` (properties such as relaxed canonicalization being
idempotent) and `FuzzSignVerify` (anything signed verifies). Their seeds are in
the targets; regression inputs belong in each target package's `testdata/fuzz`.

## Changelog

Recent releases; see [CHANGELOG.md](CHANGELOG.md) for the complete history.

### v0.5.1 (2026-10-26)

Split grammar, codecs, signature folding and key-record helpers into internal
packages. The public API is unchanged. CI's RFC proof measures coverage across
packages with `-coverpkg`.

### v0.5.0 (2026-10-26)

The library moves to `pkg/dkim` (breaking: the import path changes, every name
stays; the changelog has a migration table).

### v0.4.0 (2026-10-23)

RFC 8616 internationalized mail: U-labels in `d=`, `s=` and `i=` now verify
(breaking: they were a `permerror`). `SignOptions.Expiration` emits `x=`.
`VerifySignatureBareTags` verifies a tag-list the caller parsed. An empty
optional tag and an `l=` beyond the body are `permerror`.

### v0.3.1 (2026-10-17)

Tag-lists accept only folding whitespace, so `i\f=1` is no longer read as
`i=1`.

### v0.3.0 (2026-10-17)

Ed25519 (RFC 8463); RFC 8301 (no `rsa-sha1`, RSA keys of at least 1024 bits);
the RFC 6376 §5.4.1 default header set with oversigning; a folded signature
field; case-sensitive tag values; an RFC checklist, a 95% coverage gate,
fuzzing and differential tests (breaking: `SignOptions.PrivateKey` is a
`crypto.Signer`, and the default signatures change).

### v0.2.1 (2026-07-25)

`VerifySignatureBare`, a policy-free verification primitive, so a versionless
ARC-Message-Signature verifies without inheriting DKIM policy.

### v0.2.0 (2026-07-25)

The key record's `v=`, `s=`, `t=s` and `h=` are enforced, the signature's `v=`
is required, `Sign` requires From among the signed fields, and unpadded base64
is accepted (breaking: `FetchKey` changed).

### v0.1.3 (2026-07-25)

A signature that leaves From unsigned, has an unaligned `i=`, repeats a tag or
has expired or malformed timing is refused. `ParseTagListStrict` is exported.

### v0.1.2 (2026-07-25)

A non-digit `l=` is refused, fixing a remotely triggerable panic.

### v0.1.1 (2026-07-23)

The module path is `github.com/rest-mail/go-dkim`.

## Licence

[MIT](LICENSE) © 2026 rest-mail

[RFC 6376]: https://www.rfc-editor.org/rfc/rfc6376
[RFC 8301]: https://www.rfc-editor.org/rfc/rfc8301
[RFC 8463]: https://www.rfc-editor.org/rfc/rfc8463
[RFC 8616]: https://www.rfc-editor.org/rfc/rfc8616
