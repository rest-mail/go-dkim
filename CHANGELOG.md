# Changelog

All notable changes to this project are documented here. This project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html); releases are Go
module tags of the form `vMAJOR.MINOR.PATCH`.

## [Unreleased]

The API stays compatible where that cost nothing: `SignOptions` keeps its
fields, `PrivateKey` widened to a `crypto.Signer` (which an `*rsa.PrivateKey`
still is), `FetchKey` keeps its signature and still returns an RSA key (what
ARC's seal needs), and `ParsePrivateKey` still returns an `*rsa.PrivateKey`.
Everything else is a clean break, listed below; the module is v0.x and its
users are REST Mail's server and go-arc.
(rest-mail/rest-mail-server#374, rest-mail/rest-mail-server#128)

### BREAKING CHANGES

- `SignOptions.PrivateKey` is a `crypto.Signer`. Existing code that assigns an
  `*rsa.PrivateKey` compiles unchanged.
- `Sign` signs the RFC 6376 §5.4.1 header set by default and **oversigns**
  From, To, Cc, Subject, Reply-To, Date, Message-ID, Content-Type and
  MIME-Version (see Added), so default signatures have a longer `h=` and break
  when one of those fields is added after signing.
- `SignOptions.Headers` signs every instance of a named field the message
  carries, not only the last one. Setting `Headers` without `Oversign`
  oversigns nothing.
- The value `Sign` returns is folded: it contains CRLF followed by a space
  wherever a line would pass 78 characters. Prepend `DKIM-Signature: ` exactly
  (with one space), as before.
- `rsa-sha1` signatures are a `permerror` (RFC 8301 §3.1), and an RSA key under
  1024 bits is unusable: `Sign` refuses it and a verifier treats its key record
  as unusable, a `permerror` (RFC 8301 §3.2).
- `GenerateKey` refuses sizes under 2048 bits (RFC 8301 §3.2 SHOULD).
- `Sign` refuses a `Domain` or `Selector` that is not an A-label DNS name, a
  header name that is not an RFC 5322 field name, and a canonicalization other
  than `simple` or `relaxed`.
- Tag values are case-sensitive, as RFC 6376 §3.2 requires: `a=RSA-SHA256`,
  `c=Relaxed`, and key record values such as `k=RSA`, `h=SHA256`, `s=EMAIL` or
  `t=S` are no longer read as their lower-case forms.
- `ParseTagListStrict` also rejects a tag name that is not `ALPHA *ALNUMPUNC`
  (`x-foo=1`, say) and a value with a character outside VALCHAR and folding
  whitespace.

### Added

- Ed25519 (RFC 8463): `Sign` signs with `ed25519-sha256` given an
  `ed25519.PrivateKey`, verification accepts `ed25519-sha256` against a
  `k=ed25519` key record, and `RecordValue` renders an Ed25519 public key's
  record.
- Oversigning: `SignOptions.Oversign` names fields signed once more than they
  appear (RFC 6376 §5.4.2), so a copy added after signing breaks the
  signature; a name the message lacks is signed as absent.
  `DefaultSignedHeaders` and `DefaultOversignedHeaders` are the defaults.
- `CHECKLIST.md`, which maps every signer and verifier requirement of RFC 6376,
  RFC 8301 and RFC 8463 to its tests (109 items: 95 tested, 14 not applicable
  with a reason), and `internal/checklist`, copied from go-spf, which checks
  the two agree in CI.
- A CI gate at 95% statement coverage (99.6% now), with `COVERAGE.md` listing
  what is left uncovered and why.
- Five fuzz targets, each run for 30 seconds in CI: tag-lists, the
  DKIM-Signature field, key records, canonicalization properties, and
  sign-then-verify of any message.
- Tests from the RFCs: RFC 8463 Appendix A (both signatures verify against its
  keys, and its oversigning holds), and the body hash and key record of RFC
  6376 Appendix A and C.
- Differential tests against `github.com/emersion/go-msgauth/dkim` (MIT, a
  test-only dependency): messages signed by either verify with the other, in
  all four canonicalizations, with RSA and Ed25519 keys.

### Fixed

Found by writing the checklist and by fuzzing:

- `rsa-sha1` signatures were verified; RFC 8301 forbids it.
- A key record holding an RSA key under 1024 bits was not refused.
- The signature field was one unfolded line; with a 4096-bit key and the
  wider header set it passed RFC 5322's 998-character line limit.
- Under simple header canonicalization, a signature whose first tag is `b=`
  had its `b=` value hashed rather than emptied, so valid signatures from
  signers that put `b=` first failed.
- `RemoveBValue` also emptied a `B=` tag, which is an unknown tag that must be
  hashed as it is (tag names are case-sensitive).
- `a=` and the key record's `k=`, `h=`, `s=` and `t=` values were compared
  without regard to case (RFC 6376 §3.2).
- `q=` was ignored: a signature naming only unknown key query methods was
  verified through DNS anyway. It is now a `permerror`.
- `d=`, `s=` and `i=` were not checked: a U-label or a name with whitespace
  was sent to the resolver, and a U-label `i=` under `d=` passed the alignment
  check.
- A key record whose `p=` is an RSAPublicKey, the form RFC 6376 §3.6.1 names,
  was rejected; only SubjectPublicKeyInfo was read. Both are read now.
- `ParseTagListStrict` accepted tag names and values outside the §3.2 ABNF.
- A header line with a field name holding whitespace was read as a field, and
  the continuation lines of a line that is not a field were glued onto the
  field above (found by `FuzzCanonicalization`).
- A message starting with an empty line had its body read as header fields.
- `Sign` accepted an unknown canonicalization name: it declared it in `c=` and
  hashed with simple, making a signature no verifier accepts.
- `SignOptions.Headers` signed only the last instance of a repeated field.

## [0.2.1] - 2026-07-25

### Added

- `VerifySignatureBare`, a policy-free sibling of `VerifySignature` that verifies
  ONLY the cryptographic mechanism of a DKIM-shaped signature — it selects the
  `h=` headers, canonicalizes per `c=`, hashes per `a=` (honoring `l=`), resolves
  the `d=`/`s=` DNS key and checks `b=` — and applies NONE of the RFC 6376
  DKIM-Signature policy: no `v=` version requirement, no From-must-be-signed rule,
  no `i=` (AUID) alignment to `d=`, no `t=`/`x=` timing, and no enforcement of the
  key record's `t=s` / `s=` policy flags. A layered scheme whose signature is
  structurally a DKIM-Signature but governed by its own rules can verify the
  mechanism through this primitive and then apply that scheme's policy itself.
  Selecting the correct key (the key record's own `v=DKIM1` / `h=` constraints)
  remains part of the mechanism. (#33)

### Fixed

- Restore ARC compatibility. An ARC-Message-Signature is versionless by design
  (RFC 8617 §4.1.2), but since v0.2.0 the now-required signature `v=` tag made
  `VerifySignature` PERMFAIL every AMS with `missing required tag v`, breaking ARC
  chain verification for consumers that reused it. Verifying an AMS through the
  new policy-free `VerifySignatureBare` — then applying RFC 8617 policy in the ARC
  layer — avoids inheriting DKIM policy that does not apply to ARC. Standalone
  DKIM verification through `Verify` / `VerifySignature` is unchanged and exactly
  as strict as before. (#33)

## [0.2.0] - 2026-07-25

### BREAKING CHANGES

- `FetchKey` now returns `(*rsa.PublicKey, KeyFlags, string)` — a new `KeyFlags`
  value is inserted before the result string — and takes an additional
  `hashAlg string` parameter (the hash half of the verifying signature's `a=`
  tag). The added return surfaces the selected key record's policy flags so a
  caller can enforce them against the signature: `KeyFlags.NoSubdomain` reflects
  the record's `t=s` no-subdomain flag and `KeyFlags.NotForEmail` reflects a
  restrictive `s=` service-type tag. The added parameter lets `FetchKey` honor
  the record's `h=` acceptable-hash-algorithm tag. Any code calling this exported
  primitive directly — such as a layered scheme (ARC) reusing the key path — must
  update its call site and result destructuring. `Verify` and `VerifySignature`
  are unchanged.

### Fixed

- Validate the DKIM key record's `v=` version tag (RFC 6376 §3.6.1): a record
  must either omit `v=` or set it to `DKIM1` as the very first tag. A record
  whose `v=` names a different version, or places `v=` anywhere but first, is now
  rejected as unusable instead of being parsed as a v1 key. (#30)

- Enforce the key record's `s=` service-type tag (RFC 6376 §3.6.1). When `s=` is
  present and lists neither `email` nor the `*` wildcard, the signer has
  restricted the key to other services, so it is no longer accepted for an email
  signature and the signature PERMFAILs. An absent `s=` still defaults to all
  services. (#29)

- Enforce the key record's `t=s` flag (RFC 6376 §3.6.1), which forbids
  subdomaining. When the flag is set, a signature whose `i=` (AUID) domain is a
  subdomain of `d=` rather than exactly `d=` is now a PERMFAIL. `FetchKey`
  returns the flag to the caller through the new `KeyFlags` type. (#28)

- Require the signature's `v=` version tag (RFC 6376 §3.5): a `DKIM-Signature`
  that omits `v=`, or carries a value other than `1`, is now a PERMFAIL instead
  of being verified as though it were a v1 signature. (#27)

- Require the `From` field in the signed header list when signing (RFC 6376
  §5.4). `Sign` now returns an error rather than producing a signature whose `h=`
  omits `From`, matching the verify-side requirement added in v0.1.3 and
  preventing creation of a signature that leaves the author identity outside the
  hash. (#26)

- Accept RFC-legal unpadded base64 in the `bh=` and `b=` signature tags and the
  key record's `p=` tag (RFC 6376 §2.10). The trailing `=` padding on these
  base64 fields is optional, but a correctly encoded unpadded value was
  previously rejected, failing otherwise-valid signatures. Decoding now tolerates
  missing padding. (#25)

- Enforce the key record's `h=` acceptable-hash-algorithms tag (RFC 6376 §3.6.1
  / §6.1.2). A key record whose `h=` is present but does not list the verifying
  signature's hash algorithm is now skipped, so a key published only for, say,
  `sha256` cannot be used to verify a `sha1` signature. (#24)

## [0.1.3] - 2026-07-25

### Fixed

- Reject a signature whose `h=` signed-header list does not include the `From`
  field. RFC 6376 §5.4 makes `From` mandatory in `h=` and §6.1.1 requires a
  PERMFAIL when it is absent; otherwise the displayed author identity sits
  outside the signed hash and can be altered after signing without breaking the
  signature. Verification now PERMFAILs when `h=` does not cover `From`. (#20)

- Reject a signature whose `i=` (AUID) identity domain is not the signing
  domain (`d=`) or a subdomain of it, per RFC 6376 §6.1.1. An unaligned `i=`
  let a signature that is valid for one domain be presented as authorizing
  another; the domain mismatch is now a PERMFAIL. When `i=` is absent its
  default (`@` + `d=`) is trivially aligned. (#19)

- Reject a DKIM-Signature tag-list, or a DNS key record, that contains a
  duplicate tag name. RFC 6376 §3.2 declares such a list invalid, but the
  previous last-wins parse silently kept one value, letting two verifiers reach
  different verdicts about the same message. A repeated tag name is now a
  PERMFAIL for a signature and causes a malformed key record to be skipped. (#21)

- Reject an expired signature and malformed signature timing. A signature whose
  `x=` expiration has passed (the current time is at or after `x=`) is treated
  as invalid per RFC 6376 §6.1.1; an `x=` that is not greater than `t=`, and a
  `t=` or `x=` that is not a 1–12 digit epoch-second count, are PERMFAILs rather
  than being silently ignored. Timestamps are compared as 64-bit values so the
  expiry check stays correct beyond 2038 on 32-bit platforms. (#22)

### Added

- Export `ParseTagListStrict`, a strict sibling of `ParseTagList` that enforces
  the RFC 6376 §3.2 well-formedness rules — no duplicate tag names, no segment
  missing `=`, no empty tag name — and returns an error instead of silently
  resolving a malformed list to an arbitrary value. Layered schemes such as ARC
  can reuse it on the verification path. (#21)

## [0.1.2] - 2026-07-25

### Security

- Reject a non-digit `l=` body-length tag during verification, fixing a remotely
  triggerable panic (DoS). `VerifySignature` parsed the `l=` tag with
  `strconv.Atoi`, which accepts a leading sign, so a `DKIM-Signature` carrying
  `l=-1` parsed to `-1` and then sliced the canonicalized body with a negative
  bound (`canonBody[:-1]`), panicking with `slice bounds out of range [:-1]`.
  Because the signature header is fully attacker-controlled and this fired before
  any cryptographic check, an unauthenticated sender could crash any process that
  called `Verify`/`VerifySignature` on inbound mail. `parseUint` now enforces the
  RFC 6376 §3.5 ABNF (`sig-l-tag = ... 1*76DIGIT`), rejecting any value that is
  not composed solely of ASCII digits — including a leading `+` or `-` — as a
  PERMFAIL. (#16, #17)

## [0.1.1] - 2026-07-23

### Changed

- Rename the module path to `github.com/rest-mail/go-dkim`, standardizing on the
  `go-*` naming convention shared with the wider ecosystem. The package
  identifier stays `package dkim`; only the module path and repository changed.
  (#2)

## [0.1.0] - 2026-07-23

### Added

- Initial release: RFC 6376 DKIM message signing and verification with no
  external dependencies. Signs with `rsa-sha256` and verifies `rsa-sha256` and
  legacy `rsa-sha1`; supports both simple and relaxed header and body
  canonicalization over the raw RFC 5322 message bytes; generates keypairs and
  renders DNS TXT records; reports RFC 8601 result values; accepts a pluggable
  DNS resolver; and exports the canonicalization primitives so layered schemes
  such as ARC can reuse the exact same code path.
