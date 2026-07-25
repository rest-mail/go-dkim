# Changelog

All notable changes to this project are documented here. This project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html); releases are Go
module tags of the form `vMAJOR.MINOR.PATCH`.

## v0.1.3

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

## v0.1.2

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

## v0.1.1

### Changed

- Rename the module path to `github.com/rest-mail/go-dkim`, standardizing on the
  `go-*` naming convention shared with the wider ecosystem. The package
  identifier stays `package dkim`; only the module path and repository changed.
  (#2)

## v0.1.0

### Added

- Initial release: RFC 6376 DKIM message signing and verification with no
  external dependencies. Signs with `rsa-sha256` and verifies `rsa-sha256` and
  legacy `rsa-sha1`; supports both simple and relaxed header and body
  canonicalization over the raw RFC 5322 message bytes; generates keypairs and
  renders DNS TXT records; reports RFC 8601 result values; accepts a pluggable
  DNS resolver; and exports the canonicalization primitives so layered schemes
  such as ARC can reuse the exact same code path.
