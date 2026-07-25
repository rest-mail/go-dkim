# Changelog

All notable changes to this project are documented here. This project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html); releases are Go
module tags of the form `vMAJOR.MINOR.PATCH`.

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
