# Coverage exceptions

CI measures statement coverage across `./...` with `-coverpkg=./...` and fails
below 95%. Tests in `pkg/dkim` count toward the grammar, codec, folding,
key-record and IDNA helpers they exercise, even across package boundaries.
The shared RFC proof is pinned to go-spf commit
`2409e76ef1e501e0222e6c25a0c7a6202de1051b`. These are the
statements left uncovered on purpose, each with the reason. Add an entry here
whenever you leave a statement uncovered.

| File | Function | Statements | Reason |
|------|----------|------------|--------|
| `pkg/dkim/dkim.go` | `GenerateKey` | `return "", "", err` after `rsa.GenerateKey` | With the size checked first, `rsa.GenerateKey` fails only when the system's random source does, which a test cannot arrange without replacing `crypto/rand`. |
| `pkg/dkim/dkim.go` | `GenerateKey` | `return "", "", err` after `x509.MarshalPKIXPublicKey` | Marshalling an RSA public key the standard library just generated cannot fail; the error is still checked rather than ignored. |
| `internal/checklist/main.go` | `main` | `os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))` | Exiting the process cannot be tested in-process. All of the checker's logic is in `run`, which the tests cover completely; CI also runs the command itself. |
