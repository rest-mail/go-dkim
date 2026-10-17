# Coverage exceptions

CI fails when statement coverage of `./...` falls below 95%. These are the
statements left uncovered on purpose, each with the reason. Add an entry here
whenever you leave a statement uncovered.

| File | Function | Statements | Reason |
|------|----------|------------|--------|
| `dkim.go` | `GenerateKey` | `return "", "", err` after `rsa.GenerateKey` | With the size checked first, `rsa.GenerateKey` fails only when the system's random source does, which a test cannot arrange without replacing `crypto/rand`. |
| `dkim.go` | `GenerateKey` | `return "", "", err` after `x509.MarshalPKIXPublicKey` | Marshalling an RSA public key the standard library just generated cannot fail; the error is still checked rather than ignored. |
| `internal/checklist/main.go` | `main` | `os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))` | Exiting the process cannot be tested in-process. All of the checker's logic is in `run`, which the tests cover completely; CI also runs the command itself. |
