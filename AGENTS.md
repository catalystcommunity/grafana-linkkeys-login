# Agent guidelines

- This is a public project. Keep environment-specific values (hosts, domains,
  users) out of the code, tests, and examples. Use `example.com` and
  `example.lan`.
- The LinkKeys protocol lives in the LinkKeys SDKs
  (`github.com/catalystcommunity/linkkeys/sdks/local-rp/go` and
  `.../sdks/regular-rp/go`). Do not reimplement protocol checks here. Fix
  the SDK instead. Exception: the regular-RP Go SDK has no login flow, so
  `internal/linkkeys/regularrp.go` does the login checks. It follows
  `completeLogin` in the TypeScript regular-RP SDK. Move it to the Go SDK
  when the SDK gets a login flow.
- Security behavior has a test: header stripping, single-use login state,
  browser binding, access refusal, redirect safety, cookie attributes,
  domain refusal before login start, rate limits, and each RP-mode
  assertion and claim check. Keep
  these tests when you change the server.
- Run `go test -race ./...`, `go vet ./...`, and `gofmt -l .` before you
  finish.
- Agents do not commit. The user commits.
- Documentation follows ASD-STE100 Simplified Technical English.
