# Agent guidelines

- This is a public project. Keep environment-specific values (hosts, domains,
  users) out of the code, tests, and examples. Use `example.com` and
  `example.lan`.
- The LinkKeys protocol lives in the LinkKeys SDK
  (`github.com/catalystcommunity/linkkeys/sdks/local-rp/go`). Do not
  reimplement protocol checks here. Fix the SDK instead.
- Security behavior has a test: header stripping, single-use login state,
  browser binding, access refusal, redirect safety, cookie attributes. Keep
  these tests when you change the server.
- Run `go test -race ./...`, `go vet ./...`, and `gofmt -l .` before you
  finish.
- Agents do not commit. The user commits.
- Documentation follows ASD-STE100 Simplified Technical English.
