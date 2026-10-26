# grafana-linkkeys-login

Sign in to Grafana with [LinkKeys](https://github.com/catalystcommunity/linkkeys).

Grafana has no plugin type that can replace its login. This project is a
small reverse proxy instead. It sits in front of Grafana, signs the user in
with LinkKeys, and sends the verified identity to Grafana's
[auth proxy](https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/configure-authentication/auth-proxy/)
feature. You need no Grafana fork and no Grafana Enterprise.

```
browser ──TLS──> TLS server ──> grafana-linkkeys-login ──> Grafana
                 (Caddy etc.)   127.0.0.1:3001             127.0.0.1:3000
                                     │
                                     └── LinkKeys IDP of the user's domain
```

The proxy uses the LinkKeys **DNS-less local RP** mode. The proxy has its own
signing key. You do not run a LinkKeys RP server, and you need no API key. A
LinkKeys domain admin approves the proxy's key fingerprint one time.

## Security model

- Grafana must listen only where the proxy can reach it. Grafana trusts the
  identity headers from the IP addresses in its `whitelist`. If any other
  client can reach Grafana, that client can be any user.
- The proxy removes the identity headers from every incoming request. A
  client cannot set them.
- A login that matches no `access` rule is refused. The proxy does not start
  without at least one rule.
- The login state is single-use and expires after `session.login_timeout`.
  A browser cookie binds the callback to the browser that started the login.
  This prevents login CSRF.
- The proxy builds the callback URL from `public_url`, not from the `Host`
  header. The LinkKeys SDK verifies it against the URL that the IDP signed.
- The proxy keeps only SHA-256 hashes of session tokens. It never sends its
  own cookies to Grafana.
- After login, the proxy redirects only to a path on the same site.
- The SDK verifies the assertion, the audience, the nonce, the times, and
  every claim signature against DNS-pinned domain keys.

Limits:

- Sessions are in memory. A restart signs every user out. Run one instance.
- Grafana's auth proxy can set the organization role (Viewer, Editor, Admin).
  It cannot make a user a Grafana server admin. Do that one time in Grafana.
- By default the Grafana username is `<user-id>@<domain>`. A user id never
  changes. The `handle` option gives `<handle>@<domain>`, which is easier to
  read. But a domain can give a released handle to a different account, and
  that account then gets the Grafana user.

## Install

Build from source (Go 1.26 or later):

```sh
go install github.com/catalystcommunity/grafana-linkkeys-login/cmd/grafana-linkkeys-login@latest
```

Or build the container image:

```sh
docker build -t grafana-linkkeys-login .
```

## Set up

1. Write the configuration file. Start from
   [`examples/config.yaml`](examples/config.yaml). Set `public_url` to the
   URL that browsers use.

2. Create the local-RP identity. The file is a secret.

   ```sh
   grafana-linkkeys-login init-identity -config /etc/grafana-linkkeys-login/config.yaml
   ```

   The command prints the fingerprint.

3. Configure Grafana. Use [`examples/grafana.ini`](examples/grafana.ini).
   Make sure that Grafana listens on `127.0.0.1` only, and that `whitelist`
   contains only the proxy address.

4. Start the proxy. Use [`examples/grafana-linkkeys-login.service`](examples/grafana-linkkeys-login.service)
   for systemd, or [`examples/docker-compose.yaml`](examples/docker-compose.yaml).

   ```sh
   grafana-linkkeys-login serve -config /etc/grafana-linkkeys-login/config.yaml
   ```

5. Put a TLS server in front of the proxy. See
   [`examples/Caddyfile`](examples/Caddyfile).

6. Sign in one time. If the domain uses the `admin-approval-required` policy,
   the first attempt puts the fingerprint in the domain's pending queue. A
   domain admin approves it:

   ```sh
   linkkeys local-rp list --status pending
   linkkeys local-rp approve <fingerprint>
   ```

   Then sign in again.

## Configuration

| Key | Default | Description |
| --- | --- | --- |
| `listen` | `127.0.0.1:3001` | Address of the proxy. |
| `public_url` | (required) | Origin that browsers use, such as `https://grafana.example.lan`. No path. |
| `upstream` | `http://127.0.0.1:3000` | Grafana. |
| `identity_file` | (required) | Local-RP key material. Mode must be 0600. |
| `app_name` | `Grafana` | Name for a new identity. LinkKeys shows it as unverified text. |
| `default_domain` | none | Users can type only a handle. This domain is added. |
| `grafana_username` | `subject` | `subject` or `handle`. See the limits above. |
| `session.ttl` | `12h` | Session lifetime. Users sign in again after this. |
| `session.login_timeout` | `5m` | Time to complete a login. 30s to 15m. |
| `access.users[]` | none | `identity` (`<handle>@<domain>` or `<user-id>@<domain>`) and `role`. |
| `access.domains[]` | none | `domain` and `role`. Allows every account of the domain. |
| `headers.*` | `X-WEBAUTH-USER`, `-NAME`, `-EMAIL`, `-ROLE` | Must match Grafana's `[auth.proxy]` settings. |

Roles are `Viewer`, `Editor`, and `Admin`. A user rule takes precedence over
a domain rule.

## Paths

The proxy uses these paths. Everything else goes to Grafana.

| Path | Use |
| --- | --- |
| `/linkkeys/login` | Login form. |
| `/linkkeys/callback` | Return from the LinkKeys IDP. |
| `/linkkeys/logout` | Sign out. Set Grafana's `signout_redirect_url` to this path. |
| `/linkkeys/healthz` | Health check. |

## Identity expiry

A local-RP identity expires. `serve` logs a warning when the expiry is near,
and refuses to start when the identity has expired. A new identity has a new
fingerprint, so each domain must approve it again.

## Development

```sh
go test -race ./...
go vet ./...
gofmt -l .
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
