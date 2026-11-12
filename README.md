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

The proxy has two modes:

| Mode | How it works | Use it when |
| --- | --- | --- |
| `local-rp` (default) | The proxy has its own signing key (LinkKeys DNS-less local RP). An admin of each LinkKeys domain approves the key fingerprint one time. | You do not have a LinkKeys RP server. |
| `rp` | The proxy is an application of an RP domain. It calls the domain's LinkKeys RP server with an API key, over TLS that is pinned to the server's key fingerprints. | You have a LinkKeys server with the RP function enabled. Its admin manages the application and its API key. |

In `rp` mode, `public_url` must use https. It can be on any host. It does
not have to be in the RP domain. When it is outside the RP domain, the IDP
of each user must run LinkKeys 0.16.7 or later. An older IDP refuses the
login with `callback_off_domain`.

## Security model

- Grafana must listen only where the proxy can reach it. Grafana trusts the
  identity headers from the IP addresses in its `whitelist`. If any other
  client can reach Grafana, that client can be any user.
- The proxy removes the identity headers from every incoming request. A
  client cannot set them.
- A login that matches no `access` rule is refused. The proxy does not start
  without at least one rule.
- The proxy starts a login only for a domain that an `access` rule names.
  Thus an unauthenticated client cannot make the proxy contact other
  domains.
- Login starts are rate limited: 10 at once and then 1 each 30 seconds for
  each client address, and 60 each second for all clients. Behind a reverse
  proxy, set `trusted_proxies`. If you do not, all clients share the address
  of the reverse proxy.
- Unauthenticated requests get only the login pages. Grafana receives a
  request only after a successful login. This makes the proxy safe to put
  on the internet, if Grafana itself is not reachable.
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
- In `rp` mode, the RP server verifies the assertion signature. The proxy
  then checks the domain, the audience (the RP domain), the nonce, the
  issue and expiry times, that user info and each claim are about the same
  user, that the user authorized each claim type, and that the `handle`
  claim is present. The proxy itself verifies every claim signature. It
  gets the keys of the signing domain through the RP server, keeps only the
  keys that the domain's own `_linkkeys` DNS record pins, and applies the
  revocation certificates. Thus the RP server is not a trust anchor for
  claims, and the proxy connects only to the RP server. One failed check
  stops the login, with one exception: an optional claim (`display_name`,
  `email`) with a signature that does not verify is not used, and the
  proxy logs a warning. The login continues without that claim.

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

### Set up `rp` mode

Do these steps instead of steps 2 and 6 above.

1. On the LinkKeys server of the RP domain (the RP function must be enabled),
   create a service account with an API key:

   ```sh
   linkkeys user create grafana "Grafana" --api-key --relation api_access
   ```

   The command shows the API key one time. The consent screen shows the
   display name ("Grafana") to users. The account username is the
   application ID, so it must contain only `A-Z a-z 0-9 - _ .`.

2. Write the API key to a file with mode 0600, for example
   `/etc/grafana-linkkeys-login/rp-api-key`.

3. Get the server fingerprints from the `fp=` values of the domain's
   `_linkkeys` TXT record:

   ```sh
   dig +short TXT _linkkeys.example.com
   ```

4. Set `mode: rp` and the `rp` keys in the configuration file. See the
   comments in [`examples/config.yaml`](examples/config.yaml).

The proxy asks for the `handle` claim (required), and for the `display_name`
and `email` claims (optional). The user sees this request on the LinkKeys
consent screen.

## Configuration

Set the environment variable `LOG_LEVEL=debug` to log more. In debug mode, the
log contains the value and signatures of each claim that does not verify.
This is user data; use debug mode only to find a fault.

| Key | Default | Description |
| --- | --- | --- |
| `listen` | `127.0.0.1:3001` | Address of the proxy. |
| `public_url` | (required) | Origin that browsers use, such as `https://grafana.example.lan`. No path. |
| `upstream` | `http://127.0.0.1:3000` | Grafana. |
| `mode` | `local-rp` | `local-rp` or `rp`. |
| `identity_file` | (required in `local-rp`) | Local-RP key material. Mode must be 0600. |
| `rp.domain` | (required in `rp`) | The RP domain. It is the audience of each assertion. |
| `rp.address` | (required in `rp`) | RP server CSIL-RPC endpoint, `host:port` (port 4987 by default on LinkKeys). The host is the TLS server name. |
| `rp.dial_address` | none | Connect to this `host:port` instead, for example a gateway on the LAN. TLS still uses the host of `rp.address` and the fingerprints. |
| `rp.fingerprints` | (required in `rp`) | SHA-256 fingerprints of the RP server keys. These are the trust anchor. |
| `rp.api_key_file` | (required in `rp`) | File with the RP API key. Mode must be 0600. |
| `app_name` | `Grafana` | Name for a new identity. LinkKeys shows it as unverified text. |
| `default_domain` | none | Users can type only a handle. This domain is added. |
| `grafana_username` | `subject` | `subject` or `handle`. See the limits above. |
| `trusted_proxies` | none | CIDR ranges of reverse proxies in front of this proxy, such as `127.0.0.1/32`. The client address for rate limits comes from `X-Forwarded-For` only for these. |
| `session.ttl` | `12h` | Session lifetime. Users sign in again after this. |
| `session.login_timeout` | `5m` | Time to complete a login. 30s to 15m. |
| `access.users[]` | none | `identity` (`<handle>@<domain>` or `<user-id>@<domain>`) and `role`. The handle is the verified `handle` claim, which can be different from the name that the user types to log in. |
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
