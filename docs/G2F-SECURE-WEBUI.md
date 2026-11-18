# G2-F Secure WebUI Integration

## Verified integration slice

The dashboard API client now uses the page's exact origin when the page is
loaded over HTTPS. The HTTPS endpoint is expected to serve the existing SPA
and reverse-proxy `/api/*` to `http://127.0.0.1:9090`. The HTTP development
and legacy full-Agent path keeps its existing `http://HOST:9090` API base.
There is no HTTPS-to-HTTP fallback. Network and certificate errors on an
HTTPS page are reported as secure gateway/trust failures. Login omits any
previous session Bearer token, and the legacy LAN reconnection action refuses
to send its one-time token to an HTTP endpoint when the page itself is HTTPS.
Legacy full-Agent mode still uses plaintext HTTP on its existing LAN path; it
retains that compatibility behavior and is outside the G2-F secure proxy-only
entrypoint.

The proxy-only Agent still binds only to `127.0.0.1:9090`. Its optional
`--proxy-https-origin https://HOST[:PORT]` setting allows one exact HTTPS
Origin; it does not open a LAN listener or add a TLS implementation. The
project launcher can supply that setting from the private single-line file
`/data/u60-pro-managed/auth/webui-origin` (owner-only mode `0600`). The Agent
continues to authenticate management operations and enforce its proxy-only
route/method allowlist. The Mihomo controller is not part of the gateway
contract and must remain private to the managed Agent.
The launcher does not live-reload this file; use its controlled `restart`
action after an approved origin change.

The Agent currently keys failed-login lockout to the TCP peer address. Behind
a local reverse proxy, all iPhone clients appear to the Agent as loopback.
Before deployment, the gateway must provide source-aware login throttling (or
an independently reviewed trusted-client-address contract); this change does
not add trust in caller-supplied forwarding headers.

The local HTTPS integration test generates an ephemeral test certificate in
a disposable temporary directory, serves a small synthetic UI, and forwards
same-origin API requests to a synthetic loopback Agent. It checks login,
Bearer-authenticated subscription/node/Rule calls, exact Origin handling,
unauthorized requests, denial of router endpoints, and normal certificate
verification failure. No private key or certificate is stored in the source
tree. This tests the browser/API integration contract; it is not a packaged
router TLS gateway.

## Existing router-facing evidence

The repository's existing dashboard launcher runs the pinned upstream
`dashboard-uhttpd` on plain HTTP port `8080`. The existing Agent has no TLS
stack. The source tree contains no TLS-enabled dashboard invocation, TLS
reverse-proxy configuration, or verified TLS module/package for the router.
The extracted firmware tree is not present in this worktree, and no device
inspection was performed. Therefore the current router cannot be assumed to
have a usable TLS listener, TLS module, or free LAN port for this design.

Do not change the dashboard to a LAN HTTPS binding until a separate read-only
device stage identifies the installed uhttpd build/modules, port ownership,
LAN firewall reachability, writable certificate paths, and a project-owned
gateway that can preserve `Origin` and forward only to the loopback Agent.
The current 8080 service remains plain HTTP for legacy full-Agent users; the
proxy-only UI must be opened through the eventual trusted HTTPS origin.

## iPhone trust and identity path

The smallest no-cloud trust route is an Owner-managed private CA kept offline,
with a short-lived server certificate whose Subject Alternative Name matches
the stable U60 LAN address or a verified local DNS name. Only the CA
certificate is imported on the iPhone; the private CA key is never placed on
the router or committed. For a manually installed profile, iOS requires the
Owner to enable full SSL trust in **Settings → General → About → Certificate
Trust Settings**; installing a profile alone does not establish SSL trust
([Apple Support](https://support.apple.com/en-us/102390)).

This trust path is operationally possible but not yet provisioned. The exact
router certificate location, gateway implementation, address/hostname,
listener port, certificate renewal procedure, and safe offline CA delivery
method remain to be selected after device inventory and independent review.
If iPhone does not trust the gateway certificate, the dashboard fails closed
and reports the HTTPS trust error; it never retries over HTTP.

## Proxy-only presentation

`App.tsx` detects `mode: "proxy_only"` before asking for credentials, switches
to the existing Proxy feature, and renders `Shell` with `proxyOnly`. That shell
shows only the proxy navigation item and omits the unrelated router alert
banner. The Agent independently returns `404` for paths outside the explicit
proxy/login allowlist. The frontend mode tests and Agent route tests remain
part of the G2-F validation.
