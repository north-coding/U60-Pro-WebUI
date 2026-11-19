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
not add trust in caller-supplied `X-Forwarded-For`, `Forwarded`, or other
client-address headers. Exact HTTPS Origin matching and the proxy-only
endpoint allowlist remain enforced at the Agent. Source-aware gateway login
throttling is a deployment blocker.

The local HTTPS integration test generates an ephemeral test certificate in
a disposable temporary directory, serves a small synthetic UI, and forwards
same-origin API requests to a synthetic loopback Agent. Rust Agent-shaped
subscription, refresh, and group envelopes are consumed through the existing
frontend API methods and response mappers; refresh outcomes also pass through
the production per-provider result validator. The test covers successful and
partial refreshes, malformed and missing provider results, exact Origin
handling, unauthorized requests, denial of router endpoints, and normal
certificate verification failure. No private key or certificate is stored in
the source tree. This is a synthetic TLS transport and frontend API-contract
test: it does not run the Rust Agent or a browser, and it does not prove
device-side gateway, certificate, or deployment behavior.

## Existing router-facing evidence

The repository launches the project dashboard with upstream `dashboard-uhttpd`
on port 8080 over HTTP. The Agent has no TLS stack. The Owner's 2026-11-19
read-only snapshot reports that stock uhttpd serves ports 80 and 443 from
`/usr/zte_web/web` with temporary ZTE certificate files. This establishes stock
TLS capability. The certificate is self-signed, and neither the snapshot nor
the repository establishes reverse proxy or per-source rate limiting support.

Keep the stock listener, web root and certificates reserved for ZTE. The
smallest candidate is a separate project-owned HTTPS origin on a free LAN port
serving the existing dashboard bundle and forwarding the explicit Agent API
allowlist to `127.0.0.1:9090`. Forward Origin unchanged, enforce the exact
management origin and rate-limit login by the connection's actual source IP.
Strip client-supplied forwarding headers. Keep the Mihomo controller on its
private Unix socket. The proxy-only UI requires this trusted HTTPS origin.

Before choosing a gateway, verify one capability: whether an available
ARM64 gateway build can serve static files and reverse-proxy an explicit path
allowlist with per-source login limits under TLS, as a separate invocation
with its own certificate. If the installed uhttpd build cannot do this,
stage a vetted standalone ARM64 gateway for approval. Verify the chosen LAN
port is free and reachable under the existing LAN policy before using it.

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
