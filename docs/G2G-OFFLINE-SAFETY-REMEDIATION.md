# G2-G Offline Safety Remediation

## Startup-file transaction

`scripts/device/startup_transaction.py` implements an activation transaction
only for a marked directory under the operating system's temporary directory.
The CLI requires `--test-root`; it does not accept an arbitrary rc.local path,
does not invoke the Agent launcher, and cannot target `/etc/rc.local` on a
device. Device activation remains disabled.

Before a synthetic replacement, the transaction validates private managed
directories, the strong credential file, required artifact paths and SHA-256
sidecars, declared ARM64 identities, launcher syntax and explicit loopback
proxy-only arguments. It accepts exactly one unchanged
`sh /data/mihomo/start-mihomo.sh >/data/mihomo/autostart.log 2>&1 &` entry and rejects missing, duplicate,
modified, or already-replaced entries. An independent inventory pins the
complete file hash and its file identity before replacement. It writes and verifies the complete
original startup file at
`staging/startup-transaction/original.rc.local` (mode `0400`), plus owner,
group, mode, device, inode, length, and SHA-256 metadata before replacing the
entry. All non-entry bytes and line endings are preserved.

The bounded synthetic health exchange is at most eight seconds total, with
each loopback HTTP request bounded to one second and at most eight attempts.
It checks proxy-only capabilities, logs in with the test-root credential, then
checks proxy status using the returned Bearer token. Readiness requires the
managed process and its controller to be responsive in Rule/bypass_cn with TUN off. The probe refuses any
password path outside the marked temporary tree. It is not a device-ready
health adapter: before a future device adapter may send the production
credential over TCP, it must positively verify the listener's executable and
process identity first (for example through a peer-credential-checked Unix
socket). That check depends on the separately authorized read-only process
inventory below.

Failure or interruption removes only the exact new startup entry. It retains
the complete original snapshot and deliberately does not put the abandoned
legacy startup command back into the boot file. The transaction does not stop
processes, delete routes or firewall rules, remove interfaces, or clean legacy
Mihomo files. If the exact rollback cannot be verified, it leaves the
candidate and protected snapshot in place and reports recovery as blocked.

The synthetic test suite covers successful activation, health and launch
failure, interruption before and after replacement, malformed or mismatched
snapshots, partial staging, permission errors, failed rollback and later
recovery, concurrent attempts, ambiguous startup entries, wrong ownership,
private-file permissions, artifact digest mismatch, and the authenticated
loopback health exchange.

## Proxy-only credential

New proxy-only mode accepts exactly the canonical 43-character unpadded
base64url representation of 32 random bytes. The credential file must be a
single-link regular file owned by the Agent identity, exactly mode `0600`,
and contain one newline-terminated value. The synthetic provisioning helper
uses the standard cryptographic random source, refuses replacement, writes
without displaying the value, and is limited to marked temporary test roots.
The legacy full-Agent password behavior is unchanged.

## HTTPS gateway boundary

The proxy-only Agent remains on `127.0.0.1:9090`. It keeps exact HTTPS Origin
matching and the existing login/proxy-management endpoint allowlist; unrelated
router endpoints remain denied. No TLS server is selected before read-only
router inventory, and no plaintext LAN login or certificate-verification
bypass is added. The Agent does not trust arbitrary forwarded-client-address
headers. Since local gateway clients share the loopback login-throttle bucket,
source-aware gateway login throttling remains a deployment blocker.

## U60 cutover evidence and acceptance

The Owner's 2026-11-19 snapshot reports OpenWrt 23.05.4, Linux 5.15.194-perf,
ARM64, about 1.7 GB free in /data and no managed directory. The old startup
line is at line 43, after the separate Dropbear entry. Legacy Mihomo owns
LAN ports 7890 and 9090 in that snapshot. Line numbers and historical PIDs are
informational.

After separate authorization, capture a current complete startup digest and
file identity and confirm the exact entry is the active project startup
command. Rediscover the legacy listener owners and match the executable path,
device/inode, digest, start ticks and launch ownership. Any controlled stop
needs a verified pidfd tied to the same process identity and a post-stop
recheck that the process is gone and LAN 7890/9090 are free. Unverified
ownership blocks cutover. Retain old files until a separate post-acceptance
cleanup decision.

The launcher uses explicit proxy-only mode and starts in the background on
boot. Binding 127.0.0.1:9090 alone does not prove that LAN 9090 is free.
Managed start checks that the legacy executable is absent, the LAN controller
port is free and the selected mixed port is available. Recovery checks for
legacy process conflicts and keeps the existing durable owner record and pidfd
verification. A Linux boot ID distinguishes records from previous boots.
Such a record is removed only when the binary digest still matches and no
current process claims the managed runtime. No PID from a previous boot is
used for adoption or signalling. The loopback Agent and private controller socket
serve different roles.

First activation uses fresh managed state with TUN disabled. Start Mihomo
explicitly through the authenticated API. An Agent capability response is not
the activation check. Require running managed process and controller readiness
in authenticated status. The existing Agent watchdog restarts an enabled
managed instance after reboot and reconciles only a verified owned process
after Agent restart. Test a real subscription and node from iPhone Safari
through the separately validated HTTPS origin. Start with the iPhone's
explicit Wi-Fi HTTP proxy on LAN 7890 and check Rule behavior with supported
client traffic. This does not establish transparent forwarding or TUN safety.
Verify restart and reboot, cached nodes, both traffic paths, cellular service
and USB SSH. If activation fails, disable only the new entry and retain the
snapshot. No legacy boot entry should be restored.

The remaining gateway capability check and iPhone certificate path are in
[G2F-SECURE-WEBUI.md](G2F-SECURE-WEBUI.md). The live health adapter also needs
a verified local channel before it can send real credentials. Device
execution is disabled in this candidate.
