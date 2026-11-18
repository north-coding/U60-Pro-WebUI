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
`sh /data/local/tmp/start_zte_agent.sh` entry and rejects missing, duplicate,
modified, or already-replaced entries. It writes and verifies the complete
original startup file at
`staging/startup-transaction/original.rc.local` (mode `0400`), plus owner,
group, mode, device, inode, length, and SHA-256 metadata before replacing the
entry. All non-entry bytes and line endings are preserved.

The bounded health contract is at most eight seconds total, with each
loopback HTTP request bounded to one second and at most eight attempts. It
checks proxy-only capabilities, logs in with the private credential, then
checks proxy status using the returned Bearer token. Failure or interruption
removes only the exact new startup entry. It retains the complete original
snapshot and deliberately does not put the abandoned legacy startup command
back into the boot file. The transaction does not stop processes, delete
routes or firewall rules, remove interfaces, or clean legacy Mihomo files.
If the exact rollback cannot be verified, it leaves the candidate and
protected snapshot in place and reports recovery as blocked.

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

## Proposed first read-only U60 inventory

This procedure is a proposal only; it has not been run and requires separate
Owner authorization before any device connection.

1. Record firmware/build, uptime, available `/data` space, and ownership/mode
   for the exact managed directories and candidate startup scripts. Redact
   serial, SIM, subscriber, and credential values.
2. Capture listeners and owning processes for ports `8080`, `9090`, `9097`,
   and the first available candidate HTTPS port, using read-only `ss` or
   `netstat` and `ps` output. Identify installed TLS-capable server binaries,
   uhttpd modules, package versions, and existing TLS configuration without
   reading or printing private keys.
3. Record the existing WebUI/Agent/dashboard/Dropbear listeners and exact
   project-owned launcher files. Read `/etc/rc.local` with line numbers and
   hashes; verify the exact old Agent entry and preserve every stock line.
4. Record kernel release, `/proc` visibility, and support for process identity
   checks. A future read-only helper can call `pidfd_open` on itself and
   inspect its own `/proc/<pid>/stat` and `/proc/<pid>/exe`; it must not signal
   or attach to another process during inventory.
5. Capture `ip addr`, `ip rule`, route tables, and read-only firewall rule
   listings as the stock routing baseline. Do not flush, add, or delete any
   resource. Confirm existing Wi-Fi, cellular/WAN, USB ECM, SSH, and stock
   management services are present and healthy using read-only status calls.
6. Stop at an inventory report. Do not edit startup files, install a TLS
   server, generate production certificates, start Mihomo, or clean old
   components during this stage.
