# gopacket ntlmrelayx — Known Issues

## How to Report Issues

When reporting, please include:
- Exact command line used (both gopacket and coercion command)
- Full output with `-debug` flag enabled
- Target OS version and patch level if known
- Whether the same operation works with Impacket's ntlmrelayx

---

## 1. SMB Relay samdump / secretsdump: Relayed Principal Must Have Admin on Target

**Symptom:** `BaseRegOpenKey(SYSTEM\Select) failed: 0x00000005` (ACCESS_DENIED) after a relay appears to succeed.

**Root cause:** The relayed principal does not have local administrator rights on the target. Reading the SAM/SYSTEM/SECURITY hives requires admin access, so the attack fails at the first privileged registry open. Verified against GOAD with `WINTERFELL$` (DC machine account) relayed to srv02 (fails as described), then `eddard.stark` (Domain Admin) relayed to the same srv02 (dumps hashes successfully).

**This is not a gopacket bug** — it is the same constraint Impacket's `ntlmrelayx -attack samdump` has. The access mask on the subkey open has been aligned with Impacket (`MAXIMUM_ALLOWED`) so we pick up the widest effective access the token allows, but a token with no admin rights still can't read the protected keys no matter what we request.

**Common pitfall:** PetitPotam, PrinterBug, and similar coercion tools force a HOST's machine account to authenticate. A domain controller's machine account does NOT have admin on member servers by default, so relaying a DC$ auth to a member server always produces this ACCESS_DENIED. Relay scenarios that succeed involve user-context auth from a principal who is actually a local or domain admin on the target (e.g., a scheduled task running as a Domain Admin, an interactive login reaching out over SMB, Responder-style LLMNR poisoning catching a user credential).

**Workaround:** ensure the relayed principal has admin rights on the target, or use `-attack shares` / `-attack smbexec` which don't require registry access.

---

## 2. tschexec / enum-local-admins: RPC Access Denied

**Symptom:** `RPC Fault 0x05 (ACCESS_DENIED)` when running `tschexec` or `enumlocaladmins` via relay.

**Details:** Task Scheduler (TSCH) and SAMR require RPC-level authentication (PKT_INTEGRITY / PKT_PRIVACY) which is not available in relay sessions. The relay provides session-level auth (SMB session setup) but cannot provide packet-level RPC signing/encryption because we don't have the session key.

**This is the same limitation as Impacket** — these attacks only work with Impacket's `-auth-smb` flag which provides full RPC auth. Relay mode cannot provide this.

**Workaround:** Use `smbexec` for command execution via relay instead. For local admin enumeration, use `shares` attack — access to ADMIN$ confirms local admin.

**Status:** By design. Would require implementing RPC-level NTLM auth forwarding, which is not feasible without the session key.

---

## 3. Shadow Credentials: Certificate Generation Not Implemented

**Symptom:** `-attack shadowcreds` reads existing `msDS-KeyCredentialLink` values but cannot write new shadow credentials.

**Details:** The attack requires generating a self-signed X.509 certificate and constructing a `KeyCredentialLink` structure (CBOR-encoded). The LDAP write path works, but the certificate generation is not implemented.

**Workaround:** Use `pywhisker` (Python) to generate shadow credentials, or use the `delegate` (RBCD) attack instead for similar privilege escalation.

**Status:** Stub. Needs Go X.509 certificate generation + CBOR KeyCredentialLink encoding.

---

## 4. LDAP Relay: Plain LDAP (Port 389) Post-Auth Signing Failure

**Symptom:** LDAP relay to port 389 authenticates successfully but subsequent LDAP operations fail with signing errors on patched DCs.

**Details:** After NTLM bind with NEGOTIATE_SIGN set, the DC requires LDAP message signing on all subsequent operations. The underlying `go-ldap` library doesn't support LDAP signing, so post-auth operations fail.

**Workaround:** Always relay to LDAPS (port 636) instead of plain LDAP (port 389). LDAPS uses TLS for transport security, so LDAP-level signing is not required.

**Status:** By design. Would require implementing LDAP message signing in the go-ldap fork. LDAPS is the recommended relay path.

---

## 5. SMB→LDAPS Relay Fails on Patched DCs

**Symptom:** Relay from SMB capture to LDAPS target fails with MIC validation errors.

**Details:** SMB clients always set NEGOTIATE_SIGN in NTLM Type 1. When relaying cross-protocol (SMB→LDAPS), stripping this flag from Type 1 causes the MIC in Type 3 to be invalid (the client computed the MIC over the original Type 1 with SIGN set). The `--remove-mic` flag strips the MIC from Type 3, but patched DCs (post-CVE-2019-1040) reject messages with missing MIC.

**This is the same limitation as Impacket.** SMB→LDAPS relay is fundamentally broken on patched DCs.

**Workaround:** Use HTTP coercion (WebClient service + PetitPotam) to capture authentication over HTTP instead of SMB. HTTP clients don't set NEGOTIATE_SIGN, so HTTP→LDAPS relay works on patched DCs.

**Status:** By design (protocol limitation). Not fixable.

---

## 6. UDP Features Disabled Under `-proxy`

**Symptom:** Tools that depend on UDP fail with `UDP disabled under -proxy; the underlying feature cannot be tunneled` when `-proxy` (or `ALL_PROXY`) is set.

**Details:** SOCKS5 UDP ASSOCIATE is rarely implemented correctly by proxy servers and client libraries. Silently bypassing the proxy for UDP when `-proxy` is configured would leak the operator's real source IP. gopacket therefore refuses UDP when proxied and surfaces a clear error through `transport.ErrUDPUnderProxy`.

**Affected features:**

| Feature | Tool(s) | Workaround |
|---------|---------|------------|
| SQL Server Browser discovery (UDP 1434) | `mssqlinstance` | Specify the port directly with `-port 1433` on `mssqlclient`; skip auto-discovery |
| DNS SRV lookup routed through the DC | `CheckLDAPStatus` | Pass `-dc-host <hostname>` to skip discovery |
| DNS hostname resolution via the DC | `GetADComputers` | Pass the target as an IP, or `-dc-ip <ip>` |
| Forest-FQDN DNS fallback | `raiseChild` | Pass `-parent-dc <ip>` explicitly |
| Local source-IP discovery | `smbexec` | Set `-target-ip <ip>` manually |

**Status:** By design. UDP tunneling over SOCKS5 is not a gopacket goal. If your workflow genuinely needs UDP over a proxy, use `proxychains` (which hooks libc at a lower level and can intercept UDP sockets) or a full VPN instead of `-proxy`.

---

## 7. Remaining Gaps (Low Priority)

These Impacket features are not yet implemented due to infrastructure requirements:

| Feature | Requirement |
|---------|-------------|
| IMAP relay client + attack | Needs Exchange/IMAP server |
| SMTP relay client | Needs SMTP server |
| SCCM policies/DP attacks | Needs SCCM infrastructure |
