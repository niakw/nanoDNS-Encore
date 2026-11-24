# Safe installation — console firmware 13.60

**Latest Release 0.4-13.60.3:** Control D (unfiltered), then AdGuard DNS (non-filtering), in order `76.76.2.0`, `76.76.10.0`, `94.140.14.140`, `94.140.14.141`. These profiles do not add malware/ad filtering; local mandatory rules remain unchanged. UDP DNS is unencrypted. Replace both ELF and INI; an existing INI is not overwritten automatically. This build has not yet been user-tested. Previous 0.4-13.60.2 passed startup, 5/5 blocked A queries and shutdown/power-on on firmware 13.60.

**Language:** English (default) | [Français](INSTALL.fr.md)

## Download: two-file ZIP installation bundle (recommended)

**[Download the ready-to-place installation ZIP](https://github.com/niakw/nanoDNS-Encore/releases/download/v0.4-13.60.3/nanodns-13.60-v0.4-13.60.3-install.zip)** · [GitHub release and checksums](https://github.com/niakw/nanoDNS-Encore/releases/tag/v0.4-13.60.3)

The ZIP contains **exactly two files**, without an installer, autorun or any alteration to the payload manager's autoload configuration:

```text
data/
├── pldmgr/payloads/local/nanodns/nanodns.elf
└── nanodns/nanodns.ini
```

These are the resulting **absolute console paths**:

- `/data/pldmgr/payloads/local/nanodns/nanodns.elf` — new independent console payload.
- `/data/nanodns/nanodns.ini` — 124-rule / zero-exception / Control D + AdGuard profile.

**Extract the ZIP on your computer, then FTP-copy the contents with `data/` mapped to the console filesystem root `/`.** Do not copy the `data/` folder *inside* `/data/` (which would create an incorrect `/data/data/` path). Create missing subdirectories if the FTP client does not do it automatically. A ZIP is **not** a self-installing payload.

The source of the archive is the **already-published ELF and INI from this precise release**, verified against its `SHA256SUMS`. The packaging workflow verifies the ZIP contents against those originals before publication. Do not use the original catalog entry's **Update** function.

## Upgrade from Drakmor's original nanoDNS 0.4

**Follow these steps in order. The old and new versions may coexist on disk, but must never run or autoload together.**

1. **Back up first.** Keep your original catalog installation, typically `/data/pldmgr/payloads/repo/nanodns@e8cce5d1/nanoDNS_0.4.elf`, or copy it to your computer. Also back up `/data/nanodns/nanodns.ini` and `/data/nanodns/nanodns.log`. Keep an external IPv4 **and** IPv6 router/firewall rule denying unrestricted console WAN access while preserving local FTP and loader access.
2. **Remove or disable the old payload in Payload Manager.** **Option A:** after backing it up, uninstall the original nanoDNS 0.4 through Payload Manager. **Option B (recommended while retaining a rollback option):** keep it installed but **disable its autoload**. If another autoloader launches the original nanoDNS, remove/disable that startup entry as well. Do **not** uninstall Payload Manager or unrelated payloads.
3. **Stop the currently running old process.** If the manager supports a safe stop operation, use its normal UI. Otherwise, **power the console off fully and start it again** with original nanoDNS autoload disabled. Avoid forced `SIGKILL` and never hot-swap a running executable. A disabled autoload entry does not itself stop an already-running process.
4. **Install the new two-file ZIP.** Download the [ready-to-place installation archive](https://github.com/niakw/nanoDNS-Encore/releases/download/v0.4-13.60.3/nanodns-13.60-v0.4-13.60.3-install.zip), extract it on your computer and FTP-copy its **`data/` tree to the console root** so the ELF is at `/data/pldmgr/payloads/local/nanodns/nanodns.elf` and the INI at `/data/nanodns/nanodns.ini`. **Do not** copy the ZIP into `/data/` without extracting it and **do not** overwrite the old `repo/nanodns@e8cce5d1` folder.
5. **Refresh Payload Manager.** Restart or refresh its interface so it scans the local payload library. Select the new **local `nanodns`** entry (`local/nanodns`), **not** the original repository/catalog entry. Direct local-file installation is supported without a `meta.json` file in current Payload Manager source; behavior on older manager versions needs verification. If this local entry is not visible, use the manager's **import local payload** feature with the extracted `nanodns.elf` instead, and ensure you do not enable two new entries.
6. **Replace autoload, do not append.** Enable automatic startup **only** for the new local nanoDNS. The old nanoDNS 0.4 entry must be **deleted from autoload or explicitly disabled** in Payload Manager (and other loaders, if configured). Confirm the active startup entry resolves to `local/nanodns`, not `repo/nanodns@e8cce5d1`. A duplicate process may fail to bind DNS UDP port 53.
7. **Verify DNS configuration and operation.** Both **console-side DNS fields** remain `127.0.0.1`. Only the installed `[upstream]` INI block uses `76.76.2.0`, `76.76.10.0`, `94.140.14.140`, `94.140.14.141` (Control D then AdGuard). Verify the new `/data/nanodns/nanodns.log` for the listener, **`124 rule(s)`**, **`0 exception(s)`**, expected local denials and permitted DNS lookups when external network access is intentionally allowed.
8. **Test system lifecycle.** Follow the [hardware validation checklist](TEST_PLAN.md): normal power-off, cold start, controller wake, rest/resume, and no duplicate launch. A first **user-tested 13.60** shutdown/power-on cycle passed without the previously reported issue; repeated cycles and rest/resume still need tests.

**Rollback:** disable or remove the new local autoload entry, shut down cleanly, restore the old INI and original ELF (or re-enable the backed-up original repo entry) and set **only the original nanoDNS** to autoload. Keep the previous/current logs for diagnosis.

## First-time installation (no existing nanoDNS)

Use the same [ZIP](https://github.com/niakw/nanoDNS-Encore/releases/download/v0.4-13.60.3/nanodns-13.60-v0.4-13.60.3-install.zip) and copy both files to the exact locations above. Configure both console DNS slots to `127.0.0.1`, refresh Payload Manager, select `local/nanodns` and set **one** autoload entry. Keep WAN isolation at the external router/firewall until your chosen connectivity tests. See the [hardware validation checklist](TEST_PLAN.md).

## Upstream DNS configuration

Only **permitted** names are sent to the four ordered non-filtering upstreams; these are **not** the DNS addresses configured on the console:

```ini
[upstream]
server=76.76.2.0
server=76.76.10.0
server=94.140.14.140
server=94.140.14.141
timeout_ms=1500
```

The timeout is per upstream (up to six seconds of response waiting across the four attempts).

The runtime's DNS upstream transport is still unencrypted UDP. The new ELF does not overwrite an existing INI: the ZIP deliberately includes the new INI to avoid mixing the new binary with the old policy.

## Safety, limitations and credits

- nanoDNS is a DNS filter, **not** a firewall. IP-direct communication, cached IPs, different/encrypted DNS resolvers, TCP DNS, unknown hostnames, and pre-payload network traffic are outside its guarantee. Require an independent router/firewall deny rule for strict WAN isolation.
- Do not test filtering by opening blocked platform services or firmware-update features.
- On firmware 13.60, a **user shutdown/power-on test passed**, but repeated tests, rest mode and full controller wake behavior still need independent verification; other firmware remains unvalidated.
- The user-provided original catalog path is an example of an existing installation; do not assume that hash or folder name is identical on every console.
- **Source and license:** [Drakmor](https://github.com/drakmor/nanoDNS), GPL-3.0; [community blocklist](https://github.com/niakw/nanodns-console-blocklist); [independent nanoDNS 13.60](https://github.com/niakw/nanoDNS-Encore).

See [security](../SECURITY.md), [DNS policy](DNS_POLICY.md), and [test plan](TEST_PLAN.md).
