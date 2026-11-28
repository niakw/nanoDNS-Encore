<div align="center">

# nanoDNS 13.60 — Hardened Runtime

### Stronger DNS enforcement. Cleaner shutdown. One auditable payload.

**1719 mandatory protected patterns · Control D + AdGuard DNS · Native checks · Safer process lifecycle**

[![Protected masks](https://img.shields.io/badge/Mandatory_rules-1719-394965)](nanodns4096.ini)
[![Resolver](https://img.shields.io/badge/DNS-Control_D%20%2B%20AdGuard-456b90)](docs/DNS_POLICY.md)
[![License](https://img.shields.io/badge/License-GPL--3.0-555)](LICENSE)

**English (default)** · [Français](README.fr.md)

[**English installation**](docs/INSTALL.md) · [**Policy architecture**](docs/DNS_POLICY.md) · [**Runtime audit**](docs/PS5_13_60_LIFECYCLE.md) · [**Validation**](docs/TEST_PLAN.md)

</div>

---


## Release 0.4-13.60.4 — extended mandatory profile, user-tested on 28 November 2026

**0.4-13.60.4 is USER-TESTED on firmware 13.60 for startup, profile selection, protected A-query blocking and permitted A-query upstream resolution.** The submitted runtime log identifies the .4 development build used to qualify this release behavior, selects `/data/nanodns/nanodns4096.ini`, loads **1719 rules / 0 exceptions**, opens both loopback listeners, answers **15/15 observed protected A queries locally with `0.0.0.0`**, and returns **7/7 observed permitted A queries through the first configured upstream**. No runtime error is visible in the supplied trace.

The release keeps bounded dynamic policy storage (**4096 overrides + 4096 exceptions**, 4 MiB INI ceiling). The original 124-rule canonical core remains included in the 1719 mandatory masks. `nanodns4096.ini` is selected first; `nanodns.ini` is a compatibility fallback only when the preferred file is absent. The two files are never merged.

**Validation boundary:** the supplied .4 trace does not contain a shutdown sequence and does not prove rest/resume, controller wake, AAAA behavior, failover to later upstreams, repeated power cycles or long-term stability.

## Historical Release 0.4-13.60.2 — hardware evidence

**Previous ELF/ZIP: `0.4-13.60.2`; USER-TESTED on firmware 13.60 for startup, configuration loading and blocked A queries.** The user's log confirms 5/5 observed A queries blocked with `0.0.0.0`, 124 rules, zero exceptions and both loopback listeners. **The tester also confirmed a successful normal shutdown and power-on with 0.4-13.60.2**, without recurrence of the original issue. This outcome is user-reported; the DNS log itself has no terminal shutdown marker. Rest/resume, permitted Quad9 lookups, AAAA, repeated cycles and endurance remain unverified. The earlier **0.4-13.60.1** release ([previous release](https://github.com/niakw/nanoDNS-Encore/releases/tag/v0.4-13.60.1-beta.1)) separately passed a shutdown/power-on trial. No other firmware is user-validated.

## Hardware validation status — 19 November 2026

| Target | Real-user hardware status | Scope |
| --- | --- | --- |
| Current-generation console, firmware **13.60** | **0.4-13.60.4 USER-TESTED for startup and DNS path; earlier 0.4-13.60.2 shutdown/power-on trial passed** | .4 loaded 1719/0, blocked 15/15 observed protected A queries and resolved 7/7 observed permitted A queries upstream. .4 shutdown/rest/wake remain unverified |
| Current-generation console, **other firmware** | **NOT USER-VALIDATED** | SDK compilation and automated tests are not hardware validation |
| Secondary/older-generation console build, **all firmware** | **NOT USER-VALIDATED** | Successful SDK compilation only; no real-user hardware report |

The two sanitized runtime logs from the **0.4-13.60.1** test showed **23 blocked A queries**, **124 configured rules**, **0 exceptions**, both loopback listeners, and the configured Quad9 pair. This is **not** proof of permitted upstream lookups, AAAA filtering, system-wide absence of DNS leaks, rest/resume, long-term stability, or an OS-delivered shutdown callback. The shutdown/power-on successes for both versions are based on the user's reports, not an observed `shutdown: complete` marker in the supplied logs.

**Do not extend the 13.60 validation to any other firmware or hardware without independent user tests.** Published as a **standard GitHub Release** for the user-tested 13.60 firmware; this does not imply the remaining hardware validation matrix is complete. See [validation matrix](docs/TEST_PLAN.md).

## Go beyond a blocklist file

A DNS denylist can be edited, replaced or bypassed through local exceptions. A runtime can also fail during duplicate launch or system shutdown.

**nanoDNS 13.60 builds on [Drakmor's original nanoDNS](https://github.com/drakmor/nanoDNS)** and retains the independent [124-rule Console Blocklist](https://github.com/niakw/nanodns-console-blocklist) as the canonical core and extends the release policy to **1719 mandatory masks compiled directly into the binary**. Known protected names are evaluated **before** user-defined exceptions, while permitted DNS lookups still use **Control D and AdGuard non-filtering upstream resolvers**.

The goal is stronger **DNS-layer policy enforcement and process reliability** without unnecessarily breaking unrelated Internet access.

## Before and after: clear, testable improvements

| Capability | Original nanoDNS v0.4 | Standalone blocklist | **Independent hardened runtime** |
| --- | --- | --- | --- |
| Shipped default deny rules | **8** | **124** in INI | **1719 mandatory** masks in binary |
| Shipped default exceptions | **6** | **0** | No exception can override a mandatory protected name |
| Upstream DNS | Three mixed resolvers | Control D + AdGuard | **Ordered Control D, then AdGuard** |
| Special DNS questions | Original forwarding behavior | Original behavior | Reject unsupported or multiple questions |
| Upstream reply checks | Basic transaction checking | Original behavior | Validate question identity and protected aliases |
| Wildcard matching | Recursive | Depends on payload | **Iterative, native regression-tested** |
| Duplicate payload start | Can force-kill old instance | Original behavior | **No SIGKILL; exclusive UDP bind** |
| Logs and shutdown | Current log overwritten | Original behavior | Previous log retained, size bounded, shutdown milestones |
| Entire Internet / direct-IP blocking | **No** | **No** | **No — external firewall needed** |
| Firmware 13.60 user test | Not established | Not applicable | **Basic shutdown/power-on user trial passed; broader tests remain open** |

The original software supports custom rules; the 8/6 values refer to its **unchanged defaults**. An INI alone cannot enforce mandatory precedence or modify the payload's process lifecycle.

## How mandatory protection works

```text
DNS query received by nanoDNS
              |
              v
  Compiled mandatory 1719 masks
         /          \
    Protected     Not protected
        |              |
   Local deny      Additional INI rules /
 A: 0.0.0.0        user exceptions
 AAAA: no answer        |
                         v
                 Control D (unfiltered)
                  76.76.2.0 / 76.76.10.0
                 AdGuard (non-filtering)
                  94.140.14.140 / 94.140.14.141
```

Control D and AdGuard provide independent upstream fallback in the configured order. Transport remains **unencrypted UDP**; these profiles do not provide additional malware/ad filtering. [Control D](https://docs.controld.com/docs/free-dns) · [AdGuard](https://adguard-dns.io/en/public-dns.html) · [Quad9 withdrawal](https://quad9.net/news/blog/au-revoir-france/).

## Built for stability, not risky system patches

- Removed process enumeration using fixed internal-structure offsets and forced termination of existing instances.
- Preserved the existing process label to maintain compatibility with payload managers.
- Requires exclusive ownership of the IPv4 DNS listener; a second launch fails rather than stealing queries.
- Responds to supported termination signals and closes sockets and networking resources in documented stages.
- Uses bounded upstream operations and monotonic timekeeping when available.
- Retains the previous DNS log and limits log size.
- Adds static policy parity checks, native wildcard differential tests and SDK build workflows.

**No verified system shutdown callback has been established.** A firmware 13.60 user's shutdown/power-on trial passed, but this does not by itself prove a complete hardware shutdown/controller-wake fix.

## Already using Drakmor's original nanoDNS 0.4?

**Use our single ready-to-copy ZIP:** [**nanoDNS 13.60 installation bundle**](https://github.com/niakw/nanoDNS-Encore/releases/download/v0.4-13.60.4/nanodns-13.60-v0.4-13.60.4-install.zip).

After backing up the existing ELF/INI, **uninstall the original nanoDNS in Payload Manager or disable it and remove its autoload entry**, stop it through the manager when supported or shut down/restart the console cleanly. Then extract the ZIP on your computer, copy its `data/` tree to the **console filesystem root**, refresh Payload Manager, and enable **only `local/nanodns`** in autoload. **Do not** update the original repository/catalog entry or overwrite its existing `repo/nanodns@e8cce5d1` slot.

[**Step-by-step migration guide (English)**](docs/INSTALL.md#upgrade-from-drakmors-original-nanodns-04) · [Guide français](docs/INSTALL.fr.md#migration-depuis-le-nanodns-04-officiel-de-drakmor) · [Release and standalone files](https://github.com/niakw/nanoDNS-Encore/releases/tag/v0.4-13.60.4)

## Installation: ZIP first, English first

The recommended download is a **two-file installation ZIP**. Copy the extracted files to these exact destinations (not `/data/data/`):

```text
/data/pldmgr/payloads/local/nanodns/nanodns.elf
/data/nanodns/nanodns4096.ini
```

Then refresh Payload Manager, enable only the `local/nanodns` autoload entry, keep **both console DNS fields at `127.0.0.1`**, and verify the new-session logs. The archive **does not** update Payload Manager's autoload on its own. An independent external firewall is still required for strict WAN isolation.

**[Download installation ZIP](https://github.com/niakw/nanoDNS-Encore/releases/download/v0.4-13.60.4/nanodns-13.60-v0.4-13.60.4-install.zip)** · [Complete English instructions](docs/INSTALL.md) · [Guide français](docs/INSTALL.fr.md) · [Validation plan](docs/TEST_PLAN.md)

## When can this independent project be considered stable?

A green build and static tests are **necessary but insufficient**. One real-user firmware 13.60 startup/DNS/shutdown/power-on trial has succeeded. Repeatable DNS, rest/resume and controller-wake checks without crashes or storage repair remain required before broader stability claims. Other firmware and the secondary build have **no user hardware validation**. Even then, deleting this repository and returning to stock nanoDNS would **remove the compiled mandatory rule enforcement and lifecycle fixes**. Keep the independent repository and its audit history rather than returning to the original payload.

## Security limits

This is **not a firewall**. Direct IP connections, alternative/encrypted DNS, cached addresses, TCP DNS, pre-payload traffic and unknown hostnames remain possible. Use an independent WAN-deny policy for strict network isolation. Wide wildcard patterns and shared delivery infrastructure can also create false positives. See [security](SECURITY.md) and [test plan](docs/TEST_PLAN.md).

## Contributing and project policies

[Contributing](CONTRIBUTING.md) · [Code of conduct](CODE_OF_CONDUCT.md) · [Accessibility](ACCESSIBILITY.md) · [Security disclosure](SECURITY.md) · [Change history](CHANGELOG.md). Reports and pull requests may be written in English or French.

## Credits and license

**Original nanoDNS source:** [Drakmor](https://github.com/drakmor/nanoDNS). **Rules and research:** [niakw / Console Blocklist](https://github.com/niakw/nanodns-console-blocklist). **Firmware-specific integration:** [niakw](https://github.com/niakw/nanoDNS-Encore). Community sources are credited in the [provenance document](docs/CREDITS.md). GPL-3.0 preserved. Independent project, not an official device-manufacturer release.

---

**Secure what DNS can protect. Document what it cannot.**

### Release policy profile

[`nanodns4096.ini`](nanodns4096.ini): **1719 mandatory rules**, including the 124-rule canonical core. Runtime limits are 4,096 overrides and 4,096 exceptions with a 4 MiB INI ceiling. The 28 November .4 hardware trace exercised this profile directly; it remains a best-effort DNS inventory rather than proof of exhaustive endpoint coverage.
