# Release validation plan — firmware 13.60

**Language:** English (default) | [Français](TEST_PLAN.fr.md)

**Status: standard GitHub Release; one positive firmware 13.60 user test, with further validation pending.** Source tests and SDK builds alone cannot establish that console shutdown, controller power-on or standby are fixed.

## Release 0.4-13.60.3 — DNS migration, hardware retest pending

On 24 November 2026 Quad9 was replaced with Control D (unfiltered), then AdGuard DNS (non-filtering), in order `76.76.2.0`, `76.76.10.0`, `94.140.14.140`, `94.140.14.141`. These profiles do not add malware/ad filtering; local mandatory rules remain unchanged. UDP DNS is unencrypted. Verify four upstreams in the log, the unchanged 124/0 profile, a permitted query through Control D and failover to AdGuard when prior resolvers are unavailable. Test timeout and SERVFAIL/REFUSED failover; NXDOMAIN remains valid. The new binary is not user-tested; the following reports apply only to previous binaries.

## Release 0.4-13.60.2 — user hardware test (19 November 2026)

**USER-TESTED: startup and mandatory A-query DNS blocking PASSED on console firmware 13.60.** The submitted log identifies `NanoDNS v0.4-13.60.2`, built Nov 19 2026 15:34:13.

- The daemon loaded **124 rules**, **0 exceptions**, **2 configured upstreams** (`9.9.9.9` and `149.112.112.112`), timeout **1500 ms**.
- It opened both listeners: `127.0.0.1:53` and `[::1]:53`.
- **5/5 observed A queries** were answered locally with `0.0.0.0` under `mandatory-console-blocklist`. The four distinct names were `ps5.np.playstation.net` (twice), `telemetry-console.api.playstation.com`, `smetrics.aem.playstation.com` and `envelope2.np.dl.playstation.net`.
- No error appears in the provided excerpt. The supplied log does **not** contain a shutdown marker; the successful power-off/power-on outcome was subsequently reported separately by the user. Configured Quad9 addresses do **not** establish successful allowed upstream resolution; AAAA and missing-INI generation were not exercised by this log.

**Follow-up user validation on 19 November 2026:** the tester separately confirmed that **normal shutdown and subsequent power-on succeeded on 0.4-13.60.2 without the previously reported issue**. This is functional user evidence, not a shutdown event visible in the DNS log. **Further tests remain open:** explicit controller-wake path, rest/resume, AAAA, permitted Quad9 lookups, repeat power cycles and long-term stability. The prior 0.4-13.60.1 version also has a separate successful shutdown report. Other firmware and the secondary console build remain **NOT USER-VALIDATED**.

## Hardware test record — 19 November 2026 (0.4-13.60.1 only)

**User-tested on firmware 13.60: basic operation successful.** A tester installed the independent release payload and reported that the previous shutdown/power-on issue did **not** recur during the performed trial.

Two user-supplied log generations (`nanodns.log` and `nanodns.log.previous`) show:

- Runtime banner `NanoDNS v0.4-13.60.1`, 124 configured rules, 0 exceptions and only the two Quad9 upstreams.
- IPv4 and IPv6 listeners successfully bound to `127.0.0.1:53` and `[::1]:53`.
- **23 observed A queries** across both log files, each answered locally with `0.0.0.0` under `mandatory-console-blocklist`. No upstream query appears in either supplied log.
- No explicit terminal `shutdown: complete` sequence. The shutdown/power-on outcome comes from the **user's report**, not a shutdown log marker.

| Platform / firmware | Verification |
| --- | --- |
| Current-generation console firmware 13.60 | **USER-TESTED: basic startup, protected A DNS filtering, shutdown/power-on trial passed** |
| Current-generation console, every other firmware | **NOT USER-VALIDATED** |
| Secondary/older-generation build, every firmware | **NOT USER-VALIDATED** |

**Open hardware checks on 13.60:** permitted query resolving through Quad9, AAAA, alternative DNS behavior, rest/resume, repeated shutdown/power-on cycles, and long-duration stability. A successful SDK build alone is never a substitute for a real-user test. Do not treat one successful shutdown as a proven root-cause fix for every environment.



## 1. Offline and CI checks

- `python3 -m unittest discover -s tests -v`: verify the 124 mandatory masks, zero-exception default profile, matching INI files, ordered Control D/AdGuard addresses and native matching tests.
- Build the console ELF with the supported SDK; verify the artifact exists and is non-empty. Also compile the secondary compatibility target.
- Check the current **main commit**, not only an older successful run. Never present a build as validated hardware behavior.

## 2. Prepare without network leaks

Back up the old ELF, `/data/nanodns/nanodns.ini`, logs and important saves. Keep the console WAN-denied through an independent router/firewall rule (IPv4 and IPv6), while preserving LAN/FTP and a local loader.

Confirm one autoload mechanism and exactly one nanoDNS process. Transfer the 124-rule `nanodns.ini` explicitly; the payload deliberately does not overwrite an existing profile.

## 3. DNS security matrix

| Scenario | Required result |
| --- | --- |
| A query for a hostname from the mandatory INI | Local `0.0.0.0`; **no upstream forwarding** |
| AAAA query for the same protected hostname | Local no-address answer; **no upstream forwarding** |
| A previously excepted service hostname that is protected by the INI | **Still denied**, even with a legacy exception |
| Any additional protected publisher/legacy console hostname from the policy | Denied according to the mandatory masks |
| Multi-question, unsupported class or unsupported query opcode | Rejected rather than forwarded without checks |
| Permitted test hostname (such as `github.com`) | Successful upstream resolution when WAN is intentionally enabled |
| Upstream answer containing a CNAME to a protected hostname | Rejected; no protected target relayed |
| Duplicate payload launch | Existing IPv4 listener retained; new instance does not steal port 53 |
| Missing or invalid on-disk profile | Mandatory compiled masks still applied |
| Restart after receiving a supported termination signal | Network pool and listener released cleanly |

Select blocked names **from the actual INI**. Do not contact or deliberately request operating-system updates. Capture sanitized network traces if possible, not just successful app startup.

## 4. Hardware shutdown and wake

1. Establish clean shutdown and controller power-on behavior **without nanoDNS**, keeping other payloads unchanged.
2. Run a single nanoDNS instance for ordinary use, confirm DNS and then shut down from the system menu.
3. From a genuinely powered-off state, try the controller power button and note its light behavior.
4. Test standby, resume, controller input and restored DNS resolution.
5. Repeat after switching between apps, then close them before shutdown.
6. Check for storage repair prompts, freeze, kernel warnings or missing shutdown milestone logs.
7. If any problem recurs, save redacted logs and restore the known-working ELF and INI.

## 5. Extended hardware qualification gate

**Required:** the current commit's SDK builds and policy CI must pass, DNS deny tests must show no upstream lookup for known blocked queries, permitted names must resolve, and physical-console shutdown/rest/resume/controller-wake must be repeatable.

**Fail conditions:** any unaccounted shutdown hang, filesystem repair, improper DNS relay, regression in permitted resolution, unexpected process kill or red CI. The strict no-WAN guarantee remains the responsibility of an external firewall, never this DNS payload alone.
