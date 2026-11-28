# nanoDNS lifecycle audit — console firmware 13.60


**Language:** English (default) | [Français](PS5_13_60_LIFECYCLE.fr.md)
## Release version boundary

**0.4-13.60.2 USER-TESTED on firmware 13.60 for startup and local A DNS filtering (5/5 observed queries blocked).** The user subsequently confirmed successful shutdown/power-on with this new ELF, with no recurrence of the original problem. This observation is not accompanied by a shutdown log marker. Rest/resume, explicit controller wake and repeated cycles still need verification; **0.4-13.60.1** has its own earlier positive shutdown trial. All other firmware remain not user-validated.

## Firmware 13.60 user verification (19 November 2026, v0.4-13.60.1)

**One user test passed:** the independent release payload started, enforced protected A-query filtering and the tester reported that the earlier shutdown/power-on problem did not recur. Two log generations recorded 23 local denied A queries, 124 rules, 0 exceptions, and healthy IPv4/IPv6 listener startup. Neither included `shutdown: complete`; this is a **user-observed functional result**, not proof of an OS shutdown callback, repeated power-cycle resilience or rest/resume. All other firmware and the secondary console build are **NOT USER-VALIDATED**. See [test record](TEST_PLAN.md#hardware-test-record--19-november-2026).

## Evidence, not yet a confirmed fix

[Upstream issue #16](https://github.com/drakmor/nanoDNS/issues/16) reports console 13.60 shutdown hangs in a setup containing WebKit Autoloader, Payload Manager, kstuff-lite and ShadowMountPlus, with the symptom disappearing when nanoDNS was disabled. This is **correlation**, not proof of the root cause, and it does not establish why a the controller might fail to power on the console.

The original v0.4 source scanned OS process structures using hard-coded offsets and killed existing nanoDNS instances with `SIGKILL`. This bypassed exit handlers and cleanup. The fork removes the dangerous scan/kill path rather than guessing new firmware-specific offsets.

## Startup sequence

1. The autoloader starts Payload Manager (avoid running both distinct autoload mechanisms at once).
2. Payload Manager starts one nanoDNS process from the unchanged `nanodns.elf` installation path. The payload requests the resident thread label `nanodns-encore` and logs the syscall result and PID. Display by the manager and the OS process-command field are not yet hardware-verified.
3. The process loads `/data/nanodns/nanodns.ini`. If missing, it generates a copy of the bundled 124-rule default policy. Existing configs are not overwritten.
4. The process creates the SceNet pool, then tries IPv4 UDP `127.0.0.1:53`, plus optional IPv6 `::1:53`.
5. If IPv4 cannot bind, startup aborts and releases SceNet; a second launch must **not** steal a running listener.

Only after successful listener initialization do startup notifications occur.

## Runtime

- Matching the mandatory 124 masks occurs before user exceptions.
- Blocked A answers: `0.0.0.0`. Other blocked question types: NODATA.
- A non-IN, non-standard or multi-question packet is refused, never blindly forwarded.
- Permitted queries use upstream UDP with bounded timeouts. Returned response question/name/type/class/ID must match, and protected aliases in the answer section are rejected.
- DNS queries are logged to `/data/nanodns/nanodns.log`; sanitize logs when sharing.
- Listener sockets can be retried on errors; upstream drain loops are bounded.

## Stop, shutdown and rest mode

The process handles `SIGINT` and `SIGTERM` by setting a stop flag. It then finishes no new DNS work, closes local and upstream sockets, releases the SceNet pool, writes terminal milestones and exits. The code **does not yet have a proven console system shutdown callback**. If the OS kills the process without delivering a supported signal, that path cannot be guaranteed.

Rest mode may suspend and later resume existing sockets. console 13.60 behavior and interactions with ShadowMountPlus, kstuff-lite and Payload Manager require actual hardware validation.

**Do not apply kernel memory offsets, register kernel patches, or force-kill system processes as a substitute for this validation.**

## Required evidence before release

A green console SDK build; 124-rule parity tests; no leakage in known blocked A, AAAA, ANY and unsupported multi-question requests; at least one authorized name resolving; stable single-instance/duplicate behavior; clean 13.60 power off, physical-button power on, the controller power on and rest/resume; no filesystem repair warning; consistent logs through shutdown. See [test plan](TEST_PLAN.md).

## 2026-11-28: controller power-on recurrence

The user reported another failed controller power-on, without a system error this time. The earlier successful trials remain historical only. The resident now acquires a nonblocking kernel record lock before touching the configuration, rotating logs or initializing SceNet. The lock file stays in place; the kernel releases the lock when the process exits. A lock failure aborts startup rather than allowing duplicate initialization. UDP sockets are nonblocking and upstream polls check the stop flag at most every 100 ms of reply waiting; startup cancellation reaches cleanup. No guessed power-management callback, firmware offset, or wake fix is claimed. Native lock support, controller wake, shutdown and rest/resume still require isolated hardware qualification.

## 2026-11-28: coexistence review after firewall hard lock

The DNS resident remains independent and performs no IPFW control calls. The main listener poll and idle wait now check shutdown in 100 ms slices; cancellation is checked before SceNet initialization and listener retries. With debug disabled, startup logs the profile and rule count rather than synchronously writing each rule; per-query evidence remains enabled. No filtering, INI precedence, resolver or privilege changes are made. This does not establish the cause of the console freeze or qualify controller wake.
