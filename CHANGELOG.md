# Changelog


**Language:** English (default) | [Français](CHANGELOG.fr.md)

## Unreleased — source after 0.4-13.60.3

- Replace the fixed `MAX_RULES=128` override array and `MAX_EXCEPTIONS=128` exception array with bounded dynamic heap storage. The configuration file is capped at 4 MiB instead of silently truncating at 128 overrides; the 124 mandatory masks remain a separate compiled policy and keep precedence over user exceptions/overrides.
- This is source-only until a new current-generation console binary is built and hardware-qualified; the published 0.4-13.60.3 ELF retains the historical 128-entry override table.
## 0.4-13.60.3 — DNS migration (2026-11-24)

- Replace Quad9 after its withdrawal from France: Control D (unfiltered), then AdGuard DNS (non-filtering), in order `76.76.2.0`, `76.76.10.0`, `94.140.14.140`, `94.140.14.141`. These profiles do not add malware/ad filtering; local mandatory rules remain unchanged. UDP DNS is unencrypted.
- Give each upstream an independent response window; advance after SERVFAIL or REFUSED, preserving valid negative DNS answers.
- Keep all 124 mandatory masks, zero default exceptions and existing local DNS bindings. Rebuild ELF/ZIP; user hardware retest pending.

## 0.4-13.60.2 — standard GitHub Release, basic firmware 13.60 user test passed (2026-11-19)

- Avoid a time-of-check/time-of-use race when generating the default `nanodns.ini`: create with `O_CREAT | O_EXCL | O_NOFOLLOW` and restrictive initial file permissions, without overwriting an existing configuration.
- Open an existing INI using a no-symlink file descriptor and require a regular file; retain fallback mandatory rules if the INI cannot safely be loaded.
- Add least-privilege `contents: read` for the ordinary console build workflows; eliminate duplicate auto-release jobs from those workflows. The release publisher remains separate.
- Replace the invalid Dependabot placeholder with weekly GitHub Actions dependency checks.
- Add complete English and French contribution, accessibility, code-of-conduct and issue-reporting guides, with real project paths and privacy reminders.

**Validation boundary:** this 0.4-13.60.2 Release contains **newly built binaries** with the security changes and merged CI PRs, and **passed a firmware 13.60 user test for startup and 5/5 mandatory blocked A DNS queries**, with 124 rules, 0 exceptions and IPv4/IPv6 listeners. The same user subsequently reported a **successful normal shutdown/power-on trial on 0.4-13.60.2**, without the original issue. This lifecycle result is user-reported rather than logged by a terminal shutdown marker. Rest/resume, AAAA, permitted Quad9 resolution, repeated cycles and endurance remain unverified. The previous 0.4-13.60.1 release passed its own separate console shutdown/power-on trial. Other firmware and the secondary console build remain not user-validated.

## 0.4-13.60.1 — standard GitHub Release; 13.60 basic user test passed (2026-11-19)

### Process safety
- Remove hardcoded process-info structure offsets and SIGKILL-based replacement.
- Retain the original process label for Payload Manager interoperability.
- Require exclusive IPv4 UDP listener and cleanly release resources on bind failure.
- Improve SIGTERM/SIGINT shutdown sequencing and logging milestones.
- Use monotonic deadline where supported; bound stale upstream packet draining.

### DNS policy and security

- Upstreams changed to Quad9 secure-only primary `9.9.9.9` and backup `149.112.112.112`; no other DNS providers fallback in distributed defaults. The original 124 deny rules / 0 exceptions stay intact.
- Integrate and credit the 124-rule, zero-exception selective configuration from [niakw/nanodns-console-blocklist](https://github.com/niakw/nanodns-console-blocklist).
- Compile mandatory masks into the ELF and apply **before** any local exception.
- Reject unsupported DNS question sets rather than forwarding unchecked.
- Verify upstream response ID / question and reject protected aliases in DNS answers.
- Synchronize default generated config, shipped INI and example profile with static parity tests.

### Documentation and CI
- Add security boundary, shutdown lifecycle audit, French installation, test plan, policy provenance and credits.
- Retain console and console SDK builds and add offline security/policy validation.

**Validation note:** firmware 13.60 passed one user trial for basic startup, protected A-query DNS filtering and normal shutdown/power-on without a recurrence of the previously reported issue. Permitted upstream DNS, AAAA, rest/resume, repeated power cycles and long-term stability are not yet user-verified; other firmware and the secondary build remain untested on real hardware.
