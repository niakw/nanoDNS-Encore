# Contributing to nanoDNS 13.60

**Language:** English (default) | [Français](CONTRIBUTING.fr.md)

Thanks for helping improve this independent GPL-3.0 DNS payload, based on [Drakmor's original nanoDNS](https://github.com/drakmor/nanoDNS). Contributions in English or French are welcome.

## Scope and priorities

- Protect the existing **124 mandatory DNS masks**, which must be applied before user exceptions; don't silently change the blocklist, its semantics or the ordered Control D/AdGuard profile.
- Improve reliability without killing unrelated processes or adding guessed firmware-specific kernel offsets.
- Preserve the documented local installation paths, Payload Manager migration steps and two-file release ZIP.
- Treat real-console validation **firmware by firmware**. Basic functionality was user-tested on firmware 13.60; other firmware and the secondary console build remain unverified until independent user tests exist.
- nanoDNS is **not a firewall**. Never describe DNS filtering as guaranteed outbound network isolation.

## Changes and verification

1. Open a focused [bug report or feature request](https://github.com/niakw/nanoDNS-Encore/issues/new/choose) or link an existing issue.
2. Work in a dedicated branch and explain the bug, intended behavior, risk, rollback, and files modified.
3. Run the available host checks:
   ```sh
   python3 -m unittest discover -s tests -v
   cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic tests/test_dns_mask.c -o /tmp/nanodns-mask-test
   /tmp/nanodns-mask-test
   ```
4. When you have the supported SDK, compile the relevant ELF using `make clean all` (current-generation build) or `make -f Makefile.ps4 clean all` (secondary build). Compilation is **not** hardware verification.
5. Update documentation and tests together; important user-facing docs have English/French pairs. Keep the README, install guide, release notes and validation matrix consistent.
6. Submit a focused PR. Include command output and user-device test evidence **only when actually obtained**, noting hardware and firmware.

## Console-testing requirements

Use only your own authorized test device. Back up the existing ELF and INI, retain the ability to roll back, and keep independent router/firewall WAN restrictions during initial tests if strict isolation is needed. Never run two nanoDNS instances concurrently. Test actual blocked responses and permitted lookups where safe, plus normal shutdown and wake, rather than relying on SDK output alone.

**Protect privacy:** redact hostnames that identify the user, IP addresses, local networks, file paths containing identities, account data and console identifiers before posting logs publicly. Don't commit secrets, keys, proprietary binaries or copyrighted console SDK files.

## Security and community

For a potential vulnerability, read [SECURITY.md](SECURITY.md) before opening a public issue; avoid including exploit details or sensitive logs in public reports. Follow our [code of conduct](CODE_OF_CONDUCT.md) and [accessibility guidance](ACCESSIBILITY.md). See the [hardware test plan](docs/TEST_PLAN.md) and [GPL-3.0 license](LICENSE).
