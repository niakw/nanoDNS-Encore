# Security model and disclosure


**Language:** English (default) | [Français](SECURITY.fr.md)
## What this fork protects

The 0.4-13.60.4 built-in denylist contains **1719 mandatory masks**, including the 124-rule canonical core from [nanoDNS Console Blocklist](https://github.com/niakw/nanodns-console-blocklist). Matching queries handled by this **running** UDP DNS payload are answered locally, before configured exceptions are considered. AAAA and other types are answered without the matching IPv4 address; unsupported multi-question / non-IN requests are not relayed.

The payload additionally validates upstream reply identity, blocks protected alias names in answer sections, avoids forcible termination of old payload processes and refuses to start when the required IPv4 listener cannot bind.

## DNS upstream trust

The bundled policy uses Control D (unfiltered), then AdGuard DNS (non-filtering), in order `76.76.2.0`, `76.76.10.0`, `94.140.14.140`, `94.140.14.141`. These profiles do not add malware/ad filtering; local mandatory rules remain unchanged. UDP DNS is unencrypted. Existing user INIs must be explicitly replaced to adopt the new defaults. DNS-only filtering is not a firewall.

## What it does not protect

**DNS filtering is not a firewall or an absolute firmware-update prevention mechanism.** The following remain outside its scope:

- Cold boot or shutdown intervals before the payload starts, and failed jailbreak starts.
- Direct IPv4/IPv6 connections, cached addresses, direct package installation from local storage.
- Alternate resolvers, DNS-over-HTTPS / DNS-over-TLS, DNS-over-TCP and app-specific network stacks.
- New or hidden service domains not matching the 1719-rule best-effort inventory; service traffic on unrelated CDN names.
- Hardware controller wake, suspend/resume of the OS, full kernel-lifecycle or network stack correctness.

If you need *no unfiltered outbound traffic*, enforce WAN-deny rules on your **router/firewall**, including IPv6, even when the console is off or being jailbroken. Keep the locally hosted jailbreak path available.

## Risks and trust boundary

- Rules such as `<hostname-or-mask-from-INI>`, `<hostname-or-mask-from-INI>`, `<hostname-or-mask-from-INI>` are intentionally broad and can block innocent names. `<hostname-or-mask-from-INI>` is a shared-CDN alias and may affect unrelated services.
- `bind=0.0.0.0` / `bind6=::` makes the resolver available on LAN; default loopback listeners are safer.
- A manually edited selected INI may contain extra forwarders, exceptions or overrides. The embedded 1719 mandatory masks cannot be overridden by exceptions but extra rules can still cause false positives.
- UDP upstream DNS is not encrypted or DNSSEC-validated. Response question/ID validation is useful defense-in-depth, not authentication.
- DNS logs can contain domain names, network addresses and timestamps. Review and redact before sharing.
- A successful SDK build is not proof of safe shutdown on console 13.60. Observe [test plan](docs/TEST_PLAN.md).


## Runtime configuration hardening in 0.4-13.60.4

The release uses bounded dynamic heap storage for **4,096 overrides + 4,096 exceptions**, with a **4 MiB** INI ceiling. The 1719 mandatory masks are compiled into the ELF. `nanodns4096.ini` is preferred; legacy `nanodns.ini` is used only when the preferred file is absent and the two are never merged.

Default-file creation uses exclusive `open(O_CREAT | O_EXCL | O_NOFOLLOW, 0600)`. Reads use `O_NOFOLLOW` plus regular-file validation. Unsafe selected profiles fall back to compiled policy.

The 28 November .4 trace validates startup, selected-profile loading, protected local A replies and permitted A resolution. It does not validate shutdown/rest/wake or system-wide no-leak behavior.

## Reports

Report reproducible vulnerabilities with firmware, payload SHA, config (without identifying network information), last relevant log lines, expected versus actual DNS output, and whether you can reproduce without nanoDNS. Do not publicly upload unredacted console or DNS logs.

## Provenance

Original payload: [Drakmor/nanoDNS](https://github.com/drakmor/nanoDNS).
Denylist: [niakw/nanodns-console-blocklist](https://github.com/niakw/nanodns-console-blocklist), including [original source credits](https://github.com/niakw/nanodns-console-blocklist/blob/main/docs/SOURCES.md).
License: [GPL-3.0](LICENSE).
