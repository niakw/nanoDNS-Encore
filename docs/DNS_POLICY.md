# DNS policy architecture — firmware 13.60

**Language:** English (default) | [Français](DNS_POLICY.fr.md)

## Release policy

0.4-13.60.4 ships [`nanodns4096.ini`](../nanodns4096.ini) and compiles the same **1719 mandatory masks** into the ELF. The set includes the historical 124-rule canonical core and a broader multi-platform publisher inventory. It is a best-effort DNS inventory, not proof of exhaustive service coverage.

Runtime policy storage is bounded to **4,096 overrides + 4,096 exceptions**, with a 4 MiB INI ceiling. Mandatory compiled masks are evaluated before user exceptions.

## Selection and fallback

The runtime selects `/data/nanodns/nanodns4096.ini` first. It uses legacy `/data/nanodns/nanodns.ini` only when the preferred file does not exist. The two files are **never merged, rewritten into one another or jointly managed**.

If neither exists, the preferred profile is created from the compiled default. If the selected file exists but is invalid or unsafe, compiled mandatory defaults are used and the legacy file is not consulted.

## Query handling

1. Parse and validate the DNS question.
2. Match the 1719 mandatory masks. Protected A questions receive `0.0.0.0`; protected AAAA/other supported types receive no matching address record.
3. Apply additional selected-INI rules and exceptions only after mandatory policy.
4. Forward permitted queries through the ordered Control D/AdGuard UDP upstreams.
5. Validate response identity and reject protected aliases before relaying a reply.

Once a mandatory override is selected, that request never enters the upstream path. This is a local DNS-policy property, not a firewall guarantee.

## Hardware evidence — 28 November 2026

The .4 user trace shows the preferred profile selected, **1719 rules / 0 exceptions**, both loopback listeners, **15/15 observed protected A queries answered locally**, and **7/7 observed permitted A queries resolved through the first upstream**. No runtime error is visible in the supplied trace.

The trace does not establish AAAA behavior on hardware, later-upstream failover, system-wide absence of DNS bypass, shutdown/rest/wake or long-term stability. See [validation plan](TEST_PLAN.md) and [security boundary](../SECURITY.md).
