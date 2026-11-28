# nanoDNS 13.60 — v0.4-13.60.4

**Standard GitHub Release · firmware 13.60 targeted · 28 November 2026**

## What changes

0.4-13.60.4 promotes the extended policy/runtime work from development candidate to release:

- **1719 mandatory DNS masks**, including the historical 124-rule canonical core.
- Bounded dynamic storage for **4,096 overrides + 4,096 exceptions**, with a 4 MiB INI ceiling.
- Preferred profile: `/data/nanodns/nanodns4096.ini`.
- Compatibility fallback: legacy `/data/nanodns/nanodns.ini` only when the preferred file is absent. The runtime never merges or double-manages the two profiles.
- Ordered Control D unfiltered then AdGuard DNS non-filtering upstreams: `76.76.2.0`, `76.76.10.0`, `94.140.14.140`, `94.140.14.141`, 1500 ms per resolver.
- Bounded listener shutdown waits, nonblocking UDP sockets and reduced startup log volume without changing DNS policy.
- Existing file creation/read hardening remains: `O_CREAT | O_EXCL | O_NOFOLLOW` for safe creation, no-symlink descriptor reads and compiled-policy fallback.

## Firmware 13.60 user-test evidence — 28 November 2026

**0.4-13.60.4 DNS PATH: USER-TESTED.** The supplied runtime trace identifies `NanoDNS v0.4-13.60.4-dev`, the development build used to qualify this release behavior, and shows:

- `/data/nanodns/nanodns4096.ini` selected.
- **1719 rules / 0 exceptions / 4 upstreams**, timeout 1500 ms.
- IPv4 and IPv6 loopback listeners active.
- **15/15 observed protected A queries** answered locally with `0.0.0.0`.
- **7/7 observed permitted A queries** returned successful answers through the first configured upstream.
- No runtime error visible in the provided trace.

**Validation boundary:** the submitted .4 log contains no terminal shutdown sequence. It does not establish .4 shutdown completion, controller wake, rest/resume, AAAA, later-upstream failover, repeated power cycles, endurance or packet-capture proof of system-wide no-leak behavior. Earlier 0.4-13.60.2 has a separate user-reported successful normal shutdown and subsequent power-on. The historical 0.4-13.60.1 logs recorded **23 blocked A queries**. Other firmware and the secondary/older-generation build remain **NOT USER-VALIDATED**.

## Download and install

Download **`nanodns-13.60-v0.4-13.60.4-install.zip`**. It contains exactly:

```text
data/pldmgr/payloads/local/nanodns/nanodns.elf
data/nanodns/nanodns4096.ini
```

Copy its `data/` tree to the console filesystem root `/`, producing:

```text
/data/pldmgr/payloads/local/nanodns/nanodns.elf
/data/nanodns/nanodns4096.ini
```

Back up the previous ELF and both possible INI names first. Stop/disable the old instance and keep exactly one `local/nanodns` autoload entry. Both console DNS fields remain `127.0.0.1`. The four external resolver addresses belong only in nanoDNS upstream configuration.

Separate release assets contain `nanodns.elf`, `nanodns-ps4.elf`, `nanodns4096.ini`, `SHA256SUMS`, the installation ZIP and its SHA-256 file.

## Security boundary

nanoDNS filters DNS queries only while its UDP listeners are running. It is **not a firewall** and does not cover direct-IP traffic, cached addresses, alternate/encrypted DNS, TCP DNS or pre-payload traffic. Use independent router/firewall restrictions for strict WAN isolation.

Original work and GPL-3.0: [Drakmor/nanoDNS](https://github.com/drakmor/nanoDNS). Canonical core policy: [niakw/nanodns-console-blocklist](https://github.com/niakw/nanodns-console-blocklist).

---

## Français — notes de version

**Release GitHub standard 0.4-13.60.4 · firmware 13.60 · 28 novembre 2026**

Cette version publie le profil étendu : **1719 règles DNS obligatoires**, dont le noyau canonique historique de 124 règles, stockage dynamique borné à **4 096 overrides + 4 096 exceptions**, INI limité à 4 Mio, et priorité à `/data/nanodns/nanodns4096.ini`. L'ancien `nanodns.ini` sert uniquement de repli s'il n'existe pas de profil prioritaire ; aucun mélange ni double gestion.

**TEST UTILISATEUR DU CHEMIN DNS .4 RÉUSSI sur firmware 13.60.** La trace fournie charge 1719 règles / 0 exception / 4 DNS amont, ouvre les deux écoutes loopback, répond localement à **15/15 requêtes A protégées observées** et résout **7/7 requêtes A autorisées observées** via le premier DNS amont. Aucune erreur runtime n'est visible.

**Limite :** cette trace .4 ne contient pas de séquence finale d'extinction. Extinction .4, veille/reprise, réveil à la manette, AAAA, secours vers les DNS suivants, cycles répétés et endurance restent à vérifier. L'ancienne 0.4-13.60.2 possède séparément un essai utilisateur positif d'**extinction normale et rallumage**. Les anciens logs 0.4-13.60.1 comptaient 23 requêtes A bloquées.

Le ZIP `nanodns-13.60-v0.4-13.60.4-install.zip` contient exactement `data/pldmgr/payloads/local/nanodns/nanodns.elf` et `data/nanodns/nanodns4096.ini`. Après sauvegarde, copier l'arborescence `data/` à la racine `/`, activer seulement `local/nanodns` et conserver les deux DNS console à `127.0.0.1`.

Les autres firmwares et le binaire secondaire restent **NON VALIDÉS PAR TEST UTILISATEUR**. nanoDNS n'est pas un pare-feu.
