# nanoDNS 13.60 — v0.4-13.60.3

**Standard GitHub Release · firmware 13.60 targeted · 24 November 2026**

## DNS migration

Quad9 stopped serving users in France on 24 November 2026 ([announcement](https://quad9.net/news/blog/au-revoir-france/)). The new default profile, embedded fallback and distributed INI use these exact upstreams in order:

```ini
[upstream]
server=76.76.2.0
server=76.76.10.0
server=94.140.14.140
server=94.140.14.141
timeout_ms=1500
```

Control D unfiltered (first two), AdGuard DNS non-filtering (last two). Each resolver gets a separate 1500 ms response window; SERVFAIL/REFUSED trigger the next upstream. NXDOMAIN/NODATA remain valid responses. No additional malware/ad filtering is provided; the 124 mandatory local rules and 0 default exceptions remain unchanged. UDP DNS remains unencrypted. **0.4-13.60.3 is NOT YET USER-TESTED**. The historical tests below are for previous binaries only.

[Control D documentation](https://docs.controld.com/docs/free-dns) · [AdGuard documentation](https://adguard-dns.io/en/public-dns.html).

## Why this update?

This patch release rebuilds the actual ELF binaries after security and CI updates on `main`, instead of silently overwriting the earlier user-tested 0.4-13.60.1 Release.

- **CodeQL #2 (high / TOCTOU):** replace separate file-existence check + `fopen("w")` with atomic `open(O_CREAT | O_EXCL | O_NOFOLLOW, 0600)`, followed by descriptor-based writing. Existing `nanodns.ini` is never truncated during default creation.
- **Configuration reading:** open the INI using `O_NOFOLLOW`, validate it is a regular file with `fstat()`, and apply compiled mandatory fallback rules if it cannot be safely loaded.
- **CodeQL #1 (medium / workflow permissions):** specify read-only contents permissions for the normal build workflows, and avoid competing tag publication from these jobs.
- **Build pipeline:** Dependabot updates merged for `actions/checkout@v7`, `actions/upload-artifact@v7`, and `actions/download-artifact@v8`. Valid weekly GitHub Actions dependency monitoring.
- Updated bilingual community documentation, contribution/accessibility/conduct policies, and regression tests for atomic config creation.

**Release integrity:** the current-generation and secondary ELF binaries, policy file, ZIP and SHA-256 manifests are produced from the same GitHub Actions run after offline policy tests and both console SDK builds succeed. The existing 0.4-13.60.1 user-tested Release remains unchanged.

## Verified hardware status (version-specific)

**0.4-13.60.1 (prior release):** **USER-TESTED** on console firmware 13.60. The tester reported normal startup and shutdown/power-on without recurrence of the previous issue. Two runtime logs documented **23 blocked A queries**, 124 loaded rules, 0 exceptions, and IPv4/IPv6 DNS listeners. A `shutdown: complete` line was not observed; the power-off result is based on the tester's report.

**0.4-13.60.2 (previous release): USER-TESTED ON FIRMWARE 13.60 — startup, configuration loading and protected A-query DNS blocking PASSED.** The tester's runtime log confirms `NanoDNS v0.4-13.60.2` (built Nov 19 2026 15:34:13), 124 rules, 0 exceptions, 2 Quad9 upstream addresses configured, active loopback IPv4 and IPv6 listeners, and **5/5 observed A queries locally answered `0.0.0.0`**. No errors appear in the excerpt. **A follow-up user test also confirms that normal shutdown and subsequent power-on with 0.4-13.60.2 succeeded without recurrence of the original issue.** This shutdown/power-on outcome is a **user report**, not a terminal `shutdown: complete` marker in the DNS log. **Rest/resume, explicit controller-only wake, AAAA, permitted upstream DNS, repeated cycles and long-term stability remain unverified**. The earlier 0.4-13.60.1 build has its own separate positive shutdown trial.

**User-test outcome scope:** 0.4-13.60.2 has now passed the specific startup, mandatory DNS filtering and normal shutdown/power-on checks carried out by its tester. Further unperformed tests remain documented below; no additional hardware compatibility is implied.

**Other current-generation firmware: NOT USER-VALIDATED. Secondary/older-generation build: NOT USER-VALIDATED on any firmware.** Successful compilation does not establish compatibility.

## Download and install (recommended)

Download **`nanodns-13.60-v0.4-13.60.3-install.zip`**. It contains exactly two paths:

```text
data/pldmgr/payloads/local/nanodns/nanodns.elf
data/nanodns/nanodns.ini
```

Extract the ZIP on your computer, then FTP-copy its `data/` tree to the console filesystem root `/`, so the final paths are `/data/pldmgr/payloads/local/nanodns/nanodns.elf` and `/data/nanodns/nanodns.ini`. Never create `/data/data/`.

**Upgrade:** back up the old ELF and INI first. In Payload Manager, remove the old catalog nanoDNS 0.4 **or disable its entry**, stop it normally (or power off fully and reboot with its autoload disabled), and **remove the original entry from automatic startup**. Refresh the manager after copying files and activate only the new local `local/nanodns` entry in autoload. Do not launch two instances. Console primary **and** secondary DNS settings remain `127.0.0.1`; Control D/AdGuard `76.76.2.0`, `76.76.10.0`, `94.140.14.140`, `94.140.14.141` are INI upstreams only.

**Migrating from 0.4-13.60.1 or 0.4-13.60.2:** the destination `local/nanodns` is unchanged. Back up its current ELF and INI and ensure it is no longer running before overwriting them with this new build. Perform a full restart with only one nanoDNS autoload entry. Keep the old ZIP for rollback.

**Separate assets:** `nanodns.elf`, `nanodns-ps4.elf`, `nanodns.ini`, `SHA256SUMS`, and `nanodns-13.60-v0.4-13.60.3-install.zip.sha256` are also published. The SHA-256 files cover their respective distributions.

[English installation guide](https://github.com/niakw/nanoDNS-Encore/blob/main/docs/INSTALL.md) · [Guide français](https://github.com/niakw/nanoDNS-Encore/blob/main/docs/INSTALL.fr.md) · [Detailed test status](https://github.com/niakw/nanoDNS-Encore/blob/main/docs/TEST_PLAN.md).

## Security boundary

nanoDNS only filters DNS queries received while its UDP listeners are running. It is **not a firewall** and cannot prevent direct-IP traffic, alternate or encrypted DNS, cached addresses, or pre-payload communication. Keep independent router/firewall WAN restrictions (IPv4 and IPv6) for strict network isolation. A green build is not proof of safe shutdown on an untested firmware.

Original work and GPL-3.0: [Drakmor/nanoDNS](https://github.com/drakmor/nanoDNS). 124-mask policy: [niakw/nanodns-console-blocklist](https://github.com/niakw/nanodns-console-blocklist).

---

## Français — notes de version

**Release standard 0.4-13.60.3, firmware 13.60 : migration DNS, test utilisateur de ce nouveau binaire à effectuer.**

Quad9 a cessé son service en France le 24 novembre 2026. Les quatre DNS amont, dans l'ordre, sont `76.76.2.0`, `76.76.10.0`, `94.140.14.140`, `94.140.14.141` (Control D sans filtrage, puis AdGuard sans filtrage). Délai de 1 500 ms par serveur, secours sur timeout ou SERVFAIL/REFUSED. Les 124 règles et zéro exception restent inchangés. Le filtrage antimalware supplémentaire de Quad9 n'est pas remplacé par ces profils. Les résultats de tests suivants concernent les versions précédentes.

Ce correctif reconstruit le véritable ELF après le traitement des deux alertes CodeQL (création atomique de l'INI sans écrasement et droits minimaux des workflows) et la fusion des trois PR Dependabot (checkout v7, upload-artifact v7, download-artifact v8). Les documents d'accessibilité, contribution, conduite et issues ont été adaptés en français et en anglais.

**Version 0.4-13.60.1 précédente : test utilisateur positif sur firmware 13.60** pour le démarrage, le filtrage DNS de type A, l'extinction et le rallumage, sans répétition du problème initial. Les deux logs comptent 23 requêtes A bloquées, 124 règles et 0 exception.

**Version 0.4-13.60.2 (Release précédente) : TEST UTILISATEUR RÉUSSI SUR FIRMWARE 13.60 pour le démarrage, le chargement des règles et 5/5 requêtes DNS A bloquées.** Journal `NanoDNS v0.4-13.60.2` du 19 novembre 2026 : 2 adresses Quad9 configurées, 124 règles, 0 exception, deux écoutes IPv4/IPv6 et réponses `0.0.0.0` pour les cinq requêtes observées, sans erreur visible. **Le testeur a également confirmé une extinction normale et un rallumage réussis avec 0.4-13.60.2, sans réapparition de l'anomalie initiale.** Ce résultat repose sur son retour, et non sur une trace `shutdown: complete`. **Veille/reprise, réveil spécifique par la manette, AAAA, résolution autorisée vers Quad9, répétitions et endurance** restent non démontrés sur ce nouvel ELF. Le binaire de génération précédente et les autres firmwares de génération actuelle restent non validés par des essais utilisateurs.

Le ZIP `nanodns-13.60-v0.4-13.60.3-install.zip` contient exactement `data/pldmgr/payloads/local/nanodns/nanodns.elf` et `data/nanodns/nanodns.ini`. Après sauvegarde, décompresser sur Mac puis copier `data/` à la racine `/` de la console. Dans Payload Manager, enlever ou désactiver l'ancien nanoDNS et **retirer son ancien autoload** ; fermer l'ancienne instance ou redémarrer complètement, puis activer **seulement `local/nanodns`** en démarrage automatique. Conserver le dernier ELF en sauvegarde pour retour arrière.

Les deux DNS console restent `127.0.0.1`. Control D et AdGuard se configurent dans l'INI uniquement. nanoDNS ne remplace pas un pare-feu : garder le blocage WAN indépendant si nécessaire.

[Installation en français](https://github.com/niakw/nanoDNS-Encore/blob/main/docs/INSTALL.fr.md) · [Protocole de tests](https://github.com/niakw/nanoDNS-Encore/blob/main/docs/TEST_PLAN.fr.md).
