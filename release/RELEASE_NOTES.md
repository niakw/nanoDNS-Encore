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

## Boot and resident lifecycle hardening

0.4-13.60.4 also contains a substantial startup/shutdown hardening pass that is independent from the 1719-rule expansion:

- **Single-resident admission before side effects:** nanoDNS acquires a kernel-owned, nonblocking record lock at `/data/nanodns/resident.lock` **before** config creation/selection, log rotation or SceNet initialization. A duplicate launch is refused instead of allowing two residents to partially initialize.
- **No PID guessing or forced replacement:** the lock is released automatically by the kernel when the process exits; no stale PID-file logic, process-structure guessing or `SIGKILL` replacement is used.
- **Earlier and safer cancellation:** `SIGINT`/`SIGTERM` handlers are installed with `sigaction()` before resident admission. Startup rechecks the stop condition before privilege/network initialization, listener creation and startup notification.
- **Nonblocking DNS sockets:** local IPv4/IPv6 listeners and upstream UDP sockets are nonblocking. Upstream reply waits are split into at most **100 ms** polling slices so shutdown is observed promptly instead of waiting for a full resolver timeout.
- **Bounded listener shutdown:** listener waits are bounded and stop-aware, reducing the risk of a resident blocking console shutdown while waiting on UDP activity.
- **Distinct resident identity:** the current-generation console resident thread requests the label `nanodns-encore` and logs the label syscall result and PID, while the installation path and payload filename remain unchanged for Payload Manager compatibility.
- **Reduced synchronous boot logging:** normal startup records the selected profile and rule count instead of synchronously dumping the full rule inventory.
- **Strict profile selection:** `nanodns4096.ini` is preferred; legacy `nanodns.ini` is consulted only when the preferred path is absent. The two profiles are never merged or double-managed.
- **Fail-closed deny path:** once a mandatory override matches, the request can never fall through to an upstream resolver, even if construction of the local blocked response fails.
- **DNS wire hardening:** malformed/ambiguous names are rejected and protected alias checks cover Answer, Authority and Additional response sections.

These changes reduce risky work during boot and improve deterministic cleanup, but they are not a claim of a firmware-level power-management fix. Hardware shutdown/controller-wake/rest behavior remains version-specific and must be validated separately.

## Additional 0.4-13.60.3 hardware field report

Community issue **#4** provides unusually complete firmware 13.60 evidence for the previous 0.4-13.60.3 release: cold start after full power-off, controller power-on, single-instance startup, A and AAAA protected-name blocking, permitted Control D resolution, and rest/resume all passed. The tester recorded **273 responses, all NOERROR**, with no timeout or SERVFAIL. After resume, one stale-upstream drain triggered a reconnect and the same query then resolved immediately, with later queries normal.

The report does **not** test AdGuard failover or forced timeout/SERVFAIL/REFUSED behavior. It is kept as a public hardware-reference report rather than treated as an unresolved defect.

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

### Renforcement du boot et du cycle de vie résident

0.4-13.60.4 ne se limite pas au passage à 1719 règles. Le démarrage et l'arrêt du résident ont aussi été fortement durcis :

- **Admission d'une seule instance avant tout effet de bord :** verrou noyau non bloquant `/data/nanodns/resident.lock` acquis avant création/sélection de l'INI, rotation des logs ou initialisation SceNet. Un double lancement est refusé avant initialisation partielle.
- **Aucun PID supposé ni remplacement forcé :** le noyau libère le verrou à la fin du processus ; pas de fichier PID périmé, de scan de structures internes ni de `SIGKILL`.
- **Arrêt pris en compte plus tôt :** gestion `SIGINT`/`SIGTERM` via `sigaction()` avant l'admission, avec contrôles d'annulation avant les étapes privilèges/réseau/listeners/notification.
- **Sockets DNS non bloquantes :** listeners IPv4/IPv6 et sockets UDP amont non bloquants ; attente amont découpée en tranches de **100 ms maximum** pour réagir rapidement à l'arrêt.
- **Attentes listeners bornées** afin de réduire le risque de bloquer l'extinction de la console sur une attente UDP.
- **Identité résidente distincte :** nom de thread `nanodns-encore`, retour syscall et PID journalisés, tout en conservant le chemin/fichier attendu par Payload Manager.
- **Boot moins verbeux :** journalisation du profil choisi et du nombre de règles, sans dump synchrone de tout l'inventaire.
- **Sélection stricte du profil :** `nanodns4096.ini` prioritaire, ancien `nanodns.ini` uniquement s'il est absent ; aucun mélange ni double gestion.
- **Blocage fail-closed :** une requête reconnue comme interdite ne peut jamais repartir vers un DNS amont, même si la construction de la réponse locale échoue.
- **Durcissement du parsing DNS :** refus des noms ambigus/mal formés et contrôle des alias protégés dans Answer, Authority et Additional.

Ces changements réduisent le travail risqué au boot et rendent le nettoyage plus déterministe. Ils ne constituent pas pour autant une prétention de correctif système d'alimentation ; extinction, réveil manette et veille/reprise restent à qualifier par version.

### Retour matériel communautaire 0.4-13.60.3

L'issue **#4** apporte une preuve terrain particulièrement complète sur firmware 13.60 pour la version précédente : démarrage à froid, allumage par la manette, instance unique, blocage A/AAAA, résolutions autorisées via Control D et veille/reprise réussis. Le testeur rapporte **273 réponses, toutes NOERROR**, sans timeout ni SERVFAIL. Après reprise, un drain amont périmé provoque une reconnexion puis la requête aboutit immédiatement ; la suite reste normale.

Le failover AdGuard et les cas forcés timeout/SERVFAIL/REFUSED ne sont pas testés. L'issue peut donc rester ouverte comme **rapport matériel de référence**, pas comme anomalie non résolue.



**Release GitHub standard 0.4-13.60.4 · firmware 13.60 · 28 novembre 2026**

Cette version publie le profil étendu : **1719 règles DNS obligatoires**, dont le noyau canonique historique de 124 règles, stockage dynamique borné à **4 096 overrides + 4 096 exceptions**, INI limité à 4 Mio, et priorité à `/data/nanodns/nanodns4096.ini`. L'ancien `nanodns.ini` sert uniquement de repli s'il n'existe pas de profil prioritaire ; aucun mélange ni double gestion.

**TEST UTILISATEUR DU CHEMIN DNS .4 RÉUSSI sur firmware 13.60.** La trace fournie charge 1719 règles / 0 exception / 4 DNS amont, ouvre les deux écoutes loopback, répond localement à **15/15 requêtes A protégées observées** et résout **7/7 requêtes A autorisées observées** via le premier DNS amont. Aucune erreur runtime n'est visible.

**Limite :** cette trace .4 ne contient pas de séquence finale d'extinction. Extinction .4, veille/reprise, réveil à la manette, AAAA, secours vers les DNS suivants, cycles répétés et endurance restent à vérifier. L'ancienne 0.4-13.60.2 possède séparément un essai utilisateur positif d'**extinction normale et rallumage**. Les anciens logs 0.4-13.60.1 comptaient 23 requêtes A bloquées.

Le ZIP `nanodns-13.60-v0.4-13.60.4-install.zip` contient exactement `data/pldmgr/payloads/local/nanodns/nanodns.elf` et `data/nanodns/nanodns4096.ini`. Après sauvegarde, copier l'arborescence `data/` à la racine `/`, activer seulement `local/nanodns` et conserver les deux DNS console à `127.0.0.1`.

Les autres firmwares et le binaire secondaire restent **NON VALIDÉS PAR TEST UTILISATEUR**. nanoDNS n'est pas un pare-feu.
