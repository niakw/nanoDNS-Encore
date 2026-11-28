# Installation sécurisée — console firmware 13.60

**Dernière Release 0.4-13.60.4 :** TEST UTILISATEUR RÉUSSI sur firmware 13.60 pour le démarrage et le chemin DNS A observé. La trace charge 1719 règles / 0 exception depuis `nanodns4096.ini`, ouvre les deux écoutes loopback, bloque localement 15/15 requêtes A protégées observées et résout 7/7 requêtes A autorisées observées via le premier DNS amont. Extinction/veille/réveil ne sont pas démontrés par cette trace.

**Langues :** [English (default)](INSTALL.md) | Français

## Téléchargement : ZIP prêt à copier (recommandé)

**[Télécharger le ZIP d'installation](https://github.com/niakw/nanoDNS-Encore/releases/download/v0.4-13.60.4/nanodns-13.60-v0.4-13.60.4-install.zip)** · [Release GitHub et empreintes](https://github.com/niakw/nanoDNS-Encore/releases/tag/v0.4-13.60.4)

L'archive contient **exactement deux fichiers**, sans installation automatique, script ni modification de la configuration d'autoload :

```text
data/
├── pldmgr/payloads/local/nanodns/nanodns.elf
└── nanodns/nanodns4096.ini
```

Les **deux chemins définitifs** sur la console sont :

- `/data/pldmgr/payloads/local/nanodns/nanodns.elf` — notre nouveau payload indépendant.
- `/data/nanodns/nanodns4096.ini` — profil Release 1719 règles, 0 exception, Control D et AdGuard.

**Décompresse le ZIP sur ton Mac puis transfère par FTP le dossier `data/` en le fusionnant avec le `/data/` de la console.** Il faut que les fichiers se retrouvent aux chemins ci-dessus. **Ne copie pas `data/` à l'intérieur de `/data/` : cela créerait `/data/data/`.** Crée les sous-dossiers manquants si nécessaire. Le ZIP n'est **pas** un installateur autonome.

Le ZIP est assemblé depuis l'ELF et l'INI **déjà publiés dans cette Release**, contrôlés avec `SHA256SUMS`. Le workflow vérifie aussi les fichiers internes du ZIP avant publication.

## Migration depuis le nanoDNS 0.4 officiel de Drakmor

**L'ordre compte : les deux versions peuvent être stockées sur la console, mais ne doivent jamais être exécutées ni démarrées automatiquement ensemble.**

1. **Sauvegarde l'ancienne version.** Conserve l'ancien ELF provenant du catalogue, par exemple `/data/pldmgr/payloads/repo/nanodns@e8cce5d1/nanoDNS_0.4.elf`, ou copie-le sur ton Mac. Sauvegarde aussi `/data/nanodns/nanodns.ini` et `/data/nanodns/nanodns.log`. Garde le WAN bloqué par ta box/ton pare-feu externe (IPv4 et IPv6), tout en conservant les accès FTP et chargeur en LAN.
2. **Supprime ou désactive l'ancien nanoDNS dans Payload Manager.** **Option A :** une fois sauvegardé, désinstalle nanoDNS 0.4 **depuis l'interface de Payload Manager**. **Option B (recommandée pour les premiers tests) :** conserve-le sur le disque, mais **désactive son autoload**. Si un autre autoloader charge également nanoDNS, enlève ou désactive cette entrée. Ne supprime surtout pas Payload Manager ni les autres payloads.
3. **Ferme l'ancien processus.** Utilise la fonction d'arrêt normale de Payload Manager si elle est prise en charge ; sinon **éteins entièrement la console et redémarre-la** après avoir désactivé l'autoload d'origine. Ne tente ni remplacement à chaud d'un ELF actif ni arrêt forcé par `SIGKILL`. Enlever une entrée du boot auto **n'arrête pas** le processus déjà lancé.
4. **Copie les deux fichiers de notre ZIP.** Télécharge le [ZIP d'installation](https://github.com/niakw/nanoDNS-Encore/releases/download/v0.4-13.60.4/nanodns-13.60-v0.4-13.60.4-install.zip), décompresse-le puis transfère son arborescence `data/` vers la **racine `/` de la console**. Tu dois obtenir exactement `/data/pldmgr/payloads/local/nanodns/nanodns.elf` et `/data/nanodns/nanodns4096.ini`. **N'écrase pas** le dossier de l'ancien catalogue `repo/nanodns@e8cce5d1`.
5. **Actualise Payload Manager.** Recharge ou relance son interface pour qu'il détecte le nouveau payload **local `nanodns`** (slot `local/nanodns`), et non l'ancien payload **repo**. Le code actuel du manager accepte un dossier local avec un ELF même **sans `meta.json`** ; les anciennes versions doivent être vérifiées. Si le payload n'apparaît pas, utilise la fonction **Importer un payload local** avec le nouvel ELF plutôt que de créer une seconde entrée au démarrage.
6. **Remplace l'ancien boot auto par le nôtre.** Dans Payload Manager, active l'autoload **uniquement pour notre nouvelle entrée locale**. L'entrée officielle d'origine doit être **retirée de l'autoload ou clairement désactivée**, y compris dans tout autre chargeur configuré. Vérifie `local/nanodns` et non `repo/nanodns@e8cce5d1`. Deux processus nanoDNS peuvent se disputer le port UDP 53.
7. **Vérifie le DNS.** Les DNS **primaire et secondaire configurés sur la console** restent `127.0.0.1`. Dans le nouveau `nanodns.ini`, les quatre DNS sont renseignés dans `[upstream]` dans cet ordre : `76.76.2.0`, `76.76.10.0`, `94.140.14.140`, `94.140.14.141`. Consulte le nouveau `/data/nanodns/nanodns.log` : écoute active, `1719 rule(s)`, `0 exception(s)`, réponses bloquées localement et résolution de domaines autorisés si tu permets volontairement certaines connexions.
8. **Teste l'extinction et le redémarrage.** Suis le [protocole matériel](TEST_PLAN.fr.md) : extinction complète, allumage, réveil à la manette, veille/reprise et absence de chargement double. **La correction n'est pas encore démontrée sur console réelle.**

**Retour arrière :** retire/désactive l'autoload du nouveau payload, éteins normalement, rétablis l'ancien INI et l'ancien ELF (ou réactive son entrée repo sauvegardée), puis laisse **uniquement l'ancienne version** en démarrage automatique. Conserve les anciens et nouveaux logs.

## Première installation (aucun ancien nanoDNS)

Récupère le même [ZIP](https://github.com/niakw/nanoDNS-Encore/releases/download/v0.4-13.60.4/nanodns-13.60-v0.4-13.60.4-install.zip), copie les deux fichiers aux chemins exacts ci-dessus, garde les deux DNS console à `127.0.0.1`, relance Payload Manager pour retrouver l'entrée `local/nanodns` et n'active qu'un seul autoload. Maintiens le filtrage WAN en amont jusqu'aux tests autorisés.

## DNS amont Control D et AdGuard

Les domaines **autorisés** sont résolus par les quatre DNS amont sans filtrage, configuré dans le **fichier INI**, et non dans les DNS réseau de la console :

```ini
[upstream]
server=76.76.2.0
server=76.76.10.0
server=94.140.14.140
server=94.140.14.141
timeout_ms=1500
```

L'UDP entre nanoDNS et les résolveurs reste non chiffré. Le délai de 1 500 ms est individuel à chaque serveur (jusqu'à 6 secondes de délais de réponse pour les quatre tentatives). Le nouvel ELF n'écrase pas automatiquement un ancien fichier INI : le ZIP contient les deux fichiers pour éviter le mélange entre ancien et nouveau profil.

## Sécurité, limites et crédits

- nanoDNS filtre le DNS, **pas les connexions réseau en général** : IP directes, IP en cache, DNS alternatifs/chiffrés, DNS TCP, domaines inconnus et accès avant lancement nécessitent un pare-feu externe pour interdire strictement le WAN.
- Ne teste pas les blocages en ouvrant des services interdits ni en lançant une demande de mise à jour système.
- Extinction, veille et réveil à la manette restent **à valider sur le matériel 13.60**.
- Le chemin de l'ancien slot donné en exemple provient d'une installation précise : le suffixe du dossier peut varier d'une console à l'autre.
- **Crédits et licence :** [Drakmor](https://github.com/drakmor/nanoDNS), GPL-3.0 ; [blocklist communautaire](https://github.com/niakw/nanodns-console-blocklist) ; [nanoDNS 13.60 indépendant](https://github.com/niakw/nanoDNS-Encore).

Voir [sécurité](../SECURITY.fr.md), [politique DNS](DNS_POLICY.fr.md), [tests](TEST_PLAN.fr.md).
