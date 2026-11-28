# Sécurité, périmètre et signalement

**Langues :** [English (default)](SECURITY.md) | Français

## Ce que protège le fork

La liste obligatoire 0.4-13.60.4 contient **1719 motifs**, dont le noyau canonique de 124 règles issu de [nanoDNS Console Blocklist](https://github.com/niakw/nanodns-console-blocklist). Les requêtes UDP DNS reçues par le payload **en cours d'exécution** sont vérifiées **avant** les exceptions utilisateur. Un nom bloqué reçoit `0.0.0.0` pour une question A et aucune adresse pour AAAA ou d'autres types. Les questions multiples ou non prises en charge ne sont pas retransmises telles quelles.

Le programme vérifie également les réponses des résolveurs amont, refuse certains alias associés à des noms interdits, n'élimine plus les instances précédentes par `SIGKILL` et refuse un démarrage partiel sans écoute IPv4.

## Confiance dans les DNS amont

La configuration distribuée utilise Control D sans filtrage, puis AdGuard DNS sans filtrage, dans l'ordre `76.76.2.0`, `76.76.10.0`, `94.140.14.140`, `94.140.14.141`. Aucun filtrage antimalware/publicitaire supplémentaire ; les règles locales restent inchangées. DNS UDP non chiffré. Les anciens INI doivent être remplacés explicitement. Le filtrage DNS ne constitue pas un pare-feu.

## Ce que cette protection ne couvre pas

**Un filtrage DNS n'est pas un pare-feu et ne peut pas garantir l'absence de mise à jour du firmware.**

- Les communications avant le lancement du jailbreak et de nanoDNS, notamment après un démarrage à froid ou un échec du chargement.
- Les connexions directes en IPv4/IPv6, les adresses mises en cache et les packages déjà présents sur le stockage.
- Les serveurs DNS alternatifs, DNS-over-HTTPS/TLS, DNS sur TCP et les piles réseau propres à certaines applications.
- Les nouveaux noms de services inconnus de la liste, ou les domaines de CDN non spécifiques à une marque.
- La gestion matérielle du bouton PS, la veille/reprise système et la stabilité globale du noyau.

Si **aucun trafic non filtré** n'est acceptable, interdis l'accès WAN depuis le routeur/pare-feu pour IPv4 **et** IPv6, indépendamment de l'état du jailbreak.

## Risques et paramètres

Les masques très larges (`<hostname-or-mask-from-INI>`, `<hostname-or-mask-from-INI>`, `<hostname-or-mask-from-INI>`) peuvent bloquer des domaines sans rapport. Le nom `<hostname-or-mask-from-INI>` correspond à une infrastructure mutualisée. Les configurations `bind=0.0.0.0` et `bind6=::` rendent le résolveur accessible sur le réseau local ; privilégie les valeurs loopback par défaut.

Les fichiers INI peuvent encore ajouter des règles, mais ne doivent pas pouvoir autoriser un nom protégé par la liste obligatoire. Le DNS amont utilise UDP sans chiffrement ni validation DNSSEC ; la vérification des réponses n'en fait pas un canal authentifié. Les logs contiennent potentiellement des domaines et des informations réseau identifiantes.

Un **build vert** ne confirme pas la résolution des problèmes d'extinction de la console 13.60. Voir le [protocole de tests](docs/TEST_PLAN.fr.md).


## Durcissement de la configuration dans 0.4-13.60.4

La Release utilise un stockage dynamique borné à **4 096 overrides + 4 096 exceptions**, avec un INI limité à **4 Mio**. Les 1719 règles obligatoires sont compilées dans l'ELF. `nanodns4096.ini` est prioritaire ; l'ancien `nanodns.ini` sert uniquement de repli et les deux ne sont jamais fusionnés.

La création utilise `open(O_CREAT | O_EXCL | O_NOFOLLOW, 0600)`. La lecture utilise `O_NOFOLLOW` et valide un fichier ordinaire. Un profil sélectionné dangereux déclenche la politique compilée.

La trace .4 du 28 novembre valide démarrage, chargement du profil, réponses A protégées locales et résolutions A autorisées. Elle ne valide pas extinction/veille/réveil ni l'absence globale de fuite.

## Signaler un problème

Indiquer le firmware, l'empreinte SHA du payload, la configuration (anonymisée), les dernières lignes utiles du journal, le comportement attendu/observé et le résultat du même essai sans nanoDNS. Ne pas publier de logs non anonymisés.

**Crédits :** [nanoDNS par Drakmor](https://github.com/drakmor/nanoDNS), [niakw/nanodns-console-blocklist](https://github.com/niakw/nanodns-console-blocklist) et sa [bibliographie de sources](https://github.com/niakw/nanodns-console-blocklist/blob/main/docs/SOURCES.md). Licence [GPL-3.0](LICENSE).
