# Politique DNS, ordre des règles et protections

**Langues :** [English (default)](DNS_POLICY.md) | Français

## Origine

Le profil [`nanodns.ini`](../nanodns.ini) provient de [niakw/nanodns-console-blocklist](https://github.com/niakw/nanodns-console-blocklist), version v3 du 10 octobre 2026. Le moteur DNS original est réalisé par [Drakmor](https://github.com/drakmor/nanoDNS) et distribué sous licence GPL-3.0.

Le fork intègre des copies vérifiées automatiquement : `nanodns.ini`, `nanodns.ini.example`, la liste `k_protected_masks` compilée en C et la configuration initiale générée. **Aucun téléchargement ni remplacement automatique de règles depuis Internet au démarrage.**

## Ordre des vérifications

1. Lire une question DNS standard, unique, de classe IN. Refuser les requêtes multiples et les opcodes non pris en charge au lieu de les retransmettre sans contrôle.
2. Vérifier **d'abord les 124 motifs de blocage obligatoires compilés**. Pour un nom protégé, répondre localement en `0.0.0.0` (type A), ou sans enregistrement correspondant (AAAA/autres types). Ne pas consulter de résolveur externe.
3. Pour les seuls noms non protégés, appliquer les exceptions et les règles supplémentaires du fichier INI si elles existent.
4. Retransmettre les questions autorisées aux DNS amont, et vérifier que la réponse correspond à l'identifiant, au nom, au type et à la classe de la question.
5. Refuser les réponses dont la section des réponses contient un domaine protégé comme propriétaire ou cible d'un enregistrement de type CNAME, DNAME, NS, PTR, MX, SRV, SVCB ou HTTPS.

Une réponse malformée est refusée plutôt que retransmise. Cela ne constitue pas un pare-feu réseau.

## Configuration de référence

- **124 règles ; aucune exception**.
- Blocage de noms connus platform vendor/platform services, additional console networks, additional console networks, publisher services, publisher services, publisher services, publisher services, publisher services, publisher services, publisher services, etc.
- **DNS amont dans l'ordre :** Control D sans filtrage, puis AdGuard DNS sans filtrage, dans l'ordre `76.76.2.0`, `76.76.10.0`, `94.140.14.140`, `94.140.14.141`. Aucun filtrage antimalware/publicitaire supplémentaire ; les règles locales restent inchangées. DNS UDP non chiffré. Quad9 a quitté la France le 24 novembre 2026 ([annonce](https://quad9.net/fr/news/blog/au-revoir-france/)). Le délai s'applique par serveur ; SERVFAIL et REFUSED déclenchent le secours suivant.
- Écoutes locales : `127.0.0.1:53` et `[::1]:53`.
- Les noms non interdits, comme `github.com`, peuvent continuer à être résolus.

## Anciennes installations

Le payload ne réécrit **jamais automatiquement** `/data/nanodns/nanodns.ini` s'il existe déjà. Sauvegarder l'ancien fichier puis transférer le nouveau profil pour disposer de 124 règles et de zéro exception dans le fichier actif. Une ancienne exception platform vendor ne peut cependant pas neutraliser un motif obligatoire déjà compilé.

Les règles personnalisées supplémentaires peuvent toujours entraîner des faux positifs.

## Limites

Les communications précédant le chargement, les IP directes, caches DNS, DNS alternatifs ou chiffrés, DNS sur TCP et noms inconnus sont hors du périmètre. Pour une interdiction WAN stricte, maintenir un pare-feu externe en IPv4 et IPv6.

Les motifs étendus `<hostname-or-mask-from-INI>`, `<hostname-or-mask-from-INI>` ou l'alias partagé `<hostname-or-mask-from-INI>` peuvent bloquer des domaines légitimes. Voir [sécurité](../SECURITY.fr.md) et [tests](TEST_PLAN.fr.md).

Le candidat de développement 0.4-13.60.4 utilise les 1719 règles étendues comme politique obligatoire embarquée et configuration générée par défaut. Le ZIP candidat installe ce profil sous son propre nom. Les fichiers des versions publiées restent inchangés. Les configurations existantes ne sont pas écrasées automatiquement ; les masques embarqués restent actifs. Qualification matérielle en attente.

Les candidats de développement sélectionnent `/data/nanodns/nanodns4096.ini` en priorité, ou `/data/nanodns/nanodns.ini` uniquement si le premier chemin est absent. Si les deux sont absents, créer le fichier prioritaire. Aucun mélange ni réécriture des deux profils. Un fichier sélectionné invalide déclenche les valeurs embarquées avec un journal explicite, jamais la lecture de l'autre fichier. Les masques obligatoires embarqués restent actifs même avec le fichier historique.
