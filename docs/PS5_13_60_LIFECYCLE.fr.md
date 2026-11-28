# Audit du cycle de vie — nanoDNS console 13.60

**Langues :** [English (default)](PS5_13_60_LIFECYCLE.md) | Français

## Versions et validation

**0.4-13.60.4 : TEST UTILISATEUR RÉUSSI sur firmware 13.60 pour le démarrage et le chemin DNS A observé.** La trace du 28 novembre montre 1719 règles / 0 exception, les deux écoutes loopback, 15/15 requêtes A protégées observées bloquées localement et 7/7 requêtes A autorisées observées résolues par le premier DNS amont. Aucun arrêt n'apparaît dans cette trace : extinction/veille/réveil .4 restent à vérifier. L'ancienne 0.4-13.60.2 dispose séparément d'un essai utilisateur positif d'extinction/rallumage.

## Vérification utilisateur sur firmware 13.60 (19 novembre 2026, 0.4-13.60.1)

**Premier test réussi :** le nouveau payload démarre, bloque les requêtes A protégées et le problème d'extinction/rallumage antérieur ne s'est pas reproduit selon le testeur. Les deux journaux confirment 23 requêtes A bloquées localement, 124 règles, 0 exception et les écoutes IPv4/IPv6. Pas de ligne `shutdown: complete` : le résultat d'arrêt/rallumage est **rapporté par l'utilisateur** ; cela ne prouve ni la réception d'un callback système ni la veille/reprise ni plusieurs cycles. Les autres firmwares et la compilation pour la console de génération précédente sont **NON VALIDÉS PAR TEST UTILISATEUR**. Voir le [bilan des tests](TEST_PLAN.fr.md#compte-rendu-de-test-sur-console--19-novembre-2026).

## Éléments connus et hypothèses

L'[issue amont #16](https://github.com/drakmor/nanoDNS/issues/16) signale un blocage de l'extinction sur console 13.60 avec WebKit Autoloader, Payload Manager, Kstuff Lite et ShadowMountPlus. Dans ce signalement, désactiver nanoDNS fait disparaître le problème. Ce constat **ne démontre pas** la cause exacte ni un lien direct avec le réveil par la manette.

nanoDNS 0.4 recherchait les processus à partir d'offsets internes au système puis terminait une ancienne instance par `SIGKILL`. Ce fork supprime ces opérations à risque sans modifier les offsets internes du noyau.

## Chargement

1. WebKit Autoloader lance Payload Manager (un seul mécanisme d'autoload).
2. Payload Manager charge nanoDNS depuis le chemin inchangé de `nanodns.elf`. Le payload demande le nom de thread résident `nanodns-encore` et journalise le résultat de l'appel système et le PID. L'affichage par le gestionnaire et le champ de commande du processus restent à vérifier sur console.
3. `/data/nanodns/nanodns4096.ini` est prioritaire ; l'ancien `/data/nanodns/nanodns.ini` n'est lu que si le premier est absent. Si les deux manquent, le profil prioritaire de 1719 règles est créé. Aucun mélange des deux fichiers.
4. Initialisation de SceNet, puis écoute UDP IPv4 sur `127.0.0.1:53` et éventuellement IPv6 sur `::1:53`.
5. Si l'écoute IPv4 échoue, la nouvelle instance quitte proprement au lieu de partager le port avec un ancien nanoDNS.

## Fonctionnement

- Les motifs protégés sont évalués avant les exceptions.
- Réponse aux requêtes A bloquées : `0.0.0.0` ; AAAA bloquées : aucune adresse.
- Questions multiples ou non prises en charge refusées.
- Questions autorisées transmises aux DNS amont avec délai borné et validation de la réponse.
- Rejet des réponses contenant certains alias protégés.
- Traces dans `/data/nanodns/nanodns.log` ; conservation du journal précédent, avec rotation. Anonymiser avant partage.
- Traitement du drainage des sockets amont limité pour empêcher une boucle trop longue.

## Arrêt, veille et reprise

`SIGINT` et `SIGTERM` demandent la sortie, puis le programme ferme les sockets, libère le pool SceNet et journalise les étapes. **Ce mécanisme n'est pas équivalent à un callback d'extinction console vérifié sur firmware 13.60.** Le nettoyage ne peut pas être garanti si le système tue le processus autrement.

La reprise depuis le mode repos peut réutiliser des sockets et états réseau. Les interactions avec ShadowMountPlus, Kstuff, Payload Manager et le firmware exigent une validation sur matériel réel. Aucun patch noyau ou offset système supplémentaire ne doit être introduit sans preuve.

## Critères de validation

Build SDK console vert ; cohérence des 1719 règles ; absence de fuite DNS pour les noms interdits testés ; résolution des noms autorisés ; instances uniques ; arrêt normal, veille/reprise, démarrage la manette et absence de réparation du stockage. Voir le [plan de tests](TEST_PLAN.fr.md).

## 28 novembre 2026 : récidive du démarrage par manette

Un nouvel échec de démarrage par manette a été signalé, sans erreur système cette fois. Les anciens essais positifs restent historiques. Le résident acquiert désormais un verrou noyau non bloquant avant de modifier la configuration, de faire tourner les journaux ou d'initialiser SceNet. Le fichier persiste mais le verrou est libéré par le noyau à la sortie du processus. En cas d'échec du verrou, le démarrage est refusé. Les sockets UDP sont non bloquantes ; l'attente upstream vérifie l'arrêt par tranches de 100 ms maximum et une interruption au démarrage rejoint le nettoyage. Aucun callback d'alimentation ni offset supposé n'est ajouté. Le réveil par manette, la veille et le verrou natif restent à qualifier sur console isolée.

## 28 novembre 2026 : contre-revue après le gel du firewall

Le résident DNS reste indépendant et ne fait aucun appel de contrôle IPFW. La boucle des sockets et l'attente sans écoute vérifient l'arrêt par tranches de 100 ms ; l'annulation est vérifiée avant l'initialisation SceNet et les tentatives de réouverture. Hors debug, le journal indique le profil et le nombre de règles, sans écrire chaque règle au démarrage ; les traces de requêtes restent disponibles. Aucun changement de filtrage, de priorité INI, de résolveur ou de privilèges. Le gel de la console et le réveil par manette restent à qualifier.
