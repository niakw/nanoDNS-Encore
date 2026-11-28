# Audit du cycle de vie — nanoDNS console 13.60

**Langues :** [English (default)](PS5_13_60_LIFECYCLE.md) | Français

## Versions et validation

**0.4-13.60.2 : TEST UTILISATEUR RÉUSSI sur firmware 13.60 pour le démarrage et 5/5 requêtes A bloquées localement.** L'utilisateur a ensuite confirmé une extinction et un rallumage réussis avec ce nouvel ELF, sans retour de l'anomalie initiale, mais sans ligne de fermeture système dans le log. Veille/reprise, réveil spécifique à la manette et cycles répétés restent à valider ; **0.4-13.60.1** possède aussi un essai d'extinction positif distinct. Aucun autre firmware n'est validé par l'utilisateur.

## Vérification utilisateur sur firmware 13.60 (19 novembre 2026, 0.4-13.60.1)

**Premier test réussi :** le nouveau payload démarre, bloque les requêtes A protégées et le problème d'extinction/rallumage antérieur ne s'est pas reproduit selon le testeur. Les deux journaux confirment 23 requêtes A bloquées localement, 124 règles, 0 exception et les écoutes IPv4/IPv6. Pas de ligne `shutdown: complete` : le résultat d'arrêt/rallumage est **rapporté par l'utilisateur** ; cela ne prouve ni la réception d'un callback système ni la veille/reprise ni plusieurs cycles. Les autres firmwares et la compilation pour la console de génération précédente sont **NON VALIDÉS PAR TEST UTILISATEUR**. Voir le [bilan des tests](TEST_PLAN.fr.md#compte-rendu-de-test-sur-console--19-novembre-2026).

## Éléments connus et hypothèses

L'[issue amont #16](https://github.com/drakmor/nanoDNS/issues/16) signale un blocage de l'extinction sur console 13.60 avec WebKit Autoloader, Payload Manager, Kstuff Lite et ShadowMountPlus. Dans ce signalement, désactiver nanoDNS fait disparaître le problème. Ce constat **ne démontre pas** la cause exacte ni un lien direct avec le réveil par la manette.

nanoDNS 0.4 recherchait les processus à partir d'offsets internes au système puis terminait une ancienne instance par `SIGKILL`. Ce fork supprime ces opérations à risque sans modifier les offsets internes du noyau.

## Chargement

1. WebKit Autoloader lance Payload Manager (un seul mécanisme d'autoload).
2. Payload Manager charge nanoDNS depuis le chemin inchangé de `nanodns.elf`. Le payload demande le nom de thread résident `nanodns-encore` et journalise le résultat de l'appel système et le PID. L'affichage par le gestionnaire et le champ de commande du processus restent à vérifier sur console.
3. Le fichier `/data/nanodns/nanodns.ini` est lu. S'il est absent, un profil par défaut de 124 règles est créé. Un fichier existant n'est jamais écrasé.
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

Build SDK console vert ; cohérence des 124 règles ; absence de fuite DNS pour les noms interdits testés ; résolution des noms autorisés ; instances uniques ; arrêt normal, veille/reprise, démarrage la manette et absence de réparation du stockage. Voir le [plan de tests](TEST_PLAN.fr.md).
