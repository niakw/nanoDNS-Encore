<div align="center">

# nanoDNS 13.60 — Runtime renforcé

### Des règles DNS obligatoires, un arrêt plus propre et un payload vérifiable.

**1719 motifs protégés intégrés · Control D + AdGuard DNS · Tests natifs · Cycle de vie fiabilisé**

**Langues :** [English (default)](README.md) · Français

[**Installation française**](docs/INSTALL.fr.md) · [**Politique DNS**](docs/DNS_POLICY.fr.md) · [**Audit runtime**](docs/PS5_13_60_LIFECYCLE.fr.md) · [**Tests**](docs/TEST_PLAN.fr.md)

</div>

---


## Release 0.4-13.60.4 — profil obligatoire étendu, test utilisateur du 28 novembre 2026

**0.4-13.60.4 est TESTÉE PAR UTILISATEUR sur firmware 13.60 pour le démarrage, la sélection du profil, le blocage des requêtes A protégées et la résolution amont de requêtes A autorisées.** Le journal fourni correspond au build de développement .4 devenu cette Release : sélection de `/data/nanodns/nanodns4096.ini`, **1719 règles / 0 exception**, deux écoutes loopback actives, **15/15 requêtes A protégées observées** répondues localement en `0.0.0.0`, et **7/7 requêtes A autorisées observées** résolues via le premier DNS amont. Aucune erreur runtime n'apparaît dans la trace.

La Release conserve le stockage dynamique borné (**4 096 overrides + 4 096 exceptions**, INI limité à 4 Mio). Le noyau canonique historique de 124 règles reste inclus dans les 1719 règles obligatoires. `nanodns4096.ini` est prioritaire ; `nanodns.ini` n'est utilisé qu'en repli si le fichier prioritaire est absent. Les deux profils ne sont jamais fusionnés.

**Limite du test :** ce journal .4 ne contient pas de séquence d'extinction et ne démontre pas la veille/reprise, le réveil à la manette, AAAA, le basculement vers les DNS amont suivants, les cycles répétés ou l'endurance.

## Ancienne Release 0.4-13.60.2 — preuves matérielles

**Anciens ELF et ZIP : `0.4-13.60.2`, TEST UTILISATEUR RÉUSSI sur firmware 13.60 pour le démarrage, le chargement des paramètres et le filtrage A.** Le journal confirme 5/5 requêtes A bloquées avec `0.0.0.0`, 124 règles, aucune exception et les écoutes IPv4/IPv6. **Le testeur confirme également une extinction et un rallumage réussis avec 0.4-13.60.2**, sans réapparition de l'anomalie initiale. Ce résultat est rapporté par l'utilisateur et non attesté par un marqueur terminal des journaux. Veille/reprise, DNS autorisé, AAAA, répétitions et endurance restent à vérifier. L'ancienne **0.4-13.60.1** ([Release précédente](https://github.com/niakw/nanoDNS-Encore/releases/tag/v0.4-13.60.1-beta.1)) avait également réussi un essai d'extinction/rallumage. Les autres firmwares restent non validés.

## Validation matérielle — 19 novembre 2026

| Cible | État des tests utilisateurs | Périmètre |
| --- | --- | --- |
| Console de génération actuelle, firmware **13.60** | **0.4-13.60.4 TESTÉE pour démarrage et chemin DNS ; ancien essai extinction/rallumage 0.4-13.60.2 réussi** | .4 charge 1719/0, bloque 15/15 requêtes A protégées observées et résout 7/7 requêtes A autorisées observées. Extinction/veille/réveil .4 non vérifiés |
| Même génération, **autres firmwares** | **NON VALIDÉ PAR UN UTILISATEUR** | La compilation SDK et les tests automatiques ne sont pas des tests sur console |
| Binaire pour console de génération précédente, **tous firmwares** | **NON VALIDÉ PAR UN UTILISATEUR** | Compilation SDK réussie, mais aucun retour matériel |

Les deux journaux transmis pour **0.4-13.60.1** montrent **23 requêtes A bloquées**, **124 règles**, **0 exception**, les deux écoutes locales et la configuration Quad9. Cela **ne démontre pas** les résolutions autorisées via les DNS amont, les requêtes AAAA, l'absence globale de fuite, la veille/reprise, la stabilité prolongée ni un callback système d'extinction. Les résultats d'extinction/rallumage des deux versions reposent sur les retours de l'utilisateur et non sur une trace `shutdown: complete` dans ces journaux.

**Aucune validation sur 13.60 ne doit être étendue aux autres firmwares ou matériels sans tests utilisateurs réels.** Publication en **Release GitHub standard**, avec tests utilisateurs positifs sur 13.60 uniquement ; le reste de la matrice matérielle n'est pas encore couvert. Voir le [plan de tests](docs/TEST_PLAN.fr.md).

## Plus qu'un fichier de règles

Un fichier de blocklist peut être modifié ou contourné par une exception. Un payload mal géré peut également perturber l'arrêt ou le chargement en double.

**Ce projet indépendant, basé sur [nanoDNS par Drakmor](https://github.com/drakmor/nanoDNS)** conserve les **124 règles canoniques** de [niakw Console Blocklist](https://github.com/niakw/nanodns-console-blocklist) et étend la Release à **1719 règles obligatoires compilées**. Elles sont vérifiées avant les exceptions utilisateur. Les noms autorisés continuent de passer par **Control D et AdGuard sans filtrage**.

L'objectif est une protection DNS mieux définie et un fonctionnement plus stable, sans supprimer inutilement l'accès au Web.

## Ce qui change réellement

| Fonction | nanoDNS original | Blocklist seule | **Notre version indépendante renforcée** |
| --- | --- | --- | --- |
| Règles livrées par défaut | **8** | **124** | **1719 obligatoires compilées** |
| Exceptions par défaut | **6** | **0** | Ne peuvent pas neutraliser les motifs obligatoires |
| DNS amont | 3 fournisseurs | Control D + AdGuard | **Control D puis AdGuard sans filtrage** |
| Questions DNS non standards | Comportement d'origine | Hérité | Refus sans retransmission non contrôlée |
| Réponses des résolveurs | Contrôles d'origine | Hérité | Vérifications supplémentaires des noms et alias |
| Moteur des masques | Récursif | Hérité | Itératif avec tests natifs |
| Lancement en double | Arrêt brutal de l'ancienne instance | Hérité | Écoute exclusive, sans arrêt brutal |
| Logs / extinction | Journal précédent écrasé | Hérité | Conservation, limite de taille et traces d'arrêt |
| Garantie d'absence totale de fuite IP | **Non** | **Non** | **Non** |
| Essai d'extinction et de rallumage sur 13.60 | Non établi | Sans objet | **Test utilisateur réussi ; validations complémentaires à effectuer** |

Ces chiffres concernent **les réglages initiaux** de la version d'origine, qui sait également charger une blocklist personnalisée.

## Fonctionnement et DNS amont

Les 124 motifs obligatoires sont évalués avant toute exception. Pour les noms interdits, les requêtes A reçoivent `0.0.0.0` et les AAAA aucune adresse. Les requêtes autorisées utilisent `76.76.2.0`, `76.76.10.0`, `94.140.14.140`, `94.140.14.141`, dans cet ordre. Deux fournisseurs sans filtrage supplémentaire, via UDP non chiffré. [Control D](https://docs.controld.com/docs/free-dns) · [AdGuard](https://adguard-dns.io/fr/public-dns.html).

## Tu utilises déjà le nanoDNS 0.4 officiel ?

**Télécharge notre ZIP complet : [nanoDNS 13.60 prêt à copier](https://github.com/niakw/nanoDNS-Encore/releases/download/v0.4-13.60.4/nanodns-13.60-v0.4-13.60.4-install.zip).** Deux fichiers seulement, avec les bons emplacements.

Après sauvegarde, **supprime l'ancien nanoDNS depuis Payload Manager ou désactive-le et enlève son autoload**. Arrête ensuite proprement son processus (ou éteins puis redémarre complètement la console). Décompresse le ZIP sur ton Mac, copie son dossier `data/` vers la **racine de la console**, relance Payload Manager et active **seulement `local/nanodns`** en boot auto. **Ne réutilise pas** le bouton Update du nanoDNS officiel ni son ancien dossier `repo/nanodns@e8cce5d1`.

[**Guide de migration pas à pas (français)**](docs/INSTALL.fr.md#migration-depuis-le-nanodns-04-officiel-de-drakmor) · [English upgrade guide](docs/INSTALL.md#upgrade-from-drakmors-original-nanodns-04) · [Release et fichiers séparés](https://github.com/niakw/nanoDNS-Encore/releases/tag/v0.4-13.60.4)

## Fiabilité et installation

Notre version renforce l'application des règles et le cycle de vie du processus : pas de `SIGKILL` destiné à remplacer une ancienne instance, écoute UDP exclusive, nettoyage des ressources réseau et conservation des journaux. Un **premier test utilisateur d'extinction/rallumage sur firmware 13.60 a réussi**, sans reproduction du problème antérieur. Les essais répétés et autres firmwares restent non validés.

**Installation recommandée :** le ZIP contient les deux fichiers suivants, à placer exactement ici :

```text
/data/pldmgr/payloads/local/nanodns/nanodns.elf
/data/nanodns/nanodns4096.ini
```

Copie l'arborescence `data/` du ZIP à la **racine `/`**, pas dans `/data/` une seconde fois. Ensuite, actualise Payload Manager, active uniquement `local/nanodns` en autoload et garde les deux DNS console sur `127.0.0.1`. Le ZIP **ne modifie pas automatiquement** le boot auto. Prévois un blocage WAN externe IPv4/IPv6 si tu veux une interdiction stricte des connexions.

**[Télécharger le ZIP](https://github.com/niakw/nanoDNS-Encore/releases/download/v0.4-13.60.4/nanodns-13.60-v0.4-13.60.4-install.zip)** · [Guide français](docs/INSTALL.fr.md) · [English instructions](docs/INSTALL.md) · [Tests console](docs/TEST_PLAN.fr.md)

## Notre projet est-il prêt pour un usage stable ?

**Un premier test utilisateur sur firmware 13.60 est positif, mais ce n'est pas encore une qualification complète.** Un build vert ne prouve ni le fonctionnement des autres firmwares, ni la veille/reprise, ni l'absence durable de problème de stockage. Même après ces essais, revenir au binaire original fait perdre les **règles compilées obligatoires** et les corrections du runtime. Conserve notre dépôt indépendant et son historique pour le suivi et les futures corrections.

## Limites

Aucun DNS local ne peut bloquer toutes les IP directes, les DNS alternatifs ou chiffrés, les caches et les communications avant chargement. Une interdiction stricte du WAN exige un pare-feu externe. Voir [sécurité](SECURITY.fr.md).

## Contribuer et règles du projet

[Contribuer](CONTRIBUTING.fr.md) · [Code de conduite](CODE_OF_CONDUCT.fr.md) · [Accessibilité](ACCESSIBILITY.fr.md) · [Sécurité](SECURITY.fr.md) · [Historique](CHANGELOG.fr.md). Les signalements et contributions sont acceptés en français ou en anglais.

## Crédits

Code original : [Drakmor](https://github.com/drakmor/nanoDNS). Règles : [niakw Console Blocklist](https://github.com/niakw/nanodns-console-blocklist). Intégration : [niakw](https://github.com/niakw/nanoDNS-Encore). Licence [GPL-3.0](LICENSE), projet communautaire indépendant.

---

**Des protections mesurables. Des limites documentées.**

### Profil de politique de la Release

[`nanodns4096.ini`](nanodns4096.ini) : **1719 règles obligatoires**, dont le noyau canonique de 124 règles. Limites runtime : 4 096 overrides et 4 096 exceptions, INI de 4 Mio maximum. Le test matériel .4 du 28 novembre a exercé ce profil directement ; l'inventaire DNS reste indicatif et ne prouve pas une couverture exhaustive.
