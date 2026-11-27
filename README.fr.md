<div align="center">

# nanoDNS 13.60 — Runtime renforcé

### Des règles DNS obligatoires, un arrêt plus propre et un payload vérifiable.

**124 motifs protégés intégrés · Control D + AdGuard DNS · Tests natifs · Cycle de vie fiabilisé**

**Langues :** [English (default)](README.md) · Français

[**Installation française**](docs/INSTALL.fr.md) · [**Politique DNS**](docs/DNS_POLICY.fr.md) · [**Audit runtime**](docs/PS5_13_60_LIFECYCLE.fr.md) · [**Tests**](docs/TEST_PLAN.fr.md)

</div>

---

## Release 0.4-13.60.3 — migration DNS (24 novembre 2026)

**0.4-13.60.3 utilise Control D sans filtrage en priorité, AdGuard DNS sans filtrage en secours. Pas encore testé sur console.** Quad9 a cessé de servir les utilisateurs français le 24 novembre 2026. Ordre des DNS : `76.76.2.0`, `76.76.10.0`, `94.140.14.140`, `94.140.14.141`. Chaque serveur dispose de 1 500 ms de délai de réponse ; SERVFAIL/REFUSED déclenchent également le secours suivant. Les 124 règles obligatoires restent intactes. Aucun filtrage antimalware ou publicitaire supplémentaire par ces profils. Remplacer les deux fichiers ELF et INI ; les deux DNS de la console restent `127.0.0.1`.

## Code source actuel après 0.4-13.60.3 — capacité des règles

Les anciens tableaux fixes de **128 overrides et 128 exceptions ont été supprimés sur `main`**. Le code source actuel utilise un stockage dynamique borné pour ces deux listes, avec une limite globale de 64 Kio pour le fichier de configuration ; les 124 motifs obligatoires compilés restent séparés et prioritaires. La CI compile et teste **512 overrides + 512 exceptions** avec les fonctions de stockage de production sous sanitizers. **L'ELF 0.4-13.60.3 publié conserve encore les anciennes tables de 128 entrées** jusqu'à reconstruction et qualification matérielle d'un nouveau binaire.

## Ancienne Release 0.4-13.60.2 — preuves matérielles

**Anciens ELF et ZIP : `0.4-13.60.2`, TEST UTILISATEUR RÉUSSI sur firmware 13.60 pour le démarrage, le chargement des paramètres et le filtrage A.** Le journal confirme 5/5 requêtes A bloquées avec `0.0.0.0`, 124 règles, aucune exception et les écoutes IPv4/IPv6. **Le testeur confirme également une extinction et un rallumage réussis avec 0.4-13.60.2**, sans réapparition de l'anomalie initiale. Ce résultat est rapporté par l'utilisateur et non attesté par un marqueur terminal des journaux. Veille/reprise, DNS autorisé, AAAA, répétitions et endurance restent à vérifier. L'ancienne **0.4-13.60.1** ([Release précédente](https://github.com/niakw/nanoDNS-Encore/releases/tag/v0.4-13.60.1-beta.1)) avait également réussi un essai d'extinction/rallumage. Les autres firmwares restent non validés.

## Validation matérielle — 19 novembre 2026

| Cible | État des tests utilisateurs | Périmètre |
| --- | --- | --- |
| Console de génération actuelle, firmware **13.60** | **0.4-13.60.1 et 0.4-13.60.2 TESTÉS ; démarrage, filtrage A et extinction/rallumage réussis sur 0.4-13.60.2 ; 0.4-13.60.3 à retester** | Le binaire précédent a démarré, bloqué les requêtes A et permis une extinction/rallumage sans anomalie. L'ELF 0.4-13.60.2 a bloqué 5/5 requêtes A sur console 13.60 ; son extinction/rallumage a aussi été confirmée par l'utilisateur |
| Même génération, **autres firmwares** | **NON VALIDÉ PAR UN UTILISATEUR** | La compilation SDK et les tests automatiques ne sont pas des tests sur console |
| Binaire pour console de génération précédente, **tous firmwares** | **NON VALIDÉ PAR UN UTILISATEUR** | Compilation SDK réussie, mais aucun retour matériel |

Les deux journaux transmis pour **0.4-13.60.1** montrent **23 requêtes A bloquées**, **124 règles**, **0 exception**, les deux écoutes locales et la configuration Quad9. Cela **ne démontre pas** les résolutions autorisées via les DNS amont, les requêtes AAAA, l'absence globale de fuite, la veille/reprise, la stabilité prolongée ni un callback système d'extinction. Les résultats d'extinction/rallumage des deux versions reposent sur les retours de l'utilisateur et non sur une trace `shutdown: complete` dans ces journaux.

**Aucune validation sur 13.60 ne doit être étendue aux autres firmwares ou matériels sans tests utilisateurs réels.** Publication en **Release GitHub standard**, avec tests utilisateurs positifs sur 13.60 uniquement ; le reste de la matrice matérielle n'est pas encore couvert. Voir le [plan de tests](docs/TEST_PLAN.fr.md).

## Plus qu'un fichier de règles

Un fichier de blocklist peut être modifié ou contourné par une exception. Un payload mal géré peut également perturber l'arrêt ou le chargement en double.

**Ce projet indépendant, basé sur [nanoDNS par Drakmor](https://github.com/drakmor/nanoDNS)** intègre les **124 règles** de [niakw Console Blocklist](https://github.com/niakw/nanodns-console-blocklist) **dans le programme lui-même**. Elles sont vérifiées avant les exceptions utilisateur. Les noms autorisés continuent de passer par **Control D et AdGuard sans filtrage**.

L'objectif est une protection DNS mieux définie et un fonctionnement plus stable, sans supprimer inutilement l'accès au Web.

## Ce qui change réellement

| Fonction | nanoDNS original | Blocklist seule | **Notre version indépendante renforcée** |
| --- | --- | --- | --- |
| Règles livrées par défaut | **8** | **124** | **124 obligatoires compilées** |
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

**Télécharge notre ZIP complet : [nanoDNS 13.60 prêt à copier](https://github.com/niakw/nanoDNS-Encore/releases/download/v0.4-13.60.3/nanodns-13.60-v0.4-13.60.3-install.zip).** Deux fichiers seulement, avec les bons emplacements.

Après sauvegarde, **supprime l'ancien nanoDNS depuis Payload Manager ou désactive-le et enlève son autoload**. Arrête ensuite proprement son processus (ou éteins puis redémarre complètement la console). Décompresse le ZIP sur ton Mac, copie son dossier `data/` vers la **racine de la console**, relance Payload Manager et active **seulement `local/nanodns`** en boot auto. **Ne réutilise pas** le bouton Update du nanoDNS officiel ni son ancien dossier `repo/nanodns@e8cce5d1`.

[**Guide de migration pas à pas (français)**](docs/INSTALL.fr.md#migration-depuis-le-nanodns-04-officiel-de-drakmor) · [English upgrade guide](docs/INSTALL.md#upgrade-from-drakmors-original-nanodns-04) · [Release et fichiers séparés](https://github.com/niakw/nanoDNS-Encore/releases/tag/v0.4-13.60.3)

## Fiabilité et installation

Notre version renforce l'application des règles et le cycle de vie du processus : pas de `SIGKILL` destiné à remplacer une ancienne instance, écoute UDP exclusive, nettoyage des ressources réseau et conservation des journaux. Un **premier test utilisateur d'extinction/rallumage sur firmware 13.60 a réussi**, sans reproduction du problème antérieur. Les essais répétés et autres firmwares restent non validés.

**Installation recommandée :** le ZIP contient les deux fichiers suivants, à placer exactement ici :

```text
/data/pldmgr/payloads/local/nanodns/nanodns.elf
/data/nanodns/nanodns.ini
```

Copie l'arborescence `data/` du ZIP à la **racine `/`**, pas dans `/data/` une seconde fois. Ensuite, actualise Payload Manager, active uniquement `local/nanodns` en autoload et garde les deux DNS console sur `127.0.0.1`. Le ZIP **ne modifie pas automatiquement** le boot auto. Prévois un blocage WAN externe IPv4/IPv6 si tu veux une interdiction stricte des connexions.

**[Télécharger le ZIP](https://github.com/niakw/nanoDNS-Encore/releases/download/v0.4-13.60.3/nanodns-13.60-v0.4-13.60.3-install.zip)** · [Guide français](docs/INSTALL.fr.md) · [English instructions](docs/INSTALL.md) · [Tests console](docs/TEST_PLAN.fr.md)

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
