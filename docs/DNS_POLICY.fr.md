# Architecture de la politique DNS — firmware 13.60

**Langues :** [English (default)](DNS_POLICY.md) | Français

## Politique de la Release

0.4-13.60.4 livre [`nanodns4096.ini`](../nanodns4096.ini) et compile les mêmes **1719 motifs obligatoires** dans l'ELF. Cet ensemble contient le noyau canonique historique de 124 règles et un inventaire étendu d'éditeurs multi-plateformes. Il s'agit d'un inventaire DNS indicatif, pas d'une preuve de couverture exhaustive.

Le stockage runtime est borné à **4 096 overrides + 4 096 exceptions**, avec un INI limité à 4 Mio. Les motifs obligatoires compilés sont évalués avant les exceptions utilisateur.

## Sélection et repli

Le runtime sélectionne d'abord `/data/nanodns/nanodns4096.ini`. L'ancien `/data/nanodns/nanodns.ini` n'est utilisé que si le fichier prioritaire n'existe pas. Les deux fichiers ne sont **jamais fusionnés, réécrits l'un dans l'autre ni gérés simultanément**.

Si aucun fichier n'existe, le profil prioritaire est créé à partir de la configuration compilée. Si le fichier sélectionné existe mais est invalide ou dangereux, les règles obligatoires compilées sont utilisées et le fichier historique n'est pas consulté.

## Traitement des requêtes

1. Parser et valider la question DNS.
2. Tester les 1719 motifs obligatoires. Une question A protégée reçoit `0.0.0.0` ; AAAA/autres types pris en charge ne reçoivent pas d'adresse correspondante.
3. Appliquer ensuite les règles et exceptions supplémentaires de l'INI sélectionné.
4. Transmettre les requêtes autorisées aux DNS UDP Control D/AdGuard dans l'ordre.
5. Vérifier l'identité de la réponse et refuser les alias protégés avant relais.

Dès qu'une règle obligatoire correspond, la requête n'entre jamais dans le chemin amont. C'est une propriété locale de la politique DNS, pas une garantie de pare-feu.

## Preuve matérielle — 28 novembre 2026

La trace utilisateur .4 montre le profil prioritaire sélectionné, **1719 règles / 0 exception**, les deux écoutes loopback, **15/15 requêtes A protégées observées répondues localement**, et **7/7 requêtes A autorisées observées résolues par le premier DNS amont**. Aucune erreur runtime n'est visible.

La trace ne démontre pas AAAA sur matériel, le secours vers les DNS suivants, l'absence globale de contournement DNS, l'extinction/veille/réveil ni la stabilité longue durée. Voir le [plan de validation](TEST_PLAN.fr.md) et le [périmètre sécurité](../SECURITY.fr.md).
