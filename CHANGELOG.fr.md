# Historique des modifications

**Langues :** [English (default)](CHANGELOG.md) | Français

## Non publié — code source après 0.4-13.60.3

- Remplacement des tableaux fixes `MAX_RULES=128` et `MAX_EXCEPTIONS=128` par un stockage dynamique des overrides et exceptions sur le tas. Le fichier INI est limité à 4 Mio au lieu de tronquer silencieusement les règles au-delà de 128 ; les 124 motifs obligatoires restent une politique compilée séparée et gardent leur priorité.
- Cette évolution reste limitée au code source jusqu'à reconstruction et qualification d'un nouvel ELF pour console de génération actuelle ; l'ELF 0.4-13.60.3 publié conserve les tables historiques de 128 overrides et 128 exceptions.

## 0.4-13.60.3 — migration DNS (24 novembre 2026)

- Remplacement de Quad9 après son retrait de France : Control D sans filtrage, puis AdGuard DNS sans filtrage, dans l'ordre `76.76.2.0`, `76.76.10.0`, `94.140.14.140`, `94.140.14.141`. Aucun filtrage antimalware/publicitaire supplémentaire ; les règles locales restent inchangées. DNS UDP non chiffré.
- Délai indépendant par serveur ; passage au suivant sur SERVFAIL ou REFUSED, conservation des réponses négatives valides.
- 124 motifs obligatoires, zéro exception et écoutes locales inchangés. Reconstruction ELF/ZIP ; nouveau test matériel en attente.

## 0.4-13.60.2 — Release standard, test utilisateur de base réussi sur firmware 13.60 (19 novembre 2026)

- Suppression de la course `stat()` / `fopen("w")` lors de la création du `nanodns.ini` : ouverture atomique `O_CREAT | O_EXCL | O_NOFOLLOW`, permissions initiales restreintes, aucun écrasement du fichier existant.
- Ouverture du fichier INI existant sans suivre les liens symboliques et validation du type fichier ordinaire. Si le chargement échoue, maintien des règles intégrées obligatoires.
- Droits minimaux `contents: read` dans les workflows classiques de compilation, suppression des publications automatiques concurrentes, publication centralisée conservée.
- Correction de la configuration Dependabot pour le suivi hebdomadaire des GitHub Actions.
- Guides anglais/français d'accessibilité, de contribution, de conduite et d'issues adaptés au projet.

**Limite de validation :** la Release 0.4-13.60.2 contient de **nouveaux binaires** avec le correctif de sécurité et les PR CI fusionnées, et dispose d'un **test utilisateur positif sur firmware 13.60 pour le démarrage et 5/5 blocages DNS A**, avec 124 règles et 0 exception. Le testeur a confirmé ensuite **l'extinction et le rallumage sans anomalie avec 0.4-13.60.2**. Ce résultat est rapporté par l'utilisateur, sans marqueur d'arrêt dans les journaux. Veille/reprise, AAAA, résolutions autorisées, cycles répétés et endurance restent à vérifier. Le binaire 0.4-13.60.1 disposait également d'un essai d'extinction positif distinct. Les autres firmwares et le binaire secondaire restent non validés.

## 0.4-13.60.1 — Release GitHub standard ; premier test utilisateur positif sur 13.60 (19 novembre 2026)

### Fiabilité des processus
- Suppression du scan système dépendant d'offsets internes et des remplacements d'instances par `SIGKILL`.
- Conservation de l'étiquette d'origine des processus pour Payload Manager.
- Exigence d'une écoute IPv4 UDP exclusive et libération des ressources en cas d'échec.
- Sortie sur `SIGINT` / `SIGTERM` avec étapes de nettoyage journalisées.
- Délais monotones selon disponibilité et traitement limité des anciens paquets réseau.
- Conservation du journal précédent et taille maximale pour les logs actifs.

### Politique DNS et sécurité

- DNS amont désormais uniquement Quad9 : `9.9.9.9` et `149.112.112.112`, sans résolveur supplémentaire dans les valeurs par défaut. Conservation des 124 règles / zéro exception.
- Intégration avec crédits de la [liste de blocage multi-consoles](https://github.com/niakw/nanodns-console-blocklist) : 124 règles, aucune exception par défaut.
- Compilation des règles obligatoires dans le binaire et application prioritaire sur toute exception utilisateur.
- Rejet des questions DNS non prises en charge sans retransmission non filtrée.
- Contrôle des identifiants/questions des réponses amont et refus de certains alias vers des domaines protégés.
- Synchronisation de la configuration générée, du profil livré et des tests de cohérence.
- Remplacement du moteur de correspondance récursif par une version itérative, testée nativement.

### Documentation et intégration continue
- Documentation de sécurité, d'architecture du cycle de vie, d'installation, de tests et de provenance.
- Conservation des compilations SDK console/console et ajout de validations automatiques de la politique DNS.
- Anglais par défaut et traductions françaises séparées.

**Validation :** un premier essai utilisateur sur firmware 13.60 a confirmé le démarrage, les blocages DNS de type A et l'extinction/rallumage sans reproduction du problème. La veille/reprise, les essais répétés, la résolution autorisée et les autres firmwares restent non validés. Un build CI vert ne remplace jamais les tests matériels.
