# Plan de validation — firmware 13.60

**Langues :** [English (default)](TEST_PLAN.md) | Français

**Statut : Release GitHub standard ; test utilisateur du chemin DNS 0.4-13.60.4 réussi sur firmware 13.60, vérifications de cycle de vie/protocole encore ouvertes.** Un build seul ne prouve ni une extinction correcte, ni un réveil à la manette, ni une reprise de veille fiable.


## Release 0.4-13.60.4 — test utilisateur du chemin DNS (28 novembre 2026)

**TEST UTILISATEUR RÉUSSI : démarrage, chargement du profil prioritaire, blocage A protégé et résolution A autorisée sur firmware 13.60.** Le journal transmis identifie `NanoDNS v0.4-13.60.4-dev`, build de développement utilisé pour qualifier ce comportement de Release.

- Profil sélectionné : `/data/nanodns/nanodns4096.ini`.
- **1719 règles**, **0 exception**, **4 DNS amont**, timeout **1 500 ms**.
- Écoutes actives : `127.0.0.1:53` et `[::1]:53`.
- **15/15 requêtes A protégées observées** répondues localement en `0.0.0.0`.
- **7/7 requêtes A autorisées observées** résolues avec succès via le premier DNS amont.
- Aucune erreur runtime visible dans la trace fournie.

**Non démontré par cette trace :** fin d'extinction, réveil à la manette, veille/reprise, AAAA, basculement vers les DNS suivants, cycles répétés, endurance ou preuve par capture réseau de l'absence globale de fuite.

## Release 0.4-13.60.2 — test utilisateur du 19 novembre 2026

**TEST UTILISATEUR RÉUSSI pour le démarrage et le filtrage DNS A obligatoire sur firmware 13.60.** Journal `NanoDNS v0.4-13.60.2`, compilation du 19 novembre 2026 à 15:34:13.

- Chargement de **124 règles**, **0 exception**, **2 DNS amont configurés** (`9.9.9.9` et `149.112.112.112`), délai de **1 500 ms**.
- Écoutes locales IPv4 `127.0.0.1:53` et IPv6 `[::1]:53` établies.
- **5/5 requêtes A observées** bloquées localement avec `0.0.0.0` par `mandatory-console-blocklist` : `ps5.np.playstation.net` (deux fois), `telemetry-console.api.playstation.com`, `smetrics.aem.playstation.com` et `envelope2.np.dl.playstation.net`.
- Aucune erreur visible dans cet extrait. Le log ne présente pas de trace d'extinction ; le testeur a confirmé séparément l'arrêt et le rallumage sans anomalie. Quad9 est **configuré**, mais la résolution autorisée effective n'est pas démontrée. Aucun test AAAA ni création d'INI absent dans ce journal.

**Validation complémentaire du 19 novembre 2026 :** l'utilisateur confirme que **l'extinction normale et le rallumage de 0.4-13.60.2 ont également réussi**, sans réapparition de l'anomalie initiale. Le succès est rapporté par l'utilisateur et n'apparaît pas dans les logs DNS. **Encore à vérifier :** chemin spécifique de réveil à la manette, veille/reprise, AAAA, DNS autorisé via Quad9, cycles répétés et stabilité prolongée. La version 0.4-13.60.1 dispose aussi de son propre test d'extinction positif. Autres firmwares et binaire secondaire : **NON VALIDÉS PAR TEST UTILISATEUR**.

## Compte rendu de test sur console — 19 novembre 2026 (0.4-13.60.1 uniquement)

**Firmware 13.60 : test utilisateur réussi pour le fonctionnement de base.** Le testeur a installé notre bêta et indique que le précédent problème d'extinction et de rallumage **ne s'est pas reproduit** lors de l'essai réalisé.

Deux générations de journaux transmises (`nanodns.log` et `nanodns.log.previous`) confirment :

- Version `NanoDNS v0.4-13.60.1`, 124 règles chargées, aucune exception et les deux adresses Quad9.
- Écoute IPv4 sur `127.0.0.1:53` et IPv6 sur `[::1]:53`.
- **23 requêtes A** au total, toutes bloquées localement avec `0.0.0.0` par `mandatory-console-blocklist`. Aucune requête amont n'est visible dans ces fichiers.
- Aucune trace finale `shutdown: complete`. L'extinction et le rallumage corrects sont **rapportés par le testeur**, non prouvés par ce marqueur de journal.

| Console / firmware | Vérification |
| --- | --- |
| Génération actuelle, firmware 13.60 | **TEST UTILISATEUR RÉUSSI : démarrage, filtrage DNS A, essai d'extinction/rallumage** |
| Génération actuelle, tous les autres firmwares | **NON VALIDÉ PAR TEST UTILISATEUR** |
| Binaire de génération précédente, tous firmwares | **NON VALIDÉ PAR TEST UTILISATEUR** |

**Vérifications encore nécessaires sur 13.60 :** résolution d'un nom autorisé via Quad9, AAAA, DNS alternatifs, veille/reprise, cycles répétés d'arrêt/rallumage et stabilité prolongée. Une CI verte n'est jamais une validation matérielle. Un essai d'arrêt réussi n'établit pas définitivement la cause racine du problème initial.



## 1. Vérifications automatiques

- `python3 -m unittest discover -s tests -v` : cohérence des 1719 règles obligatoires, absence d'exceptions par défaut, correspondance entre INI et code, adresses Control D/AdGuard dans l'ordre et tests natifs.
- Compiler l'ELF avec le SDK compatible, vérifier sa présence et sa taille, puis vérifier aussi la compilation secondaire.
- Contrôler le commit `main` actuel, pas uniquement un ancien build vert.

## 2. Préparation réseau

Sauvegarder l'ELF d'origine, `/data/nanodns/nanodns.ini`, les journaux et les sauvegardes utiles. Bloquer le WAN au niveau du routeur/pare-feu en IPv4 et IPv6 tout en conservant le LAN/FTP et un chargeur local.

Vérifier qu'un seul mécanisme d'autoload est actif et qu'une seule instance nanoDNS est chargée. Transférer explicitement `nanodns4096.ini` avec ses 1719 règles ; conserver `nanodns.ini` uniquement comme repli si le profil prioritaire est absent.

## 3. Matrice DNS

| Scénario | Résultat attendu |
| --- | --- |
| Requête A vers un nom protégé de l'INI | `0.0.0.0` en local, aucune transmission amont |
| Requête AAAA vers le même nom | Aucune adresse IPv6, aucune transmission amont |
| Domaine historiquement exempté mais présent parmi les motifs obligatoires | Bloqué malgré une ancienne exception |
| Autres domaines de services ou d'éditeurs protégés par l'INI | Bloqués conformément aux motifs |
| Plusieurs questions, classe ou opcode non pris en charge | Rejet, aucune retransmission non contrôlée |
| Domaine autorisé comme `github.com` | Résolution via Control D ou AdGuard si WAN volontairement activé |
| CNAME amont dirigé vers un nom protégé | Rejet et absence de relais vers le client |
| Double lancement du payload | Le premier écouteur demeure, le second ne récupère pas le port 53 |
| Fichier INI absent ou invalide | Liste obligatoire compilée toujours appliquée |
| Signal d'arrêt supporté | Sockets et pool réseau libérés proprement |

Choisir les domaines bloqués **directement dans le fichier INI**, sans lancer volontairement de requête de mise à jour système. Préserver des journaux anonymisés.

## 4. Tests sur console

1. Tester extinction et démarrage à la manette **sans nanoDNS** comme référence.
2. Charger une seule instance, utiliser normalement le système et l'éteindre.
3. Depuis un état complètement éteint, tenter le démarrage via la manette.
4. Tester veille, reprise, manette et continuité DNS.
5. Répéter après des changements d'applications.
6. Surveiller gel, messages de réparation du stockage, avertissements système et absence de trace de fermeture.
7. En cas de défaut, revenir à l'ELF et à l'INI précédents.

## 5. Critères de qualification matérielle complémentaire

**Obligatoire :** builds du dernier commit et CI sécurité verts, blocage démontré des requêtes connues, résolution des noms autorisés et extinction/veille/réveil reproductibles sur matériel.

**Bloquant :** anomalie d'extinction, réparation du stockage, requête connue retransmise, régression réseau, terminaison inattendue ou CI rouge. La garantie d'absence totale de trafic WAN reste du ressort du pare-feu externe.
