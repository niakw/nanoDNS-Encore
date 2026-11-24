# Crédits et provenance

**Langues :** [English (default)](CREDITS.md) | Français

## Code original

Le payload C [nanoDNS](https://github.com/drakmor/nanoDNS) a été créé par **Drakmor** et distribué sous licence GNU GPL-3.0. Ce fork conserve les crédits, les mentions de droits et le fichier [LICENSE](../LICENSE) du dépôt d'origine.

## Configuration de blocage

Les 124 règles et les travaux de recherche sur les domaines de consoles et d'éditeurs sont issus de [niakw/nanodns-console-blocklist](https://github.com/niakw/nanodns-console-blocklist), profil v3. La [liste des sources](https://github.com/niakw/nanodns-console-blocklist/blob/main/docs/SOURCES.md) rend hommage aux projets indépendants dont les recherches ont été comparées, notamment Al-Azif, MagicStuffCL, cjrb007, Misl3d et ZixX3r.

La liste figure dans le fichier `nanodns.ini` et dans le code source du binaire. Les tests automatisés vérifient leur cohérence. Aucun téléchargement distant de règles n'est exécuté automatiquement au démarrage.

## DNS amont

Résolveurs par défaut : [Control D](https://docs.controld.com/docs/free-dns) et [AdGuard DNS](https://adguard-dns.io/fr/public-dns.html), profils sans filtrage. Aucun de ces fournisseurs ne maintient le projet. Quad9 était utilisé dans les versions antérieures.

## Intégration 13.60

Le fork [niakw/nanoDNS-Encore](https://github.com/niakw/nanoDNS-Encore) vise la fiabilité et la sécurité du payload sur firmware console 13.60. Il ne constitue pas une publication officielle de Drakmor, platform vendor, additional console networks ou platform operator. Il ne contient pas d'actifs propriétaires supplémentaires et reste soumis à la licence [GPL-3.0](../LICENSE).
