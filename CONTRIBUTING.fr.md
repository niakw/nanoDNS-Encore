# Contribuer à nanoDNS 13.60

**Langues :** [English (default)](CONTRIBUTING.md) | Français

Merci de contribuer à ce payload DNS indépendant, distribué sous GPL-3.0 et basé sur [le nanoDNS de Drakmor](https://github.com/drakmor/nanoDNS). Les contributions en français et en anglais sont acceptées.

## Objectifs et limites

- Conserver les **124 motifs DNS obligatoires**, évalués avant les exceptions ; ne pas changer silencieusement la blocklist ni le profil Control D/AdGuard ordonné.
- Fiabiliser le cycle de vie du processus sans tuer les autres processus ni ajouter d'offsets noyau supposés.
- Préserver les chemins d'installation et la migration Payload Manager, ainsi que le ZIP de deux fichiers.
- Vérifier le matériel **firmware par firmware** : le fonctionnement de base sur 13.60 bénéficie d'un test utilisateur positif ; les autres firmwares et le binaire secondaire ne sont pas validés sans nouveaux essais.
- Ne jamais présenter le filtrage DNS comme un pare-feu ou une garantie d'absence totale d'accès WAN.

## Proposer une modification

1. Crée une [issue ciblée](https://github.com/niakw/nanoDNS-Encore/issues/new/choose) ou référence une issue existante.
2. Travaille dans une branche dédiée en décrivant cause, effet attendu, risque et retour arrière.
3. Lance les tests disponibles :
   ```sh
   python3 -m unittest discover -s tests -v
   cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic tests/test_dns_mask.c -o /tmp/nanodns-mask-test
   /tmp/nanodns-mask-test
   ```
4. Si le SDK adapté est installé, construis le binaire principal avec `make clean all`, ou le binaire secondaire avec `make -f Makefile.ps4 clean all`. Une compilation réussie **n'est pas** une validation sur console.
5. Adapte les tests et la documentation correspondante en anglais et en français.
6. Ouvre une PR ciblée, avec sorties de tests et preuves matérielles **uniquement si les essais ont réellement eu lieu**, en précisant console et firmware.

## Tests et confidentialité

Teste uniquement sur tes appareils autorisés. Sauvegarde l'ancien ELF et l'INI, préserve un retour arrière, conserve le blocage WAN externe si nécessaire et ne lance pas deux nanoDNS simultanément. Vérifie le filtrage, les domaines autorisés lorsque cela est sûr, l'extinction et le réveil.

**Anonymise les logs** : identifiants de console, adresses réseau, noms d'hôtes personnels, chemins identifiants, données de compte et autres secrets. Ne publie ni SDK propriétaire, ni clé, ni binaire non redistribuable.

Pour un risque de sécurité, consulte [SECURITY.fr.md](SECURITY.fr.md) avant une issue publique. Respecte le [code de conduite](CODE_OF_CONDUCT.fr.md) et les [recommandations d'accessibilité](ACCESSIBILITY.fr.md). Voir aussi le [protocole de tests](docs/TEST_PLAN.fr.md) et la [licence GPL-3.0](LICENSE).
