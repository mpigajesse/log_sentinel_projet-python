# Guide de Démonstration — Soutenance Log Sentinel

**Auteur :** NAOMIE NGWIDJOMBY MOUSSAVOU
**Module :** Python / Master 1 Cybersécurité
**Durée totale estimée :** 10 minutes

---

## Checklist avant la démo (à faire 5 min avant)

- [ ] Terminal ouvert dans le dossier `log_sentinel/`
- [ ] Environnement virtuel activé
- [ ] Navigateur web prêt (pour ouvrir le rapport HTML)
- [ ] Fichier `samples/sample_access.log` présent
- [ ] Police du terminal agrandie (taille 14 minimum pour la lisibilité)

```bash
# Se placer dans le bon dossier
cd "H:\Mon Drive\NAOMIE_MASTER\Python\log_sentinel_projet-python\log_sentinel"

# Activer l'environnement virtuel (Windows)
env\Scripts\activate

# Vérifier que Python est bien actif
python --version
```

---

## Étape 1 — Présentation du projet (1 min)

> **Ce qu'on dit au jury :**
>
> *"Log Sentinel est un outil Python orienté Blue Team. Son rôle est d'analyser
> automatiquement des fichiers de logs serveur et de détecter des comportements
> suspects : attaques par injection SQL, XSS, brute-force, scan de ressources...
> et de générer un rapport HTML exploitable par un analyste SOC."*

Montrer rapidement l'arborescence du projet :

```bash
# Afficher la structure du projet
dir /s /b *.py
```

> **Point clé à souligner :**
> *"J'ai choisi une architecture modulaire en 7 modules — chaque module a
> une seule responsabilité. C'est le principe SRP (Single Responsibility Principle)
> utilisé dans les outils professionnels."*

---

## Étape 2 — Analyse standard du log (3 min)

### Commande à exécuter :

```bash
python main.py -f samples/sample_access.log
```

### Ce que le jury va voir — points à commenter :

**1. Chargement et détection de format**
```
Fichier chargé : samples/sample_access.log
Lignes lues    : 60
Format détecté : NGINX
```
> *"L'outil détecte automatiquement le format du log — ici Nginx —
> grâce à des expressions régulières testées sur les premières lignes."*

**2. Les 25 alertes détectées**

Pointer chaque type au jury :

| # | Alerte | IP | Ce qu'on dit |
|---|--------|----|-------------|
| 1-4 | `sql_injection` | 185.220.101.34 | *"UNION SELECT dans l'URI — tentative d'extraction de base de données"* |
| 5-7 | `xss` | 91.108.4.201 | *"Balise `<script>` dans l'URL — injection de code JavaScript"* |
| 8-11 | `path_traversal` | 45.33.32.156 | *"`../../etc/passwd` — tentative d'accès aux fichiers système"* |
| 12-14 | `sensitive_files` | 77.88.55.242 | *"`.env`, `.git/config` — vol potentiel de credentials"* |
| 15-23 | `malicious_ua` | 185.220.101.9 / 104.21.14.77 | *"User-Agent `sqlmap` et `Nikto` — outils de scan automatiques"* |
| 24 | `brute_force` | 192.168.1.100 | *"10 POST /login avec code 401 — attaque par force brute"* |
| 25 | `scan` | 10.0.0.55 | *"15 URIs distinctes avec 404 — exploration de l'infrastructure"* |

**3. Statistiques**
> *"60 requêtes analysées, 12 IPs uniques, taux d'erreur de 71.67% — ce taux
> élevé est lui-même un indicateur de compromission potentielle."*

---

## Étape 3 — Option OSINT (2 min)

### Commande à exécuter :

```bash
python main.py -f samples/sample_access.log --check-ip
```

> **Ce qu'on dit au jury :**
>
> *"Avec l'option `--check-ip`, l'outil interroge l'API publique `ip-api.com`
> pour géolocaliser les IPs suspectes — pays, ville, fournisseur d'accès.
> C'est ce qu'on appelle l'enrichissement OSINT (Open Source Intelligence)."*

---

## Étape 4 — Rapport HTML (2 min)

### Commande à exécuter :

```bash
python main.py -f samples/sample_access.log
```

Puis ouvrir le fichier généré :
```
reports/report.html
```

> **Ce qu'on dit au jury :**
>
> *"Le rapport HTML est entièrement autonome — pas de dépendance externe,
> le CSS est intégré. Il affiche un score de risque global calculé selon
> le poids de chaque type d'attaque : brute-force vaut 25 points,
> SQLi 20 points, XSS 15 points... ici on obtient le score maximum : 100/100 CRITIQUE."*

---

## Étape 5 — Options avancées CLI (1 min)

### Personnaliser les seuils :

```bash
# Seuil brute-force à 3 tentatives (plus sensible)
python main.py -f samples/sample_access.log --bf-threshold 3

# Sans rapport HTML
python main.py -f samples/sample_access.log --no-report
```

> *"L'interface CLI avec argparse permet de personnaliser le comportement
> de l'outil sans modifier le code — essentiel en environnement professionnel."*

---

## Étape 6 — Tests unitaires (1 min)

```bash
python -m unittest discover -s tests -v
```

> **Ce qu'on dit au jury :**
>
> *"25 tests unitaires couvrent les modules critiques : détection de chaque
> type d'attaque, parsing des logs, statistiques, chargement de fichiers.
> Tous passent — 25/25 OK."*

---

## Questions jury — Réponses préparées

**Q : Pourquoi une architecture modulaire plutôt qu'un seul fichier ?**
> *"Chaque module a une responsabilité unique : loader charge, parser parse,
> detector détecte, reporter génère. Si demain on veut ajouter un format de log,
> on modifie uniquement `parser.py`. C'est plus maintenable et testable."*

**Q : Comment fonctionne la détection de format ?**
> *"On teste des expressions régulières sur les 10 premières lignes du fichier.
> Le format qui obtient le plus de correspondances est retenu.
> Si aucun ne correspond : `unknown`."*

**Q : Quelle est la différence entre détection par signature et par seuil ?**
> *"Par signature : on cherche des patterns connus dans l'URI ou le User-Agent —
> comme `UNION SELECT` pour SQLi. Par seuil : on compte les occurrences —
> plus de 5 erreurs 401 depuis la même IP déclenche une alerte brute-force."*

**Q : Pourquoi avoir utilisé `rich` ?**
> *"`rich` permet d'afficher des tableaux colorés, des barres de progression
> et des panels dans le terminal — ce qui rend l'outil plus professionnel
> et lisible qu'un simple `print()`."*

**Q : Quelles sont les limites de l'outil ?**
> *"Pas de corrélation temporelle — on ne détecte pas une attaque étalée sur
> plusieurs jours. Les regex peuvent générer des faux positifs.
> En amélioration : fenêtre temporelle glissante et machine learning."*

**Q : Où sont utilisés les sets, listes et dictionnaires ?**
> *"Les `set` pour l'unicité des URIs dans la détection de scan,
> les `dict` pour les statistiques et la configuration,
> les `list` pour stocker les entrées parsées et les alertes."*

---

## Ordre recommandé — Chrono 10 min

| Temps | Action |
|-------|--------|
| 0:00 – 1:00 | Présentation projet + architecture |
| 1:00 – 4:00 | Démo analyse standard + commentaire des alertes |
| 4:00 – 6:00 | Option OSINT + rapport HTML |
| 6:00 – 7:00 | Options CLI avancées |
| 7:00 – 8:00 | Tests unitaires |
| 8:00 – 10:00 | Questions / réponses |

---

> **Conseil final :** Avoir ce guide ouvert dans un second onglet
> pendant la soutenance pour ne pas perdre le fil.
