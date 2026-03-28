# main.py — Point d'entrée CLI

## Rôle

`main.py` est le **point d'entrée en ligne de commande** de Log Sentinel. Il orchestre l'intégralité du pipeline d'analyse de sécurité en enchaînant les modules du répertoire `src/` :

1. Lecture et détection du format du fichier de log
2. Parsing structuré des lignes
3. Détection des attaques par signatures, brute-force et scan
4. Calcul des statistiques
5. Vérification OSINT des IPs suspectes (optionnelle)
6. Génération d'un rapport HTML (optionnelle)
7. Affichage d'un résumé final avec score de risque

L'interface utilisateur est entièrement construite avec la bibliothèque **Rich**, qui offre des tableaux colorés, des barres de progression et des panneaux formatés dans le terminal.

---

## Arguments CLI

Le programme est invoqué via la commande `python main.py` (ou `log-sentinel` si installé). Tous les arguments sont déclarés dans `build_parser()` via `argparse`.

| Flag court | Flag long          | Type    | Défaut     | Description                                                                 |
|------------|--------------------|---------|------------|-----------------------------------------------------------------------------|
| `-f`       | `--file`           | `str`   | *(requis)* | Chemin vers le fichier de log à analyser.                                   |
| —          | `--bf-threshold`   | `int`   | `5`        | Nombre d'échecs d'authentification (codes 401/403) avant alerte brute-force.|
| —          | `--scan-threshold` | `int`   | `10`       | Nombre d'URIs distinctes avant déclenchement d'une alerte de scan.          |
| —          | `--report` / `--no-report` | `bool` | `True` | Activer ou désactiver la génération du rapport HTML.               |
| —          | `--check-ip`       | flag    | `False`    | Activer la vérification OSINT des IPs suspectes via `ip-api.com`.           |
| —          | `--output-dir`     | `str`   | `"reports"`| Dossier de destination pour le rapport HTML généré.                         |

### Exemples d'utilisation

```bash
# Analyse de base avec rapport HTML dans le dossier par défaut
python main.py -f samples/sample_access.log

# Analyse avec vérification OSINT et dossier de sortie personnalisé
python main.py -f access.log --check-ip --output-dir out/

# Analyse sans rapport HTML, seuil brute-force abaissé à 3 tentatives
python main.py -f access.log --no-report --bf-threshold 3

# Seuils personnalisés pour environnement très actif
python main.py -f access.log --bf-threshold 10 --scan-threshold 20
```

---

## Pipeline d'exécution

La fonction `main()` suit un pipeline séquentiel en dix étapes :

```
┌─────────────────────────────────────────────────────────────────┐
│  Étape 1  │  Affichage de la bannière ASCII (print_banner)       │
├─────────────────────────────────────────────────────────────────┤
│  Étape 2  │  Chargement du fichier de log (LogLoader.load)       │
├─────────────────────────────────────────────────────────────────┤
│  Étape 3  │  Détection automatique du format (detect_format)     │
│           │  → "apache" | "nginx" | "syslog" | "unknown"         │
├─────────────────────────────────────────────────────────────────┤
│  Étape 4  │  Parsing structuré des lignes (LogParser.parse_all)  │
│           │  → list[LogEntry] → list[dict]                        │
├─────────────────────────────────────────────────────────────────┤
│  Étape 5  │  Détection des attaques (AttackDetector)             │
│           │  avec barre de progression Rich (Progress)            │
│           │  → detect_signature + detect_brute_force + detect_scan│
├─────────────────────────────────────────────────────────────────┤
│  Étape 6  │  Affichage des alertes (print_alerts)                │
├─────────────────────────────────────────────────────────────────┤
│  Étape 7  │  Calcul et affichage des statistiques (print_stats)  │
├─────────────────────────────────────────────────────────────────┤
│  Étape 8  │  Vérification OSINT (OSINTChecker) — si --check-ip   │
│           │  → top 5 IPs suspectes interrogées sur ip-api.com     │
├─────────────────────────────────────────────────────────────────┤
│  Étape 9  │  Génération du rapport HTML (HTMLReporter) — si      │
│           │  --report (activé par défaut)                         │
├─────────────────────────────────────────────────────────────────┤
│  Étape 10 │  Résumé final dans un Panel Rich avec score de risque │
└─────────────────────────────────────────────────────────────────┘
```

À chaque étape, les erreurs sont capturées et affichées proprement avec Rich avant d'appeler `sys.exit(1)` si elles sont bloquantes.

---

## Fonctions clés

### build_parser()

```python
def build_parser() -> argparse.ArgumentParser:
```

Construit et retourne le parseur de la ligne de commande. Utilise `argparse.ArgumentParser` avec les paramètres suivants :

- `prog="log-sentinel"` — nom du programme affiché dans l'aide
- `formatter_class=argparse.RawDescriptionHelpFormatter` — conserve la mise en forme du texte `epilog`
- `epilog` — bloc d'exemples d'utilisation affiché avec `--help`

Le flag `--report` / `--no-report` utilise `argparse.BooleanOptionalAction`, disponible depuis Python 3.9. Ce mécanisme génère automatiquement les deux formes `--report` et `--no-report` à partir d'une seule déclaration, avec un comportement booléen natif.

```python
parser.add_argument(
    "--report",
    action=argparse.BooleanOptionalAction,
    default=True,
    help="Générer (ou non) un rapport HTML. (défaut : activé)",
)
```

---

### print_banner()

```python
def print_banner(console: Console) -> None:
```

Affiche la bannière ASCII de Log Sentinel encadrée dans un `Panel` Rich avec une bordure rouge. La constante `BANNER` contient le texte ASCII art multiligne, rendu en `[bold red]`. Le sous-titre `Blue Team Security Analyzer | v1.0.0` est affiché en dessous.

```
╭──────────────────────────────────────────────────────────────╮
│  _                  _____            _   _            _      │
│ | |    ___   __ _  / ____|          | | (_)          | |     │
│ ...                                                          │
│   Blue Team Security Analyzer  |  v1.0.0                     │
╰──────────────────────────────────────────────────────────────╯
```

---

### print_alerts()

```python
def print_alerts(console: Console, alerts: list) -> None:
```

Affiche la liste des alertes de sécurité dans une `Table` Rich à cinq colonnes.

| Colonne   | Style Rich          | Largeur | Description                              |
|-----------|---------------------|---------|------------------------------------------|
| `#`       | `dim`               | 4       | Numéro séquentiel de l'alerte            |
| `Type`    | `bold` + couleur    | 18      | Type d'attaque (coloré via `_ATTACK_COLORS`) |
| `IP`      | `cyan`              | 16      | Adresse IP source                        |
| `URI`     | `yellow`            | 30      | URI ciblée (tronquée à 80 caractères)    |
| `Détails` | `white`             | min 20  | Informations complémentaires             |

La couleur de la colonne `Type` est déterminée par le dictionnaire `_ATTACK_COLORS` :

```python
_ATTACK_COLORS: dict[str, str] = {
    "sql_injection":     "bold red",
    "xss":               "bold magenta",
    "path_traversal":    "bold yellow",
    "command_injection": "bold red",
    "sensitive_files":   "yellow",
    "malicious_ua":      "bold cyan",
    "brute_force":       "bold orange1",
    "scan":              "bold blue",
}
```

Si aucune alerte n'est détectée, un message vert `Aucune alerte détectée.` est affiché à la place du tableau.

---

### print_stats()

```python
def print_stats(console: Console, stats: dict) -> None:
```

Affiche quatre tableaux Rich distincts à partir du dictionnaire `stats` produit par `LogStatistics.compute()` :

**1. Résumé global** — métriques principales

| Métrique         | Clé dans `stats`    |
|------------------|---------------------|
| Total requêtes   | `total_requests`    |
| IPs uniques      | `unique_ips`        |
| Taux d'erreur    | `error_rate`        |

**2. Top IPs** — adresses IP les plus actives (clé `top_ips`, liste de tuples `(ip, count)`)

**3. Codes HTTP** — distribution des codes de réponse (clé `status_codes`, dict) avec colorisation automatique :

| Plage de code | Couleur Rich |
|---------------|--------------|
| `< 300`       | `green`      |
| `300–399`     | `yellow`     |
| `≥ 400`       | `red`        |

**4. Top URIs** — ressources les plus demandées (clé `top_uris`, liste de tuples `(uri, count)`)

**5. Méthodes HTTP** — répartition par verbe HTTP (`GET`, `POST`, etc.), triées par fréquence décroissante (clé `methods`, dict)

---

### main()

```python
def main() -> None:
```

Fonction orchestratrice principale. Elle :

1. Instancie un objet `Console` Rich partagé par toutes les fonctions d'affichage.
2. Parse les arguments via `build_parser().parse_args()`.
3. Exécute chaque étape du pipeline en gérant les exceptions individuellement.
4. Utilise `console.rule()` pour séparer visuellement chaque section dans le terminal.
5. Gère la détection des attaques avec une barre de progression `Progress` (mode `transient=True`, disparaît après la fin).

La détection des signatures est effectuée **entrée par entrée** en découpant les données en chunks de 5 % (`CHUNK = max(1, len(entries) // 20)`) pour que la barre de progression avance régulièrement. Les détections brute-force et scan sont lancées ensuite sur l'ensemble des données.

```python
with Progress(transient=True, console=console) as progress:
    task = progress.add_task("[cyan]Analyse en cours...[/cyan]", total=len(entries))
    CHUNK = max(1, len(entries) // 20)
    for i in range(0, len(all_entries_local), CHUNK):
        chunk = all_entries_local[i : i + CHUNK]
        for entry in chunk:
            alerts.extend(detector.detect_signature(entry))
        progress.advance(task, advance=len(chunk))

    alerts.extend(detector.detect_brute_force(all_entries_local))
    alerts.extend(detector.detect_scan(all_entries_local))
```

---

## Calcul du score de risque

Le score de risque est une valeur entière comprise entre **0 et 100**, calculée à partir de trois composantes indépendantes :

### Formule

```python
alert_score   = min(50, alert_count * 2)
error_score   = min(30, error_rate * 0.6)
heavy_types   = {"brute_force", "scan", "sql_injection", "command_injection"}
heavy_penalty = 20 if any(a.attack_type in heavy_types for a in alerts) else 0
risk_score    = int(min(100, alert_score + error_score + heavy_penalty))
```

### Décomposition des composantes

| Composante       | Formule                             | Maximum | Description                                                                 |
|------------------|-------------------------------------|---------|-----------------------------------------------------------------------------|
| `alert_score`    | `alert_count × 2`, plafonné à 50    | 50      | Chaque alerte rapporte 2 points. 25 alertes suffisent à atteindre le plafond.|
| `error_score`    | `error_rate × 0.6`, plafonné à 30   | 30      | Un taux d'erreur de 50 % donne 30 points (score maximal pour cette composante).|
| `heavy_penalty`  | 20 si attaque grave présente, sinon 0 | 20    | Bonus fixe si au moins une alerte est de type brute-force, scan, SQL injection ou injection de commande. |

### Seuils et niveaux de risque

| Score         | Niveau      | Couleur Rich    |
|---------------|-------------|-----------------|
| `< 20`        | FAIBLE      | `bold green`    |
| `20 – 49`     | MODÉRÉ      | `bold yellow`   |
| `50 – 74`     | ÉLEVÉ       | `bold orange1`  |
| `≥ 75`        | CRITIQUE    | `bold red`      |

Le score et le niveau sont affichés dans le panneau de résumé final, dont la bordure adopte la couleur du niveau de risque.

### Exemple de calcul

Pour un log avec **18 alertes**, un taux d'erreur de **40 %** et une alerte de type `brute_force` :

```
alert_score   = min(50, 18 × 2) = min(50, 36) = 36
error_score   = min(30, 40 × 0.6) = min(30, 24) = 24
heavy_penalty = 20  (brute_force présent)
risk_score    = min(100, 36 + 24 + 20) = 80  → CRITIQUE
```

---

## Points clés techniques

### argparse — BooleanOptionalAction

`argparse.BooleanOptionalAction` (Python ≥ 3.9) permet de déclarer un argument booléen avec ses deux formes (`--report` / `--no-report`) en une seule instruction. Sans cette action, il faudrait deux appels séparés à `add_argument` avec `store_true` et `store_false`.

### Rich — Console

`Console()` est l'objet central de Rich. Toutes les fonctions d'affichage le reçoivent en paramètre pour garantir un rendu cohérent (encodage, largeur du terminal, thème). L'utilisation d'une instance unique évite les conflits d'écriture dans le terminal.

### Rich — Table

`Table` permet de construire des tableaux formatés avec contrôle fin sur :
- le style de chaque colonne (`style=`, `justify=`, `width=`, `overflow=`)
- le style de l'en-tête (`header_style=`)
- la bordure (`border_style=`)
- l'alternance des lignes (`row_styles=["", "dim"]`)

### Rich — Panel

`Panel` encadre un contenu (texte, table, markup Rich) dans une boîte avec titre et bordure colorée. Utilisé ici pour la bannière ASCII et le résumé final.

### Rich — Progress (mode transient)

`Progress(transient=True)` affiche une barre de progression qui **disparaît automatiquement** du terminal une fois la tâche terminée, évitant d'encombrer la sortie. Les étapes d'avancement sont contrôlées manuellement avec `progress.advance(task, advance=N)`.

### Gestion de l'import optionnel

`HTMLReporter` est importé dans un bloc `try/except ImportError`. Si `src/reporter.py` est absent, la variable `_REPORTER_AVAILABLE` est positionnée à `False` et le rapport est simplement ignoré, sans que cela ne bloque l'analyse. Ce pattern permet une dégradation gracieuse de l'application.

```python
try:
    from src.reporter import HTMLReporter
    _REPORTER_AVAILABLE = True
except ImportError:
    _REPORTER_AVAILABLE = False
```

### Conversion LogEntry → dict

Les objets `LogEntry` produits par `LogParser` sont convertis en dictionnaires Python avant d'être transmis aux modules `AttackDetector` et `LogStatistics`. Cette décision de conception découple les modules en aval du dataclass `LogEntry`, les rendant utilisables avec n'importe quelle source de données structurée.
