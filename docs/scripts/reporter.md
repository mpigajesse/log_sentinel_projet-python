# reporter.py — Module de génération du rapport HTML

## Rôle

`reporter.py` est le module de **présentation finale** de Log Sentinel. Son rôle est de transformer les données brutes produites par le pipeline d'analyse (alertes, statistiques, données OSINT) en un **fichier HTML autonome et lisible**, prêt à être remis ou archivé.

Le rapport généré est entièrement **auto-contenu** : aucun fichier CSS externe, aucune dépendance JavaScript, aucune requête réseau. Tout le style est embarqué dans la balise `<style>` du document. Cela garantit qu'il s'affiche correctement hors-ligne, dans tout navigateur moderne.

Le module n'importe que la bibliothèque standard Python (`html`, `os`, `datetime`, `pathlib`) : **zéro dépendance tierce**.

---

## Architecture du rapport HTML généré

Le document HTML produit est composé de neuf sections assemblées dans l'ordre suivant par la méthode `generate()` :

| Ordre | Section | Fonction de rendu | Description |
|-------|---------|-------------------|-------------|
| 1 | En-tête | `_render_header()` | Titre, date de génération, badge « BLUE TEAM » |
| 2 | Score de risque global | `_render_risk()` | Score numérique 0-100, barre de progression colorée, décomposition par type |
| 3 | Statistiques globales | `_render_stats()` | 4 cartes : requêtes totales, IPs uniques, taux d'erreur, nombre d'alertes |
| 4 | Tableau des alertes | `_render_alerts()` | Tableau complet : badge type, IP, URI, détails |
| 5 | Top 10 IPs | `_render_top_ips()` | Classement des IPs par volume de requêtes |
| 6 | Top URIs | `_render_top_uris()` | Classement des ressources les plus demandées |
| 7 | Distribution des codes HTTP | `_render_http_codes()` | Tableau codes HTTP triés, colorés par famille |
| 8 | Données OSINT | `_render_osint()` | Cartes géolocalisation par IP (pays, ville, ISP) |
| 9 | Pied de page | `_render_footer()` | Date de génération, mention d'usage interne |

```
┌─────────────────────────────────────────┐
│  HEADER  (titre + horodatage + badge)   │
├─────────────────────────────────────────┤
│  SCORE DE RISQUE  (jauge 0-100)         │
├─────────────────────────────────────────┤
│  STATS  (4 cartes)                      │
├─────────────────────────────────────────┤
│  ALERTES  (tableau complet)             │
├──────────────────┬──────────────────────┤
│  TOP IPs         │  TOP URIs            │
├──────────────────┴──────────────────────┤
│  CODES HTTP  (distribution)             │
├─────────────────────────────────────────┤
│  OSINT  (cartes géolocalisation)        │
├─────────────────────────────────────────┤
│  FOOTER                                 │
└─────────────────────────────────────────┘
```

---

## Calcul du score de risque

### Tableau des points par type d'attaque

Le score est calculé en attribuant un **nombre de points fixe** à chaque type d'attaque détecté, puis en additionnant les contributions de toutes les alertes présentes.

| Type d'attaque | Constante | Points |
|----------------|-----------|--------|
| `brute_force` | `ATTACK_SCORES["brute_force"]` | **25** |
| `sqli` | `ATTACK_SCORES["sqli"]` | **20** |
| `command_injection` | `ATTACK_SCORES["command_injection"]` | **20** |
| `xss` | `ATTACK_SCORES["xss"]` | **15** |
| `path_traversal` | `ATTACK_SCORES["path_traversal"]` | **15** |
| `scan` | `ATTACK_SCORES["scan"]` | **10** |
| `sensitive_files` | `ATTACK_SCORES["sensitive_files"]` | **10** |
| `malicious_ua` | `ATTACK_SCORES["malicious_ua"]` | **5** |

### Formule appliquée dans `reporter.py`

```python
ATTACK_SCORES = {
    "sqli":               20,
    "xss":                15,
    "brute_force":        25,
    "scan":               10,
    "path_traversal":     15,
    "command_injection":  20,
    "sensitive_files":    10,
    "malicious_ua":        5,
}

score = sum(ATTACK_SCORES.get(alert["type"], 0) for alert in alerts)
score = min(score, 100)
```

- Chaque alerte contribue individuellement selon son type.
- Un type inconnu contribue `0` (valeur par défaut du `.get()`).
- Le score est **plafonné à 100** via `min(score, 100)`.

### Exemple de calcul

Pour un rapport contenant 2 alertes `sqli` (2 × 20 = 40) et 1 alerte `brute_force` (1 × 25 = 25) :

```
score = 40 + 25 = 65  →  "RISQUE MODERE"
```

### Niveaux de risque

| Score | Classe CSS | Libellé | Couleur de la barre |
|-------|-----------|---------|---------------------|
| 0 – 29 | `low` | RISQUE FAIBLE | `#56d364` (vert) |
| 30 – 69 | `medium` | RISQUE MODERE | `#ffa657` (orange) |
| 70 – 100 | `high` | RISQUE ELEVE | `#f85149` (rouge) |

### Différence avec le score de `main.py` / `app.py`

> **Point important pour le jury** : il existe **deux formules de score de risque différentes** dans Log Sentinel.

| | `reporter.py` | `main.py` / `app.py` |
|--|--------------|----------------------|
| **Méthode** | Somme pondérée par type d'alerte | Formule composite à trois composantes |
| **Formule** | `sum(ATTACK_SCORES.get(type, 0) for alert in alerts)` | `min(50, n_alertes × 2) + min(30, error_rate × 0.6) + (20 si type grave présent)` |
| **Données utilisées** | Liste d'alertes uniquement | Alertes + taux d'erreur HTTP + présence de types graves |
| **Plafond** | 100 | 100 (somme des trois termes) |
| **Localisation** | Fonction `_compute_risk_score()` | Fonction `_calculer_score_risque()` |

Le score affiché dans le **rapport HTML** est donc celui de `reporter.py`, plus granulaire et directement lié aux types d'attaques détectés.

---

## Classe `HTMLReporter`

```python
class HTMLReporter:
    """Génère un rapport HTML autonome (CSS inline) pour Log Sentinel."""
```

`HTMLReporter` est la **seule classe** du module. Elle sert de point d'entrée unique pour la génération du rapport. Son constructeur ne prend aucun paramètre : toute la configuration est passée directement à la méthode `generate()`.

### `generate(alerts, stats, osint_data, output_path)`

```python
def generate(
    self,
    alerts: list,
    stats: dict,
    osint_data: dict,
    output_path: str,
) -> str:
```

**Paramètres :**

| Paramètre | Type | Description |
|-----------|------|-------------|
| `alerts` | `list` | Liste de dictionnaires décrivant chaque alerte détectée. Chaque dict doit comporter au minimum les clés `type`, `ip`, `uri` (ou `url`) et `details` (ou `message`). |
| `stats` | `dict` | Dictionnaire de statistiques globales produit par `LogStatistics.compute()`. Clés attendues : `total_requests`, `unique_ips`, `error_rate`, `total_alerts`, `top_ips`, `top_uris`, `status_codes`. |
| `osint_data` | `dict` | Dictionnaire `{ip: {country, city, isp, ...}}` produit par `OSINTChecker.check_ips()`. Peut être vide (`{}`). |
| `output_path` | `str` | Chemin du fichier HTML à créer. Le répertoire parent est créé automatiquement s'il n'existe pas. |

**Retour :** `str` — chemin absolu du fichier HTML créé (résolu via `Path.resolve()`).

**Comportement interne :**

```python
generated_at = datetime.now().strftime("%d/%m/%Y à %H:%M:%S")

body = (
    _render_header(generated_at)
    + '<div class="container">'
    + _render_risk(alerts)
    + _render_stats(stats)
    + _render_alerts(alerts)
    + _render_top_ips(stats)
    + _render_top_uris(stats)
    + _render_http_codes(stats)
    + _render_osint(osint_data)
    + _render_footer(generated_at)
    + "</div>"
)
```

1. L'horodatage de génération est capturé une seule fois et transmis aux fonctions qui en ont besoin (`_render_header`, `_render_footer`).
2. Le corps HTML est construit par **concaténation de chaînes** retournées par chaque fonction de rendu.
3. Le document complet est encapsulé dans une structure `<!DOCTYPE html>` valide, avec la balise `<style>` contenant la constante `CSS`.
4. Le fichier est écrit via `Path.write_text(..., encoding="utf-8")`.
5. Le répertoire de destination est créé si nécessaire via `Path.mkdir(parents=True, exist_ok=True)`.

**Exemple d'utilisation :**

```python
from log_sentinel.src.reporter import HTMLReporter

reporter = HTMLReporter()
output = reporter.generate(
    alerts=alerts,
    stats=stats,
    osint_data=osint_data,
    output_path="reports/rapport_2026-03-28.html"
)
print(f"Rapport généré : {output}")
# → Rapport généré : C:\...\reports\rapport_2026-03-28.html
```

---

## Fonctions privées importantes

Les fonctions préfixées par `_` sont des **helpers internes** du module. Elles ne font pas partie de l'interface publique et ne doivent pas être appelées directement depuis l'extérieur du module.

### `_h(value)`

```python
def _h(value: object) -> str:
    """Échappe une valeur pour insertion HTML."""
    return html.escape(str(value) if value is not None else "")
```

**Rôle** : sécuriser toute valeur avant son insertion dans le HTML généré.

- Accepte n'importe quel type (`object`) et le convertit en chaîne via `str()`.
- Gère le cas `None` en retournant une chaîne vide.
- Délègue l'échappement à `html.escape()` de la bibliothèque standard, qui substitue les caractères dangereux :

| Caractère | Substitution |
|-----------|-------------|
| `&` | `&amp;` |
| `<` | `&lt;` |
| `>` | `&gt;` |
| `"` | `&quot;` |

> **Importance en cybersécurité** : sans `_h()`, une URI malveillante contenant `<script>alert(1)</script>` serait injectée telle quelle dans le rapport HTML, créant une faille XSS dans le rapport lui-même. `_h()` est donc appelée **systématiquement** sur toutes les données dynamiques (IPs, URIs, détails d'alertes, valeurs OSINT).

```python
# Exemple
_h('<script>alert("xss")</script>')
# → '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'

_h(None)
# → ''

_h(404)
# → '404'
```

---

### `_compute_risk_score(alerts)`

```python
def _compute_risk_score(alerts: list) -> int:
    """Calcule le score de risque global (0-100) à partir de la liste d'alertes."""
    score = 0
    for alert in alerts:
        attack_type = str(alert.get("type", "")).lower()
        score += ATTACK_SCORES.get(attack_type, 0)
    return min(score, 100)
```

**Rôle** : calculer le score de risque numérique utilisé par `_render_risk()`.

Points de robustesse notables :
- Le type est converti en minuscules via `.lower()` pour éviter les erreurs de casse (`"SQLI"` et `"sqli"` sont traités identiquement).
- `.get("type", "")` évite un `KeyError` si la clé `type` est absente du dictionnaire.
- `ATTACK_SCORES.get(attack_type, 0)` retourne `0` pour tout type inconnu, sans lever d'exception.
- `min(score, 100)` garantit que le score ne dépasse jamais 100, quelle que soit la quantité d'alertes.

---

### `_badge_html(attack_type)`

```python
def _badge_html(attack_type: str) -> str:
    color = BADGE_COLORS.get(str(attack_type).lower(), DEFAULT_BADGE_COLOR)
    return (
        f'<span class="badge-attack" style="background:{color};">'
        f'{_h(attack_type.upper())}</span>'
    )
```

**Rôle** : générer le code HTML d'un badge coloré représentant un type d'attaque dans le tableau des alertes.

- La couleur est lue depuis le dictionnaire `BADGE_COLORS`. Si le type est inconnu, la constante `DEFAULT_BADGE_COLOR` (`#8b949e`, gris) est utilisée.
- Le libellé du badge est affiché en majuscules (`SQLI`, `XSS`, `BRUTE_FORCE`…).
- Le texte passe par `_h()` pour échapper les éventuels caractères spéciaux.

**Palette de couleurs `BADGE_COLORS` :**

| Type d'attaque | Couleur hex | Rendu visuel |
|----------------|-------------|-------------|
| `sqli` | `#f85149` | Rouge vif |
| `command_injection` | `#f85149` | Rouge vif |
| `xss` | `#ff7b72` | Rouge clair |
| `brute_force` | `#ffa657` | Orange |
| `path_traversal` | `#ffa657` | Orange |
| `scan` | `#d2a8ff` | Violet |
| `sensitive_files` | `#79c0ff` | Bleu clair |
| `malicious_ua` | `#56d364` | Vert |
| *(inconnu)* | `#8b949e` | Gris |

---

## Points clés techniques

| Point | Détail |
|-------|--------|
| **`html.escape()`** | Utilisé via le wrapper `_h()` sur toutes les données dynamiques. Prévient toute injection HTML ou XSS dans le rapport lui-même, ce qui est essentiel pour un outil de sécurité. |
| **`pathlib.Path`** | Employé pour l'écriture du fichier (`write_text`) et la création du répertoire parent (`mkdir(parents=True, exist_ok=True)`). Gère correctement les chemins multi-plateformes (Windows, Linux, macOS). |
| **CSS embarqué (inline)** | La constante `CSS` est une chaîne de 270+ lignes de CSS injectée dans la balise `<style>` du document. Le thème est sombre (dark theme), inspiré de l'interface GitHub, avec une palette monochrome adaptée aux terminaux de sécurité. |
| **Aucune dépendance externe** | Le module n'utilise que `html`, `os`, `datetime` et `pathlib`, tous issus de la bibliothèque standard Python. Aucun `pip install` n'est requis pour faire fonctionner ce module. |
| **Robustesse aux formats variés** | Les fonctions `_render_top_ips()` et `_render_top_uris()` acceptent indifféremment des listes de tuples `(ip, count)` ou des listes de dictionnaires `{ip: ..., count: ...}`, ce qui les rend compatibles avec différentes implémentations de `LogStatistics`. |
| **Sections vides gracieuses** | Chaque fonction de rendu gère le cas où ses données sont vides ou absentes : elle retourne une `<div class="empty-notice">` plutôt que de lever une exception ou d'afficher un tableau vide. |
| **Horodatage unique** | La date et l'heure de génération sont capturées une seule fois dans `generate()` et propagées aux fonctions qui en ont besoin, garantissant la cohérence entre le header et le footer. |
| **Couleurs codées par famille HTTP** | Dans `_render_http_codes()`, une fonction interne `_code_color()` associe une couleur à chaque famille de codes (2xx vert, 3xx bleu, 4xx orange, 5xx rouge), facilitant la lecture visuelle de la distribution des réponses. |
