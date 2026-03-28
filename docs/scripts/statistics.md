# statistics.py — Module de statistiques

## Rôle

Le module `statistics.py` est responsable de l'**analyse agrégée** de l'ensemble des entrées de logs parsées par Log Sentinel. Il constitue le moteur statistique du projet : à partir d'une liste brute d'entrées de logs (issues du parsing), il calcule un ensemble d'indicateurs quantitatifs qui permettent de dresser un portrait global du trafic observé.

Ces indicateurs sont ensuite exploités par les autres couches du projet (détection d'anomalies, génération de rapports, interface utilisateur) pour produire une analyse de sécurité cohérente et lisible.

---

## Classe `LogStatistics`

La classe `LogStatistics` encapsule toute la logique de calcul statistique. Elle ne conserve aucun état interne entre deux appels : elle reçoit une liste d'entrées, effectue ses calculs, et retourne un dictionnaire structuré.

```python
class LogStatistics:
    def compute(self, entries: list) -> dict[str, Any]:
        ...
```

### Méthode `compute(entries)`

**Signature :**

```python
def compute(self, entries: list) -> dict[str, Any]
```

**Paramètre :**

| Paramètre | Type   | Description                                                                 |
|-----------|--------|-----------------------------------------------------------------------------|
| `entries` | `list` | Liste des entrées de log parsées (dictionnaires ou objets dataclass)        |

**Valeur de retour :**

La méthode retourne un dictionnaire `dict[str, Any]` contenant les clés suivantes :

| Clé               | Type                        | Description                                                                 |
|-------------------|-----------------------------|-----------------------------------------------------------------------------|
| `total_requests`  | `int`                       | Nombre total d'entrées de log traitées                                      |
| `unique_ips`      | `int`                       | Nombre d'adresses IP sources distinctes                                     |
| `top_ips`         | `list[tuple[str, int]]`     | Les 10 adresses IP les plus actives, triées par fréquence décroissante      |
| `status_codes`    | `dict[str, int]`            | Répartition de toutes les requêtes par code de statut HTTP                  |
| `top_uris`        | `list[tuple[str, int]]`     | Les 10 URI les plus demandées, triées par fréquence décroissante            |
| `top_user_agents` | `list[tuple[str, int]]`     | Les 5 User-Agent les plus fréquents, triés par fréquence décroissante       |
| `methods`         | `dict[str, int]`            | Répartition de toutes les requêtes par méthode HTTP (GET, POST, etc.)       |
| `error_rate`      | `float`                     | Pourcentage de requêtes ayant généré une erreur client (4xx) ou serveur (5xx) |

---

## Fonctionnement interne

### La fonction interne `_get(entry, key)`

Log Sentinel est conçu pour fonctionner avec deux formats de représentation des entrées de log :

- **Dictionnaire Python** (`dict`) : accès par clé, ex. `entry["ip"]`
- **Dataclass Python** (`@dataclass`) : accès par attribut, ex. `entry.ip`

Pour abstraire cette différence et rendre le code de calcul uniforme, une fonction interne `_get(entry, key)` est définie au sein de `compute`. Son rôle est de retourner la valeur associée à `key` quelle que soit la nature de l'objet `entry` :

```python
def _get(entry, key):
    if isinstance(entry, dict):
        return entry.get(key)
    return getattr(entry, key, None)
```

Ainsi, le reste du code peut appeler `_get(entry, "ip")` sans se soucier du type de l'entrée. Cela garantit la **compatibilité ascendante** du module si le format des entrées évolue.

---

### Utilisation de `Counter` et `most_common()`

La classe `Counter` du module standard `collections` est au coeur du moteur statistique. Elle permet de compter efficacement les occurrences de valeurs dans une liste.

**Principe :**

```python
from collections import Counter

ips = [_get(e, "ip") for e in entries]
ip_counter = Counter(ips)
```

`Counter` produit un objet qui se comporte comme un dictionnaire `{valeur: nombre_occurrences}`. La méthode `.most_common(n)` retourne les `n` éléments les plus fréquents, triés par ordre décroissant :

```python
top_ips = ip_counter.most_common(10)
# Exemple : [("192.168.1.1", 342), ("10.0.0.5", 118), ...]
```

Ce mécanisme est utilisé de manière identique pour les URI (`top_uris`) et les User-Agent (`top_user_agents`). Pour `status_codes` et `methods`, le `Counter` entier est converti en dictionnaire classique afin de présenter la distribution complète sans troncature.

---

### Formule du taux d'erreur (`error_rate`)

Le taux d'erreur mesure la proportion de requêtes HTTP ayant abouti à une réponse d'erreur, c'est-à-dire dont le code de statut est compris entre **400 et 599** (erreurs client 4xx et erreurs serveur 5xx).

**Formule :**

```
error_rate = (nombre de requêtes avec code >= 400 et <= 599 / total_requests) * 100
```

**Implémentation :**

```python
error_count = sum(
    count
    for code, count in status_counter.items()
    if 400 <= int(code) <= 599
)
error_rate = (error_count / total_requests * 100) if total_requests > 0 else 0.0
```

Le résultat est exprimé en **pourcentage** (type `float`). La protection contre la division par zéro (`if total_requests > 0`) évite toute exception lorsque la liste d'entrées est vide.

---

## Exemple de résultat

Voici un exemple représentatif du dictionnaire retourné par `compute()` pour une session d'analyse de 1 200 requêtes :

```json
{
    "total_requests": 1200,
    "unique_ips": 47,
    "top_ips": [
        ["203.0.113.42", 312],
        ["198.51.100.7", 198],
        ["10.0.0.15", 145],
        ["192.168.0.3", 97],
        ["203.0.113.8", 82],
        ["172.16.0.22", 74],
        ["198.51.100.99", 61],
        ["10.0.0.1", 53],
        ["203.0.113.55", 48],
        ["192.168.1.100", 44]
    ],
    "status_codes": {
        "200": 876,
        "301": 54,
        "403": 138,
        "404": 89,
        "500": 43
    },
    "top_uris": [
        ["/index.html", 430],
        ["/api/login", 215],
        ["/admin", 138],
        ["/static/app.js", 102],
        ["/api/data", 88],
        ["/robots.txt", 61],
        ["/favicon.ico", 54],
        ["/api/logout", 47],
        ["/contact", 33],
        ["/about", 29]
    ],
    "top_user_agents": [
        ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", 510],
        ["python-requests/2.28.0", 312],
        ["curl/7.88.1", 198],
        ["Googlebot/2.1", 112],
        ["Mozilla/5.0 (iPhone; CPU iPhone OS 16_0)", 68]
    ],
    "methods": {
        "GET": 980,
        "POST": 175,
        "PUT": 28,
        "DELETE": 12,
        "OPTIONS": 5
    },
    "error_rate": 22.5
}
```

> Dans cet exemple, 22,5 % des requêtes ont produit une réponse d'erreur (codes 403, 404 et 500 combinés), ce qui constitue un signal d'alerte pertinent dans un contexte de sécurité.

---

## Points clés techniques

### `collections.Counter`

`Counter` est une sous-classe de `dict` spécialisée dans le comptage d'occurrences. Elle est particulièrement adaptée à l'analyse de logs car :

- Elle accepte directement un itérable en entrée et construit le comptage en une seule passe (complexité O(n)).
- Elle gère nativement les clés absentes (retourne 0 au lieu de lever une `KeyError`).
- Elle offre la méthode `.most_common(n)` qui retourne les n éléments les plus fréquents en O(n log n), sans avoir à trier manuellement.

```python
# Equivalent manuel de Counter + most_common
from collections import Counter

counter = Counter(["GET", "POST", "GET", "GET", "DELETE"])
# Counter({'GET': 3, 'POST': 1, 'DELETE': 1})

counter.most_common(2)
# [('GET', 3), ('POST', 1)]
```

### Compatibilité `dict` / dataclass

Le module `statistics.py` applique le **principe ouvert/fermé** : il est ouvert à l'extension (tout nouveau format d'entrée compatible avec `_get`) sans nécessiter de modification du code de calcul. Cette approche est typique des architectures modulaires robustes.

| Format d'entrée | Accès à la valeur         | Gestion dans `_get`         |
|-----------------|---------------------------|-----------------------------|
| `dict`          | `entry["ip"]`             | `entry.get(key)`            |
| `dataclass`     | `entry.ip`                | `getattr(entry, key, None)` |

### Protection contre les données manquantes

L'utilisation de `.get(key)` pour les dictionnaires et `getattr(entry, key, None)` pour les dataclasses retourne `None` en cas de clé ou d'attribut absent, plutôt que de lever une exception. Cela rend le module **tolérant aux entrées incomplètes**, ce qui est essentiel lors de l'analyse de logs réels susceptibles de contenir des lignes malformées.
