# detector.py — Module de détection d'attaques

## Rôle

`detector.py` est le cœur analytique de Log Sentinel. Son rôle est d'examiner les entrées de logs HTTP (représentées sous forme de dictionnaires Python) et d'y détecter trois grandes familles de menaces : les attaques par signature (injection SQL, XSS, traversée de chemin, etc.), les attaques par force brute (accumulation d'erreurs 401/403 depuis une même IP), et les scans de reconnaissance (exploration massive de ressources inexistantes). En sortie, il produit une liste d'objets `Alert` structurés, prêts à être consommés par les couches de rapport ou d'export du projet.

---

## Dataclass `Alert`

La dataclass `Alert` est le format de sortie unifié pour toute détection. Elle regroupe, dans un objet immuable et lisible, toutes les informations nécessaires pour qualifier et tracer une menace.

```python
@dataclass
class Alert:
    attack_type: str   # Catégorie de l'attaque détectée
    ip: str            # Adresse IP source de la requête
    uri: str           # URI ciblée dans la requête HTTP
    user_agent: str    # User-Agent de la requête
    details: str       # Message explicatif libre sur la détection
```

| Champ         | Type  | Description                                                      |
|---------------|-------|------------------------------------------------------------------|
| `attack_type` | `str` | Identifiant de la catégorie d'attaque (ex. `"sql_injection"`)    |
| `ip`          | `str` | Adresse IP de l'attaquant ou du scanner                          |
| `uri`         | `str` | Chemin de la ressource ciblée (ex. `/admin?id=1 OR 1=1`)         |
| `user_agent`  | `str` | En-tête `User-Agent` envoyé par le client                        |
| `details`     | `str` | Message contextuel décrivant pourquoi l'alerte a été levée       |

L'utilisation d'une `dataclass` garantit que chaque alerte est un objet structuré, comparable et facilement sérialisable, sans écrire de `__init__` manuellement.

---

## Dictionnaire `ATTACK_PATTERNS`

`ATTACK_PATTERNS` est un dictionnaire global qui associe chaque type d'attaque à une expression régulière précompilée (`re.Pattern`). La précompilation via `re.compile()` est effectuée une seule fois au chargement du module, ce qui optimise les performances lors de l'analyse de milliers de lignes de logs.

```python
ATTACK_PATTERNS: dict[str, re.Pattern] = {
    "sql_injection":      re.compile(r"UNION\s+SELECT|OR\s+1\s*=\s*1|DROP\s+TABLE|...", re.IGNORECASE),
    "xss":                re.compile(r"<script|javascript:|onerror\s*=|...",            re.IGNORECASE),
    "path_traversal":     re.compile(r"\.\./|\.\.\\|/etc/passwd|...",                   re.IGNORECASE),
    "command_injection":  re.compile(r";ls|\|cat|\$\(|&&rm|`whoami`",                   re.IGNORECASE),
    "sensitive_files":    re.compile(r"\.env|\.git|\.htaccess|wp-config\.php|...",      re.IGNORECASE),
    "malicious_ua":       re.compile(r"sqlmap|nikto|nmap|burp|wpscan|...",              re.IGNORECASE),
}
```

| Clé                 | Cible analysée | Exemples de motifs détectés                              |
|---------------------|----------------|----------------------------------------------------------|
| `sql_injection`     | URI            | `UNION SELECT`, `OR 1=1`, `DROP TABLE`, commentaires SQL |
| `xss`               | URI            | `<script>`, `javascript:`, `onerror=`, `alert(`          |
| `path_traversal`    | URI            | `../`, `/etc/passwd`, `/etc/shadow`, `C:\Windows`        |
| `command_injection` | URI            | `;ls`, `\|cat`, `$()`, `&&rm`, `` `whoami` ``            |
| `sensitive_files`   | URI            | `.env`, `.git`, `.htaccess`, `wp-config.php`, `id_rsa`   |
| `malicious_ua`      | User-Agent     | `sqlmap`, `nikto`, `nmap`, `burp`, `wpscan`, `metasploit`|

Le flag `re.IGNORECASE` est appliqué à tous les patterns, rendant la détection insensible à la casse (`UNION`, `union`, `Union` sont tous interceptés).

---

## Classe `AttackDetector`

`AttackDetector` est la classe principale du module. Elle encapsule toute la logique de détection et expose une interface simple via sa méthode publique `analyze()`.

### `CONFIG`

```python
CONFIG: dict[str, int] = {
    "BRUTE_FORCE_THRESHOLD": 5,
    "SCAN_THRESHOLD": 10,
}
```

`CONFIG` est un attribut de classe (partagé par toutes les instances) qui centralise les seuils de détection comportementale. Cela permet de les modifier en un seul endroit sans toucher à la logique des méthodes.

| Paramètre               | Valeur par défaut | Signification                                                              |
|-------------------------|-------------------|----------------------------------------------------------------------------|
| `BRUTE_FORCE_THRESHOLD` | `5`               | Nombre minimum d'erreurs 401/403 depuis une même IP pour déclencher une alerte |
| `SCAN_THRESHOLD`        | `10`              | Nombre minimum d'URIs distinctes pour qualifier un scan de reconnaissance  |

---

### `detect_signature(entry: dict) -> list[Alert]`

**Objectif** : Analyser une unique entrée de log et y rechercher des signatures d'attaques connues.

**Entrée** : un dictionnaire représentant une ligne de log, avec au minimum les clés `ip`, `uri` et `user_agent`.

**Logique** :
- Parcourt les 5 premiers patterns (hors `malicious_ua`) et les applique sur le champ `uri`.
- Applique le pattern `malicious_ua` sur le champ `user_agent`.
- Pour chaque correspondance trouvée, crée et retourne un objet `Alert`.

**Sortie** : une liste d'`Alert` (potentiellement vide si aucune signature ne correspond).

```python
# Exemple d'entrée
entry = {
    "ip": "192.168.1.42",
    "uri": "/search?q=1' OR '1'='1",
    "user_agent": "Mozilla/5.0"
}

# Sortie attendue
[Alert(attack_type="sql_injection", ip="192.168.1.42", uri="/search?q=1' OR '1'='1", ...)]
```

---

### `detect_brute_force(entries: list[dict]) -> list[Alert]`

**Objectif** : Détecter les tentatives de force brute en analysant un ensemble de logs.

**Entrée** : une liste de dictionnaires de logs, chacun possédant au minimum les clés `ip` et `status` (code de réponse HTTP).

**Logique** :
1. Utilise `Counter` pour compter le nombre de réponses `401` (Unauthorized) ou `403` (Forbidden) par adresse IP.
2. Compare ce compteur au seuil `BRUTE_FORCE_THRESHOLD`.
3. Lève une alerte pour chaque IP dont le nombre de refus dépasse le seuil.

**Sortie** : une liste d'`Alert` de type `"brute_force"`.

```python
# Schéma de la logique
counts = Counter(entry["ip"] for entry in entries if entry["status"] in (401, 403))
for ip, count in counts.items():
    if count > self.CONFIG["BRUTE_FORCE_THRESHOLD"]:
        alerts.append(Alert(attack_type="brute_force", ip=ip, ...))
```

---

### `detect_scan(entries: list[dict]) -> list[Alert]`

**Objectif** : Identifier les comportements de scan de reconnaissance (exploration automatique de ressources).

**Entrée** : une liste de dictionnaires de logs, avec au minimum les clés `ip`, `uri` et `status`.

**Logique** :
1. Utilise `defaultdict(set)` pour regrouper les URIs distinctes consultées par chaque IP.
2. Pour chaque IP, vérifie deux conditions simultanées :
   - Le nombre d'URIs distinctes dépasse `SCAN_THRESHOLD`.
   - Plus de 50 % des requêtes de cette IP ont retourné un code `404` (Not Found).
3. Si les deux conditions sont réunies, une alerte de type `"scan"` est levée.

**Sortie** : une liste d'`Alert` de type `"scan"`.

```python
# Schéma de la logique
uris_by_ip = defaultdict(set)
for entry in entries:
    uris_by_ip[entry["ip"]].add(entry["uri"])

for ip, uris in uris_by_ip.items():
    total = len([e for e in entries if e["ip"] == ip])
    not_found = len([e for e in entries if e["ip"] == ip and e["status"] == 404])
    if len(uris) > SCAN_THRESHOLD and (not_found / total) > 0.5:
        alerts.append(Alert(attack_type="scan", ip=ip, ...))
```

---

### `analyze(entries: list[dict]) -> list[Alert]`

**Objectif** : Méthode publique principale. Orchestrer les trois détections sur l'intégralité des logs fournis.

**Entrée** : une liste complète de dictionnaires de logs.

**Logique** :
1. Appelle `detect_signature()` sur chaque entrée individuelle (boucle sur `entries`).
2. Appelle `detect_brute_force()` sur la liste complète.
3. Appelle `detect_scan()` sur la liste complète.
4. Concatène toutes les alertes produites et retourne la liste unifiée.

**Sortie** : une liste consolidée de tous les objets `Alert` détectés, toutes méthodes confondues.

```python
def analyze(self, entries: list[dict]) -> list[Alert]:
    alerts = []
    for entry in entries:
        alerts.extend(self.detect_signature(entry))
    alerts.extend(self.detect_brute_force(entries))
    alerts.extend(self.detect_scan(entries))
    return alerts
```

---

## Flux de données

```
Entrée : list[dict]  (logs HTTP parsés)
         │
         ├──► detect_signature(entry)    ──► Matching regex uri / user_agent
         │         (par entrée)               └──► Alert(attack_type, ip, uri, ...)
         │
         ├──► detect_brute_force(entries) ──► Counter(ip) sur codes 401/403
         │         (sur l'ensemble)            └──► Alert("brute_force", ip, ...)
         │
         └──► detect_scan(entries)        ──► defaultdict(set) URIs + ratio 404
                   (sur l'ensemble)            └──► Alert("scan", ip, ...)
                                                        │
                                                        ▼
                                          Sortie : list[Alert]  (alertes unifiées)
```

Chaque méthode est indépendante et peut être invoquée séparément à des fins de test ou de débogage. `analyze()` est le point d'entrée unique pour une analyse complète.

---

## Points clés techniques

- **`@dataclass`** : génère automatiquement `__init__`, `__repr__` et `__eq__` pour la classe `Alert`, rendant le code plus concis et les objets plus faciles à comparer dans les tests unitaires.

- **`re.compile()`** : précompile les expressions régulières une seule fois au chargement du module. Sur un fichier de logs de 100 000 lignes, cela évite de recompiler chaque pattern à chaque appel et réduit significativement le temps d'exécution.

- **`Counter`** (module `collections`) : structure optimisée pour le comptage d'occurrences. Utilisée dans `detect_brute_force()` pour agréger rapidement le nombre d'erreurs par IP en une seule passe sur la liste.

- **`defaultdict(set)`** (module `collections`) : dictionnaire qui crée automatiquement un `set` vide pour chaque nouvelle clé. Utilisé dans `detect_scan()` pour accumuler les URIs uniques par IP sans avoir à vérifier l'existence de la clé au préalable.

- **`set`** : la collection d'URIs par IP est un `set` (ensemble), ce qui garantit que chaque URI n'est comptabilisée qu'une seule fois, même si elle apparaît plusieurs fois dans les logs. C'est ce qui permet de mesurer la *diversité* des ressources consultées, critère central de la détection de scan.

- **`re.IGNORECASE`** : flag appliqué à tous les patterns pour rendre la détection robuste face aux variations de casse dans les payloads d'attaque (`<SCRIPT>`, `<Script>`, `<script>` sont tous interceptés).

- **Attribut de classe `CONFIG`** : les seuils sont définis au niveau de la classe et non de l'instance, ce qui facilite leur modification globale ou leur surcharge dans des sous-classes pour des contextes d'analyse différents (environnement de prod vs. environnement de test).
