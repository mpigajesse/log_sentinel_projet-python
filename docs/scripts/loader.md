# loader.py — Module de chargement des logs

## Rôle

Le module `loader.py` est le **point d'entrée des données** dans Log Sentinel. Il assure deux responsabilités distinctes et complémentaires :

1. **Lire** un fichier de logs depuis le système de fichiers, en gérant les problèmes d'encodage fréquents dans les environnements hétérogènes.
2. **Identifier automatiquement** le format du fichier (Apache, Nginx, Syslog ou inconnu) afin que les modules en aval puissent appliquer le bon parseur.

Ce module est volontairement **sans dépendance externe** : il n'utilise que la bibliothèque standard Python (`re`, `os`, `pathlib`), ce qui garantit sa portabilité et sa robustesse dans tout environnement cybersécurité.

---

## Constantes de classe

La classe `LogLoader` définit deux constantes de classe qui pilotent son comportement interne.

| Constante       | Type        | Valeur par défaut | Rôle                                                                          |
|-----------------|-------------|-------------------|-------------------------------------------------------------------------------|
| `_SAMPLE_SIZE`  | `int`       | `10`              | Nombre de lignes analysées pour détecter le format                            |
| `_ENCODINGS`    | `list[str]` | `["utf-8", "latin-1"]` | Ordre de tentative de décodage lors de la lecture du fichier            |

### Pourquoi ces valeurs ?

**`_SAMPLE_SIZE = 10`**

Les fichiers de logs sont souvent volumineux (plusieurs gigaoctets). Analyser l'intégralité du fichier pour en détecter le format serait inefficace. Les 10 premières lignes constituent un échantillon statistiquement représentatif : les logs sont homogènes par nature, chaque ligne suivant le même gabarit. Cette valeur offre un bon compromis entre fiabilité de la détection et performance.

**`_ENCODINGS = ["utf-8", "latin-1"]`**

Les fichiers de logs proviennent de systèmes d'exploitation, de serveurs web ou d'équipements réseau dont les encodages varient. L'ordre de tentative est intentionnel :

- **UTF-8** est l'encodage moderne standard, prioritaire car il couvre la quasi-totalité des systèmes Linux/Unix récents.
- **Latin-1 (ISO-8859-1)** est le repli pour les systèmes plus anciens ou les logs Windows qui contiennent des caractères accentués hors de la plage ASCII.

Ce mécanisme de **fallback** évite une erreur bloquante `UnicodeDecodeError` sur des fichiers légitimes mais non-UTF-8.

---

## Méthode `load(filepath)`

### Signature

```python
def load(self, filepath: str) -> list[str]:
```

### Description

Lit un fichier de logs et retourne son contenu sous forme de liste de lignes (chaînes de caractères). Chaque élément de la liste correspond à une ligne du fichier.

### Paramètres

| Paramètre  | Type  | Description                                                  |
|------------|-------|--------------------------------------------------------------|
| `filepath` | `str` | Chemin absolu ou relatif vers le fichier de logs à charger   |

### Valeur de retour

| Type         | Description                                              |
|--------------|----------------------------------------------------------|
| `list[str]`  | Liste des lignes du fichier (sans le caractère `\n` final si les lignes sont strippées) |

### Exceptions levées

| Exception             | Condition de déclenchement                                                  |
|-----------------------|-----------------------------------------------------------------------------|
| `FileNotFoundError`   | Le fichier indiqué par `filepath` n'existe pas sur le système de fichiers   |
| `UnicodeDecodeError`  | Le fichier ne peut être décodé ni en UTF-8 ni en Latin-1                    |
| `OSError`             | Erreur système générique (permissions insuffisantes, fichier verrouillé, disque défaillant, etc.) |

### Fonctionnement du fallback d'encodage

La méthode délègue la lecture brute à `_read_raw()`. Elle l'appelle successivement avec chaque encodage de `_ENCODINGS`, dans l'ordre :

```
load(filepath)
    │
    ├─► _read_raw(path, "utf-8")  ──── succès ? ──► retourne les lignes
    │
    └─► _read_raw(path, "latin-1") ─── succès ? ──► retourne les lignes
                                  └─── échec   ? ──► propage UnicodeDecodeError
```

Ce comportement garantit qu'un fichier mal encodé n'interrompt pas brutalement l'analyse, tant qu'un encodage de la liste permet de le lire.

---

## Méthode `detect_format(lines)`

### Signature

```python
def detect_format(self, lines: list[str]) -> str:
```

### Description

Analyse un échantillon de lignes pour déterminer le format du fichier de logs. Elle retourne une chaîne identifiant le format détecté, ou `"unknown"` si aucun format connu ne correspond.

### Paramètres

| Paramètre | Type        | Description                                   |
|-----------|-------------|-----------------------------------------------|
| `lines`   | `list[str]` | Liste des lignes issues de la méthode `load()` |

### Valeur de retour

| Valeur retournée | Signification                                          |
|------------------|--------------------------------------------------------|
| `"apache"`       | Format Combined Log Format d'Apache HTTP Server        |
| `"nginx"`        | Format access log de Nginx                             |
| `"syslog"`       | Format Syslog standard (RFC 3164)                      |
| `"unknown"`      | Aucun des formats connus n'a été identifié             |

### Algorithme de scoring pas-à-pas

La détection repose sur un **vote majoritaire par expression régulière**, en quatre étapes :

**Etape 1 — Echantillonnage**

Seules les `_SAMPLE_SIZE` (10) premières lignes sont examinées, évitant de parcourir un fichier entier.

```python
sample = lines[:self._SAMPLE_SIZE]
```

**Etape 2 — Initialisation des compteurs**

Un compteur de correspondances est initialisé à zéro pour chaque format connu.

```python
scores = {"apache": 0, "nginx": 0, "syslog": 0}
```

**Etape 3 — Test de chaque ligne contre les trois patterns**

Pour chaque ligne de l'échantillon, les trois expressions régulières compilées au niveau du module sont testées. Chaque correspondance incrémente le score du format concerné.

```python
for line in sample:
    if _NGINX_PATTERN.match(line):
        scores["nginx"] += 1
    elif _APACHE_PATTERN.match(line):
        scores["apache"] += 1
    elif _SYSLOG_PATTERN.match(line):
        scores["syslog"] += 1
```

> Note : l'ordre de test **Nginx avant Apache** est important. Le pattern Nginx est plus strict (il exige la présence du user-agent et du referrer) ; tester Apache en premier produirait des faux positifs sur des logs Nginx.

**Etape 4 — Sélection du format gagnant**

Le format ayant obtenu le score le plus élevé est retourné. Si tous les scores sont à zéro, la méthode retourne `"unknown"`.

```python
best = max(scores, key=scores.get)
return best if scores[best] > 0 else "unknown"
```

### Tableau des formats, patterns et exemples

| Format   | Pattern clé (simplifié)                                                    | Exemple de ligne                                                                                                                  |
|----------|----------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------|
| `apache` | `IP DATE "METHODE URI HTTP/x.x" CODE`                                      | `192.168.1.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200`                                            |
| `nginx`  | `IP - - DATE "METHODE URI HTTP/x.x" CODE TAILLE "REFERRER" "USER-AGENT"`  | `192.168.1.1 - - [10/Oct/2000:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 612 "http://example.com" "Mozilla/5.0 (...)"`       |
| `syslog` | `MMM JJ HH:MM:SS HOTE SERVICE:`                                            | `Mar 28 14:22:01 srv-prod sshd: Failed password for root from 10.0.0.1 port 22`                                                 |

### Expressions régulières détaillées

Les patterns sont compilés **une seule fois** au chargement du module (niveau module, hors classe), ce qui optimise les performances lors d'appels répétés.

```python
# Apache — présence de la date entre crochets et du code HTTP, sans contrainte sur referrer/user-agent
_APACHE_PATTERN = re.compile(
    r'^\S+\s+\S+\s+\S+\s+'                    # IP identd user
    r'\[\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4}\]\s+'  # [date timezone]
    r'"[A-Z]+\s+\S+\s+HTTP/\d\.\d"\s+\d{3}'  # "METHODE URI HTTP/x.x" CODE
)

# Nginx — plus strict : referrer et user-agent obligatoires
_NGINX_PATTERN = re.compile(
    r'^\S+\s+-\s+-\s+'                          # IP - -
    r'\[\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4}\]\s+'
    r'"[A-Z]+\s+\S+\s+HTTP/\d\.\d"\s+\d{3}\s+\d+\s+'  # CODE TAILLE
    r'"[^"]*"\s+"[^"]*"'                         # "referrer" "user-agent"
)

# Syslog — mois abrégé, jour, heure, hôte, service suivi de deux-points
_SYSLOG_PATTERN = re.compile(
    r'^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+'
    r'\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+:'
)
```

---

## Exemple d'utilisation

```python
from src.loader import LogLoader

loader = LogLoader()

# 1. Chargement du fichier
try:
    lines = loader.load("/var/log/nginx/access.log")
except FileNotFoundError:
    print("Fichier introuvable.")
except UnicodeDecodeError:
    print("Encodage non supporté.")
except OSError as e:
    print(f"Erreur système : {e}")

# 2. Détection du format
fmt = loader.detect_format(lines)
print(f"Format détecté : {fmt}")
# Affiche par exemple : Format détecté : nginx

# 3. Passage au parseur approprié
if fmt == "nginx":
    # parser_nginx.parse(lines)
    pass
elif fmt == "apache":
    # parser_apache.parse(lines)
    pass
elif fmt == "syslog":
    # parser_syslog.parse(lines)
    pass
else:
    print("Format inconnu — analyse manuelle requise.")
```

Flux complet dans Log Sentinel :

```
Fichier .log
    │
    ▼
LogLoader.load()          ──► list[str]  (toutes les lignes)
    │
    ▼
LogLoader.detect_format() ──► str       ("nginx" | "apache" | "syslog" | "unknown")
    │
    ▼
Parseur dédié            ──► structures de données normalisées
    │
    ▼
Moteur d'analyse / alertes
```

---

## Points clés techniques

### Utilisation de `pathlib.Path`

La méthode interne `_read_raw()` accepte un objet `pathlib.Path` plutôt qu'une chaîne brute. `pathlib` offre plusieurs avantages par rapport à la manipulation de chaînes avec `os.path` :

- **Portabilité** : gestion transparente des séparateurs `/` et `\` entre Linux et Windows.
- **Lisibilité** : les opérations sur les chemins sont exprimées de manière orientée objet (`path.exists()`, `path.suffix`, `path.parent`).
- **Sécurité** : la conversion depuis `str` vers `Path` normalise le chemin, réduisant les risques d'injection de chemin (`path traversal`).

```python
# Conversion implicite dès l'entrée dans load()
path = Path(filepath)
```

### Fallback d'encodage

Le mécanisme de fallback est une pratique courante en analyse forensique et cybersécurité : les fichiers de preuves ou de journaux ne sont pas toujours maîtrisés (systèmes tiers, exports d'équipements réseau, logs Windows hérités). Ne pas anticiper les variantes d'encodage rendrait l'outil fragile face à des fichiers pourtant valides.

La stratégie adoptée est conservatrice : on tente les encodages dans un ordre du plus strict au plus permissif. `latin-1` (ISO-8859-1) est un encodage dit « sans perte » — chaque octet est un caractère valide — ce qui garantit qu'aucun fichier texte ne peut lever une `UnicodeDecodeError` lors du décodage en `latin-1`. Il constitue donc un filet de sécurité efficace.

### Scoring par vote majoritaire

Le choix d'un algorithme de **vote** plutôt que d'une détection sur la première ligne offre deux bénéfices :

1. **Robustesse aux lignes atypiques** : certains fichiers de logs contiennent des lignes d'en-tête, des commentaires ou des entrées malformées en début de fichier. Un vote sur 10 lignes absorbe ces anomalies.
2. **Confiance statistique** : un score de 8/10 pour `nginx` est bien plus fiable qu'un simple test de la première ligne. En contexte de cybersécurité, la fiabilité de la classification conditionne directement la pertinence des alertes générées en aval.

| Approche           | Avantage                       | Inconvénient                              |
|--------------------|--------------------------------|-------------------------------------------|
| Première ligne     | Rapide, simple                 | Fragile si la première ligne est atypique |
| Vote sur N lignes  | Robuste, fiable statistiquement | Légèrement plus coûteux (négligeable)     |
| Analyse complète   | Maximum de fiabilité           | Inacceptable sur de gros fichiers         |

Le choix de `_SAMPLE_SIZE = 10` positionne Log Sentinel dans la deuxième catégorie, ce qui constitue le meilleur compromis pour un outil d'analyse de logs de sécurité.
