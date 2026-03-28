# parser.py — Module de parsing des logs

## Rôle

Le module `parser.py` est le **coeur analytique** de Log Sentinel. Son rôle est de transformer des lignes de logs brutes (sous forme de chaînes de caractères) en objets Python structurés et exploitables.

Il prend en charge trois formats de logs couramment rencontrés en environnement de production :

| Format    | Utilisation typique                          |
|-----------|----------------------------------------------|
| **Apache Combined Log** | Serveurs web Apache HTTP Server      |
| **Nginx**               | Serveurs web et reverse proxies Nginx |
| **Syslog**              | Journaux système Linux/Unix (auth, kern, etc.) |

Le module expose deux composants principaux :
- la dataclass `LogEntry`, qui représente une entrée de log normalisée ;
- la classe `LogParser`, qui orchestre la reconnaissance et l'extraction des données.

---

## Dataclass `LogEntry`

`LogEntry` est un conteneur de données déclaré avec le décorateur `@dataclass`. Chaque instance représente **une ligne de log analysée**, avec ses champs extraits et normalisés.

| Champ         | Type  | Rôle                                      | Exemple de valeur             |
|---------------|-------|-------------------------------------------|-------------------------------|
| `ip`          | `str` | Adresse IP du client ou de l'hôte source  | `"192.168.1.42"`              |
| `timestamp`   | `str` | Horodatage brut de l'événement            | `"28/Mar/2026:14:05:03 +0200"` |
| `method`      | `str` | Méthode HTTP ou action système            | `"GET"`, `"POST"`             |
| `uri`         | `str` | Chemin de la ressource demandée ou message | `"/admin/login"`, `"Failed password for root"` |
| `status_code` | `str` | Code de statut HTTP                       | `"200"`, `"403"`, `"500"`     |
| `size`        | `str` | Taille de la réponse en octets            | `"1452"`, `"-"` (non défini)  |
| `user_agent`  | `str` | Agent utilisateur du client HTTP          | `"Mozilla/5.0 ..."`           |

Tous les champs sont initialisés à `""` par défaut, ce qui garantit qu'une `LogEntry` est toujours dans un état valide, même si le parsing est partiel.

```python
from dataclasses import dataclass

@dataclass
class LogEntry:
    ip: str = ""
    timestamp: str = ""
    method: str = ""
    uri: str = ""
    status_code: str = ""
    size: str = ""
    user_agent: str = ""
```

> **Note pour le jury** : L'usage de `@dataclass` évite d'écrire manuellement `__init__`, `__repr__` et `__eq__`. C'est un choix de lisibilité et de maintenabilité.

---

## Regex de reconnaissance

Chaque format de log est identifié et découpé par une **expression régulière précompilée**. La précompilation avec `re.compile()` est effectuée une seule fois au chargement du module (niveau module, pas à chaque appel), ce qui optimise les performances lors du traitement de millions de lignes.

| Constante          | Format cible | Description du pattern                                       |
|--------------------|--------------|--------------------------------------------------------------|
| `_APACHE_PATTERN`  | Apache       | IP, date entre `[...]`, méthode, URI, code HTTP, taille, referer, user-agent |
| `_NGINX_PATTERN`   | Nginx        | Identique à Apache (même format Combined Log)               |
| `_SYSLOG_PATTERN`  | Syslog       | Date, hôte, service, message                                 |

### Pattern Apache / Nginx

```python
_APACHE_PATTERN = re.compile(
    r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)"'
)
```

Exemple de ligne reconnue :

```
192.168.1.42 - - [28/Mar/2026:14:05:03 +0200] "GET /index.html HTTP/1.1" 200 1452 "https://example.com" "Mozilla/5.0 (Windows NT 10.0)"
```

Groupes capturés dans l'ordre :

| Groupe | Contenu capturé               |
|--------|-------------------------------|
| 1      | IP client (`192.168.1.42`)    |
| 2      | Timestamp (`28/Mar/2026:...`) |
| 3      | Méthode HTTP (`GET`)          |
| 4      | URI (`/index.html`)           |
| 5      | Code statut (`200`)           |
| 6      | Taille réponse (`1452`)       |
| 7      | Referer (`https://...`)       |
| 8      | User-Agent (`Mozilla/5.0 ...`)|

### Pattern Syslog

```python
_SYSLOG_PATTERN = re.compile(
    r'(\w{3}\s+\d+\s+\d+:\d+:\d+) (\S+) ([^:]+): (.*)'
)
```

Exemple de ligne reconnue :

```
Mar 28 14:05:03 webserver01 sshd: Failed password for root from 10.0.0.5 port 22
```

Groupes capturés :

| Groupe | Contenu capturé                                       |
|--------|-------------------------------------------------------|
| 1      | Timestamp (`Mar 28 14:05:03`)                         |
| 2      | Nom d'hôte (`webserver01`)                            |
| 3      | Service/Programme (`sshd`)                            |
| 4      | Message complet (`Failed password for root from ...`) |

---

## Classe `LogParser`

`LogParser` orchestre l'ensemble du parsing. Ses méthodes de bas niveau sont déclarées `@staticmethod` car elles n'ont pas besoin d'accéder à l'état de l'instance : elles opèrent uniquement sur la ligne passée en paramètre.

### `_parse_apache` / `_parse_nginx`

```python
@staticmethod
def _parse_apache(line: str) -> LogEntry | None: ...

@staticmethod
def _parse_nginx(line: str) -> LogEntry | None: ...
```

Ces deux méthodes appliquent respectivement `_APACHE_PATTERN` et `_NGINX_PATTERN` sur la ligne. Comme les deux formats partagent la structure **Combined Log Format**, le mapping des groupes capturés vers les champs de `LogEntry` est identique :

| Groupe regex | Champ `LogEntry` |
|--------------|------------------|
| 1            | `ip`             |
| 2            | `timestamp`      |
| 3            | `method`         |
| 4            | `uri`            |
| 5            | `status_code`    |
| 6            | `size`           |
| 8            | `user_agent`     |

Si le pattern ne correspond pas (`match` est `None`), la méthode retourne `None`.

### `_parse_syslog`

```python
@staticmethod
def _parse_syslog(line: str) -> LogEntry | None: ...
```

Pour les lignes Syslog, le mapping diffère de celui d'Apache/Nginx, car le format ne transporte pas les mêmes informations :

| Groupe regex | Champ `LogEntry` | Justification                                        |
|--------------|------------------|------------------------------------------------------|
| 1            | `timestamp`      | Horodatage système                                   |
| 2            | `ip`             | Le **nom d'hôte** est placé dans `ip` par convention |
| 3            | `method`         | Le **service** (ex. `sshd`) joue le rôle de méthode |
| 4            | `uri`            | Le **message** brut est placé dans `uri`             |

> **Remarque importante** : Les champs `status_code`, `size` et `user_agent` restent vides (`""`) pour les entrées Syslog, car ce format ne contient pas ces informations. C'est un choix de normalisation : `LogEntry` reste la même structure pour tous les formats, au prix de champs non renseignés.

### `parse_line(line, fmt)`

```python
def parse_line(self, line: str, fmt: str) -> LogEntry | None:
    ...
```

Point d'entrée principal pour analyser **une seule ligne**. Le paramètre `fmt` détermine le parser à appeler :

| Valeur de `fmt` | Comportement                                                         |
|-----------------|----------------------------------------------------------------------|
| `"apache"`      | Appelle uniquement `_parse_apache`                                   |
| `"nginx"`       | Appelle uniquement `_parse_nginx`                                    |
| `"syslog"`      | Appelle uniquement `_parse_syslog`                                   |
| `"unknown"`     | Essaie successivement `_parse_apache`, `_parse_nginx`, `_parse_syslog` et retourne le premier résultat non `None` |

Si aucun parser ne reconnait la ligne, la méthode retourne `None`. Ce comportement permet à l'appelant de savoir explicitement qu'une ligne est malformée ou dans un format non supporté.

### `parse_all(lines, fmt)`

```python
def parse_all(self, lines: list[str], fmt: str) -> list[LogEntry]:
    ...
```

Méthode de traitement **en lot**. Elle itère sur toutes les lignes d'une liste, appelle `parse_line` pour chacune, et filtre silencieusement les résultats `None` (lignes non reconnues ou vides).

Le résultat est une liste de `LogEntry` prête à être transmise aux modules d'analyse ou de détection d'anomalies.

```python
parser = LogParser()
entries = parser.parse_all(raw_lines, fmt="apache")
# entries ne contient que les lignes valides
```

---

## Exemple concret

Voici le cycle complet, de la ligne brute Apache à l'objet `LogEntry` rempli.

**Ligne brute en entrée :**

```
10.0.0.5 - admin [28/Mar/2026:22:31:07 +0200] "POST /wp-login.php HTTP/1.1" 403 512 "-" "python-requests/2.28.0"
```

**Appel :**

```python
parser = LogParser()
entry = parser.parse_line(
    '10.0.0.5 - admin [28/Mar/2026:22:31:07 +0200] "POST /wp-login.php HTTP/1.1" 403 512 "-" "python-requests/2.28.0"',
    fmt="apache"
)
```

**`LogEntry` résultante :**

```python
LogEntry(
    ip          = "10.0.0.5",
    timestamp   = "28/Mar/2026:22:31:07 +0200",
    method      = "POST",
    uri         = "/wp-login.php",
    status_code = "403",
    size        = "512",
    user_agent  = "python-requests/2.28.0"
)
```

**Interprétation en contexte cybersécurité :** cette entrée est un indicateur fort d'une tentative de brute-force sur une interface d'administration WordPress (`/wp-login.php`) depuis un script Python, avec un code de réponse `403 Forbidden`. Un module de détection pourrait déclencher une alerte sur la combinaison `POST` + `/wp-login` + code `4xx` + user-agent non-navigateur.

---

## Points clés techniques

| Point                       | Détail                                                                                             |
|-----------------------------|----------------------------------------------------------------------------------------------------|
| **Précompilation des regex** | Les patterns sont compilés une seule fois à l'import du module, pas à chaque appel. Gain de performance significatif sur de grands volumes. |
| **Typage explicite**         | Les signatures utilisent `LogEntry | None` (union type Python 3.10+), ce qui force les appelants à gérer le cas d'échec. |
| **Méthodes statiques**       | `_parse_apache`, `_parse_nginx` et `_parse_syslog` sont `@staticmethod` : elles sont sans effet de bord et testables isolément. |
| **Normalisation par `LogEntry`** | Un seul type de retour pour tous les formats facilite les traitements en aval (filtrage, agrégation, export). |
| **Mode `"unknown"`**         | Le fallback automatique permet d'analyser des fichiers de format hétérogène sans configuration préalable. |
| **Filtrage silencieux**      | `parse_all` ignore les `None` : les lignes de commentaire, les lignes vides ou les formats inconnus ne font pas planter le traitement. |
| **Champs vides pour Syslog** | `status_code`, `size` et `user_agent` restent à `""` pour les entrées Syslog. Le code consommateur doit en tenir compte. |
