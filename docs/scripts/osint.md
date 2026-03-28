# osint.py — Module d'enrichissement OSINT

## Rôle

Le module `osint.py` enrichit les adresses IP extraites des logs avec des **informations géographiques et réseau** issues de sources publiques. Il permet à Log Sentinel de contextualiser automatiquement chaque IP suspecte : pays d'origine, ville, fournisseur d'accès et indicateur de proxy.

Ce module repose sur une unique classe, `OSINTChecker`, qui interroge l'API publique **ip-api.com** pour récupérer ces métadonnées sans nécessiter de clé d'authentification.

---

## API utilisée : ip-api.com

### Endpoint

```
GET http://ip-api.com/json/{ip}
```

Exemple concret :

```
GET http://ip-api.com/json/185.220.101.45
```

### Paramètres

| Paramètre | Type   | Description                          |
|-----------|--------|--------------------------------------|
| `{ip}`    | string | Adresse IPv4 ou IPv6 à interroger     |

Aucun en-tête, aucun token, aucune authentification n'est nécessaire.

### Réponse JSON type

```json
{
  "status": "success",
  "country": "Germany",
  "city": "Frankfurt am Main",
  "isp": "Frantech Solutions",
  "proxy": true,
  "query": "185.220.101.45"
}
```

### Limite gratuite

| Critère              | Valeur             |
|----------------------|--------------------|
| Clé API requise      | Non                |
| Requêtes / minute    | 45 (IP publique)   |
| HTTPS en gratuit     | Non (HTTP uniquement) |
| Champ `proxy`        | Disponible en gratuit |

> Le module fixe un timeout de **3 secondes** (`_REQUEST_TIMEOUT = 3`) pour éviter de bloquer l'analyse en cas d'API lente ou inaccessible.

---

## Classe `OSINTChecker`

La classe ne possède pas d'état persistant (pas d'`__init__` spécifique). Elle expose deux méthodes publiques.

### `check_ip(ip)`

#### Description

Interroge l'API ip-api.com pour une seule adresse IP et retourne un dictionnaire normalisé de résultats OSINT.

#### Paramètre

| Paramètre | Type  | Description                  |
|-----------|-------|------------------------------|
| `ip`      | `str` | Adresse IP à enrichir (IPv4) |

#### Valeur de retour

Retourne un `dict` avec les champs suivants en cas de succès :

| Champ        | Type   | Description                                                          |
|--------------|--------|----------------------------------------------------------------------|
| `country`    | `str`  | Pays associé à l'adresse IP (ex. `"Germany"`)                        |
| `city`       | `str`  | Ville associée (ex. `"Frankfurt am Main"`)                           |
| `isp`        | `str`  | Fournisseur d'accès Internet (ex. `"Frantech Solutions"`)            |
| `is_proxy`   | `bool` | `True` si l'IP est détectée comme proxy, VPN ou nœud Tor             |

En cas d'erreur (réseau, réponse invalide, statut API non `"success"`), la méthode retourne **un dictionnaire vide `{}`**.

#### Gestion des erreurs réseau

| Exception capturée          | Situation déclenchante                                |
|-----------------------------|-------------------------------------------------------|
| `requests.ConnectionError`  | Pas de connectivité réseau, DNS inaccessible          |
| `requests.Timeout`          | L'API ne répond pas dans les 3 secondes imparties     |
| `requests.HTTPError`        | Réponse HTTP avec code d'erreur (4xx, 5xx)            |
| `requests.RequestException` | Toute autre erreur liée à la bibliothèque `requests`  |
| `ValueError`                | Corps de réponse non décodable en JSON                |

Dans tous ces cas, la méthode retourne `{}` sans propager l'exception, garantissant que l'analyse des logs se poursuit même si l'enrichissement OSINT échoue.

---

### `check_ips(ips, max_ips=5)`

#### Description

Vérifie en lot les `N` premières adresses IP d'une liste et retourne un dictionnaire associant chaque IP à son résultat OSINT.

#### Paramètres

| Paramètre | Type        | Valeur par défaut | Description                                  |
|-----------|-------------|-------------------|----------------------------------------------|
| `ips`     | `list[str]` | —                 | Liste d'adresses IP à enrichir               |
| `max_ips` | `int`       | `5`               | Nombre maximum d'IPs à traiter               |

#### Valeur de retour

Retourne un `dict[str, dict]` de la forme :

```python
{
    "185.220.101.45": {"country": "Germany", "city": "Frankfurt am Main", "isp": "Frantech Solutions", "is_proxy": True},
    "45.142.212.10":  {"country": "Russia",  "city": "Moscow",            "isp": "Selectel",          "is_proxy": False},
    "203.0.113.99":   {}
}
```

#### Pourquoi limiter à 5 IPs ?

La limitation à `max_ips=5` répond à trois contraintes concrètes :

1. **Quota de l'API gratuite** : ip-api.com autorise 45 requêtes par minute. Traiter un grand fichier de logs d'un coup risquerait de dépasser ce seuil et de provoquer des erreurs HTTP 429.
2. **Performance** : chaque appel peut prendre jusqu'à 3 secondes (timeout). 5 appels séquentiels représentent au maximum 15 secondes, ce qui reste acceptable dans un flux d'analyse.
3. **Pertinence OSINT** : dans un contexte d'analyse de logs, seules les IPs les plus fréquentes ou les plus suspectes nécessitent un enrichissement. Les analyser toutes serait redondant.

---

## Exemple de résultat

Appel avec deux IPs, dont une qui provoque une erreur réseau :

```python
checker = OSINTChecker()

results = checker.check_ips(
    ips=["185.220.101.45", "203.0.113.99", "45.142.212.10"],
    max_ips=5
)

# Résultat retourné :
{
    "185.220.101.45": {
        "country": "Germany",
        "city": "Frankfurt am Main",
        "isp": "Frantech Solutions",
        "is_proxy": True
    },
    "203.0.113.99": {},          # Erreur réseau ou réponse invalide
    "45.142.212.10": {
        "country": "Russia",
        "city": "Moscow",
        "isp": "Selectel",
        "is_proxy": False
    }
}
```

---

## Gestion des erreurs

Le tableau suivant résume le comportement de `check_ip()` face à chaque type de défaillance :

| Exception / Situation                  | Cause probable                               | Comportement de `check_ip()` |
|----------------------------------------|----------------------------------------------|-------------------------------|
| `requests.ConnectionError`             | Réseau absent, DNS en échec                  | Retourne `{}`                 |
| `requests.Timeout`                     | API lente (> 3 s)                            | Retourne `{}`                 |
| `requests.HTTPError`                   | Code HTTP 4xx ou 5xx                         | Retourne `{}`                 |
| `requests.RequestException`            | Autre erreur `requests`                      | Retourne `{}`                 |
| `ValueError`                           | JSON malformé dans la réponse                | Retourne `{}`                 |
| Champ `"status"` != `"success"` en JSON | IP privée, réservée ou non trouvée par l'API | Retourne `{}`                 |

Aucune de ces exceptions n'est propagée vers l'appelant : le module est conçu pour **dégrader gracieusement** en cas d'indisponibilité de l'API.

---

## Points clés techniques

### `requests.get` avec timeout

```python
response = requests.get(
    _IP_API_BASE_URL.format(ip=ip),
    timeout=_REQUEST_TIMEOUT  # 3 secondes
)
```

Le paramètre `timeout` est indispensable dans un contexte de production : sans lui, une API non répondante bloquerait indéfiniment le processus d'analyse.

### `raise_for_status()`

```python
response.raise_for_status()
```

Cette méthode de `requests` lève automatiquement une `HTTPError` si le code HTTP de la réponse est >= 400. Elle évite de traiter silencieusement un corps de réponse d'erreur comme s'il contenait des données valides.

### Champ `is_proxy`

Le champ `is_proxy` est mappé depuis le champ `"proxy"` retourné par ip-api.com. Il indique si l'adresse IP appartient à une infrastructure de type :

- **Proxy HTTP/SOCKS**
- **VPN commercial**
- **Nœud de sortie Tor**
- **Hébergeur dédié à l'anonymisation**

Ce champ est particulièrement utile en cybersécurité pour qualifier rapidement une IP suspecte : une connexion provenant d'un proxy ou d'un nœud Tor renforce le niveau d'alerte associé à un événement de log.

### Constantes de configuration

| Constante          | Valeur                              | Rôle                                      |
|--------------------|-------------------------------------|-------------------------------------------|
| `_IP_API_BASE_URL` | `"http://ip-api.com/json/{ip}"`     | Template de l'URL de l'API                |
| `_REQUEST_TIMEOUT` | `3`                                 | Délai maximum d'attente réseau (secondes) |

Le préfixe `_` indique que ces constantes sont internes au module et ne font pas partie de l'interface publique.
