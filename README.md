# Log Sentinel — Analyseur Intelligent de Logs (Blue Team)

> Outil Python de cybersécurité défensive orienté **Blue Team** pour l'analyse automatique
> de fichiers de logs, la détection d'attaques et la génération de rapports HTML.

---

## Présentation

**Log Sentinel** répond à une problématique concrète en cybersécurité :

> *Comment automatiser l'analyse de logs de sécurité afin de détecter rapidement
> des comportements suspects, tout en restant dans une implémentation Python
> modulaire, robuste et exploitable en entreprise ?*

L'outil charge un fichier de log, détecte automatiquement son format, analyse
chaque ligne et identifie plusieurs types d'attaques — le tout présenté dans
un tableau de bord terminal **Rich** et un **rapport HTML** autonome.

---

## Fonctionnalités

| Fonctionnalité | Description |
|----------------|-------------|
| Détection de format | Apache, Nginx, Syslog — automatique |
| SQL Injection | `UNION SELECT`, `OR 1=1`, `DROP TABLE`... |
| XSS | `<script>`, `onerror=`, `javascript:`... |
| Path Traversal | `../../etc/passwd`, `/etc/shadow`... |
| Brute-Force | Seuil configurable de tentatives 401/403 |
| Scan de ressources | Détection d'exploration massive d'URIs |
| Fichiers sensibles | `.env`, `.git`, `wp-config.php`... |
| Command Injection | `;ls`, `$(`, `\|cat`... |
| Scanners connus | `sqlmap`, `nikto`, `nmap`, `burp`... |
| OSINT | Géolocalisation IP via `ip-api.com` |
| Rapport HTML | Dashboard complet, score de risque, dark theme |
| **Interface Web** | **Tableau de bord Streamlit interactif** |

---

## Architecture

```
log_sentinel/
├── main.py                  # Point d'entrée CLI (argparse + Rich)
├── app.py                   # Interface Web Streamlit (tableau de bord)
├── requirements.txt         # Dépendances Python
├── README.md                # Documentation
├── src/
│   ├── loader.py            # Chargement fichier + détection format
│   ├── parser.py            # Parsing lignes → LogEntry (dataclass)
│   ├── detector.py          # Détection attaques (signatures + seuils)
│   ├── statistics.py        # Statistiques (Top IPs, codes HTTP...)
│   ├── osint.py             # Vérification IP externe (ip-api.com)
│   └── reporter.py          # Génération rapport HTML autonome
├── tests/
│   ├── test_detector.py     # 13 tests unitaires (AttackDetector, LogParser)
│   └── test_statistics.py   # 12 tests unitaires (LogStatistics, LogLoader)
└── samples/
    └── sample_access.log    # Fichier de log de démonstration (58 lignes)
```

---

## Installation

### Prérequis

- Python 3.10+
- pip

### Étapes

```bash
# 1. Cloner ou télécharger le projet
cd log_sentinel

# 2. Créer un environnement virtuel (recommandé)
python -m venv env
env\Scripts\activate        # Windows
# source env/bin/activate   # Linux / macOS

# 3. Installer les dépendances
pip install -r requirements.txt
```

### Dépendances (`requirements.txt`)

```
requests>=2.31.0   # Requêtes HTTP (OSINT)
rich>=13.7.0       # Interface terminal colorée
streamlit>=1.32.0  # Interface Web interactive
pandas>=2.0.0      # Tableaux de données (interface web)
```

---

## Utilisation

### Interface Web (Streamlit) — Recommandée pour la démonstration

```bash
# Depuis le dossier log_sentinel/
streamlit run app.py
```

Le tableau de bord s'ouvre automatiquement dans le navigateur (`http://localhost:8501`).

**Fonctionnalités de l'interface web :**
- 📂 Upload de fichier de log par glisser-déposer
- 🧪 Bouton "Utiliser le fichier démo" (sample_access.log)
- ⚙️ Paramètres configurables dans la barre latérale (seuils, OSINT)
- 🚨 Tableau d'alertes filtrable par type d'attaque
- 📈 Graphiques interactifs (Top IPs, codes HTTP, URIs, méthodes)
- 🌍 Résultats OSINT avec géolocalisation IP
- ⬇️ Téléchargement du rapport HTML en un clic

---

### Interface CLI (ligne de commande)

### Commande de base

```bash
python main.py -f samples/sample_access.log
```

### Toutes les options

```bash
python main.py -f <fichier_log> [OPTIONS]

Options :
  -f, --file          Chemin vers le fichier de log (obligatoire)
  --bf-threshold INT  Seuil de détection brute-force (défaut : 5)
  --scan-threshold INT Seuil de détection scan (défaut : 10)
  --report            Générer le rapport HTML (défaut : activé)
  --no-report         Désactiver la génération du rapport HTML
  --check-ip          Activer la vérification OSINT des IPs suspectes
  --output-dir DIR    Dossier de sortie pour le rapport (défaut : reports/)
```

### Exemples

```bash
# Analyse standard
python main.py -f /var/log/apache2/access.log

# Avec OSINT (géolocalisation des IPs)
python main.py -f access.log --check-ip

# Seuil brute-force personnalisé (alerte dès 3 tentatives)
python main.py -f access.log --bf-threshold 3

# Sans rapport HTML
python main.py -f access.log --no-report

# Rapport dans un dossier personnalisé
python main.py -f access.log --output-dir ./output
```

---

## Exemple de résultat

### Terminal (Rich)

```
+-----------------------------------------------------------------------------+
|   _                  _____            _   _            _                    |
|  | |    ___   __ _  / ____|          | | (_)          | |                   |
|  | |   / _ \ / _` | \___  \  ___ _ __ | |_ _ _ __   ___|                   |
|  | |__| (_) | (_| |  ___) |/ _ \ '_ \| __| | '_ \ / _ \|                   |
|  |_____\___/ \__, | |____/ \  __/ | | | |_| | | | |  __/|                   |
|              |___/                                                          |
|    Blue Team Security Analyzer  |  v1.0.0                                   |
+-----------------------------------------------------------------------------+

 Fichier chargé : samples/sample_access.log
 Lignes lues    : 60
 Format détecté : NGINX

 Analyse terminée. 25 alerte(s) détectée(s).

+------+-------------------+------------------+--------------------------------+
| #    | Type              | IP               | URI                            |
+------+-------------------+------------------+--------------------------------+
|  1   | sql_injection     | 185.220.101.34   | /products?id=1+UNION+SELECT... |
|  2   | sql_injection     | 185.220.101.34   | /search?q=1'+OR+1=1--          |
|  5   | xss               | 91.108.4.201     | /search?q=<script>alert(1)...  |
|  8   | path_traversal    | 45.33.32.156     | /download?file=../../etc/pass  |
| 12   | sensitive_files   | 77.88.55.242     | /.env                          |
| 15   | malicious_ua      | 185.220.101.9    | /index.php?id=1                |
| 24   | brute_force       | 192.168.1.100    | /login                         |
| 25   | scan              | 10.0.0.55        | (multiple)                     |
+------+-------------------+------------------+--------------------------------+

 Score de risque : 100/100 — CRITIQUE
 Rapport HTML    : reports/report.html
```

### Rapport HTML

Le rapport HTML généré contient :
- **Score de risque global** (0–100) avec code couleur (vert / orange / rouge)
- **Tableau complet des alertes** avec badge par type d'attaque
- **Top 10 IPs** les plus actives
- **Distribution des codes HTTP** (2xx, 3xx, 4xx, 5xx)
- **Top URIs** ciblées
- **Données OSINT** (pays, ville, ISP) si `--check-ip` activé

---

## Lancer les tests

```bash
python -m unittest discover -s tests -v
```

Résultat attendu : `25 tests — OK`

```
test_brute_force_detected ... ok
test_sql_injection_detected ... ok
test_xss_detected ... ok
test_path_traversal_detected ... ok
test_scan_detected ... ok
...
Ran 25 tests in 0.016s
OK
```

---

## Formats de logs supportés

| Format | Exemple |
|--------|---------|
| **Apache** Combined | `127.0.0.1 - - [28/Mar/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 512 "-" "Mozilla"` |
| **Nginx** access log | Identique à Apache Combined |
| **Syslog** (RFC 3164) | `Mar 28 12:00:00 hostname sshd: Failed password for root` |

---

## Concepts techniques clés

| Concept | Usage dans le projet |
|---------|---------------------|
| `dataclass` | `LogEntry`, `Alert` — structures de données typées |
| `re.compile()` | Patterns d'attaque pré-compilés (performance) |
| `collections.Counter` | Comptage IPs, codes HTTP, méthodes |
| `defaultdict` | Accumulation des entrées par IP |
| `set` | Unicité des URIs pour détection de scan |
| `argparse` | Interface CLI professionnelle |
| `rich` | Tableaux et panels colorés dans le terminal |
| `requests` | Requêtes OSINT vers `ip-api.com` |

---

## Avertissement

> Cet outil est destiné à l'analyse de logs sur des systèmes dont vous êtes
> propriétaire ou pour lesquels vous disposez d'une autorisation explicite.
> Toute utilisation à des fins malveillantes est illégale et contraire à
> l'éthique professionnelle.

---

## Auteur

| Champ | Détail |
|-------|--------|
| **Nom** | NAOMIE NGWIDJOMBY MOUSSAVOU |
| **Module** | Python / Master 1 Cybersécurité |
| **Thème** | Analyse de Logs / Blue Team |
| **Date de remise** | 1 avril 2026 |
