# app.py — Interface Web Streamlit

## Rôle

`app.py` est le **point d'entrée de l'interface web** de Log Sentinel. Il expose, via le framework Streamlit, un tableau de bord interactif accessible depuis un navigateur, sans aucune ligne de commande côté utilisateur.

Son rôle est de piloter l'intégralité du pipeline d'analyse (chargement → parsing → détection → statistiques → OSINT → rapport) depuis une interface graphique, en offrant :

- le **chargement d'un fichier de log** par upload ou via un fichier démo préintégré ;
- le **paramétrage des seuils** de détection en temps réel depuis la barre latérale ;
- la **visualisation des résultats** dans quatre onglets thématiques ;
- la **génération et le téléchargement** d'un rapport HTML autonome.

```bash
# Lancement depuis le répertoire log_sentinel/
streamlit run app.py
```

---

## Architecture Streamlit

L'interface suit le modèle d'organisation classique d'une application Streamlit : une barre latérale pour les paramètres, une zone principale pour les résultats, et des onglets pour compartimenter l'affichage.

```
┌─────────────────────────────────────────────────────────────────┐
│  BARRE LATÉRALE (st.sidebar)                                    │
│  ─ Titre + version                                              │
│  ─ bf_threshold     (st.number_input, défaut 5)                 │
│  ─ scan_threshold   (st.number_input, défaut 10)                │
│  ─ check_ip         (st.checkbox, défaut False)                 │
│  ─ Formats supportés + mention auteur                           │
├─────────────────────────────────────────────────────────────────┤
│  ZONE PRINCIPALE                                                │
│  ─ En-tête h1 + description                                     │
│  ─ Zone chargement : st.file_uploader | bouton "Fichier démo"   │
│  ─ Résumé 5 métriques (st.metric) + score de risque coloré      │
│  ─ Onglets (st.tabs) :                                          │
│    ├── Alertes                                                  │
│    ├── Statistiques                                             │
│    ├── OSINT                                                    │
│    └── Rapport HTML                                             │
└─────────────────────────────────────────────────────────────────┘
```

### Sidebar — Paramètres

| Widget Streamlit  | Variable Python  | Plage         | Défaut | Rôle                                              |
|-------------------|------------------|---------------|--------|---------------------------------------------------|
| `st.number_input` | `bf_threshold`   | 2 – 100       | `5`    | Seuil d'erreurs 401/403 pour détecter un brute-force |
| `st.number_input` | `scan_threshold` | 5 – 500       | `10`   | Nombre d'URIs distinctes avant de lever une alerte de scan |
| `st.checkbox`     | `check_ip`       | `True`/`False`| `False`| Active la géolocalisation OSINT des IPs suspectes |

Ces trois valeurs sont injectées directement dans `_executer_pipeline()` à chaque analyse, ce qui permet à l'utilisateur de relancer l'analyse avec de nouveaux seuils sans recharger la page.

### Zone principale — En-tête et chargement

La zone principale est divisée en deux colonnes (`st.columns([3, 1])`) :

- **Colonne gauche** : `st.file_uploader` — accepte les extensions `.log`, `.txt`, `.access`.
- **Colonne droite** : bouton `st.button("Utiliser le fichier démo")` — lit directement `samples/sample_access.log` sans interaction supplémentaire.

---

## Fonction `_executer_pipeline()`

C'est le **moteur central** de `app.py`. Elle encapsule l'intégralité du pipeline Log Sentinel dans une fonction Python ordinaire, séparant proprement la logique métier du rendu Streamlit.

### Signature

```python
def _executer_pipeline(
    contenu_log: str,
    nom_fichier: str,
    bf_threshold: int,
    scan_threshold: int,
    check_ip: bool,
) -> dict:
```

### Paramètres

| Paramètre      | Type   | Description                                                         |
|----------------|--------|---------------------------------------------------------------------|
| `contenu_log`  | `str`  | Contenu brut du fichier de log (déjà lu en mémoire)                 |
| `nom_fichier`  | `str`  | Nom du fichier (pour affichage dans les résultats)                  |
| `bf_threshold` | `int`  | Seuil brute-force transmis à `AttackDetector.CONFIG`               |
| `scan_threshold`| `int` | Seuil scan transmis à `AttackDetector.CONFIG`                      |
| `check_ip`     | `bool` | Si `True`, lance la géolocalisation OSINT sur les 5 premières IPs suspectes |

### Étapes internes

```
1. tempfile.NamedTemporaryFile()
   └─► Écrit contenu_log sur disque (LogLoader attend un chemin de fichier)

2. LogLoader.load(chemin_tmp)
   └─► Lit le fichier avec fallback d'encodage → list[str] (lignes brutes)

3. LogLoader.detect_format(lines)
   └─► Détecte "apache" | "nginx" | "syslog" | "unknown"

4. LogParser.parse_all(lines, log_format)
   └─► Convertit les lignes en LogEntry[], puis en list[dict]
       (clés : ip, timestamp, method, uri, status, size, user_agent)

5. AttackDetector.analyze(entries)
   └─► Configure bf_threshold et scan_threshold via detector.CONFIG
       └─► Retourne list[Alert] (les 3 détections en un seul appel)

6. LogStatistics.compute(entries)
   └─► Retourne un dict de statistiques

7. OSINTChecker.check_ips(ips_suspectes[:5])   ← seulement si check_ip=True
   └─► Géolocalise les IPs via ip-api.com

8. os.unlink(chemin_tmp)   ← nettoyage garanti par finally
```

### Valeur de retour

La fonction retourne un dictionnaire unique contenant tous les résultats :

```python
{
    "nom_fichier": str,         # Nom du fichier analysé
    "lines":       list[str],   # Lignes brutes chargées
    "log_format":  str,         # Format détecté ("apache", "nginx", etc.)
    "entries":     list[dict],  # Entrées parsées et normalisées
    "alerts":      list[Alert], # Alertes de sécurité détectées
    "stats":       dict,        # Statistiques (top IPs, codes HTTP, etc.)
    "osint_data":  dict,        # Géoloc par IP (vide si check_ip=False)
}
```

Ce dictionnaire est ensuite stocké dans `st.session_state["resultats"]` pour être accessible par tous les onglets sans relancer l'analyse.

### Gestion des erreurs

`_executer_pipeline()` laisse remonter les exceptions (`ValueError`, erreurs réseau OSINT, etc.) vers l'appelant Streamlit, qui les affiche via `st.error()`. Le bloc `finally` garantit que le fichier temporaire est supprimé même en cas d'erreur.

---

## Gestion du cache (`session_state`)

Streamlit réexécute l'intégralité du script à chaque interaction utilisateur (clic, saisie, upload). Sans mécanisme de cache, cela relancerait le pipeline d'analyse à chaque frappe dans un champ de texte. `st.session_state` est le mécanisme natif de Streamlit pour conserver des valeurs entre deux exécutions du script.

### `cle_params` — Invalidation si les paramètres changent

```python
cle_params = f"{bf_threshold}_{scan_threshold}_{check_ip}"

if st.session_state.derniere_cle_params != cle_params:
    st.session_state.pop("resultats", None)        # invalide le cache
    st.session_state.derniere_cle_params = cle_params
```

**Pourquoi ?** Si l'utilisateur change le seuil brute-force de `5` à `3` dans la sidebar, les résultats en cache ne correspondent plus aux nouveaux paramètres. La clé `cle_params` encode la combinaison des trois paramètres dans une chaîne. Dès qu'elle change, le cache est purgé et la prochaine interaction déclenchera une nouvelle analyse.

### `cle_fichier` — Éviter de réanalyser le même fichier deux fois

```python
cle_fichier = f"{uploaded_file.name}_{uploaded_file.size}"

if st.session_state.get("derniere_cle_fichier") != cle_fichier:
    st.session_state.derniere_cle_fichier = cle_fichier
    # ... lance l'analyse
```

**Pourquoi ?** `st.file_uploader` renvoie l'objet fichier à chaque re-rendu de la page, même si l'utilisateur n'a pas rechargé de nouveau fichier. Sans cette vérification, le pipeline serait relancé en boucle. La clé combine le nom et la taille du fichier pour distinguer deux fichiers différents portant le même nom.

### Tableau récapitulatif

| Clé `session_state`      | Contenu                          | Quand est-elle créée ?         | Quand est-elle invalidée ?        |
|--------------------------|----------------------------------|-------------------------------|-----------------------------------|
| `"resultats"`            | `dict` retourné par le pipeline  | Après chaque analyse réussie   | Si `cle_params` change            |
| `"derniere_cle_params"`  | `str` encodant les 3 paramètres  | Au premier rendu               | Jamais (mise à jour uniquement)   |
| `"derniere_cle_fichier"` | `str` `nom_fichier_taille`       | Au premier upload              | Si un nouveau fichier est uploadé |

---

## Les 4 onglets

```python
onglet_alertes, onglet_stats, onglet_osint, onglet_rapport = st.tabs([
    f"Alertes ({len(alerts)})",
    "Statistiques",
    "OSINT",
    "Rapport HTML",
])
```

| Onglet            | Contenu principal                                                                 | Fonctionnalité clé                                              |
|-------------------|-----------------------------------------------------------------------------------|-----------------------------------------------------------------|
| **Alertes**       | Tableau HTML construit manuellement avec une ligne par `Alert`                    | `st.multiselect` pour filtrer par type d'attaque en temps réel |
| **Statistiques**  | 4 `st.dataframe` + 3 `st.bar_chart` (Top IPs, Codes HTTP, Méthodes HTTP, Top URIs) | Mise en page en deux colonnes (`st.columns(2)`)                |
| **OSINT**         | `st.dataframe` avec IP, Pays, Ville, FAI et indicateur Proxy                     | Conditionnel : s'affiche uniquement si `check_ip=True`          |
| **Rapport HTML**  | Bouton de génération + `st.download_button` + aperçu inline via `st.components`  | `st.components.v1.html()` intègre le rapport dans un iframe    |

### Onglet Alertes — détail du tableau HTML

Le tableau est construit **manuellement en HTML** (et non avec `st.dataframe`) pour permettre l'affichage des badges colorés par type d'attaque, ce qu'un dataframe pandas ne peut pas rendre nativement.

```python
# Construction d'une ligne du tableau
lignes_html.append(
    f"<tr>"
    f"<td>{_badge_html(a.attack_type)}</td>"
    f"<td style='color:#79c0ff;font-family:monospace'>{a.ip or '-'}</td>"
    f"<td style='color:#e3b341;'>{uri_affiche}</td>"
    f"<td style='color:#8b949e;'>{details_affiche}</td>"
    f"</tr>"
)

# Injection dans la page
st.markdown(tableau_html, unsafe_allow_html=True)
```

Les URIs et les détails sont tronqués à 60 et 80 caractères respectivement pour éviter que le tableau ne déborde horizontalement.

### Onglet Rapport HTML — génération et aperçu

```python
# Génération du fichier dans reports/report.html
reporter = HTMLReporter()
chemin_rapport = reporter.generate(alerts=..., stats=..., osint_data=..., output_path=...)

# Téléchargement côté navigateur
st.download_button(
    label="Télécharger le rapport HTML",
    data=contenu_rapport,
    file_name="log_sentinel_report.html",
    mime="text/html",
)

# Aperçu inline dans la page (iframe Streamlit)
st.components.v1.html(contenu_rapport, height=600, scrolling=True)
```

`HTMLReporter` sérialise les objets `Alert` en dictionnaires via `vars(a)` (ou directement si l'objet est déjà un `dict`) avant de les passer au reporter.

---

## Fonctions utilitaires

### `_calculer_score_risque(alerts, error_rate)`

```python
def _calculer_score_risque(alerts: list, error_rate: float) -> tuple[int, str, str]:
```

Calcule un score global de risque sur 100 points, identique à la logique utilisée dans `main.py`.

**Formule :**

```
score = min(50, nombre_alertes × 2)
      + min(30, error_rate × 0.6)
      + 20  si au moins une alerte de type "lourd" est présente, sinon 0
```

Types "lourds" déclenchant la pénalité de 20 points : `brute_force`, `scan`, `sql_injection`, `command_injection`.

**Valeurs de retour selon le score :**

| Score    | Label       | Classe CSS     | Couleur affichée |
|----------|-------------|----------------|------------------|
| < 20     | `"FAIBLE"`  | `"faible"`     | Vert `#98c379`   |
| 20 – 49  | `"MODÉRÉ"`  | `"modere"`     | Jaune `#e5c07b`  |
| 50 – 74  | `"ÉLEVÉ"`   | `"eleve"`      | Orange `#d19a66` |
| >= 75    | `"CRITIQUE"`| `"critique"`   | Rouge `#ff4b4b`  |

Le triplet `(score, label, css_class)` est utilisé dans l'en-tête des résultats :

```python
score, label_risque, css_risque = _calculer_score_risque(alerts, stats.get("error_rate", 0.0))

st.markdown(
    f'<span class="risk-{css_risque}">{score}/100 — {label_risque}</span>',
    unsafe_allow_html=True,
)
```

### `_badge_html(attack_type)`

```python
def _badge_html(attack_type: str) -> str:
```

Retourne une balise `<span>` HTML représentant un badge coloré pour un type d'attaque donné.

```python
# Exemple d'appel
_badge_html("sql_injection")
# Retourne :
# <span class="badge badge-sql_injection">SQL INJECTION</span>
```

La classe CSS `badge-{attack_type}` est définie dans le bloc `st.markdown(unsafe_allow_html=True)` injecté en haut de page. Chaque type d'attaque possède sa propre couleur :

| Type d'attaque       | Couleur fond | Couleur texte |
|----------------------|-------------|---------------|
| `sql_injection`      | Rouge `#ff4b4b` | Blanc     |
| `xss`                | Violet `#c678dd` | Blanc    |
| `path_traversal`     | Jaune `#e5c07b` | Noir      |
| `command_injection`  | Rouge `#ff4b4b` | Blanc     |
| `sensitive_files`    | Jaune `#e5c07b` | Noir      |
| `malicious_ua`       | Cyan `#56b6c2` | Noir       |
| `brute_force`        | Orange `#d19a66` | Noir    |
| `scan`               | Bleu `#61afef` | Noir       |

---

## Différence avec `main.py`

Les deux fichiers utilisent exactement les mêmes modules `src/`, mais diffèrent dans la façon d'appeler la détection et dans leur gestion de l'affichage de la progression.

| Aspect                       | `app.py` (Streamlit)                                           | `main.py` (CLI Rich)                                              |
|------------------------------|----------------------------------------------------------------|-------------------------------------------------------------------|
| **Appel de détection**       | `detector.analyze(entries)` — les 3 détections en un seul appel | `detect_signature()`, `detect_brute_force()`, `detect_scan()` appelées séparément |
| **Raison de ce choix**       | La simplicité suffit ; pas besoin de contrôle fin de l'avancement | Permet de mettre à jour une barre de progression Rich entre chaque étape |
| **Affichage progression**    | `st.spinner("Analyse en cours...")` — indicateur global         | `Progress` Rich avec une tâche par étape de détection            |
| **Paramétrage des seuils**   | Widgets sidebar modifiables à la volée                         | Arguments `--bf-threshold` et `--scan-threshold` en ligne de commande |
| **Cache des résultats**      | `st.session_state` (persistance entre re-rendus Streamlit)      | Aucun (exécution linéaire, résultats en mémoire le temps du script) |
| **Fichier temporaire**       | `tempfile.NamedTemporaryFile` — nécessaire car `LogLoader` attend un chemin | Non nécessaire : `LogLoader` reçoit directement le chemin CLI    |
| **Génération du rapport**    | Bouton on-demand dans l'onglet "Rapport HTML"                   | Automatique à la fin du pipeline (sauf flag `--no-report`)       |

---

## Points clés techniques

### `st.session_state`

`st.session_state` est un dictionnaire persistant côté serveur Streamlit. Contrairement aux variables Python classiques, qui sont réinitialisées à chaque re-rendu, les valeurs stockées dans `session_state` survivent aux interactions utilisateur. C'est le seul mécanisme natif de Streamlit pour mémoriser un état entre deux exécutions du script sans recourir à une base de données.

### `tempfile.NamedTemporaryFile`

`LogLoader.load()` attend un **chemin de fichier** sur le système de fichiers. Or, Streamlit reçoit le contenu du fichier uploadé en mémoire (objet `UploadedFile`). La solution est d'écrire ce contenu dans un fichier temporaire via `tempfile.NamedTemporaryFile`, de transmettre son chemin à `LogLoader`, puis de supprimer le fichier dans un bloc `finally` pour éviter toute fuite de données.

```python
with tempfile.NamedTemporaryFile(mode="w", suffix=".log", encoding="utf-8", delete=False) as tmp:
    tmp.write(contenu_log)
    chemin_tmp = tmp.name
try:
    lines = loader.load(chemin_tmp)
finally:
    os.unlink(chemin_tmp)   # suppression garantie
```

### `unsafe_allow_html=True`

Par défaut, Streamlit échappe tout le HTML pour des raisons de sécurité. Le paramètre `unsafe_allow_html=True` dans `st.markdown()` permet d'injecter du HTML brut, utilisé ici pour :

- le **thème sombre CSS** global (fond, typographies, badges, classes de risque) ;
- les **badges colorés** dans le tableau d'alertes ;
- le **score de risque** mis en forme avec sa classe CSS dynamique.

Ce paramètre doit être utilisé avec précaution : il n'est acceptable ici que parce que le HTML provient entièrement du code applicatif et non de données utilisateur non validées.

### `st.components.v1.html()`

Cette fonction intègre du contenu HTML arbitraire dans la page Streamlit via un `<iframe>` sandboxé. Elle est utilisée dans l'onglet "Rapport HTML" pour afficher un aperçu du rapport généré directement dans l'interface, sans redirection vers un fichier externe.

```python
st.components.v1.html(contenu_rapport, height=600, scrolling=True)
```

### `st.download_button()`

`st.download_button()` déclenche un téléchargement côté navigateur. Le contenu est transmis directement depuis la mémoire Python (variable `contenu_rapport`), sans passer par une URL temporaire. Streamlit gère lui-même l'encodage et les en-têtes HTTP nécessaires.

```python
st.download_button(
    label="Télécharger le rapport HTML",
    data=contenu_rapport,           # str ou bytes
    file_name="log_sentinel_report.html",
    mime="text/html",
)
```

### Résolution des imports (`sys.path`)

Streamlit peut être lancé depuis un répertoire de travail différent de celui où se trouve `app.py`. Pour garantir que les modules `src/` soient toujours trouvables, `app.py` insère dynamiquement son propre répertoire parent en tête de `sys.path` au chargement :

```python
_BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(_BASE_DIR))
```

`_BASE_DIR` est ensuite réutilisé pour construire les chemins vers `samples/` et `reports/` de manière absolue et portable.
