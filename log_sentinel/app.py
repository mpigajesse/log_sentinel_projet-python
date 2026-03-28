"""
app.py - Interface Web Streamlit pour Log Sentinel.

Tableau de bord interactif permettant de piloter l'analyse de logs
directement depuis un navigateur web, sans passer par la ligne de commande.

Utilisation :
    streamlit run app.py
"""

import sys
import os
import tempfile
from pathlib import Path
from io import StringIO

# Assure que les modules src/ sont trouvables peu importe le répertoire
# de lancement de Streamlit.
_BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(_BASE_DIR))

import streamlit as st

from src.loader import LogLoader
from src.parser import LogParser
from src.detector import AttackDetector
from src.statistics import LogStatistics
from src.osint import OSINTChecker
from src.reporter import HTMLReporter


# ---------------------------------------------------------------------------
# Configuration de la page Streamlit
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="Log Sentinel — Blue Team Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ---------------------------------------------------------------------------
# Styles CSS personnalisés (thème sombre cohérent avec le rapport HTML)
# ---------------------------------------------------------------------------

st.markdown(
    """
    <style>
    /* Fond global */
    .main { background-color: #0d1117; }

    /* Titre principal */
    h1 { color: #ff4b4b; font-family: 'Courier New', monospace; }
    h2, h3 { color: #58a6ff; }

    /* Badges de type d'attaque */
    .badge {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.78em;
        font-weight: bold;
        font-family: monospace;
    }
    .badge-sql_injection   { background: #ff4b4b; color: #fff; }
    .badge-xss             { background: #c678dd; color: #fff; }
    .badge-path_traversal  { background: #e5c07b; color: #000; }
    .badge-command_injection{ background: #ff4b4b; color: #fff; }
    .badge-sensitive_files { background: #e5c07b; color: #000; }
    .badge-malicious_ua    { background: #56b6c2; color: #000; }
    .badge-brute_force     { background: #d19a66; color: #000; }
    .badge-scan            { background: #61afef; color: #000; }

    /* Carte score de risque */
    .risk-critique { color: #ff4b4b; font-size: 2em; font-weight: bold; }
    .risk-eleve    { color: #d19a66; font-size: 2em; font-weight: bold; }
    .risk-modere   { color: #e5c07b; font-size: 2em; font-weight: bold; }
    .risk-faible   { color: #98c379; font-size: 2em; font-weight: bold; }
    </style>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Fonctions utilitaires
# ---------------------------------------------------------------------------

def _calculer_score_risque(alerts: list, error_rate: float) -> tuple[int, str, str]:
    """Calcule le score de risque global (0-100) identique à main.py."""
    alert_score = min(50, len(alerts) * 2)
    error_score = min(30, error_rate * 0.6)
    heavy_types = {"brute_force", "scan", "sql_injection", "command_injection"}
    heavy_penalty = 20 if any(a.attack_type in heavy_types for a in alerts) else 0
    score = int(min(100, alert_score + error_score + heavy_penalty))

    if score < 20:
        return score, "FAIBLE", "faible"
    elif score < 50:
        return score, "MODÉRÉ", "modere"
    elif score < 75:
        return score, "ÉLEVÉ", "eleve"
    else:
        return score, "CRITIQUE", "critique"


def _badge_html(attack_type: str) -> str:
    """Retourne un badge HTML coloré pour le type d'attaque."""
    return (
        f'<span class="badge badge-{attack_type}">'
        f'{attack_type.replace("_", " ").upper()}'
        f'</span>'
    )


def _executer_pipeline(
    contenu_log: str,
    nom_fichier: str,
    bf_threshold: int,
    scan_threshold: int,
    check_ip: bool,
) -> dict:
    """
    Exécute le pipeline complet Log Sentinel sur le contenu fourni.

    Retourne un dict avec : lines, log_format, entries, alerts, stats, osint_data.
    Lève une exception en cas d'erreur bloquante.
    """
    # 1. Sauvegarde temporaire pour que LogLoader puisse lire le fichier
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".log", encoding="utf-8", delete=False
    ) as tmp:
        tmp.write(contenu_log)
        chemin_tmp = tmp.name

    try:
        # 2. Chargement
        loader = LogLoader()
        lines = loader.load(chemin_tmp)
        if not lines:
            raise ValueError("Le fichier est vide ou ne contient aucune ligne valide.")

        log_format = loader.detect_format(lines)

        # 3. Parsing
        log_parser = LogParser()
        entries_obj = log_parser.parse_all(lines, log_format)
        if not entries_obj:
            raise ValueError(
                "Aucune entrée n'a pu être parsée. Vérifiez le format du fichier."
            )

        # Conversion LogEntry → dict (même logique que main.py)
        entries = [
            {
                "ip":         e.ip,
                "timestamp":  e.timestamp,
                "method":     e.method,
                "uri":        e.uri,
                "status":     e.status_code,
                "size":       e.size,
                "user_agent": e.user_agent,
            }
            for e in entries_obj
        ]

        # 4. Détection
        detector = AttackDetector()
        detector.CONFIG["BRUTE_FORCE_THRESHOLD"] = bf_threshold
        detector.CONFIG["SCAN_THRESHOLD"]        = scan_threshold
        alerts = detector.analyze(entries)

        # 5. Statistiques
        stats = LogStatistics().compute(entries)

        # 6. OSINT (optionnel)
        osint_data: dict = {}
        if check_ip and alerts:
            ips_suspectes: list[str] = []
            vus: set[str] = set()
            for a in alerts:
                if a.ip and a.ip not in vus:
                    ips_suspectes.append(a.ip)
                    vus.add(a.ip)
            osint = OSINTChecker()
            osint_data = osint.check_ips(ips_suspectes[:5], max_ips=5)

    finally:
        # Nettoyage du fichier temporaire
        try:
            os.unlink(chemin_tmp)
        except OSError:
            pass

    return {
        "nom_fichier": nom_fichier,
        "lines":      lines,
        "log_format": log_format,
        "entries":    entries,
        "alerts":     alerts,
        "stats":      stats,
        "osint_data": osint_data,
    }


# ---------------------------------------------------------------------------
# Barre latérale — Paramètres
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown("## 🛡️ Log Sentinel")
    st.markdown(
        "*Blue Team Security Analyzer*  \nv1.0.0 — Master 1 Cybersécurité"
    )
    st.divider()

    st.markdown("### ⚙️ Paramètres d'analyse")

    bf_threshold = st.number_input(
        "Seuil brute-force (tentatives 401/403)",
        min_value=2,
        max_value=100,
        value=5,
        step=1,
        help="Nombre d'échecs d'authentification avant de lever une alerte brute-force.",
    )

    scan_threshold = st.number_input(
        "Seuil de scan (URIs distinctes)",
        min_value=5,
        max_value=500,
        value=10,
        step=1,
        help="Nombre d'URIs distinctes sondées depuis une même IP avant alerte scan.",
    )

    check_ip = st.checkbox(
        "🌍 Enrichissement OSINT",
        value=False,
        help="Géolocalise les IPs suspectes via ip-api.com (nécessite Internet).",
    )

    st.divider()
    st.markdown("### 📁 Formats supportés")
    st.markdown("- **Apache** Combined Log\n- **Nginx** access log\n- **Syslog** RFC 3164")

    st.divider()
    st.markdown(
        "**Auteur :** NAOMIE NGWIDJOMBY MOUSSAVOU  \n"
        "**Module :** Python / Master 1 Cybersécurité"
    )


# ---------------------------------------------------------------------------
# En-tête principal
# ---------------------------------------------------------------------------

st.markdown(
    "<h1>🛡️ Log Sentinel — Blue Team Analyzer</h1>",
    unsafe_allow_html=True,
)
st.markdown(
    "Analyseur intelligent de logs serveur pour la détection d'attaques "
    "(SQLi, XSS, Brute-Force, Path Traversal, Scan, Command Injection...)"
)
st.divider()


# ---------------------------------------------------------------------------
# Zone de chargement du fichier
# ---------------------------------------------------------------------------

col_upload, col_sample = st.columns([3, 1])

with col_upload:
    uploaded_file = st.file_uploader(
        "📂 Charger un fichier de log",
        type=["log", "txt", "access"],
        help="Formats acceptés : .log, .txt, .access",
    )

with col_sample:
    st.markdown(" ")
    st.markdown(" ")
    utiliser_sample = st.button(
        "🧪 Utiliser le fichier démo",
        help="Charge le fichier samples/sample_access.log inclus dans le projet.",
        use_container_width=True,
    )


# ---------------------------------------------------------------------------
# Logique de déclenchement de l'analyse
# ---------------------------------------------------------------------------

# Réinitialise les résultats si les paramètres changent
cle_params = f"{bf_threshold}_{scan_threshold}_{check_ip}"
if "derniere_cle_params" not in st.session_state:
    st.session_state.derniere_cle_params = cle_params

if st.session_state.derniere_cle_params != cle_params:
    st.session_state.pop("resultats", None)
    st.session_state.derniere_cle_params = cle_params

# Analyse déclenchée par le bouton "fichier démo"
if utiliser_sample:
    chemin_sample = _BASE_DIR / "samples" / "sample_access.log"
    if not chemin_sample.exists():
        st.error(f"Fichier démo introuvable : {chemin_sample}")
    else:
        with st.spinner("Analyse du fichier démo en cours..."):
            try:
                contenu = chemin_sample.read_text(encoding="utf-8", errors="replace")
                st.session_state.resultats = _executer_pipeline(
                    contenu_log=contenu,
                    nom_fichier="sample_access.log",
                    bf_threshold=int(bf_threshold),
                    scan_threshold=int(scan_threshold),
                    check_ip=check_ip,
                )
            except Exception as e:
                st.error(f"Erreur lors de l'analyse : {e}")

# Analyse déclenchée par un fichier uploadé
if uploaded_file is not None:
    cle_fichier = f"{uploaded_file.name}_{uploaded_file.size}"
    if st.session_state.get("derniere_cle_fichier") != cle_fichier:
        st.session_state.derniere_cle_fichier = cle_fichier
        with st.spinner(f"Analyse de **{uploaded_file.name}** en cours..."):
            try:
                contenu = uploaded_file.read().decode("utf-8", errors="replace")
                st.session_state.resultats = _executer_pipeline(
                    contenu_log=contenu,
                    nom_fichier=uploaded_file.name,
                    bf_threshold=int(bf_threshold),
                    scan_threshold=int(scan_threshold),
                    check_ip=check_ip,
                )
            except Exception as e:
                st.error(f"Erreur lors de l'analyse : {e}")


# ---------------------------------------------------------------------------
# Affichage des résultats
# ---------------------------------------------------------------------------

if "resultats" not in st.session_state:
    st.info(
        "👆 Chargez un fichier de log ou cliquez sur **Utiliser le fichier démo** "
        "pour démarrer l'analyse."
    )
    st.stop()

res = st.session_state.resultats
alerts = res["alerts"]
stats  = res["stats"]
osint_data = res["osint_data"]
log_format = res["log_format"]
lines      = res["lines"]
entries    = res["entries"]
nom_fichier = res["nom_fichier"]

score, label_risque, css_risque = _calculer_score_risque(
    alerts, stats.get("error_rate", 0.0)
)


# ── Résumé en métriques ────────────────────────────────────────────────────

st.markdown("## 📊 Résumé de l'analyse")
st.markdown(f"**Fichier :** `{nom_fichier}` — Format détecté : `{log_format.upper()}`")

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("📄 Lignes lues",      f"{len(lines):,}")
col2.metric("✅ Entrées parsées",  f"{len(entries):,}")
col3.metric("🚨 Alertes",          str(len(alerts)))
col4.metric("🌐 IPs uniques",      str(stats.get("unique_ips", 0)))
col5.metric("⚠️ Taux d'erreur",    f"{stats.get('error_rate', 0.0):.1f}%")

# Score de risque
st.markdown(" ")
st.markdown(
    f"**Score de risque :** "
    f'<span class="risk-{css_risque}">{score}/100 — {label_risque}</span>',
    unsafe_allow_html=True,
)
st.divider()


# ── Onglets principaux ────────────────────────────────────────────────────

onglet_alertes, onglet_stats, onglet_osint, onglet_rapport = st.tabs([
    f"🚨 Alertes ({len(alerts)})",
    "📈 Statistiques",
    "🌍 OSINT",
    "📄 Rapport HTML",
])


# ==========================================================================
# Onglet 1 — Alertes
# ==========================================================================

with onglet_alertes:
    if not alerts:
        st.success("✅ Aucune alerte détectée dans ce fichier.")
    else:
        # Filtres
        types_presents = sorted({a.attack_type for a in alerts})
        types_selectionnes = st.multiselect(
            "Filtrer par type d'attaque",
            options=types_presents,
            default=types_presents,
        )

        alertes_filtrees = [a for a in alerts if a.attack_type in types_selectionnes]

        st.markdown(
            f"**{len(alertes_filtrees)}** alerte(s) affichée(s) "
            f"sur {len(alerts)} détectée(s)."
        )

        # Construction du tableau HTML
        lignes_html = []
        for idx, a in enumerate(alertes_filtrees, start=1):
            uri_affiche = (a.uri[:60] + "…") if len(a.uri or "") > 60 else (a.uri or "-")
            details_affiche = (
                (a.details[:80] + "…") if len(a.details or "") > 80 else (a.details or "-")
            )
            lignes_html.append(
                f"<tr>"
                f"<td style='text-align:center;color:#8b949e'>{idx}</td>"
                f"<td>{_badge_html(a.attack_type)}</td>"
                f"<td style='color:#79c0ff;font-family:monospace'>{a.ip or '-'}</td>"
                f"<td style='color:#e3b341;font-family:monospace;font-size:0.85em'>"
                f"{uri_affiche}</td>"
                f"<td style='color:#8b949e;font-size:0.82em'>{details_affiche}</td>"
                f"</tr>"
            )

        tableau_html = f"""
        <table style='width:100%;border-collapse:collapse;font-size:0.9em;'>
          <thead>
            <tr style='background:#161b22;color:#58a6ff;text-align:left;'>
              <th style='padding:8px 6px;width:40px'>#</th>
              <th style='padding:8px 6px;'>Type</th>
              <th style='padding:8px 6px;'>IP</th>
              <th style='padding:8px 6px;'>URI</th>
              <th style='padding:8px 6px;'>Détails</th>
            </tr>
          </thead>
          <tbody>
            {''.join(lignes_html)}
          </tbody>
        </table>
        """
        st.markdown(tableau_html, unsafe_allow_html=True)


# ==========================================================================
# Onglet 2 — Statistiques
# ==========================================================================

with onglet_stats:
    col_ips, col_codes = st.columns(2)

    # Top IPs
    with col_ips:
        st.markdown("### 🌐 Top IPs")
        top_ips = stats.get("top_ips", [])
        if top_ips:
            import pandas as pd
            df_ips = pd.DataFrame(top_ips, columns=["IP", "Requêtes"])
            st.dataframe(df_ips, use_container_width=True, hide_index=True)
            st.bar_chart(df_ips.set_index("IP"))
        else:
            st.info("Aucune donnée disponible.")

    # Codes HTTP
    with col_codes:
        st.markdown("### 📡 Codes HTTP")
        status_codes = stats.get("status_codes", {})
        if status_codes:
            import pandas as pd
            df_codes = pd.DataFrame(
                sorted(status_codes.items()),
                columns=["Code HTTP", "Nombre"],
            )
            df_codes["Code HTTP"] = df_codes["Code HTTP"].astype(str)
            st.dataframe(df_codes, use_container_width=True, hide_index=True)
            st.bar_chart(df_codes.set_index("Code HTTP"))
        else:
            st.info("Aucune donnée disponible.")

    st.divider()

    col_uris, col_methods = st.columns(2)

    # Top URIs
    with col_uris:
        st.markdown("### 🔗 Top URIs ciblées")
        top_uris = stats.get("top_uris", [])
        if top_uris:
            import pandas as pd
            df_uris = pd.DataFrame(top_uris, columns=["URI", "Requêtes"])
            df_uris["URI"] = df_uris["URI"].str[:60]
            st.dataframe(df_uris, use_container_width=True, hide_index=True)
        else:
            st.info("Aucune donnée disponible.")

    # Méthodes HTTP
    with col_methods:
        st.markdown("### ⚡ Méthodes HTTP")
        methods = stats.get("methods", {})
        if methods:
            import pandas as pd
            df_methods = pd.DataFrame(
                sorted(methods.items(), key=lambda x: -x[1]),
                columns=["Méthode", "Nombre"],
            )
            st.dataframe(df_methods, use_container_width=True, hide_index=True)
            st.bar_chart(df_methods.set_index("Méthode"))
        else:
            st.info("Aucune donnée disponible.")


# ==========================================================================
# Onglet 3 — OSINT
# ==========================================================================

with onglet_osint:
    if not check_ip:
        st.info(
            "ℹ️ L'enrichissement OSINT est désactivé.  \n"
            "Activez l'option **🌍 Enrichissement OSINT** dans la barre latérale "
            "puis relancez l'analyse."
        )
    elif not osint_data:
        st.warning("Aucune donnée OSINT disponible (aucune alerte ou erreur réseau).")
    else:
        st.markdown("### 🌍 Géolocalisation des IPs suspectes")

        import pandas as pd
        lignes_osint = []
        for ip, info in osint_data.items():
            lignes_osint.append({
                "IP":      ip,
                "Pays":    info.get("country", "N/A"),
                "Ville":   info.get("city", "N/A"),
                "FAI":     info.get("isp", "N/A"),
                "Proxy":   "OUI ⚠️" if info.get("is_proxy") else "non",
            })

        if lignes_osint:
            st.dataframe(
                pd.DataFrame(lignes_osint),
                use_container_width=True,
                hide_index=True,
            )


# ==========================================================================
# Onglet 4 — Rapport HTML
# ==========================================================================

with onglet_rapport:
    st.markdown("### 📄 Générer le rapport HTML")
    st.markdown(
        "Le rapport HTML est autonome (CSS intégré, aucune dépendance externe) "
        "et contient l'ensemble des alertes, statistiques et le score de risque global."
    )

    if st.button("⚙️ Générer le rapport HTML", type="primary"):
        with st.spinner("Génération du rapport..."):
            try:
                # Dossier de sortie dans reports/
                output_dir = _BASE_DIR / "reports"
                output_dir.mkdir(parents=True, exist_ok=True)
                output_path = str(output_dir / "report.html")

                reporter = HTMLReporter()
                chemin_rapport = reporter.generate(
                    alerts=[
                        vars(a) if hasattr(a, "__dataclass_fields__") else a
                        for a in alerts
                    ],
                    stats=stats,
                    osint_data=osint_data,
                    output_path=output_path,
                )

                # Lecture pour le téléchargement
                with open(chemin_rapport, "r", encoding="utf-8") as fh:
                    contenu_rapport = fh.read()

                st.success(f"Rapport généré : `{chemin_rapport}`")
                st.download_button(
                    label="⬇️ Télécharger le rapport HTML",
                    data=contenu_rapport,
                    file_name="log_sentinel_report.html",
                    mime="text/html",
                )

                # Aperçu inline
                st.markdown("#### Aperçu du rapport")
                st.components.v1.html(contenu_rapport, height=600, scrolling=True)

            except Exception as e:
                st.error(f"Erreur lors de la génération du rapport : {e}")
