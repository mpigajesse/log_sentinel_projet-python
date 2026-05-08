"""
app.py - Interface Web Streamlit pour Log Sentinel.

Tableau de bord interactif permettant de piloter l'analyse de logs
directement depuis un navigateur web, sans passer par la ligne de commande.

Utilisation :
    streamlit run app.py
"""

import sys
import os
import io
import tempfile
from pathlib import Path

try:
    from weasyprint import HTML as WeasyHTML
    _WEASYPRINT_OK = True
except Exception:
    _WEASYPRINT_OK = False

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
# Configuration de la page
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="Log Sentinel — Blue Team Analyzer",
    page_icon="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><text y='20' font-size='20'>🛡</text></svg>",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ---------------------------------------------------------------------------
# Icônes SVG inline (Lucide subset)
# ---------------------------------------------------------------------------

def _icon(name: str, size: int = 16, color: str = "currentColor") -> str:
    """Retourne un SVG inline pour l'icône demandée."""
    s = size
    c = color
    paths = {
        "shield": f'<svg xmlns="http://www.w3.org/2000/svg" width="{s}" height="{s}" viewBox="0 0 24 24" fill="none" stroke="{c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
        "alert-triangle": f'<svg xmlns="http://www.w3.org/2000/svg" width="{s}" height="{s}" viewBox="0 0 24 24" fill="none" stroke="{c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
        "bar-chart": f'<svg xmlns="http://www.w3.org/2000/svg" width="{s}" height="{s}" viewBox="0 0 24 24" fill="none" stroke="{c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle"><line x1="12" y1="20" x2="12" y2="10"/><line x1="18" y1="20" x2="18" y2="4"/><line x1="6" y1="20" x2="6" y2="16"/></svg>',
        "globe": f'<svg xmlns="http://www.w3.org/2000/svg" width="{s}" height="{s}" viewBox="0 0 24 24" fill="none" stroke="{c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>',
        "file-text": f'<svg xmlns="http://www.w3.org/2000/svg" width="{s}" height="{s}" viewBox="0 0 24 24" fill="none" stroke="{c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>',
        "settings": f'<svg xmlns="http://www.w3.org/2000/svg" width="{s}" height="{s}" viewBox="0 0 24 24" fill="none" stroke="{c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle"><circle cx="12" cy="12" r="3"/><path d="M19.07 4.93a10 10 0 010 14.14M4.93 4.93a10 10 0 000 14.14"/><path d="M12 2v2M12 20v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M2 12h2M20 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>',
        "upload": f'<svg xmlns="http://www.w3.org/2000/svg" width="{s}" height="{s}" viewBox="0 0 24 24" fill="none" stroke="{c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0018 9h-1.26A8 8 0 103 16.3"/></svg>',
        "download": f'<svg xmlns="http://www.w3.org/2000/svg" width="{s}" height="{s}" viewBox="0 0 24 24" fill="none" stroke="{c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle"><polyline points="8 17 12 21 16 17"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.88 18.09A5 5 0 0018 9h-1.26A8 8 0 103 16.29"/></svg>',
        "cpu": f'<svg xmlns="http://www.w3.org/2000/svg" width="{s}" height="{s}" viewBox="0 0 24 24" fill="none" stroke="{c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/></svg>',
        "activity": f'<svg xmlns="http://www.w3.org/2000/svg" width="{s}" height="{s}" viewBox="0 0 24 24" fill="none" stroke="{c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
        "server": f'<svg xmlns="http://www.w3.org/2000/svg" width="{s}" height="{s}" viewBox="0 0 24 24" fill="none" stroke="{c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>',
        "user": f'<svg xmlns="http://www.w3.org/2000/svg" width="{s}" height="{s}" viewBox="0 0 24 24" fill="none" stroke="{c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>',
        "zap": f'<svg xmlns="http://www.w3.org/2000/svg" width="{s}" height="{s}" viewBox="0 0 24 24" fill="none" stroke="{c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',
        "link": f'<svg xmlns="http://www.w3.org/2000/svg" width="{s}" height="{s}" viewBox="0 0 24 24" fill="none" stroke="{c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle"><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/></svg>',
        "eye": f'<svg xmlns="http://www.w3.org/2000/svg" width="{s}" height="{s}" viewBox="0 0 24 24" fill="none" stroke="{c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>',
        "wifi": f'<svg xmlns="http://www.w3.org/2000/svg" width="{s}" height="{s}" viewBox="0 0 24 24" fill="none" stroke="{c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle"><path d="M5 12.55a11 11 0 0114.08 0"/><path d="M1.42 9a16 16 0 0121.16 0"/><path d="M8.53 16.11a6 6 0 016.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>',
        "check-circle": f'<svg xmlns="http://www.w3.org/2000/svg" width="{s}" height="{s}" viewBox="0 0 24 24" fill="none" stroke="{c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
        "info": f'<svg xmlns="http://www.w3.org/2000/svg" width="{s}" height="{s}" viewBox="0 0 24 24" fill="none" stroke="{c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
        "lock": f'<svg xmlns="http://www.w3.org/2000/svg" width="{s}" height="{s}" viewBox="0 0 24 24" fill="none" stroke="{c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>',
        "target": f'<svg xmlns="http://www.w3.org/2000/svg" width="{s}" height="{s}" viewBox="0 0 24 24" fill="none" stroke="{c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>',
        "play": f'<svg xmlns="http://www.w3.org/2000/svg" width="{s}" height="{s}" viewBox="0 0 24 24" fill="none" stroke="{c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle"><polygon points="5 3 19 12 5 21 5 3"/></svg>',
        "list": f'<svg xmlns="http://www.w3.org/2000/svg" width="{s}" height="{s}" viewBox="0 0 24 24" fill="none" stroke="{c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>',
    }
    return paths.get(name, "")


# ---------------------------------------------------------------------------
# CSS — Thème Cybersécurité
# ---------------------------------------------------------------------------

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&display=swap');

/* ── Variables ───────────────────────────────────────────────────────────── */
:root {
    --bg-primary:   #080c14;
    --bg-card:      #0d1421;
    --bg-panel:     #111827;
    --cyan:         #00d4ff;
    --cyan-dim:     rgba(0, 212, 255, 0.18);
    --cyan-border:  rgba(0, 212, 255, 0.28);
    --green:        #4ade80;
    --red:          #f87171;
    --amber:        #fbbf24;
    --purple:       #a78bfa;
    --text-primary: #d1d5db;
    --text-muted:   #6b7280;
    --text-bright:  #f3f4f6;
}

/* ── Global ──────────────────────────────────────────────────────────────── */
.stApp, .main, [data-testid="stAppViewContainer"] {
    background-color: var(--bg-primary) !important;
    background-image:
        linear-gradient(rgba(0,212,255,0.025) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,212,255,0.025) 1px, transparent 1px);
    background-size: 48px 48px;
    font-family: 'JetBrains Mono', 'Courier New', monospace !important;
}

/* ── Sidebar ─────────────────────────────────────────────────────────────── */
[data-testid="stSidebar"] {
    background-color: #070a12 !important;
    border-right: 1px solid var(--cyan-border) !important;
}
[data-testid="stSidebar"] * {
    font-family: 'JetBrains Mono', 'Courier New', monospace !important;
    color: var(--text-primary) !important;
}
[data-testid="stSidebar"] hr { border-color: var(--cyan-border) !important; }
[data-testid="stSidebar"] .stNumberInput input,
[data-testid="stSidebar"] .stCheckbox span {
    color: var(--cyan) !important;
}

/* ── Typography ──────────────────────────────────────────────────────────── */
h1, h2, h3, h4, p, label, span, div {
    font-family: 'JetBrains Mono', 'Courier New', monospace !important;
}
h1 { color: var(--cyan) !important; letter-spacing: 2px; text-transform: uppercase; }
h2 { color: var(--text-bright) !important; letter-spacing: 1px; }
h3 { color: var(--cyan) !important; font-size: 0.95rem !important; letter-spacing: 1px; text-transform: uppercase; }

/* ── Inputs ──────────────────────────────────────────────────────────────── */
input, textarea, select {
    background-color: var(--bg-card) !important;
    border: 1px solid var(--cyan-border) !important;
    color: var(--cyan) !important;
    font-family: 'JetBrains Mono', monospace !important;
    border-radius: 2px !important;
}
input:focus { border-color: var(--cyan) !important; box-shadow: 0 0 8px var(--cyan-dim) !important; }

/* ── Buttons ─────────────────────────────────────────────────────────────── */
.stButton > button {
    background-color: transparent !important;
    border: 1px solid var(--cyan) !important;
    color: var(--cyan) !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.82rem !important;
    letter-spacing: 1px !important;
    text-transform: uppercase !important;
    border-radius: 2px !important;
    transition: all 0.2s ease !important;
}
.stButton > button:hover {
    background-color: var(--cyan-dim) !important;
    box-shadow: 0 0 12px var(--cyan-dim) !important;
}
.stButton > button[kind="primary"] {
    background-color: var(--cyan-dim) !important;
    border-color: var(--cyan) !important;
    box-shadow: 0 0 10px var(--cyan-dim) !important;
}
.stDownloadButton > button {
    background-color: transparent !important;
    border: 1px solid var(--cyan-border) !important;
    color: var(--text-primary) !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.80rem !important;
    border-radius: 2px !important;
    text-transform: uppercase !important;
    letter-spacing: 1px !important;
}
.stDownloadButton > button:hover {
    border-color: var(--cyan) !important;
    color: var(--cyan) !important;
}

/* ── File uploader ───────────────────────────────────────────────────────── */
[data-testid="stFileUploader"] {
    border: 1px dashed var(--cyan-border) !important;
    background-color: var(--bg-card) !important;
    border-radius: 4px !important;
}
[data-testid="stFileUploader"]:hover {
    border-color: var(--cyan) !important;
    box-shadow: 0 0 12px var(--cyan-dim) !important;
}

/* ── Tabs ────────────────────────────────────────────────────────────────── */
.stTabs [data-baseweb="tab-list"] {
    background-color: transparent !important;
    border-bottom: 1px solid var(--cyan-border) !important;
    gap: 0 !important;
}
.stTabs [data-baseweb="tab"] {
    background-color: transparent !important;
    color: var(--text-muted) !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.78rem !important;
    letter-spacing: 1px !important;
    text-transform: uppercase !important;
    padding: 8px 20px !important;
    border: none !important;
    border-bottom: 2px solid transparent !important;
    transition: all 0.2s !important;
}
.stTabs [aria-selected="true"] {
    color: var(--cyan) !important;
    border-bottom: 2px solid var(--cyan) !important;
    background-color: var(--cyan-dim) !important;
}
.stTabs [data-baseweb="tab"]:hover {
    color: var(--text-primary) !important;
    background-color: rgba(0,212,255,0.05) !important;
}

/* ── Metrics ─────────────────────────────────────────────────────────────── */
[data-testid="metric-container"] {
    background-color: var(--bg-card) !important;
    border: 1px solid var(--cyan-border) !important;
    border-radius: 4px !important;
    padding: 12px 16px !important;
}
[data-testid="metric-container"] label {
    color: var(--text-muted) !important;
    font-size: 0.72rem !important;
    text-transform: uppercase !important;
    letter-spacing: 1px !important;
}
[data-testid="metric-container"] [data-testid="stMetricValue"] {
    color: var(--cyan) !important;
    font-size: 1.6rem !important;
    font-weight: 700 !important;
}

/* ── DataFrames ──────────────────────────────────────────────────────────── */
[data-testid="stDataFrame"] {
    border: 1px solid var(--cyan-border) !important;
    border-radius: 4px !important;
}
.dvn-scroller { background-color: var(--bg-card) !important; }
[data-testid="glideDataEditor"] { background-color: var(--bg-card) !important; }

/* ── Alerts ──────────────────────────────────────────────────────────────── */
[data-testid="stAlert"] {
    border-radius: 2px !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.82rem !important;
    border-left-width: 3px !important;
}
.stSuccess { border-left-color: var(--green) !important; background-color: rgba(74,222,128,0.08) !important; }
.stWarning { border-left-color: var(--amber) !important; background-color: rgba(251,191,36,0.08) !important; }
.stError   { border-left-color: var(--red)   !important; background-color: rgba(248,113,113,0.08) !important; }
.stInfo    { border-left-color: var(--cyan)   !important; background-color: var(--cyan-dim) !important; }

/* ── Divider ─────────────────────────────────────────────────────────────── */
hr { border-color: var(--cyan-border) !important; }

/* ── Spinner ─────────────────────────────────────────────────────────────── */
.stSpinner > div { border-top-color: var(--cyan) !important; }

/* ── Checkbox ────────────────────────────────────────────────────────────── */
[data-testid="stCheckbox"] > label { color: var(--text-primary) !important; font-size: 0.82rem !important; }

/* ── Scrollbar ───────────────────────────────────────────────────────────── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg-primary); }
::-webkit-scrollbar-thumb { background: var(--cyan-border); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--cyan); }

/* ── Badges attaque ──────────────────────────────────────────────────────── */
.badge {
    display: inline-block;
    padding: 2px 7px;
    border-radius: 2px;
    font-size: 0.70em;
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
    letter-spacing: 0.5px;
    text-transform: uppercase;
}
.badge-sql_injection    { background: rgba(248,113,113,0.15); color: #f87171; border: 1px solid #f87171; }
.badge-xss              { background: rgba(167,139,250,0.15); color: #a78bfa; border: 1px solid #a78bfa; }
.badge-path_traversal   { background: rgba(251,191,36,0.15);  color: #fbbf24; border: 1px solid #fbbf24; }
.badge-command_injection { background: rgba(248,113,113,0.15); color: #f87171; border: 1px solid #f87171; }
.badge-sensitive_files  { background: rgba(251,191,36,0.15);  color: #fbbf24; border: 1px solid #fbbf24; }
.badge-malicious_ua     { background: rgba(0,212,255,0.12);   color: #00d4ff; border: 1px solid #00d4ff; }
.badge-brute_force      { background: rgba(251,146,60,0.15);  color: #fb923c; border: 1px solid #fb923c; }
.badge-scan             { background: rgba(96,165,250,0.15);  color: #60a5fa; border: 1px solid #60a5fa; }

/* ── Score de risque ─────────────────────────────────────────────────────── */
.risk-box {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    padding: 10px 20px;
    border-radius: 3px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.05em;
    font-weight: 700;
    letter-spacing: 2px;
    text-transform: uppercase;
}
.risk-critique { background: rgba(248,113,113,0.12); color: #f87171; border: 1px solid #f87171; box-shadow: 0 0 16px rgba(248,113,113,0.2); }
.risk-eleve    { background: rgba(251,146,60,0.12);  color: #fb923c; border: 1px solid #fb923c; box-shadow: 0 0 16px rgba(251,146,60,0.2); }
.risk-modere   { background: rgba(251,191,36,0.12);  color: #fbbf24; border: 1px solid #fbbf24; }
.risk-faible   { background: rgba(74,222,128,0.12);  color: #4ade80; border: 1px solid #4ade80; }

/* ── Section header ──────────────────────────────────────────────────────── */
.section-header {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 0;
    border-bottom: 1px solid var(--cyan-border);
    margin-bottom: 14px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.82rem;
    font-weight: 700;
    color: var(--cyan);
    letter-spacing: 2px;
    text-transform: uppercase;
}

/* ── Terminal header ─────────────────────────────────────────────────────── */
.terminal-header {
    background: linear-gradient(135deg, #0d1421 0%, #111827 100%);
    border: 1px solid var(--cyan-border);
    border-radius: 4px;
    padding: 20px 28px;
    margin-bottom: 24px;
    position: relative;
    overflow: hidden;
}
.terminal-header::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, var(--cyan), transparent);
}
.terminal-title {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.6rem;
    font-weight: 700;
    color: var(--cyan);
    letter-spacing: 4px;
    text-transform: uppercase;
    margin: 0;
}
.terminal-subtitle {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
    color: var(--text-muted);
    letter-spacing: 2px;
    margin-top: 4px;
}
.terminal-prompt::before { content: '> '; color: var(--green); }

/* ── Alerte table ────────────────────────────────────────────────────────── */
.alert-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.82em;
    font-family: 'JetBrains Mono', monospace;
    margin-top: 8px;
}
.alert-table thead tr {
    background: #0d1421;
    border-bottom: 1px solid var(--cyan-border);
}
.alert-table thead th {
    padding: 10px 8px;
    text-align: left;
    color: var(--cyan);
    font-size: 0.72em;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    font-weight: 600;
}
.alert-table tbody tr {
    border-bottom: 1px solid rgba(0,212,255,0.06);
    transition: background 0.15s;
}
.alert-table tbody tr:hover { background: rgba(0,212,255,0.04); }
.alert-table tbody td { padding: 8px 8px; vertical-align: middle; }

/* ── Sidebar brand ───────────────────────────────────────────────────────── */
.sidebar-brand {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 4px 0 12px 0;
}
.sidebar-brand-title {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.1rem;
    font-weight: 700;
    color: #00d4ff;
    letter-spacing: 3px;
    text-transform: uppercase;
}
.sidebar-brand-sub {
    font-size: 0.68rem;
    color: #6b7280;
    letter-spacing: 1px;
    font-family: 'JetBrains Mono', monospace;
}

/* ══════════════════════════════════════════════════════════════════════════
   KEYFRAME ANIMATIONS
   ══════════════════════════════════════════════════════════════════════════ */

@keyframes blink {
    0%, 49% { opacity: 1; }
    50%, 100% { opacity: 0; }
}

@keyframes pulse-red {
    0%, 100% { box-shadow: 0 0 8px rgba(248,113,113,0.25); }
    50%       { box-shadow: 0 0 28px rgba(248,113,113,0.65), 0 0 56px rgba(248,113,113,0.18); }
}

@keyframes pulse-orange {
    0%, 100% { box-shadow: 0 0 8px rgba(251,146,60,0.25); }
    50%       { box-shadow: 0 0 22px rgba(251,146,60,0.55), 0 0 44px rgba(251,146,60,0.15); }
}

@keyframes fadeInUp {
    from { opacity: 0; transform: translateY(12px); }
    to   { opacity: 1; transform: translateY(0); }
}

@keyframes scanline {
    0%   { top: -3px; opacity: 0; }
    5%   { opacity: 1; }
    92%  { opacity: 0.7; }
    100% { top: 105%; opacity: 0; }
}

@keyframes live-pulse {
    0%, 100% { box-shadow: 0 0 0 0 rgba(74,222,128,0.5); transform: scale(1); }
    50%       { box-shadow: 0 0 0 5px rgba(74,222,128,0);  transform: scale(1.1); }
}

@keyframes border-shimmer {
    0%   { background-position: -200% center; }
    100% { background-position: 200% center; }
}

@keyframes progress-fill {
    from { width: 0%; opacity: 0.4; }
    to   { width: var(--w, 0%); opacity: 1; }
}

@keyframes row-in {
    from { opacity: 0; transform: translateX(-6px); }
    to   { opacity: 1; transform: translateX(0); }
}

@keyframes glow-border {
    0%, 100% { border-color: rgba(0,212,255,0.18); }
    50%       { border-color: rgba(0,212,255,0.45); }
}

/* ── Appliquer les animations ──────────────────────────────────────────── */

/* Threat badges pulsent selon le niveau */
.risk-critique { animation: pulse-red    2s   ease-in-out infinite !important; }
.risk-eleve    { animation: pulse-orange 2.8s ease-in-out infinite !important; }

/* Metric cards s'affichent en fondu */
[data-testid="metric-container"] {
    animation: fadeInUp 0.45s ease forwards;
    animation-delay: calc(var(--i, 0) * 0.06s);
}

/* Ligne animée dans le header terminal */
.terminal-header::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent 0%, #00d4ff 50%, transparent 100%);
    background-size: 200% 100%;
    animation: border-shimmer 3.5s linear infinite;
}

/* Lignes du tableau alertes */
.alert-table tbody tr {
    animation: row-in 0.25s ease forwards;
    opacity: 0;
}
.alert-table tbody tr:nth-child(1)  { animation-delay: 0.02s; }
.alert-table tbody tr:nth-child(2)  { animation-delay: 0.06s; }
.alert-table tbody tr:nth-child(3)  { animation-delay: 0.10s; }
.alert-table tbody tr:nth-child(4)  { animation-delay: 0.14s; }
.alert-table tbody tr:nth-child(5)  { animation-delay: 0.18s; }
.alert-table tbody tr:nth-child(6)  { animation-delay: 0.22s; }
.alert-table tbody tr:nth-child(7)  { animation-delay: 0.26s; }
.alert-table tbody tr:nth-child(8)  { animation-delay: 0.30s; }
.alert-table tbody tr:nth-child(n+9){ animation-delay: 0.34s; }

/* Cartes principales glowent lentement */
.terminal-header {
    animation: glow-border 4s ease-in-out infinite;
}

/* ── Nouveaux composants ───────────────────────────────────────────────── */

.live-dot {
    display: inline-block;
    width: 7px;
    height: 7px;
    background-color: #4ade80;
    border-radius: 50%;
    flex-shrink: 0;
    animation: live-pulse 1.8s ease-in-out infinite;
}

.blink-cursor {
    display: inline-block;
    width: 7px;
    height: 0.85em;
    background-color: #00d4ff;
    margin-left: 3px;
    vertical-align: middle;
    border-radius: 1px;
    animation: blink 1s step-end infinite;
}

.scan-overlay {
    position: absolute;
    left: 0;
    right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent 0%, rgba(0,212,255,0.55) 50%, transparent 100%);
    pointer-events: none;
    animation: scanline 5s linear infinite;
}

.risk-progress-track {
    height: 3px;
    background: rgba(255,255,255,0.05);
    border-radius: 2px;
    margin-top: 10px;
    overflow: hidden;
    width: 100%;
    max-width: 400px;
}
.risk-progress-fill {
    height: 100%;
    border-radius: 2px;
    animation: progress-fill 1.2s cubic-bezier(0.22, 1, 0.36, 1) forwards;
}
.risk-progress-critique { background: linear-gradient(90deg, #7f1d1d 0%, #f87171 100%); }
.risk-progress-eleve    { background: linear-gradient(90deg, #7c2d12 0%, #fb923c 100%); }
.risk-progress-modere   { background: linear-gradient(90deg, #713f12 0%, #fbbf24 100%); }
.risk-progress-faible   { background: linear-gradient(90deg, #14532d 0%, #4ade80 100%); }

.results-fade {
    animation: fadeInUp 0.4s ease forwards;
}
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Fonctions utilitaires
# ---------------------------------------------------------------------------

def _calculer_score_risque(alerts: list, error_rate: float) -> tuple[int, str, str]:
    """Calcule le score de risque global (0-100)."""
    alert_score = min(50, len(alerts) * 2)
    error_score = min(30, error_rate * 0.6)
    heavy_types = {"brute_force", "scan", "sql_injection", "command_injection"}
    heavy_penalty = 20 if any(a.attack_type in heavy_types for a in alerts) else 0
    score = int(min(100, alert_score + error_score + heavy_penalty))

    if score < 20:
        return score, "FAIBLE", "faible"
    elif score < 50:
        return score, "MODERE", "modere"
    elif score < 75:
        return score, "ELEVE", "eleve"
    else:
        return score, "CRITIQUE", "critique"


def _badge_html(attack_type: str) -> str:
    return (
        f'<span class="badge badge-{attack_type}">'
        f'{attack_type.replace("_", " ").upper()}'
        f'</span>'
    )


def _section_header(icon_name: str, label: str) -> str:
    return (
        f'<div class="section-header">'
        f'{_icon(icon_name, 14, "#00d4ff")}'
        f'&nbsp;{label}'
        f'</div>'
    )


def _executer_pipeline(
    contenu_log: str,
    nom_fichier: str,
    bf_threshold: int,
    scan_threshold: int,
    check_ip: bool,
) -> dict:
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".log", encoding="utf-8", delete=False
    ) as tmp:
        tmp.write(contenu_log)
        chemin_tmp = tmp.name

    try:
        loader = LogLoader()
        lines = loader.load(chemin_tmp)
        if not lines:
            raise ValueError("Le fichier est vide ou ne contient aucune ligne valide.")

        log_format = loader.detect_format(lines)

        log_parser = LogParser()
        entries_obj = log_parser.parse_all(lines, log_format)
        if not entries_obj:
            raise ValueError("Aucune entrée parsée. Vérifiez le format du fichier.")

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

        detector = AttackDetector()
        detector.CONFIG["BRUTE_FORCE_THRESHOLD"] = bf_threshold
        detector.CONFIG["SCAN_THRESHOLD"]        = scan_threshold
        alerts = detector.analyze(entries)

        stats = LogStatistics().compute(entries)

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
        try:
            os.unlink(chemin_tmp)
        except OSError:
            pass

    return {
        "nom_fichier": nom_fichier,
        "lines":       lines,
        "log_format":  log_format,
        "entries":     entries,
        "alerts":      alerts,
        "stats":       stats,
        "osint_data":  osint_data,
    }


# ---------------------------------------------------------------------------
# Barre latérale
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown(
        f"""
        <div class="sidebar-brand">
            {_icon("shield", 22, "#00d4ff")}
            <div>
                <div class="sidebar-brand-title" style="display:flex;align-items:center;gap:8px">
                    Log Sentinel
                    <span class="live-dot" title="Système actif"></span>
                </div>
                <div class="sidebar-brand-sub">BLUE TEAM ANALYZER · v1.0.0</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.divider()

    st.markdown(
        _section_header("settings", "Parametres d'analyse"),
        unsafe_allow_html=True,
    )

    bf_threshold = st.number_input(
        "Seuil brute-force (tentatives 401/403)",
        min_value=2, max_value=100, value=5, step=1,
        help="Nombre d'échecs d'authentification avant alerte brute-force.",
    )

    scan_threshold = st.number_input(
        "Seuil de scan (URIs distinctes)",
        min_value=5, max_value=500, value=10, step=1,
        help="Nombre d'URIs distinctes sondées depuis une même IP avant alerte scan.",
    )

    check_ip = st.checkbox(
        "Enrichissement OSINT",
        value=False,
        help="Géolocalise les IPs suspectes via ip-api.com (nécessite Internet).",
    )

    st.divider()
    st.markdown(
        _section_header("file-text", "Formats supportes"),
        unsafe_allow_html=True,
    )
    st.markdown(
        "<span style='color:#6b7280;font-size:0.78rem;font-family:monospace'>"
        "Apache Combined Log<br>Nginx access log<br>Syslog RFC 3164"
        "</span>",
        unsafe_allow_html=True,
    )

    st.divider()
    st.markdown(
        "<span style='color:#4b5563;font-size:0.72rem;font-family:monospace;letter-spacing:1px'>"
        "NAOMIE NGWIDJOMBY MOUSSAVOU<br>"
        "Master 1 Cybersécurité — Python"
        "</span>",
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# En-tête principal
# ---------------------------------------------------------------------------

st.markdown(
    f"""
    <div class="terminal-header">
        <div class="scan-overlay"></div>
        <div style="display:flex;align-items:center;gap:14px">
            {_icon("shield", 32, "#00d4ff")}
            <div>
                <div class="terminal-title">Log Sentinel<span class="blink-cursor"></span></div>
                <div class="terminal-subtitle terminal-prompt">
                    Blue Team Security Analyzer &mdash;
                    Détection SQLi · XSS · Brute-Force · Path Traversal · Scan · Command Injection
                </div>
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Navigation top-level
# ---------------------------------------------------------------------------

tab_analyse, tab_guide, tab_apropos = st.tabs([
    "  Analyser  ",
    "  Guide  ",
    "  A propos  ",
])


# ===========================================================================
# TAB : ANALYSER
# ===========================================================================

with tab_analyse:

    # ── Zone de chargement ─────────────────────────────────────────────────
    col_upload, col_sample = st.columns([3, 1])

    with col_upload:
        uploaded_file = st.file_uploader(
            "Charger un fichier de log",
            type=["log", "txt", "access"],
            help="Formats acceptés : .log, .txt, .access",
            label_visibility="collapsed",
        )
        st.markdown(
            f"<span style='color:#4b5563;font-size:0.74rem;font-family:monospace'>"
            f"{_icon('upload', 12, '#4b5563')} &nbsp;Glisser-deposer ou selectionner un fichier .log / .txt / .access"
            f"</span>",
            unsafe_allow_html=True,
        )

    with col_sample:
        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
        utiliser_sample = st.button(
            "Charger le fichier demo",
            help="Charge samples/sample_access.log",
            use_container_width=True,
        )

    # ── Déclenchement de l'analyse ─────────────────────────────────────────
    cle_params = f"{bf_threshold}_{scan_threshold}_{check_ip}"
    if "derniere_cle_params" not in st.session_state:
        st.session_state.derniere_cle_params = cle_params

    if st.session_state.derniere_cle_params != cle_params:
        st.session_state.pop("resultats", None)
        st.session_state.derniere_cle_params = cle_params

    if utiliser_sample:
        chemin_sample = _BASE_DIR / "samples" / "sample_access.log"
        if not chemin_sample.exists():
            st.error(f"Fichier demo introuvable : {chemin_sample}")
        else:
            with st.spinner("Analyse du fichier demo en cours..."):
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

    if uploaded_file is not None:
        cle_fichier = f"{uploaded_file.name}_{uploaded_file.size}"
        if st.session_state.get("derniere_cle_fichier") != cle_fichier:
            st.session_state.derniere_cle_fichier = cle_fichier
            with st.spinner(f"Analyse de {uploaded_file.name} en cours..."):
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

    # ── Affichage des résultats ────────────────────────────────────────────
    if "resultats" not in st.session_state:
        st.markdown(
            f"""
            <div style="
                margin-top:32px;padding:24px;
                background:var(--bg-card);border:1px solid var(--cyan-border);
                border-radius:4px;display:flex;align-items:center;gap:12px;
                font-family:monospace;font-size:0.85rem;color:#6b7280;
            ">
                {_icon("info", 18, "#00d4ff")}
                Chargez un fichier de log ou activez le fichier demo pour demarrer l'analyse.
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        res         = st.session_state.resultats
        alerts      = res["alerts"]
        stats       = res["stats"]
        osint_data  = res["osint_data"]
        log_format  = res["log_format"]
        lines       = res["lines"]
        entries     = res["entries"]
        nom_fichier = res["nom_fichier"]

        score, label_risque, css_risque = _calculer_score_risque(
            alerts, stats.get("error_rate", 0.0)
        )

        # ── Métriques ──────────────────────────────────────────────────────
        st.markdown('<div class="results-fade">', unsafe_allow_html=True)
        st.markdown(
            _section_header("activity", f"Resume — {nom_fichier} &nbsp;·&nbsp; Format : {log_format.upper()}"),
            unsafe_allow_html=True,
        )

        col1, col2, col3, col4, col5, col6 = st.columns(6)
        col1.metric("Lignes lues",     f"{len(lines):,}")
        col2.metric("Entrees parsees", f"{len(entries):,}")
        col3.metric("Alertes",         str(len(alerts)))
        col4.metric("IPs uniques",     str(stats.get("unique_ips", 0)))
        col5.metric("Taux d'erreur",   f"{stats.get('error_rate', 0.0):.1f}%")
        col6.metric("Score de risque", f"{score}/100")

        st.markdown(
            f'<div style="margin:12px 0">'
            f'<span class="risk-box risk-{css_risque}">'
            f'{_icon("target", 16, "currentColor")}'
            f'&nbsp;&nbsp;THREAT LEVEL &nbsp;—&nbsp; {score}/100 &nbsp;{label_risque}'
            f'</span>'
            f'<div class="risk-progress-track">'
            f'<div class="risk-progress-fill risk-progress-{css_risque}" style="--w:{score}%"></div>'
            f'</div>'
            f'</div>',
            unsafe_allow_html=True,
        )
        st.divider()

        # ── Onglets résultats ──────────────────────────────────────────────
        onglet_alertes, onglet_stats, onglet_osint, onglet_rapport = st.tabs([
            f"Alertes ({len(alerts)})",
            "Statistiques",
            "OSINT",
            "Rapport",
        ])

        # ── Onglet Alertes ─────────────────────────────────────────────────
        with onglet_alertes:
            if not alerts:
                st.success("Aucune alerte detectee dans ce fichier.")
            else:
                types_presents = sorted({a.attack_type for a in alerts})
                types_selectionnes = st.multiselect(
                    "Filtrer par type d'attaque",
                    options=types_presents,
                    default=types_presents,
                )
                alertes_filtrees = [a for a in alerts if a.attack_type in types_selectionnes]
                st.markdown(
                    f"<span style='color:#6b7280;font-size:0.78rem;font-family:monospace'>"
                    f"{len(alertes_filtrees)} alerte(s) affichee(s) sur {len(alerts)} detectee(s)"
                    f"</span>",
                    unsafe_allow_html=True,
                )
                st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

                lignes_html = []
                for idx, a in enumerate(alertes_filtrees, start=1):
                    uri_aff = (a.uri[:60] + "…") if len(a.uri or "") > 60 else (a.uri or "-")
                    det_aff = (a.details[:80] + "…") if len(a.details or "") > 80 else (a.details or "-")
                    lignes_html.append(
                        f"<tr>"
                        f"<td style='text-align:center;color:#374151;width:36px'>{idx}</td>"
                        f"<td>{_badge_html(a.attack_type)}</td>"
                        f"<td style='color:#60a5fa;font-family:monospace'>{a.ip or '-'}</td>"
                        f"<td style='color:#d1d5db;font-family:monospace;font-size:0.80em'>{uri_aff}</td>"
                        f"<td style='color:#6b7280;font-size:0.78em'>{det_aff}</td>"
                        f"</tr>"
                    )
                st.markdown(
                    f"<table class='alert-table'>"
                    f"<thead><tr><th>#</th><th>Type</th><th>IP Source</th><th>URI ciblee</th><th>Details</th></tr></thead>"
                    f"<tbody>{''.join(lignes_html)}</tbody></table>",
                    unsafe_allow_html=True,
                )

        # ── Onglet Statistiques ────────────────────────────────────────────
        with onglet_stats:
            import pandas as pd
            col_ips, col_codes = st.columns(2)
            with col_ips:
                st.markdown(_section_header("wifi", "Top IPs sources"), unsafe_allow_html=True)
                top_ips = stats.get("top_ips", [])
                if top_ips:
                    df_ips = pd.DataFrame(top_ips, columns=["IP", "Requetes"])
                    st.dataframe(df_ips, use_container_width=True, hide_index=True)
                    st.bar_chart(df_ips.set_index("IP"))
                else:
                    st.info("Aucune donnee disponible.")
            with col_codes:
                st.markdown(_section_header("server", "Codes HTTP"), unsafe_allow_html=True)
                status_codes = stats.get("status_codes", {})
                if status_codes:
                    df_codes = pd.DataFrame(sorted(status_codes.items()), columns=["Code HTTP", "Nombre"])
                    df_codes["Code HTTP"] = df_codes["Code HTTP"].astype(str)
                    st.dataframe(df_codes, use_container_width=True, hide_index=True)
                    st.bar_chart(df_codes.set_index("Code HTTP"))
                else:
                    st.info("Aucune donnee disponible.")
            st.divider()
            col_uris, col_methods = st.columns(2)
            with col_uris:
                st.markdown(_section_header("link", "Top URIs ciblees"), unsafe_allow_html=True)
                top_uris = stats.get("top_uris", [])
                if top_uris:
                    df_uris = pd.DataFrame(top_uris, columns=["URI", "Requetes"])
                    df_uris["URI"] = df_uris["URI"].str[:60]
                    st.dataframe(df_uris, use_container_width=True, hide_index=True)
                else:
                    st.info("Aucune donnee disponible.")
            with col_methods:
                st.markdown(_section_header("zap", "Methodes HTTP"), unsafe_allow_html=True)
                methods = stats.get("methods", {})
                if methods:
                    df_methods = pd.DataFrame(
                        sorted(methods.items(), key=lambda x: -x[1]),
                        columns=["Methode", "Nombre"],
                    )
                    st.dataframe(df_methods, use_container_width=True, hide_index=True)
                    st.bar_chart(df_methods.set_index("Methode"))
                else:
                    st.info("Aucune donnee disponible.")

        # ── Onglet OSINT ───────────────────────────────────────────────────
        with onglet_osint:
            if not check_ip:
                st.markdown(
                    f"""<div style="padding:18px;background:var(--bg-card);border:1px solid var(--cyan-border);
                    border-radius:4px;display:flex;align-items:center;gap:12px;
                    font-family:monospace;font-size:0.82rem;color:#6b7280;">
                    {_icon("info", 16, "#00d4ff")}
                    Enrichissement OSINT desactive. Activez l'option dans la barre laterale puis relancez.</div>""",
                    unsafe_allow_html=True,
                )
            elif not osint_data:
                st.warning("Aucune donnee OSINT disponible (aucune alerte ou erreur reseau).")
            else:
                st.markdown(_section_header("globe", "Geolocalisation des IPs suspectes"), unsafe_allow_html=True)
                import pandas as pd
                lignes_osint = [
                    {"IP": ip, "Pays": info.get("country","N/A"), "Ville": info.get("city","N/A"),
                     "FAI": info.get("isp","N/A"), "Proxy": "OUI" if info.get("is_proxy") else "non"}
                    for ip, info in osint_data.items()
                ]
                if lignes_osint:
                    st.dataframe(pd.DataFrame(lignes_osint), use_container_width=True, hide_index=True)

        # ── Onglet Rapport ─────────────────────────────────────────────────
        with onglet_rapport:
            st.markdown(_section_header("file-text", "Generer le rapport"), unsafe_allow_html=True)
            st.markdown(
                "<span style='color:#6b7280;font-size:0.80rem;font-family:monospace'>"
                "Rapport complet : alertes, statistiques, score de risque. "
                "Disponible en HTML (interactif) et PDF (impression / archivage)."
                "</span>", unsafe_allow_html=True,
            )
            st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

            if not _WEASYPRINT_OK:
                st.warning("Export PDF indisponible (WeasyPrint non charge). L'export HTML reste fonctionnel.")

            if st.button("Generer le rapport", type="primary"):
                with st.spinner("Generation du rapport..."):
                    try:
                        output_dir = Path(tempfile.gettempdir()) / "log_sentinel_reports"
                        output_dir.mkdir(parents=True, exist_ok=True)
                        reporter = HTMLReporter()
                        chemin_rapport = reporter.generate(
                            alerts=[vars(a) if hasattr(a, "__dataclass_fields__") else a for a in alerts],
                            stats=stats,
                            osint_data=osint_data,
                            output_path=str(output_dir / "report.html"),
                        )
                        with open(chemin_rapport, "r", encoding="utf-8") as fh:
                            contenu_rapport = fh.read()
                        st.success("Rapport genere avec succes.")
                        col_html, col_pdf = st.columns(2)
                        with col_html:
                            st.download_button("Telecharger HTML", data=contenu_rapport,
                                file_name="log_sentinel_report.html", mime="text/html",
                                use_container_width=True)
                        with col_pdf:
                            if _WEASYPRINT_OK:
                                with st.spinner("Conversion PDF..."):
                                    try:
                                        pdf_buf = io.BytesIO()
                                        WeasyHTML(string=contenu_rapport).write_pdf(pdf_buf)
                                        pdf_buf.seek(0)
                                        st.download_button("Telecharger PDF", data=pdf_buf.getvalue(),
                                            file_name="log_sentinel_report.pdf", mime="application/pdf",
                                            use_container_width=True)
                                    except Exception as pdf_err:
                                        st.error(f"Erreur PDF : {pdf_err}")
                            else:
                                st.button("PDF (indisponible)", disabled=True, use_container_width=True)
                        st.markdown(_section_header("eye", "Apercu du rapport"), unsafe_allow_html=True)
                        st.components.v1.html(contenu_rapport, height=600, scrolling=True)
                    except Exception as e:
                        st.error(f"Erreur lors de la generation du rapport : {e}")


# ===========================================================================
# TAB : GUIDE
# ===========================================================================

with tab_guide:
    st.markdown('<div class="results-fade">', unsafe_allow_html=True)

    st.markdown(
        f"""<div class="terminal-header">
            <div class="scan-overlay"></div>
            <div class="terminal-title">{_icon("info", 22, "#00d4ff")}&nbsp; Guide d'utilisation</div>
            <div class="terminal-subtitle">Documentation — Log Sentinel v1.0</div>
        </div>""",
        unsafe_allow_html=True,
    )

    # ── Étapes ────────────────────────────────────────────────────────────
    st.markdown(_section_header("list", "Etapes d'utilisation"), unsafe_allow_html=True)

    for i, (ico, titre, desc) in enumerate([
        ("upload",     "Charger un fichier de log",
         "Glissez-deposez votre fichier dans la zone de depot, ou cliquez sur "
         "<strong style='color:#00d4ff'>Charger le fichier demo</strong> pour tester avec l'exemple Apache fourni."),
        ("settings",   "Ajuster les parametres",
         "Dans la barre laterale : <strong style='color:#00d4ff'>seuil brute-force</strong> "
         "(codes 401/403 par IP), <strong style='color:#00d4ff'>seuil scan</strong> (URIs distinctes par IP), "
         "et optionnellement <strong style='color:#00d4ff'>enrichissement OSINT</strong> (geolocalisation via ip-api.com)."),
        ("eye",        "Consulter les resultats",
         "Onglet <strong style='color:#00d4ff'>Alertes</strong> : menaces detectees avec filtres. "
         "<strong style='color:#00d4ff'>Statistiques</strong> : metriques globales et graphiques. "
         "<strong style='color:#00d4ff'>OSINT</strong> : localisation des IPs. "
         "<strong style='color:#00d4ff'>Rapport</strong> : resume executif."),
        ("file-text",  "Generer et telecharger le rapport",
         "Depuis l'onglet <strong style='color:#00d4ff'>Rapport</strong>, generez le rapport HTML auto-contenu. "
         "Utilisez <strong style='color:#00d4ff'>Telecharger HTML</strong> ou "
         "<strong style='color:#00d4ff'>Telecharger PDF</strong> si WeasyPrint est installe."),
    ], start=1):
        st.markdown(
            f"""<div style="display:flex;align-items:flex-start;gap:16px;background:#0d1421;
            border:1px solid rgba(0,212,255,0.18);border-radius:4px;padding:18px 20px;margin-bottom:12px;">
                <div style="width:36px;height:36px;min-width:36px;border-radius:50%;
                background:rgba(0,212,255,0.10);border:1px solid #00d4ff;display:flex;align-items:center;
                justify-content:center;font-family:'JetBrains Mono',monospace;font-size:0.95rem;
                font-weight:700;color:#00d4ff;flex-shrink:0;">{i:02d}</div>
                <div style="flex:1;">
                    <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;
                    font-family:'JetBrains Mono',monospace;font-size:0.85rem;font-weight:700;
                    color:#f3f4f6;letter-spacing:1px;text-transform:uppercase;">
                    {_icon(ico, 14, "#00d4ff")} {titre}</div>
                    <div style="font-family:'JetBrains Mono',monospace;font-size:0.80rem;
                    color:#9ca3af;line-height:1.6;">{desc}</div>
                </div>
            </div>""",
            unsafe_allow_html=True,
        )

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Formats supportés ──────────────────────────────────────────────────
    st.markdown(_section_header("server", "Formats de log supportes"), unsafe_allow_html=True)

    fc1, fc2, fc3 = st.columns(3)
    for col, (ico, label, desc, ex) in zip([fc1, fc2, fc3], [
        ("globe",  "Apache Combined Log",
         "Format par defaut d'Apache HTTPD. Inclut IP, horodatage, requete, code HTTP, taille, referent et User-Agent.",
         '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/" "Mozilla/4.08"'),
        ("server", "Nginx Access Log",
         "Format access_log de Nginx. Meme structure que Combined Log Apache. Detection automatique du format.",
         '192.168.1.1 - - [10/Oct/2023:14:20:01 +0000] "POST /login HTTP/1.1" 401 152 "-" "python-requests/2.28"'),
        ("cpu",    "Syslog RFC 3164",
         "Journaux systeme Unix/Linux. Le champ host remplace l\'IP, le processus remplace la methode.",
         "Oct 10 13:55:36 myserver sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2"),
    ]):
        with col:
            st.markdown(
                f"""<div style="background:#0d1421;border:1px solid rgba(0,212,255,0.22);
                border-top:2px solid #00d4ff;border-radius:4px;padding:16px;height:100%;">
                    <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;
                    font-family:'JetBrains Mono',monospace;font-size:0.78rem;font-weight:700;
                    color:#00d4ff;letter-spacing:1.5px;text-transform:uppercase;">
                    {_icon(ico, 14, "#00d4ff")} {label}</div>
                    <div style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;
                    color:#9ca3af;line-height:1.5;margin-bottom:12px;">{desc}</div>
                    <div style="background:#080c14;border:1px solid rgba(0,212,255,0.12);
                    border-radius:3px;padding:10px 12px;font-family:'JetBrains Mono',monospace;
                    font-size:0.68rem;color:#4ade80;line-height:1.6;word-break:break-all;">{ex}</div>
                </div>""",
                unsafe_allow_html=True,
            )

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Tableau des détections ─────────────────────────────────────────────
    st.markdown(_section_header("target", "Types d'attaques detectees"), unsafe_allow_html=True)

    rows = "".join([
        f"<tr><td style='white-space:nowrap'><span class='badge badge-{t}'>{t.replace('_',' ').upper()}</span></td>"
        f"<td style='color:#d1d5db'>{d}</td><td style='color:#9ca3af;font-size:0.78em'>{ind}</td></tr>"
        for t, d, ind in [
            ("sql_injection",     "Injection de code SQL malveillant",            "<code>UNION SELECT</code>, <code>' OR 1=1</code>, <code>--</code>"),
            ("xss",               "Cross-Site Scripting — injection JS",           "<code>&lt;script&gt;</code>, <code>javascript:</code>, <code>onerror=</code>"),
            ("brute_force",       "Authentification repetee depuis une meme IP",   "Codes 401/403 repetes &gt; seuil"),
            ("path_traversal",    "Acces a des fichiers systeme hors racine web",  "<code>../</code>, <code>/etc/passwd</code>, <code>/etc/shadow</code>"),
            ("scan",              "Reconnaissance de ports / exploration d'URIs",  "URIs distinctes &gt; seuil ET taux 404 &gt; 50%"),
            ("command_injection", "Execution de commandes systeme via HTTP",       "<code>; ls</code>, <code>| cat</code>, <code>&amp;&amp; rm</code>"),
            ("malicious_ua",      "User-Agent identifie comme outil d'attaque",    "<code>sqlmap</code>, <code>nikto</code>, <code>nmap</code>, <code>masscan</code>"),
            ("sensitive_files",   "Acces tente sur des fichiers sensibles",        "<code>.env</code>, <code>.git</code>, <code>wp-config.php</code>"),
        ]
    ])
    st.markdown(
        f"""<div style="background:#0d1421;border:1px solid rgba(0,212,255,0.18);border-radius:4px;padding:16px;overflow-x:auto;">
        <table class="alert-table">
        <thead><tr><th>Type d'attaque</th><th>Description</th><th>Indicateurs</th></tr></thead>
        <tbody>{rows}</tbody></table></div>""",
        unsafe_allow_html=True,
    )

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Score de risque ────────────────────────────────────────────────────
    st.markdown(_section_header("activity", "Interpretation du score de risque"), unsafe_allow_html=True)

    rc1, rc2, rc3, rc4 = st.columns(4)
    for col, (lvl, rng, color, bg, border, desc) in zip([rc1, rc2, rc3, rc4], [
        ("FAIBLE",   "0 — 19",   "#4ade80", "rgba(74,222,128,0.08)",  "rgba(74,222,128,0.25)",
         "Aucune menace significative. Activite normale ou bruit de fond reseau."),
        ("MODERE",   "20 — 49",  "#fbbf24", "rgba(251,191,36,0.08)",  "rgba(251,191,36,0.25)",
         "Activite suspecte. Surveiller les IPs et verifier les alertes."),
        ("ELEVE",    "50 — 74",  "#fb923c", "rgba(251,146,60,0.08)",  "rgba(251,146,60,0.25)",
         "Attaques avancees detectees. Intervention recommandee."),
        ("CRITIQUE", "75 — 100", "#f87171", "rgba(248,113,113,0.08)", "rgba(248,113,113,0.25)",
         "Compromission potentielle. Isolation et investigation immediates."),
    ]):
        with col:
            st.markdown(
                f"""<div style="background:{bg};border:1px solid {border};border-top:3px solid {color};
                border-radius:4px;padding:16px 14px;text-align:center;">
                <div style="font-family:'JetBrains Mono',monospace;font-size:0.95rem;font-weight:700;
                color:{color};letter-spacing:2px;text-transform:uppercase;margin-bottom:4px;">{lvl}</div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:1.1rem;font-weight:700;
                color:{color};margin-bottom:10px;opacity:0.75;">{rng}</div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;color:#9ca3af;line-height:1.55;">{desc}</div>
                </div>""",
                unsafe_allow_html=True,
            )

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Conseils ───────────────────────────────────────────────────────────
    st.markdown(_section_header("info", "Conseils pratiques"), unsafe_allow_html=True)

    for ico, titre, contenu in [
        ("file-text", "Taille des fichiers",
         "Pour de tres grands fichiers (plusieurs centaines de Mo), filtrez en amont avec "
         "<code style='color:#00d4ff'>grep</code> ou <code style='color:#00d4ff'>awk</code> "
         "pour n'extraire que la plage horaire pertinente avant de charger dans Log Sentinel."),
        ("wifi",      "Limites de taux OSINT",
         "Le service ip-api.com (tier gratuit) autorise environ <strong style='color:#00d4ff'>45 requetes/min</strong>. "
         "L'outil limite automatiquement les verifications aux 5 premieres IPs suspectes."),
        ("zap",       "Ajustement des seuils",
         "Le seuil <strong style='color:#00d4ff'>brute-force</strong> (defaut : 5) doit etre adapte au contexte. "
         "Le seuil <strong style='color:#00d4ff'>scan</strong> (defaut : 10) doit tenir compte des crawlers legitimes."),
    ]:
        st.markdown(
            f"""<div style="display:flex;align-items:flex-start;gap:14px;background:#0d1421;
            border:1px solid rgba(0,212,255,0.15);border-left:3px solid #00d4ff;
            border-radius:4px;padding:16px 18px;margin-bottom:10px;">
            <div style="margin-top:2px;flex-shrink:0;">{_icon(ico, 16, "#00d4ff")}</div>
            <div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:0.80rem;font-weight:700;
                color:#f3f4f6;letter-spacing:1px;text-transform:uppercase;margin-bottom:6px;">{titre}</div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:0.78rem;color:#9ca3af;line-height:1.65;">{contenu}</div>
            </div></div>""",
            unsafe_allow_html=True,
        )

    st.markdown("</div>", unsafe_allow_html=True)


# ===========================================================================
# TAB : A PROPOS
# ===========================================================================

with tab_apropos:

    # ── Header ─────────────────────────────────────────────────────────────
    st.markdown(
        f"""<div style="background:#0d1421;border:1px solid #00d4ff;border-radius:8px;
        padding:28px 32px 24px;margin-bottom:24px;box-shadow:0 0 24px rgba(0,212,255,0.08);">
            <div style="display:flex;align-items:center;gap:14px;margin-bottom:10px;">
                {_icon('shield', 32, '#00d4ff')}
                <span style="font-family:'JetBrains Mono',monospace;font-size:1.45rem;font-weight:700;
                color:#00d4ff;letter-spacing:0.12em;text-transform:uppercase;">Log Sentinel</span>
            </div>
            <div style="font-family:'JetBrains Mono',monospace;font-size:0.78rem;color:#6b7280;
            letter-spacing:0.18em;text-transform:uppercase;">
            v1.0.0 &nbsp;&#9670;&nbsp; Blue Team Security Analyzer</div>
            <div style="width:48px;height:2px;background:linear-gradient(90deg,#00d4ff,transparent);margin-top:14px;"></div>
        </div>""",
        unsafe_allow_html=True,
    )

    # ── Description ────────────────────────────────────────────────────────
    st.markdown(
        f"""<div style="background:#0d1421;border:1px solid rgba(0,212,255,0.25);border-radius:8px;
        padding:24px 28px;margin-bottom:20px;">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;">
                {_icon('target', 18, '#00d4ff')}
                <span style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;color:#00d4ff;
                letter-spacing:0.2em;text-transform:uppercase;">Description du projet</span>
            </div>
            <p style="font-family:'JetBrains Mono',monospace;font-size:0.88rem;color:#cbd5e1;line-height:1.75;margin:0 0 14px;">
                <strong style="color:#f1f5f9;">Log Sentinel</strong> est un analyseur de logs oriente Blue Team.
                Il ingere des fichiers Apache, Nginx et Syslog, les parse automatiquement, puis applique
                des regles de detection par signatures et heuristiques pour identifier les vecteurs d'attaque
                les plus courants.
            </p>
            <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-top:6px;">
                {''.join([f"""<div style="background:rgba(0,212,255,0.06);border:1px solid rgba(0,212,255,0.15);
                border-radius:5px;padding:8px 12px;font-family:'JetBrains Mono',monospace;
                font-size:0.72rem;color:#00d4ff;">{lbl}</div>""" for lbl in [
                    '&#9670; SQL Injection','&#9670; XSS','&#9670; Brute-Force',
                    '&#9670; Path Traversal','&#9670; Port Scan','&#9670; Cmd Injection',
                ]])}
            </div>
        </div>""",
        unsafe_allow_html=True,
    )

    # ── Stack technique ────────────────────────────────────────────────────
    st.markdown(
        f"""<div style="background:#0d1421;border:1px solid rgba(0,212,255,0.25);border-radius:8px;
        padding:22px 28px;margin-bottom:20px;">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;">
                {_icon('cpu', 18, '#00d4ff')}
                <span style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;color:#00d4ff;
                letter-spacing:0.2em;text-transform:uppercase;">Stack technique</span>
            </div>
            <div style="display:flex;flex-wrap:wrap;gap:10px;">
                {''.join([f"""<span style="background:rgba(74,222,128,0.08);border:1px solid rgba(74,222,128,0.25);
                border-radius:4px;padding:5px 14px;font-family:'JetBrains Mono',monospace;
                font-size:0.75rem;color:#4ade80;">{tech}</span>""" for tech in [
                    'Python 3.13','Streamlit','WeasyPrint','Docker','Hugging Face Spaces',
                ]])}
            </div>
        </div>""",
        unsafe_allow_html=True,
    )

    # ── Equipe ─────────────────────────────────────────────────────────────
    st.markdown(
        f"""<div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;">
        {_icon('user', 18, '#00d4ff')}
        <span style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;color:#00d4ff;
        letter-spacing:0.2em;text-transform:uppercase;">Equipe</span></div>""",
        unsafe_allow_html=True,
    )

    col_naomie, col_jesse = st.columns(2)

    with col_naomie:
        st.markdown(
            f"""<div style="background:#0d1421;border:1px solid rgba(0,212,255,0.25);border-radius:8px;
            padding:22px 24px;">
                <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;">
                    {_icon('user', 20, '#00d4ff')}
                    <div style="font-family:'JetBrains Mono',monospace;font-size:0.85rem;
                    font-weight:700;color:#f1f5f9;line-height:1.3;">
                    Naomie NGWIDJOMBY<br>MOUSSAVOU</div>
                </div>
                <div style="background:rgba(0,212,255,0.07);border-left:3px solid #00d4ff;
                border-radius:0 4px 4px 0;padding:8px 12px;margin-bottom:10px;
                font-family:'JetBrains Mono',monospace;font-size:0.73rem;color:#00d4ff;">
                &#9654; Auteure principale</div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:0.73rem;
                color:#94a3b8;line-height:1.6;">Master 1 Cybersecurite</div>
            </div>""",
            unsafe_allow_html=True,
        )

    with col_jesse:
        st.markdown(
            f"""<div style="background:#0d1421;border:1px solid rgba(0,212,255,0.35);border-radius:8px;
            padding:22px 24px;box-shadow:0 0 18px rgba(0,212,255,0.06);">
                <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;">
                    {_icon('user', 20, '#00d4ff')}
                    <div>
                        <div style="font-family:'JetBrains Mono',monospace;font-size:0.85rem;
                        font-weight:700;color:#f1f5f9;">Jesse MPIGA-ODOUMBA</div>
                        <span style="display:inline-block;margin-top:5px;padding:2px 9px;
                        background:rgba(0,212,255,0.12);border:1px solid #00d4ff;border-radius:3px;
                        font-family:'JetBrains Mono',monospace;font-size:0.65rem;color:#00d4ff;
                        letter-spacing:0.12em;box-shadow:0 0 8px rgba(0,212,255,0.3);">&#10003; VERIFIE</span>
                    </div>
                </div>
                <div style="background:rgba(0,212,255,0.07);border-left:3px solid #00d4ff;
                border-radius:0 4px 4px 0;padding:8px 12px;margin-bottom:10px;
                font-family:'JetBrains Mono',monospace;font-size:0.73rem;color:#00d4ff;">
                &#9654; Co-auteur</div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:0.70rem;
                color:#94a3b8;line-height:1.7;">
                    Ingenieur generaliste en systemes industriels et intelligents<br>
                    <span style="color:#6b7280;">option : IA &amp; Big Data</span><br><br>
                    <span style="color:#cbd5e1;">Administrateur Systeme &amp; Securite des Reseaux</span>
                </div>
            </div>""",
            unsafe_allow_html=True,
        )

    st.markdown("<div style='margin-top:20px'></div>", unsafe_allow_html=True)

    # ── Open source ─────────────────────────────────────────────────────────
    st.markdown(
        f"""<div style="background:#0d1421;border:1px solid rgba(74,222,128,0.3);border-radius:8px;
        padding:22px 28px;margin-bottom:20px;display:flex;align-items:flex-start;gap:16px;">
            <div style="flex-shrink:0;margin-top:2px;">{_icon('lock', 22, '#4ade80')}</div>
            <div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;color:#4ade80;
                letter-spacing:0.2em;text-transform:uppercase;margin-bottom:10px;">Open Source</div>
                <p style="font-family:'JetBrains Mono',monospace;font-size:0.83rem;color:#cbd5e1;line-height:1.75;margin:0;">
                    Ce projet est open source. Vous etes libres de l'utiliser, le modifier et l'ameliorer
                    selon vos besoins. <span style="color:#4ade80;">Contributions bienvenues.</span>
                    Que ce soit une correction de bug, une nouvelle detection, ou l'integration d'agents IA —
                    toute amelioration est la bienvenue.
                </p>
            </div>
        </div>""",
        unsafe_allow_html=True,
    )

    # ── Futures ameliorations ───────────────────────────────────────────────
    st.markdown(
        f"""<div style="background:#0d1421;border:1px solid rgba(0,212,255,0.25);border-radius:8px;
        padding:22px 28px;margin-bottom:20px;display:flex;align-items:flex-start;gap:16px;">
            <div style="flex-shrink:0;margin-top:2px;">{_icon('zap', 22, '#00d4ff')}</div>
            <div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;color:#00d4ff;
                letter-spacing:0.2em;text-transform:uppercase;margin-bottom:10px;">Futures ameliorations</div>
                <p style="font-family:'JetBrains Mono',monospace;font-size:0.83rem;color:#cbd5e1;line-height:1.75;margin:0;">
                    Integration d'<strong style="color:#00d4ff;">agents IA</strong> pour l'analyse automatisee,
                    correlation d'evenements multi-sources, et reponse aux incidents en temps reel.
                    Support de formats supplementaires (Windows Event Log, JSON).
                    Tableau de bord multi-fichiers.
                </p>
            </div>
        </div>""",
        unsafe_allow_html=True,
    )

    # ── Lien live ──────────────────────────────────────────────────────────
    st.markdown(
        f"""<div style="background:#0d1421;border:1px solid rgba(0,212,255,0.25);border-radius:8px;
        padding:20px 28px;display:flex;align-items:center;gap:14px;">
            <div style="flex-shrink:0;">{_icon('link', 18, '#00d4ff')}</div>
            <div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:0.68rem;color:#6b7280;
                letter-spacing:0.18em;text-transform:uppercase;margin-bottom:6px;">Application en ligne</div>
                <a href="https://mpigajesse-log-sentinel.hf.space/" target="_blank"
                style="font-family:'JetBrains Mono',monospace;font-size:0.82rem;color:#00d4ff;
                text-decoration:none;border-bottom:1px solid rgba(0,212,255,0.35);padding-bottom:1px;">
                https://mpigajesse-log-sentinel.hf.space/</a>
            </div>
            <div style="margin-left:auto;display:flex;align-items:center;gap:7px;">
                <span class="live-dot"></span>
                <span style="font-family:'JetBrains Mono',monospace;font-size:0.68rem;
                color:#4ade80;letter-spacing:0.12em;">LIVE</span>
            </div>
        </div>""",
        unsafe_allow_html=True,
    )

