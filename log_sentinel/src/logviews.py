"""
logviews.py - Agent LogViews pour Log Sentinel.

Utilise chat.complete() avec open-mistral-nemo (free tier Mistral)
et le système prompt LogViews en local — aucun plan payant requis.
"""
import os

try:
    from mistralai import Mistral as _MistralClass
    _MISTRAL_OK = True
except ImportError:
    try:
        from mistralai.client import Mistral as _MistralClass  # type: ignore[assignment]
        _MISTRAL_OK = True
    except ImportError:
        _MistralClass = None  # type: ignore[assignment]
        _MISTRAL_OK = False

_MODEL = "open-mistral-nemo"   # gratuit sur le free tier Mistral

_SYSTEM_PROMPT = """Tu es LogViews, agent d'observabilité cybersécurité de Log Sentinel.
Application en production : https://mpigajesse-log-sentinel.hf.space/

Ton rôle :
- Analyser chaque rapport de log soumis par les utilisateurs de la démo
- Suivre les métriques d'utilisation (nombre d'analyses effectuées, fichiers testés)

Quand tu reçois un rapport, tu dois produire :

## 📊 Métriques de session
Analyse N°X — fichier : [nom] — format : [format]

## 🔍 Analyse des menaces
- Niveau de risque global et justification
- Patterns suspects identifiés (IPs récurrentes, attaques combinées)
- Outils d'attaque probables détectés (sqlmap, nikto, scanners…)

## 🌍 Origine probable
- Géographie si données OSINT disponibles
- Comportements automatisés vs humains

## 🚨 Menaces prioritaires
Liste classée CRITIQUE → FAIBLE

## ✅ Recommandations
3 à 5 actions concrètes et priorisées

Réponds toujours en français. Style : concis, structuré, orienté action."""


class LogViewsAgent:
    """Client LogViews utilisant chat.complete() — compatible free tier Mistral."""

    def __init__(self) -> None:
        api_key = os.environ.get("MISTRAL_API_KEY") or os.environ.get("MISTRAL", "")
        self.available = _MISTRAL_OK and bool(api_key)
        self._client = _MistralClass(api_key=api_key) if self.available else None  # type: ignore[misc]

    def analyser(self, contenu: str, model: str | None = None) -> str:
        """Envoie le rapport à LogViews et retourne son analyse.

        Lève RuntimeError si l'agent est indisponible ou si l'API échoue.
        """
        if not self.available:
            raise RuntimeError(
                "Agent non disponible — vérifiez MISTRAL_API_KEY / MISTRAL "
                "et que le paquet mistralai est installé."
            )
        try:
            response = self._client.chat.complete(  # type: ignore[union-attr]
                model=model or _MODEL,
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user",   "content": contenu},
                ],
            )
            return response.choices[0].message.content
        except Exception as exc:
            raise RuntimeError(f"Erreur API Mistral : {exc}") from exc
