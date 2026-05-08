"""
logviews.py - Agent Mistral AI « LogViews » pour Log Sentinel.

Utilise agents.complete() pour interroger l'agent LogViews (Codestral)
et récupérer directement la réponse dans l'application.
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

_AGENT_ID = "ag_019e08b1610c736d9255133090d6f877"


class LogViewsAgent:
    """Client pour l'agent Mistral LogViews.

    Appelle agents.complete() — réponse synchrone, pas besoin du Playground.
    """

    def __init__(self) -> None:
        api_key = os.environ.get("MISTRAL_API_KEY", "")
        self.available = _MISTRAL_OK and bool(api_key)
        self._client = _MistralClass(api_key=api_key) if self.available else None  # type: ignore[misc]

    def analyser(self, contenu: str) -> str:
        """Envoie le rapport à LogViews et retourne directement son analyse.

        Lève RuntimeError si l'agent est indisponible ou si l'API échoue.
        """
        if not self.available:
            raise RuntimeError(
                "Agent non disponible — vérifiez MISTRAL_API_KEY "
                "et que le paquet mistralai est installé."
            )
        try:
            response = self._client.agents.complete(  # type: ignore[union-attr]
                agent_id=_AGENT_ID,
                messages=[{"role": "user", "content": contenu}],
            )
            return response.choices[0].message.content
        except Exception as exc:
            raise RuntimeError(f"Erreur API Mistral : {exc}") from exc
