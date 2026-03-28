"""
loader.py - Module de chargement et de détection de format des logs.

Fournit la classe LogLoader responsable de :
  - Lire les fichiers de logs avec repli automatique d'encodage (utf-8 -> latin-1)
  - Détecter le format du log (apache, nginx, syslog, inconnu)
"""

import re
import os
from pathlib import Path


# ---------------------------------------------------------------------------
# Expressions régulières compilées pour la détection du format.
# Testées sur les premières lignes du fichier pour identifier le dialecte.
# ---------------------------------------------------------------------------

# Format Apache Combined/Common Log :
#   127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326
_APACHE_PATTERN = re.compile(
    r'^\S+\s+\S+\s+\S+\s+\[\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4}\]'
    r'\s+"[A-Z]+\s+\S+\s+HTTP/\d\.\d"\s+\d{3}'
)

# Format Nginx access log (très similaire à Apache mais légèrement différent) :
#   127.0.0.1 - - [28/Mar/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0"
_NGINX_PATTERN = re.compile(
    r'^\S+\s+-\s+-\s+\[\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4}\]'
    r'\s+"[A-Z]+\s+\S+\s+HTTP/\d\.\d"\s+\d{3}\s+\d+\s+"[^"]*"\s+"[^"]*"'
)

# Format Syslog (RFC 3164) :
#   Mar 28 12:00:00 hostname process[pid]: message
_SYSLOG_PATTERN = re.compile(
    r'^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}'
    r'\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+:'
)


class LogLoader:
    """
    Charge les fichiers de logs depuis le disque et détecte leur format.

    Formats supportés
    -----------------
    - "apache"  : Format Apache HTTP Server Combined/Common
    - "nginx"   : Format Nginx access log par défaut
    - "syslog"  : Syslog Unix standard (RFC 3164)
    - "unknown" : Format non identifié

    Exemple
    -------
    >>> loader = LogLoader()
    >>> lignes = loader.load("/var/log/nginx/access.log")
    >>> fmt = loader.detect_format(lignes)
    >>> print(fmt)
    'nginx'
    """

    # Nombre de lignes échantillonnées en début de fichier pour la détection.
    _SAMPLE_SIZE: int = 10

    # Encodages essayés dans l'ordre lors de la lecture d'un fichier.
    _ENCODINGS: list[str] = ["utf-8", "latin-1"]

    # ---------------------------------------------------------------------------
    # API publique
    # ---------------------------------------------------------------------------

    def load(self, filepath: str) -> list[str]:
        """
        Lit un fichier de log et retourne ses lignes non vides.

        Paramètres
        ----------
        filepath : str
            Chemin absolu ou relatif vers le fichier de log.

        Retourne
        --------
        list[str]
            Lignes du fichier sans espaces de début/fin.
            Les lignes vides sont ignorées.

        Lève
        ----
        FileNotFoundError
            Si le chemin ne pointe pas vers un fichier existant.
        OSError
            Si le fichier ne peut pas être lu pour une autre raison système.
        UnicodeDecodeError
            Si le fichier ne peut être décodé ni en utf-8 ni en latin-1
            (extrêmement rare en pratique).
        """
        path = Path(filepath)

        if not path.exists():
            raise FileNotFoundError(
                f"Fichier de log introuvable : '{filepath}'"
            )

        if not path.is_file():
            raise FileNotFoundError(
                f"Le chemin existe mais n'est pas un fichier régulier : '{filepath}'"
            )

        last_error: Exception | None = None

        for encoding in self._ENCODINGS:
            try:
                with open(path, "r", encoding=encoding, errors="strict") as fh:
                    lignes = [
                        line.rstrip("\n").rstrip("\r")
                        for line in fh
                        if line.strip()  # ignore les lignes vides
                    ]
                return lignes
            except UnicodeDecodeError as exc:
                last_error = exc
                continue

        # Les deux encodages ont échoué — on relève la dernière erreur avec contexte.
        raise UnicodeDecodeError(
            last_error.encoding,         # type: ignore[union-attr]
            last_error.object,           # type: ignore[union-attr]
            last_error.start,            # type: ignore[union-attr]
            last_error.end,              # type: ignore[union-attr]
            f"Impossible de décoder '{filepath}' avec les encodages {self._ENCODINGS}",
        )

    def detect_format(self, lines: list[str]) -> str:
        """
        Identifie le format du log par correspondance de motifs sur un échantillon.

        La détection fonctionne en attribuant un score à chaque format candidat
        sur les premiers ``_SAMPLE_SIZE`` lignes non vides, puis retourne le
        format ayant obtenu le plus de correspondances.

        Paramètres
        ----------
        lines : list[str]
            Lignes de log telles que retournées par :meth:`load`.

        Retourne
        --------
        str
            L'un des formats : ``"apache"``, ``"nginx"``, ``"syslog"`` ou ``"unknown"``.
        """
        if not lines:
            return "unknown"

        # Échantillon des premières lignes pour la détection
        echantillon: list[str] = lines[: self._SAMPLE_SIZE]

        # Scores de correspondance par format
        scores: dict[str, int] = {
            "nginx": 0,
            "apache": 0,
            "syslog": 0,
        }

        for ligne in echantillon:
            if _NGINX_PATTERN.match(ligne):
                scores["nginx"] += 1
            elif _APACHE_PATTERN.match(ligne):
                scores["apache"] += 1
            elif _SYSLOG_PATTERN.match(ligne):
                scores["syslog"] += 1

        # Format avec le score le plus élevé
        meilleur_format = max(scores, key=lambda fmt: scores[fmt])
        meilleur_score = scores[meilleur_format]

        if meilleur_score == 0:
            return "unknown"

        return meilleur_format

    # ---------------------------------------------------------------------------
    # Méthodes privées
    # ---------------------------------------------------------------------------

    def _read_raw(self, path: Path, encoding: str) -> list[str]:
        """
        Méthode interne : ouvre le fichier avec l'encodage donné et retourne
        les lignes nettoyées et non vides. Lève ``UnicodeDecodeError`` en cas d'échec.
        """
        with open(path, "r", encoding=encoding, errors="strict") as fh:
            return [
                line.rstrip("\n").rstrip("\r")
                for line in fh
                if line.strip()
            ]
