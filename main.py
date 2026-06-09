"""
main.py
-------
Entry point for the Threat Hunting Dashboard application.

Usage:
    python main.py

Configures application-level logging, then launches the GUI.
"""

import logging
import sys
from pathlib import Path

# ── Logging setup ─────────────────────────────────────────────────────────
LOGS_DIR = Path(__file__).parent / "logs"
LOGS_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(LOGS_DIR / "application.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)

logger = logging.getLogger(__name__)


def main() -> None:
    """Initialise and run the Threat Hunting Dashboard."""
    logger.info("╔══════════════════════════════════════╗")
    logger.info("║   Threat Hunting Dashboard Starting  ║")
    logger.info("╚══════════════════════════════════════╝")

    try:
        from gui.app import ThreatHuntingApp
        app = ThreatHuntingApp()
        app.mainloop()
    except ImportError as exc:
        logger.critical(
            "Failed to import a required module: %s\n"
            "Run:  pip install -r requirements.txt",
            exc,
        )
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Fatal error: %s", exc)
        sys.exit(1)

    logger.info("Application exited cleanly.")


if __name__ == "__main__":
    main()
