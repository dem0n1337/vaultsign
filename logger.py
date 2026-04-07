"""Logging configuration for VaultSign.

Sets up file logging with rotation to ~/.local/share/vaultsign/vaultsign.log.
All log output is passed through token redaction before writing.
"""

import logging
import os
import stat
from logging.handlers import RotatingFileHandler
from pathlib import Path

from vault_backend import redact_tokens

LOG_DIR = Path.home() / ".local" / "share" / "vaultsign"
LOG_FILE = LOG_DIR / "vaultsign.log"
MAX_BYTES = 1_000_000  # 1 MB
BACKUP_COUNT = 3


class RedactingFormatter(logging.Formatter):
    """Formatter that redacts Vault tokens from log messages."""

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        return redact_tokens(message)


def setup_logging() -> logging.Logger:
    """Configure and return the application logger."""
    LOG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)

    logger = logging.getLogger("vaultsign")
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        handler = RotatingFileHandler(
            LOG_FILE, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT,
        )
        # Secure the log file permissions
        try:
            os.chmod(LOG_FILE, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

        formatter = RedactingFormatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger
