"""
uPKI RA Server - Logging Module.

This module provides logging functionality for the uPKI RA Server.
It configures logging to both file and console with appropriate formatting.
"""

import logging
import os
from pathlib import Path


class UPKILogger:
    """Logger class for uPKI RA Server.

    This class provides a consistent logging interface for the RA server,
    with support for both file and console logging.
    """

    DEFAULT_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

    def __init__(
        self,
        name: str = "upki-ra",
        log_file: str | None = None,
        level: int = logging.INFO,
    ) -> None:
        """Initialize the logger.

        Args:
            name: Logger name, typically "upki-ra".
            log_file: Optional path to log file. If None, logs to console only.
            level: Logging level (default: INFO).
        """
        self.name = name
        self.log_file = log_file
        self.level = level
        self._logger: logging.Logger | None = None

    @property
    def logger(self) -> logging.Logger:
        """Get the logger instance, creating it if necessary.

        Returns:
            Configured logging.Logger instance.
        """
        if self._logger is None:
            self._logger = self._setup_logger()
        return self._logger

    def _setup_logger(self) -> logging.Logger:
        """Set up the logger with handlers and formatters.

        Returns:
            Configured logging.Logger instance.
        """
        logger = logging.getLogger(self.name)
        logger.setLevel(self.level)

        # Clear existing handlers to avoid duplicates
        logger.handlers.clear()

        # Create formatter
        formatter = logging.Formatter(self.DEFAULT_FORMAT, datefmt=self.DATE_FORMAT)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(self.level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        # File handler if log file is specified
        if self.log_file:
            log_path = Path(self.log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            file_handler = logging.FileHandler(self.log_file)
            file_handler.setLevel(self.level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        return logger

    def debug(self, message: str) -> None:
        """Log a debug message.

        Args:
            message: The debug message to log.
        """
        self.logger.debug(message)

    def info(self, message: str) -> None:
        """Log an info message.

        Args:
            message: The info message to log.
        """
        self.logger.info(message)

    def warning(self, message: str) -> None:
        """Log a warning message.

        Args:
            message: The warning message to log.
        """
        self.logger.warning(message)

    def error(self, message: str) -> None:
        """Log an error message.

        Args:
            message: The error message to log.
        """
        self.logger.error(message)

    def critical(self, message: str) -> None:
        """Log a critical message.

        Args:
            message: The critical message to log.
        """
        self.logger.critical(message)

    def exception(self, message: str) -> None:
        """Log an exception with traceback.

        Args:
            message: The exception message to log.
        """
        self.logger.exception(message)


def get_logger(
    name: str = "upki-ra", log_dir: str | None = None, level: int = logging.INFO
) -> UPKILogger:
    """Factory function to create a UPKILogger instance.

    This is the recommended way to create logger instances in the application.

    Args:
        name: Logger name.
        log_dir: Optional directory for log files. If None, logs to console only.
        level: Logging level.

    Returns:
        UPKILogger instance.
    """
    log_file = None
    if log_dir:
        log_file = os.path.join(log_dir, ".ra.log")

    return UPKILogger(name=name, log_file=log_file, level=level)
