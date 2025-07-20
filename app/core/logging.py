"""
Enhanced Logging Configuration Module

This module sets up enhanced logging with both standard Python logging and
optional structured logging (structlog) if available. Provides fallback to
standard logging if structlog is not installed.
"""

import logging
import sys
import json
from typing import Any, Dict, Optional
from datetime import datetime

from app.core.config import settings

# Try to import structlog, fall back to standard logging if not available
try:
    import structlog
    from structlog import configure, get_logger
    from structlog.processors import JSONRenderer
    from structlog.dev import ConsoleRenderer
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False


class StructuredFormatter(logging.Formatter):
    """
    Custom formatter that creates structured log output
    even without structlog dependency
    """

    def format(self, record: logging.LogRecord) -> str:
        # Create structured log entry
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }

        # Add extra fields if present
        if hasattr(record, 'extra_fields'):
            log_entry.update(getattr(record, 'extra_fields'))

        if settings.log_format == "json":
            return json.dumps(log_entry)
        else:
            # Human-readable format for development
            timestamp = log_entry["timestamp"]
            level = log_entry["level"]
            logger_name = log_entry["logger"]
            message = log_entry["message"]
            return f"{timestamp} | {level:8} | {logger_name:20} | {message}"


def setup_logging() -> None:
    """
    Configure enhanced logging for the application

    Sets up structured logging with structlog if available,
    otherwise falls back to enhanced standard logging.
    """

    # Configure standard logging
    if STRUCTLOG_AVAILABLE and settings.environment != "development":
        # Use structlog for production
        setup_structlog()
    else:
        # Use enhanced standard logging
        setup_standard_logging()

    # Set third-party loggers to WARNING to reduce noise
    logging.getLogger("uvicorn").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


def setup_structlog() -> None:
    """Setup structlog configuration"""
    if not STRUCTLOG_AVAILABLE:
        return

    # Choose processors based on environment
    if settings.environment == "development":
        processors = [
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="ISO"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            ConsoleRenderer(colors=True)
        ]
    else:
        processors = [
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="ISO"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            JSONRenderer()
        ]

    configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def setup_standard_logging() -> None:
    """Setup enhanced standard logging"""
    formatter = StructuredFormatter()

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, settings.log_level.upper()))
    root_logger.handlers.clear()
    root_logger.addHandler(handler)


class EnhancedLogger:
    """
    Enhanced logger wrapper that provides structured logging capabilities
    even without structlog
    """

    def __init__(self, name: str):
        self.name = name
        self.logger = logging.getLogger(name)

        if STRUCTLOG_AVAILABLE:
            self.struct_logger = get_logger(name)
        else:
            self.struct_logger = None

    def _log_with_context(self, level: str, message: str, **kwargs):
        """Log with additional context"""
        if self.struct_logger:
            # Use structlog if available
            getattr(self.struct_logger, level.lower())(message, **kwargs)
        else:
            # Use standard logging with extra context
            extra_fields = kwargs
            log_record = self.logger.makeRecord(
                name=self.name,
                level=getattr(logging, level.upper()),
                fn="",
                lno=0,
                msg=message,
                args=(),
                exc_info=None
            )
            setattr(log_record, 'extra_fields', extra_fields)
            self.logger.handle(log_record)

    def info(self, message: str, **kwargs):
        """Log info message with context"""
        self._log_with_context("INFO", message, **kwargs)

    def warning(self, message: str, **kwargs):
        """Log warning message with context"""
        self._log_with_context("WARNING", message, **kwargs)

    def error(self, message: str, **kwargs):
        """Log error message with context"""
        self._log_with_context("ERROR", message, **kwargs)

    def critical(self, message: str, **kwargs):
        """Log critical message with context"""
        self._log_with_context("CRITICAL", message, **kwargs)

    def debug(self, message: str, **kwargs):
        """Log debug message with context"""
        self._log_with_context("DEBUG", message, **kwargs)


def get_structured_logger(name: Optional[str] = None) -> EnhancedLogger:
    """
    Get an enhanced logger instance

    Args:
        name: Logger name (defaults to caller's module)

    Returns:
        Enhanced logger instance with structured logging capabilities
    """
    return EnhancedLogger(name or "app")


def log_keycloak_operation(operation: str, client_id: str, realm: str, **kwargs) -> Dict[str, Any]:
    """
    Create Keycloak operation context for logging

    Args:
        operation: Type of Keycloak operation (login, register, validate, etc.)
        client_id: Client ID
        realm: Keycloak realm
        **kwargs: Additional context

    Returns:
        Dict with Keycloak operation context for structured logging
    """
    context = {
        "keycloak_operation": operation,
        "client_id": client_id,
        "realm": realm,
        "service": "multi-tenant-auth"
    }
    context.update(kwargs)
    return context


# Application-specific loggers
auth_logger = get_structured_logger("auth")
keycloak_logger = get_structured_logger("keycloak")
middleware_logger = get_structured_logger("middleware")
app_logger = get_structured_logger("app")
