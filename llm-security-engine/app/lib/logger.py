"""
Structured JSON logger for the Local LLM Security Engine.

Outputs newline-delimited JSON to stdout. Each log record is a single JSON object
with standard fields (timestamp, level, logger, message) plus any extra context
passed as keyword arguments.

Usage:
    from app.lib.logger import get_logger
    log = get_logger(__name__)
    log.info("ollama_call_start", model="phi4-mini", prompt_length=420)
    log.warning("fallback_used", reason="parse failed", strategy="none")
    log.error("ollama_error", error_type="OllamaConnectionError", detail="...")
"""

import json
import logging
import time
from typing import Any


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Merge any extra fields attached via the `extra` dict
        for key, val in record.__dict__.items():
            if key not in (
                "name", "msg", "args", "levelname", "levelno", "pathname",
                "filename", "module", "exc_info", "exc_text", "stack_info",
                "lineno", "funcName", "created", "msecs", "relativeCreated",
                "thread", "threadName", "processName", "process", "message",
                "taskName",
            ):
                payload[key] = val

        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)

        return json.dumps(payload)


def _configure_root() -> None:
    root = logging.getLogger()
    if not any(isinstance(h, logging.StreamHandler) for h in root.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(_JsonFormatter())
        root.addHandler(handler)
    root.setLevel(logging.DEBUG)


_configure_root()


class _StructuredLogger:
    """Thin wrapper that forwards kwargs into LogRecord's `extra` dict."""

    def __init__(self, name: str) -> None:
        self._log = logging.getLogger(name)

    def _emit(self, level: int, message: str, **kwargs: Any) -> None:
        self._log.log(level, message, extra=kwargs, stacklevel=3)

    def debug(self, message: str, **kwargs: Any) -> None:
        self._emit(logging.DEBUG, message, **kwargs)

    def info(self, message: str, **kwargs: Any) -> None:
        self._emit(logging.INFO, message, **kwargs)

    def warning(self, message: str, **kwargs: Any) -> None:
        self._emit(logging.WARNING, message, **kwargs)

    def error(self, message: str, **kwargs: Any) -> None:
        self._emit(logging.ERROR, message, **kwargs)

    def critical(self, message: str, **kwargs: Any) -> None:
        self._emit(logging.CRITICAL, message, **kwargs)


def get_logger(name: str) -> _StructuredLogger:
    """Return a structured logger for the given module name."""
    return _StructuredLogger(name)
