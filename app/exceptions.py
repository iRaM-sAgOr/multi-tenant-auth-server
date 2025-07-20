"""
Exception Handlers Module

This module contains global exception handlers for the FastAPI application.
"""

from fastapi import Request
from fastapi.responses import JSONResponse
from app.core.config import settings


async def internal_server_error_handler(request: Request, exc: Exception):
    """Global exception handler for internal server errors"""
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred",
            "detail": str(exc) if settings.debug else "Contact administrator"
        }
    )
