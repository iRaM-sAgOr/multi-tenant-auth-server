"""
API Routes Package

This package contains all API route handlers organized by functionality.
Each module focuses on a specific domain of operations.
"""

from .auth import router as auth_router
from .health import router as health_router
from .info import router as info_router
from .console import router as console_router

__all__ = ["auth_router", "health_router", "info_router", "console_router"]
