"""
Application Factory Module

This module contains the FastAPI application factory function and configuration.
It handles application initialization, middleware setup, route registration, and logging.
"""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI

from app.core.config import settings
from app.core.logging import setup_logging, get_structured_logger
from app.routes import auth_router, health_router, info_router, console_router
from app.exceptions import internal_server_error_handler
from app.middleware import setup_security_middleware

# Setup structured logging
setup_logging()

# Get structured logger
logger = get_structured_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    logger.info(
        "🚀 Multi-Tenant Authentication Service starting up...",
        service="multi-tenant-auth",
        environment=settings.environment,
        debug=settings.debug
    )
    logger.info(
        "📡 Keycloak server configured",
        keycloak_server=settings.keycloak_server_url,
        service="multi-tenant-auth"
    )
    logger.info(
        "✅ Multi-tenant client initialized successfully",
        service="multi-tenant-auth"
    )
    yield
    logger.info(
        "🛑 Multi-Tenant Authentication Service shutting down...",
        service="multi-tenant-auth"
    )


def create_app() -> FastAPI:
    """
    Create and configure FastAPI application

    Returns:
        FastAPI: Configured FastAPI application instance
    """
    # Create FastAPI application
    app = FastAPI(
        title="Multi-Tenant Authentication Service",
        description="Authentication service supporting multiple applications with different Keycloak configurations",
        version="1.0.0",
        lifespan=lifespan
    )

    # Setup security middleware
    setup_security_middleware(app)

    # Include routers
    app.include_router(info_router)
    app.include_router(auth_router)
    app.include_router(health_router)
    app.include_router(console_router)

    # Add exception handlers
    app.add_exception_handler(500, internal_server_error_handler)

    return app


# Create application instance
app_server = create_app()
