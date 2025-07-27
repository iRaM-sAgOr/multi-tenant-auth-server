"""
Application Factory Module

This module contains the FastAPI application factory function and configuration.
It handles application initialization, middleware setup, route registration, and logging.
"""

import logging
import sys
from contextlib import asynccontextmanager
from fastapi import FastAPI

from app.core.config import settings
from app.core.logging import setup_logging, get_structured_logger
from app.core.keycloak import verify_keycloak_connectivity
from app.routes.auth import router as auth_router
from app.routes.health import router as health_router
from app.routes.info import router as info_router
from app.routes.console import router as console_router
from app.routes.admin import router as admin_router
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

    # Verify Keycloak connectivity during startup (if enabled)
    if settings.keycloak_startup_check_enabled:
        logger.info(
            "🔍 Checking Keycloak server connectivity...",
            keycloak_server=settings.keycloak_server_url,
            service="multi-tenant-auth"
        )

        keycloak_healthy = await verify_keycloak_connectivity(
            settings.keycloak_server_url,
            retry_count=settings.keycloak_startup_check_retries,
            retry_delay=settings.keycloak_startup_check_retry_delay
        )

        if not keycloak_healthy:
            logger.critical(
                "💥 STARTUP FAILED: Keycloak server is not accessible. Application cannot start without identity provider.",
                keycloak_server=settings.keycloak_server_url,
                service="multi-tenant-auth"
            )

            # Determine whether to exit based on configuration
            should_exit = settings.keycloak_startup_check_exit_on_failure or not settings.debug

            if should_exit:
                logger.critical(
                    "🛑 Exiting application due to Keycloak connectivity failure")
                sys.exit(1)
            else:
                logger.warning(
                    "⚠️  Continuing despite Keycloak connectivity issues (startup check configured to allow)")
        else:
            logger.info(
                "📡 Keycloak server connectivity verified",
                keycloak_server=settings.keycloak_server_url,
                service="multi-tenant-auth"
            )
    else:
        logger.info(
            "⏭️  Keycloak startup connectivity check is disabled",
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
    app.include_router(admin_router)

    # Add exception handlers
    app.add_exception_handler(500, internal_server_error_handler)

    return app


# Create application instance
app_server = create_app()
