"""
Security Middleware Configuration

This module contains security middleware setup and configuration for the FastAPI application.
It includes various security-related middleware for production-ready deployment.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

try:
    from starlette.middleware.gzip import GZipMiddleware
    GZIP_AVAILABLE = True
except ImportError:
    GZIP_AVAILABLE = False

from app.core.config import settings


def setup_security_middleware(app: FastAPI) -> None:
    """
    Configure security middleware for the FastAPI application
    
    This function adds various security middleware in the correct order:
    1. TrustedHost - Validates Host header to prevent Host header attacks
    2. CORS - Handles cross-origin requests for web applications
    3. GZip - Compresses responses for better performance (if available)
    
    Args:
        app: FastAPI application instance
    """
    
    # Add TrustedHost middleware for security (should be first)
    # Protects against Host header injection attacks
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.trusted_hosts
    )

    # Add CORS middleware for cross-origin requests
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=settings.cors_allow_methods,
        allow_headers=settings.cors_allow_headers,
    )

    # Add GZip middleware for response compression (if available)
    if GZIP_AVAILABLE:
        app.add_middleware(
            GZipMiddleware, 
            minimum_size=1000  # Only compress responses larger than 1KB
        )


def setup_security_headers_middleware(app: FastAPI) -> None:
    """
    Add security headers middleware for enhanced security
    
    This can be extended to add custom security headers like:
    - X-Content-Type-Options: nosniff
    - X-Frame-Options: DENY
    - X-XSS-Protection: 1; mode=block
    - Strict-Transport-Security (for HTTPS)
    
    Args:
        app: FastAPI application instance
    """
    # This can be implemented with a custom middleware or using
    # third-party packages like fastapi-security-headers
    pass
