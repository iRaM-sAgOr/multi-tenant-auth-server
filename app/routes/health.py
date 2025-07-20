"""
Health Check Routes

This module contains health check and service status endpoints.
"""

from fastapi import APIRouter
from app.core.config import settings

# Create router
router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check():
    """Service health check endpoint"""
    return {
        "status": "healthy",
        "service": "Multi-Tenant Authentication Service",
        "version": "1.0.0",
        "keycloak_server": settings.keycloak_server_url
    }
