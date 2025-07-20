"""
Health Check Routes

This module contains health check and service status endpoints.
"""

from fastapi import APIRouter
from app.core.config import settings
from app.core.keycloak import check_keycloak_health

# Create router
router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check():
    """
    Comprehensive service health check endpoint
    
    This endpoint checks:
    1. Application status
    2. Keycloak server connectivity
    3. Response times and error details
    """
    # Check Keycloak connectivity
    keycloak_health = await check_keycloak_health(settings.keycloak_server_url)
    
    # Determine overall service health
    service_healthy = keycloak_health["keycloak_available"]
    overall_status = "healthy" if service_healthy else "unhealthy"
    
    return {
        "status": overall_status,
        "service": "Multi-Tenant Authentication Service",
        "version": "1.0.0",
        "timestamp": None,  # Could add current timestamp
        "dependencies": {
            "keycloak": {
                "status": "healthy" if keycloak_health["keycloak_available"] else "unhealthy",
                "server_url": keycloak_health["server_url"],
                "response_time_ms": keycloak_health["response_time_ms"],
                "error": keycloak_health["error"]
            }
        }
    }


@router.get("/health/keycloak")
async def keycloak_health_check():
    """
    Dedicated Keycloak connectivity health check
    
    Returns detailed information about Keycloak server status,
    response times, and any connection issues.
    """
    return await check_keycloak_health(settings.keycloak_server_url)
