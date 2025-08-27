"""
Dependencies Module - FastAPI Dependency Functions

This module contains dependency functions used across the FastAPI application,
particularly for extracting and validating client configuration from request headers.
"""

from fastapi import Header
from app.core.keycloak_client import ClientConfig


def get_client_config(
    x_client_id: str = Header(..., description="Client ID"),
    x_client_secret: str = Header(..., description="Client Secret"),
    x_realm: str = Header(..., description="Keycloak Realm")
) -> ClientConfig:
    """
    Extract client configuration from request headers

    This dependency extracts multi-tenant client configuration from request headers
    and creates a ClientConfig instance that can be used to interact with the
    appropriate Keycloak client for the requesting application.

    Args:
        x_client_id: Client ID from X-Client-Id header
        x_client_secret: Client secret from X-Client-Secret header  
        x_realm: Keycloak realm from X-Realm header

    Returns:
        ClientConfig: Configuration object for the requesting client
    """
    return ClientConfig(
        client_id=x_client_id,
        client_secret=x_client_secret,
        realm=x_realm
    )
