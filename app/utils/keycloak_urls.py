"""
Keycloak Console URLs Generator

This module provides utility functions to generate Keycloak console login URLs
for both admin console and user account console access.
"""

from typing import Optional

from app.core.config import settings


def get_keycloak_admin_console_url() -> str:
    """
    Get the Keycloak Admin Console login URL
    
    This URL takes you directly to the Keycloak administration interface
    where you can manage realms, clients, users, roles, etc.
    
    Returns:
        str: Direct URL to Keycloak Admin Console login page
    """
    return f"{settings.keycloak_server_url}/admin/"


def get_keycloak_user_account_console_url(realm: str = "master") -> str:
    """
    Get the Keycloak User Account Console login URL for a specific realm
    
    This URL takes users to their account management interface where they can
    update profile, change password, manage sessions, etc.
    
    Args:
        realm: The Keycloak realm name (default: "master")
        
    Returns:
        str: Direct URL to Keycloak User Account Console for the specified realm
    """
    return f"{settings.keycloak_server_url}/realms/{realm}/account/"


def get_keycloak_realm_login_url(realm: str, client_id: str, redirect_uri: str, state: Optional[str] = None) -> str:
    """
    Generate Keycloak OAuth2/OIDC login URL for a specific realm and client
    
    This creates the standard OAuth2 authorization URL that redirects users
    to Keycloak login page and then back to your application.
    
    Args:
        realm: The Keycloak realm name
        client_id: Your application's client ID in Keycloak
        redirect_uri: Where to redirect after successful login
        state: Optional state parameter for CSRF protection
        
    Returns:
        str: OAuth2 authorization URL for Keycloak login
    """
    base_url = f"{settings.keycloak_server_url}/realms/{realm}/protocol/openid-connect/auth"
    params = [
        f"client_id={client_id}",
        "response_type=code",
        f"redirect_uri={redirect_uri}",
        "scope=openid profile email"
    ]
    
    if state:
        params.append(f"state={state}")
    
    return f"{base_url}?" + "&".join(params)


def get_keycloak_console_info() -> dict:
    """
    Get comprehensive information about available Keycloak console URLs
    
    Returns:
        dict: Dictionary containing all relevant Keycloak console URLs and information
    """
    return {
        "keycloak_server": settings.keycloak_server_url,
        "admin_console": {
            "url": get_keycloak_admin_console_url(),
            "description": "Keycloak Administration Console - Manage realms, clients, users, roles",
            "access": "Admin credentials required"
        },
        "user_account_console": {
            "master_realm": {
                "url": get_keycloak_user_account_console_url("master"),
                "description": "User Account Console for master realm",
                "access": "User credentials required"
            },
            "custom_realm_example": {
                "url": get_keycloak_user_account_console_url("your-realm-name"),
                "description": "User Account Console for custom realm",
                "access": "Replace 'your-realm-name' with actual realm name"
            }
        },
        "oauth2_login_example": {
            "url": get_keycloak_realm_login_url(
                realm="your-realm",
                client_id="your-client-id", 
                redirect_uri="http://localhost:8000/auth/callback",
                state="csrf-protection-token"
            ),
            "description": "OAuth2 login URL example",
            "usage": "Replace realm, client_id, and redirect_uri with actual values"
        },
        "common_realms": {
            "master": "Default administrative realm",
            "custom": "Your application-specific realm"
        }
    }
