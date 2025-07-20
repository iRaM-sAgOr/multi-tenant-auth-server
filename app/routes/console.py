"""
Keycloak Console Routes

This module provides endpoints to get Keycloak console login URLs
for admin console and user account management.
"""

from fastapi import APIRouter, Query
from typing import Optional

from app.utils.keycloak_urls import (
    get_keycloak_admin_console_url,
    get_keycloak_user_account_console_url,
    get_keycloak_realm_login_url,
    get_keycloak_console_info
)

# Create router
router = APIRouter(prefix="/console", tags=["Keycloak Console"])


@router.get("/admin")
async def get_admin_console_url():
    """
    Get Keycloak Admin Console login URL
    
    Returns the direct URL to access the Keycloak administration interface.
    Use this URL to manage realms, clients, users, roles, and other Keycloak configurations.
    
    Returns:
        dict: Admin console URL and access information
    """
    return {
        "admin_console_url": get_keycloak_admin_console_url(),
        "description": "Keycloak Administration Console",
        "purpose": "Manage realms, clients, users, roles, and Keycloak configurations",
        "access_required": "Admin credentials for Keycloak",
        "usage": "Open this URL in your browser to access the admin interface"
    }


@router.get("/account")
async def get_account_console_url(realm: str = Query("master", description="Keycloak realm name")):
    """
    Get Keycloak User Account Console login URL for a specific realm
    
    Returns the direct URL to access the user account management interface
    where users can update their profile, change password, manage sessions, etc.
    
    Args:
        realm: The Keycloak realm name (default: "master")
        
    Returns:
        dict: User account console URL and access information
    """
    return {
        "account_console_url": get_keycloak_user_account_console_url(realm),
        "realm": realm,
        "description": f"User Account Console for realm '{realm}'",
        "purpose": "Manage user profile, password, sessions, and account settings",
        "access_required": f"User credentials for realm '{realm}'",
        "usage": "Open this URL in your browser to access user account management"
    }


@router.get("/oauth-login")
async def get_oauth_login_url(
    realm: str = Query(..., description="Keycloak realm name"),
    client_id: str = Query(..., description="Your application's client ID"),
    redirect_uri: str = Query(..., description="Redirect URI after login"),
    state: Optional[str] = Query(None, description="State parameter for CSRF protection")
):
    """
    Generate OAuth2/OIDC login URL for Keycloak authentication
    
    Creates a standard OAuth2 authorization URL that redirects users to Keycloak
    login page and then back to your application after successful authentication.
    
    Args:
        realm: The Keycloak realm name
        client_id: Your application's client ID in Keycloak  
        redirect_uri: Where to redirect after successful login
        state: Optional state parameter for CSRF protection
        
    Returns:
        dict: OAuth2 login URL and flow information
    """
    login_url = get_keycloak_realm_login_url(realm, client_id, redirect_uri, state)
    
    return {
        "oauth_login_url": login_url,
        "realm": realm,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "description": "OAuth2/OIDC Authorization URL",
        "purpose": "Redirect users to Keycloak for authentication",
        "flow": "OAuth2 Authorization Code Flow",
        "usage": "Redirect your users to this URL for authentication",
        "next_steps": [
            "1. User will be redirected to Keycloak login page",
            "2. User authenticates with Keycloak",
            "3. Keycloak redirects back to your redirect_uri with authorization code",
            "4. Exchange the code for tokens using /auth/exchange-code endpoint"
        ]
    }


@router.get("/all")
async def get_all_console_urls():
    """
    Get comprehensive information about all available Keycloak console URLs
    
    Provides a complete overview of all available Keycloak console access points
    including admin console, user account consoles, and OAuth2 login examples.
    
    Returns:
        dict: Complete information about all Keycloak console URLs
    """
    return get_keycloak_console_info()
