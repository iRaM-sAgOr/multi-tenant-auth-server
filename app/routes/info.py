"""
Information Routes

This module contains informational endpoints like service documentation
and usage guides.
"""

from fastapi import APIRouter

# Create router
router = APIRouter(tags=["Information"])


@router.get("/")
async def root():
    """Service information and usage guide"""
    return {
        "service": "Multi-Tenant Authentication Service",
        "version": "1.0.0",
        "description": "Supports multiple applications with different Keycloak configurations",
        "endpoints": {
            "POST /auth/login": "User authentication (username/password)",
            "POST /auth/register": "User registration",
            "POST /auth/validate": "Token validation",
            "POST /auth/refresh": "Token refresh",
            "POST /auth/logout": "User logout",
            "POST /auth/auth-url": "Get OAuth2 authorization URL",
            "POST /auth/exchange-code": "Exchange authorization code for tokens",
            "GET /auth/status": "Client status check",
            "GET /health": "Service health check"
        },
        "required_headers": {
            "X-Client-Id": "Your application's client ID",
            "X-Client-Secret": "Your application's client secret",
            "X-Realm": "Keycloak realm name"
        },
        "example_usage": {
            "app1": {
                "headers": {
                    "X-Client-Id": "app1",
                    "X-Client-Secret": "app1-secret",
                    "X-Realm": "realm1"
                }
            },
            "app2": {
                "headers": {
                    "X-Client-Id": "app2",
                    "X-Client-Secret": "app2-secret",
                    "X-Realm": "realm1"
                }
            }
        },
        "authentication_flows": {
            "direct_login": {
                "description": "Direct username/password authentication",
                "endpoint": "POST /auth/login",
                "use_case": "Backend APIs, mobile apps"
            },
            "oauth2_authorization_code": {
                "description": "Standard OAuth2/OIDC web flow",
                "steps": [
                    "1. POST /auth/auth-url to get authorization URL",
                    "2. Redirect user to authorization URL",
                    "3. User authenticates with Keycloak",
                    "4. Keycloak redirects back with code",
                    "5. POST /auth/exchange-code to get tokens"
                ],
                "use_case": "Web applications, SPAs"
            }
        }
    }
