"""
Keycloak Admin Routes

This module provides administrative endpoints for managing Keycloak realms and clients.
These endpoints require direct admin credentials for security and should be used carefully.
"""

import logging
from fastapi import APIRouter, HTTPException
from typing import Dict, Any

from app.models.auth import (
    CreateRealmRequest,
    CreateClientRequest,
    RealmInfoRequest,
    ClientInfoRequest,
    DeleteRealmRequest,
    DeleteClientRequest,
    CreateRoleRequest,
    AssignRoleRequest,
    UserRoleRequest
)
from app.core.keycloak import keycloak_client
from app.core.logging import get_structured_logger

# Get structured logger
logger = get_structured_logger(__name__)

# Create router
router = APIRouter(prefix="/admin", tags=["Keycloak Administration"])


@router.post("/realms")
async def create_realm(request: CreateRealmRequest):
    """
    Create a new Keycloak realm with default configurations.

    This endpoint creates a new realm with sensible defaults for user authentication.

    Security Note: Admin credentials are required and passed in the request body.
    These credentials are NOT stored and are only used for this operation.

    Body Parameters:
    - realm_name: Name of the new realm
    - display_name: Display name for the realm (optional)
    - enabled: Whether the realm is enabled (default: true)
    - registration_allowed: Allow user registration (default: true)
    - admin_username: Keycloak admin username
    - admin_password: Keycloak admin password

    Returns:
        Dict containing created realm information and configuration
    """
    try:
        # Prepare realm configuration
        realm_data = {
            "realm": request.realm_name,
            "displayName": request.display_name or request.realm_name,
            "enabled": request.enabled,
            "registrationAllowed": request.registration_allowed,
            "registrationEmailAsUsername": request.registration_email_as_username,
            "loginWithEmailAllowed": request.login_with_email_allowed,
            "duplicateEmailsAllowed": request.duplicate_emails_allowed,
            "verifyEmail": request.verify_email,
            "resetPasswordAllowed": request.reset_password_allowed,
            "rememberMe": request.remember_me,
            # Security configurations
            "sslRequired": "external",
            "loginTheme": "keycloak",
            "accountTheme": "keycloak",
            "adminTheme": "keycloak",
            "emailTheme": "keycloak",
            # Token settings
            "accessTokenLifespan": 300,  # 5 minutes
            "refreshTokenMaxReuse": 0,
            "ssoSessionIdleTimeout": 1800,  # 30 minutes
            "ssoSessionMaxLifespan": 36000,  # 10 hours
            # Password policy
            "passwordPolicy": "length(8) and digits(1) and lowerCase(1) and upperCase(1)",
        }

        result = await keycloak_client.create_realm(
            realm_data=realm_data,
            admin_username=request.admin_username,
            admin_password=request.admin_password
        )

        logger.info(f"✅ Realm '{request.realm_name}' created successfully")

        return {
            **result,
            "realm_configuration": {
                "realm_name": request.realm_name,
                "features_enabled": {
                    "user_registration": request.registration_allowed,
                    "email_login": request.login_with_email_allowed,
                    "password_reset": request.reset_password_allowed,
                    "remember_me": request.remember_me
                },
                "security_settings": {
                    "ssl_required": "external",
                    "password_policy": "Strong password required (8+ chars, mixed case, digits)",
                    "session_timeout": "30 minutes idle, 10 hours max"
                }
            }
        }

    except HTTPException:
        logger.error(f"❌ Realm creation failed for '{request.realm_name}'")
        raise
    except Exception as e:
        logger.error(f"❌ Unexpected error during realm creation: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/clients")
async def create_client(request: CreateClientRequest):
    """
    Create a new Keycloak client with configurations suitable for user authentication.

    This endpoint creates a confidential client with proper settings for login/registration.
    When service accounts are enabled, the API automatically assigns required roles for user management.

    NEW FEATURE: Automatic Role Assignment
    - When service_accounts_enabled=true, the API automatically assigns 'manage-users' and 'view-users' roles
    - This eliminates the need for manual role assignment via Keycloak console
    - Service account can immediately perform user management operations

    Security Note: Admin credentials are required and passed in the request body.
    These credentials are NOT stored and are only used for this operation.

    Body Parameters:
    - client_id: Unique identifier for the client
    - client_name: Display name for the client (optional)
    - realm_name: Name of the realm where client should be created
    - redirect_uris: List of allowed redirect URIs
    - web_origins: List of allowed web origins for CORS
    - service_accounts_enabled: Enable service account with automatic role assignment (default: False)
    - admin_username: Keycloak admin username
    - admin_password: Keycloak admin password

    Returns:
        Dict containing created client information, credentials, and role assignment status
    """
    try:
        # Prepare client configuration for user authentication without admin access
        client_data = {
            "clientId": request.client_id,
            "name": request.client_name or request.client_id,
            "protocol": "openid-connect",
            "enabled": True,
            "publicClient": False,  # Confidential client
            "standardFlowEnabled": True,  # Authorization Code Flow
            # Direct Grant Flow (username/password)
            "directAccessGrantsEnabled": True,
            "serviceAccountsEnabled": request.service_accounts_enabled,  # Configurable service account
            "authorizationServicesEnabled": False,  # No fine-grained permissions
            "fullScopeAllowed": True,
            "redirectUris": request.redirect_uris,
            "webOrigins": request.web_origins,
            "baseUrl": request.web_origins[0] if request.web_origins else "",
            # Default client scopes for user authentication
            "defaultClientScopes": [
                "web-origins",
                "role_list",
                "profile",
                "roles",
                "email"
            ],
            "optionalClientScopes": [
                "address",
                "phone",
                "offline_access",
                "microprofile-jwt"
            ],
            # Security settings
            "implicitFlowEnabled": False,  # Disable implicit flow for security
            "bearerOnly": False,
            "consentRequired": False,
            "frontchannelLogout": True,
            # Access settings
            "surrogateAuthRequired": False,
            "alwaysDisplayInConsole": False,
            "clientAuthenticatorType": "client-secret",
            # PKCE settings for enhanced security
            "attributes": {
                "pkce.code.challenge.method": "S256",
                "client.secret.creation.time": str(int(__import__('time').time())),
                "oauth2.device.authorization.grant.enabled": "false",
                "oidc.ciba.grant.enabled": "false",
                "backchannel.logout.session.required": "true",
                "backchannel.logout.revoke.offline.tokens": "false"
            }
        }

        result = await keycloak_client.create_client(
            client_data=client_data,
            realm_name=request.realm_name,
            admin_username=request.admin_username,
            admin_password=request.admin_password
        )

        logger.info(
            f"✅ Client '{request.client_id}' created successfully in realm '{request.realm_name}'")

        return {
            **result,
            "client_configuration": {
                "client_id": request.client_id,
                "realm": request.realm_name,
                "features_enabled": {
                    "user_login": True,
                    "user_registration": False,  # Handled by realm settings
                    "authorization_code_flow": True,
                    "direct_grant_flow": True,
                    "admin_access": False,  # Explicitly disabled
                    "service_account": request.service_accounts_enabled,  # Reflects actual setting
                    "automatic_role_assignment": request.service_accounts_enabled  # New feature
                },
                "security_features": {
                    "confidential_client": True,
                    "pkce_enabled": True,
                    "implicit_flow_disabled": True,
                    "client_secret_required": True
                },
                "service_account_configuration": {
                    "enabled": request.service_accounts_enabled,
                    "automatic_role_assignment": result.get("role_assignment", {}).get("roles_assigned", False),
                    "assigned_roles": result.get("role_assignment", {}).get("assigned_roles", []),
                    "role_assignment_status": result.get("role_assignment", {}).get("role_assignment_error") or "Success" if result.get("role_assignment", {}).get("roles_assigned") else "Not applicable"
                },
                "usage_instructions": [
                    "Use the client_id and client_secret for authentication requests",
                    "This client can authenticate users but cannot perform admin operations",
                    "Redirect URIs and web origins are configured for CORS",
                    "Use Authorization Code Flow or Direct Grant Flow for user authentication"
                ] + (
                    [
                        "Service account enabled with automatic role assignment for user management",
                        "Service account can now create, manage, and view users without manual role assignment",
                        "Required roles (manage-users, view-users) have been automatically assigned"
                    ] if request.service_accounts_enabled and result.get("role_assignment", {}).get("roles_assigned") else
                    [
                        "Service account enabled but role assignment failed - check logs for details",
                        "Manual role assignment via Keycloak console may be required"
                    ] if request.service_accounts_enabled else []
                )
            }
        }

    except HTTPException:
        logger.error(
            f"❌ Client creation failed for '{request.client_id}' in realm '{request.realm_name}'")
        raise
    except Exception as e:
        logger.error(f"❌ Unexpected error during client creation: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/realms/info")
async def get_realm_info(request: RealmInfoRequest):
    """
    Get detailed information about a Keycloak realm.

    This endpoint retrieves comprehensive information about a realm including
    configuration, clients, and user statistics.

    Security Note: Admin credentials are required and passed in the request body.
    These credentials are NOT stored and are only used for this operation.

    Body Parameters:
    - realm_name: Name of the realm to query
    - admin_username: Keycloak admin username
    - admin_password: Keycloak admin password

    Returns:
        Dict containing detailed realm information
    """
    try:
        result = await keycloak_client.get_realm_info(
            realm_name=request.realm_name,
            admin_username=request.admin_username,
            admin_password=request.admin_password
        )

        logger.info(
            f"✅ Retrieved information for realm '{request.realm_name}'")

        # Enhance the response with summary information
        realm_info = result["realm_info"]
        clients = result["clients"]

        # Filter and categorize clients
        auth_clients = [c for c in clients if not c.get(
            "bearerOnly") and c.get("standardFlowEnabled")]
        service_clients = [c for c in clients if c.get(
            "serviceAccountsEnabled")]
        public_clients = [c for c in clients if c.get("publicClient")]

        return {
            **result,
            "realm_summary": {
                "realm_name": request.realm_name,
                "enabled": realm_info.get("enabled"),
                "registration_allowed": realm_info.get("registrationAllowed"),
                "login_with_email": realm_info.get("loginWithEmailAllowed"),
                "total_users": result["users_count"],
                "total_clients": len(clients),
                "client_categories": {
                    "authentication_clients": len(auth_clients),
                    "service_account_clients": len(service_clients),
                    "public_clients": len(public_clients)
                }
            }
        }

    except HTTPException:
        logger.error(
            f"❌ Failed to retrieve realm info for '{request.realm_name}'")
        raise
    except Exception as e:
        logger.error(
            f"❌ Unexpected error during realm info retrieval: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/clients/info")
async def get_client_info(request: ClientInfoRequest):
    """
    Get detailed information about a specific Keycloak client.

    This endpoint retrieves comprehensive information about a client including
    configuration, roles, and credentials.

    Security Note: Admin credentials are required and passed in the request body.
    These credentials are NOT stored and are only used for this operation.

    Body Parameters:
    - realm_name: Name of the realm containing the client
    - client_id: Client ID to query
    - admin_username: Keycloak admin username
    - admin_password: Keycloak admin password

    Returns:
        Dict containing detailed client information
    """
    try:
        result = await keycloak_client.get_client_info(
            realm_name=request.realm_name,
            client_id=request.client_id,
            admin_username=request.admin_username,
            admin_password=request.admin_password
        )

        logger.info(
            f"✅ Retrieved information for client '{request.client_id}' in realm '{request.realm_name}'")

        # Enhance the response with client capabilities summary
        client_info = result["client_info"]

        capabilities = {
            "user_authentication": client_info.get("standardFlowEnabled", False),
            "direct_grant": client_info.get("directAccessGrantsEnabled", False),
            "service_account": client_info.get("serviceAccountsEnabled", False),
            "authorization_services": client_info.get("authorizationServicesEnabled", False),
            "public_client": client_info.get("publicClient", False),
            "bearer_only": client_info.get("bearerOnly", False)
        }

        return {
            **result,
            "client_summary": {
                "client_id": request.client_id,
                "realm_name": request.realm_name,
                "enabled": client_info.get("enabled"),
                "capabilities": capabilities,
                "redirect_uris": client_info.get("redirectUris", []),
                "web_origins": client_info.get("webOrigins", []),
                "has_secret": bool(result.get("client_secret")),
                "total_roles": len(result.get("client_roles", []))
            }
        }

    except HTTPException:
        logger.error(
            f"❌ Failed to retrieve client info for '{request.client_id}' in realm '{request.realm_name}'")
        raise
    except Exception as e:
        logger.error(
            f"❌ Unexpected error during client info retrieval: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete("/realms")
async def delete_realm(request: DeleteRealmRequest):
    """
    Delete a Keycloak realm.

    ⚠️ WARNING: This operation is irreversible and will delete ALL data in the realm
    including users, clients, roles, and configurations.

    Security Note: Admin credentials are required and passed in the request body.
    These credentials are NOT stored and are only used for this operation.

    Body Parameters:
    - realm_name: Name of the realm to delete
    - admin_username: Keycloak admin username
    - admin_password: Keycloak admin password

    Returns:
        Dict containing deletion confirmation
    """
    try:
        result = await keycloak_client.delete_realm(
            realm_name=request.realm_name,
            admin_username=request.admin_username,
            admin_password=request.admin_password
        )

        logger.warning(f"🗑️ Realm '{request.realm_name}' deleted permanently")

        return {
            **result,
            "warning": "Realm and all its data have been permanently deleted",
            "affected_resources": [
                "All users in the realm",
                "All clients in the realm", 
                "All roles and permissions",
                "All realm configurations"
            ]
        }

    except HTTPException:
        logger.error(f"❌ Failed to delete realm '{request.realm_name}'")
        raise
    except Exception as e:
        logger.error(f"❌ Unexpected error during realm deletion: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete("/clients")
async def delete_client(request: DeleteClientRequest):
    """
    Delete a Keycloak client from a specific realm.

    This operation will permanently remove the client and all its configurations.
    Users will no longer be able to authenticate using this client.

    Security Note: Admin credentials are required and passed in the request body.
    These credentials are NOT stored and are only used for this operation.

    Body Parameters:
    - realm_name: Name of the realm containing the client
    - client_id: Client ID to delete
    - admin_username: Keycloak admin username
    - admin_password: Keycloak admin password

    Returns:
        Dict containing deletion confirmation
    """
    try:
        result = await keycloak_client.delete_client(
            realm_name=request.realm_name,
            client_id=request.client_id,
            admin_username=request.admin_username,
            admin_password=request.admin_password
        )

        logger.warning(f"🗑️ Client '{request.client_id}' deleted from realm '{request.realm_name}'")

        return {
            **result,
            "warning": "Client has been permanently deleted",
            "affected_resources": [
                "Client configuration and settings",
                "Client roles and permissions", 
                "Client secret (if any)",
                "All active sessions for this client"
            ],
            "next_steps": [
                "Update your applications to use a different client",
                "Users will need to re-authenticate with the new client configuration"
            ]
        }

    except HTTPException:
        logger.error(f"❌ Failed to delete client '{request.client_id}' from realm '{request.realm_name}'")
        raise
    except Exception as e:
        logger.error(f"❌ Unexpected error during client deletion: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/roles")
async def create_role(request: CreateRoleRequest):
    """
    Create a new realm role.

    This endpoint creates a new role in the specified realm that can be assigned to users.

    Security Note: Admin credentials are required and passed in the request body.
    These credentials are NOT stored and are only used for this operation.

    Body Parameters:
    - realm_name: Name of the realm where role should be created
    - role_name: Name of the role (e.g., 'user', 'paid-user', 'lawyer')
    - role_description: Description of the role (optional)
    - admin_username: Keycloak admin username
    - admin_password: Keycloak admin password

    Returns:
        Dict containing created role information
    """
    try:
        result = await keycloak_client.create_realm_role(
            realm_name=request.realm_name,
            role_name=request.role_name,
            role_description=request.role_description,
            admin_username=request.admin_username,
            admin_password=request.admin_password
        )

        logger.info(f"✅ Role '{request.role_name}' created successfully in realm '{request.realm_name}'")
        return result

    except HTTPException:
        logger.error(f"❌ Failed to create role '{request.role_name}' in realm '{request.realm_name}'")
        raise
    except Exception as e:
        logger.error(f"❌ Unexpected error during role creation: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/users/roles/assign")
async def assign_user_roles(request: AssignRoleRequest):
    """
    Assign roles to a user.

    This endpoint assigns specified roles to a user in the given realm.

    Security Note: Admin credentials are required and passed in the request body.
    These credentials are NOT stored and are only used for this operation.

    Body Parameters:
    - realm_name: Name of the realm
    - username: Username of the user
    - roles: List of role names to assign (e.g., ['user', 'paid-user'])
    - admin_username: Keycloak admin username
    - admin_password: Keycloak admin password

    Returns:
        Dict containing role assignment status
    """
    try:
        result = await keycloak_client.assign_user_roles(
            realm_name=request.realm_name,
            username=request.username,
            roles=request.roles,
            admin_username=request.admin_username,
            admin_password=request.admin_password
        )

        logger.info(f"✅ Roles assigned to user '{request.username}' in realm '{request.realm_name}'")
        return result

    except HTTPException:
        logger.error(f"❌ Failed to assign roles to user '{request.username}' in realm '{request.realm_name}'")
        raise
    except Exception as e:
        logger.error(f"❌ Unexpected error during role assignment: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/users/roles")
async def get_user_roles(request: UserRoleRequest):
    """
    Get roles assigned to a user.

    This endpoint retrieves all roles assigned to a specific user in the given realm.

    Security Note: Admin credentials are required and passed in the request body.
    These credentials are NOT stored and are only used for this operation.

    Body Parameters:
    - realm_name: Name of the realm
    - username: Username of the user
    - admin_username: Keycloak admin username
    - admin_password: Keycloak admin password

    Returns:
        Dict containing user roles information
    """
    try:
        result = await keycloak_client.get_user_roles_info(
            realm_name=request.realm_name,
            username=request.username,
            admin_username=request.admin_username,
            admin_password=request.admin_password
        )

        logger.info(f"✅ Retrieved roles for user '{request.username}' in realm '{request.realm_name}'")
        return result

    except HTTPException:
        logger.error(f"❌ Failed to get roles for user '{request.username}' in realm '{request.realm_name}'")
        raise
    except Exception as e:
        logger.error(f"❌ Unexpected error during role retrieval: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")
