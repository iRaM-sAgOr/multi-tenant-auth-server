"""
Keycloak Client Module - Multi-Tenant Identity Provider Integration

USECASE:
This module provides a multi-tenant interface for interacting with Keycloak, which serves
as the identity and access management (IAM) backend for multiple applications.
It handles all Keycloak operations including:

AUTHENTICATION OPERATIONS:
- User login with username/password for multiple clients
- Token validation and introspection across different realms
- Token refresh using refresh tokens
- User logout and session termination

USER MANAGEMENT OPERATIONS:
- User registration and profile creation for different applications
- User role assignment and management
- User profile updates and queries

ARCHITECTURE:
The KeycloakClient class supports multi-tenant operations by:
1. Creating KeycloakOpenID clients dynamically based on client credentials
2. Creating KeycloakAdmin clients for administrative operations per client
3. Supporting multiple realms and client configurations

MULTI-TENANT FLOW:
1. Each API request includes client credentials (client_id, client_secret, realm)
2. Create or reuse Keycloak clients for the specific tenant
3. Perform operations using the tenant-specific client
4. Cache clients for performance optimization
"""

import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import httpx
import asyncio
from keycloak import KeycloakOpenID, KeycloakAdmin  # type: ignore
from keycloak.exceptions import KeycloakError  # type: ignore
from jose import jwt, JWTError
from fastapi import HTTPException, status

from app.core.config import settings

# Configure logging
logger = logging.getLogger(__name__)


async def check_keycloak_health(server_url: str, timeout: int = 30) -> Dict[str, Any]:
    """
    Check Keycloak server health and availability

    Args:
        server_url: Keycloak server URL
        timeout: Request timeout in seconds

    Returns:
        Dict containing health status and details
    """
    health_status = {
        "keycloak_available": False,
        "server_url": server_url,
        "error": None,
        "response_time_ms": None
    }

    try:
        # Remove trailing slash and add health endpoint
        base_url = server_url.rstrip('/')
        health_url = f"{base_url}/health"

        start_time = asyncio.get_event_loop().time()

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(health_url)

        end_time = asyncio.get_event_loop().time()
        response_time = int((end_time - start_time) * 1000)

        health_status["response_time_ms"] = response_time

        if response.status_code == 200:
            health_status["keycloak_available"] = True
            logger.info(
                f"✅ Keycloak server is healthy - {server_url} (Response time: {response_time}ms)")
        else:
            health_status["error"] = f"HTTP {response.status_code}: {response.text}"
            logger.error(
                f"❌ Keycloak health check failed - {server_url}: {health_status['error']}")

    except httpx.TimeoutException:
        health_status["error"] = f"Connection timeout after {timeout}s"
        logger.error(f"❌ Keycloak connection timeout - {server_url}")
    except httpx.ConnectError:
        health_status["error"] = "Connection refused - server may be down"
        logger.error(f"❌ Keycloak connection refused - {server_url}")
    except Exception as e:
        health_status["error"] = str(e)
        logger.error(
            f"❌ Keycloak health check error - {server_url}: {str(e)}")

    return health_status


async def verify_keycloak_connectivity(server_url: str, retry_count: int = 3, retry_delay: int = 5) -> bool:
    """
    Verify Keycloak connectivity with retries

    Args:
        server_url: Keycloak server URL
        retry_count: Number of retry attempts
        retry_delay: Delay between retries in seconds

    Returns:
        bool: True if Keycloak is accessible, False otherwise
    """
    logger.info(f"🔍 Verifying Keycloak connectivity: {server_url}")

    for attempt in range(1, retry_count + 1):
        logger.info(
            f"🔄 Keycloak connectivity check - Attempt {attempt}/{retry_count}")

        health_status = await check_keycloak_health(server_url)

        if health_status["keycloak_available"]:
            logger.info("✅ Keycloak server connectivity verified successfully")
            return True

        if attempt < retry_count:
            logger.warning(
                f"⏳ Keycloak connectivity failed, retrying in {retry_delay}s... (Attempt {attempt}/{retry_count})")
            await asyncio.sleep(retry_delay)
        else:
            logger.error(
                f"❌ Keycloak server is not accessible after {retry_count} attempts: {health_status['error']}")

    return False


@dataclass
class ClientConfig:
    """Configuration for a specific client/tenant"""
    client_id: str
    client_secret: str
    realm: str
    server_url: Optional[str] = None

    def __post_init__(self):
        if self.server_url is None:
            self.server_url = settings.keycloak_server_url


class MultiTenantKeycloakClient:
    """
    Multi-Tenant Keycloak Client - Interface for Multiple Applications

    USECASE:
    This class provides a centralized interface for all Keycloak operations across
    multiple applications/tenants. Each operation requires client configuration
    to determine which Keycloak realm and client to use.

    MULTI-TENANT DESIGN:
    1. No fixed client configuration - clients are created dynamically
    2. Each method accepts client_config parameter
    3. Caching mechanism for performance optimization
    4. Support for multiple realms and applications

    SUPPORTED PATTERNS:
    - Multiple applications with same realm
    - Multiple applications with different realms
    - Service account authentication per client
    - Admin user authentication per client
    """

    def __init__(self):
        """
        Initialize Multi-Tenant Keycloak Client.

        Note: Unlike traditional approach, no specific client is initialized here.
        Clients are created dynamically based on incoming requests.
        """
        # Cache for Keycloak clients to avoid recreating them
        self._openid_clients: Dict[str, KeycloakOpenID] = {}
        self._admin_clients: Dict[str, KeycloakAdmin] = {}

        logger.info("Multi-tenant Keycloak client initialized successfully")

    def _get_client_key(self, config: ClientConfig) -> str:
        """Generate a unique key for client caching"""
        return f"{config.server_url}:{config.realm}:{config.client_id}"

    def _get_openid_client(self, config: ClientConfig) -> KeycloakOpenID:
        """Get or create KeycloakOpenID client for the given configuration"""
        client_key = self._get_client_key(config)

        if client_key not in self._openid_clients:
            self._openid_clients[client_key] = KeycloakOpenID(
                server_url=config.server_url,
                client_id=config.client_id,
                realm_name=config.realm,
                client_secret_key=config.client_secret
            )
            logger.debug(
                f"Created new OpenID client for {config.client_id} in realm {config.realm}")

        return self._openid_clients[client_key]

    def _get_admin_client(self, config: ClientConfig, use_service_account: bool = True) -> Optional[KeycloakAdmin]:
        """Get or create KeycloakAdmin client for the given configuration"""
        client_key = self._get_client_key(config)

        if client_key not in self._admin_clients:
            try:
                if use_service_account:
                    # Try service account authentication first
                    admin_client = KeycloakAdmin(
                        server_url=config.server_url,
                        realm_name=config.realm,
                        client_id=config.client_id,
                        client_secret_key=config.client_secret,
                        verify=True,
                        auto_refresh_token=['get', 'put', 'post', 'delete']
                    )
                    logger.debug(
                        f"Created admin client using service account for {config.client_id}")
                else:
                    # Fallback to admin user if provided in settings
                    if settings.keycloak_admin_username and settings.keycloak_admin_password:
                        admin_client = KeycloakAdmin(
                            server_url=config.server_url,
                            username=settings.keycloak_admin_username,
                            password=settings.keycloak_admin_password,
                            realm_name=config.realm,
                            client_id=config.client_id,
                            client_secret_key=config.client_secret,
                            verify=True
                        )
                        logger.debug(
                            f"Created admin client using admin user for {config.client_id}")
                    else:
                        return None

                self._admin_clients[client_key] = admin_client

            except Exception as e:
                logger.warning(
                    f"Failed to create admin client for {config.client_id}: {str(e)}")
                return None

        return self._admin_clients.get(client_key)

    async def authenticate_user(self, username: str, password: str, client_config: ClientConfig) -> Dict[str, Any]:
        """
        Authenticate User - Multi-Tenant Login Method

        USECASE:
        This method handles user authentication against Keycloak using username/password
        credentials for a specific client/tenant.

        AUTHENTICATION FLOW:
        1. Get or create KeycloakOpenID client for the specified tenant
        2. Send credentials to Keycloak token endpoint
        3. Receive access token, refresh token, and token metadata
        4. Introspect access token to get detailed token information
        5. Retrieve user profile information using the access token
        6. Return comprehensive authentication result

        Args:
            username: User's username or email address
            password: User's password (plaintext, will be transmitted securely)
            client_config: Client configuration (client_id, client_secret, realm)

        Returns:
            Dict containing:
            - access_token: JWT token for API authentication
            - refresh_token: Token for refreshing access token
            - token_type: Always "bearer"
            - expires_in: Token expiration time in seconds
            - user_info: User profile information
            - token_info: Token metadata and claims
            - client_info: Information about the client used

        Raises:
            HTTPException: 401 for invalid credentials, 500 for service errors
        """
        try:
            # Get KeycloakOpenID client for this tenant
            keycloak_openid = self._get_openid_client(client_config)

            # === STEP 1: REQUEST TOKENS FROM KEYCLOAK ===
            token_response = keycloak_openid.token(username, password)

            # === STEP 2: INTROSPECT ACCESS TOKEN ===
            token_info = keycloak_openid.introspect(
                token_response['access_token'])

            # === STEP 3: RETRIEVE USER PROFILE ===
            user_info = keycloak_openid.userinfo(
                token_response['access_token'])

            logger.info(
                f"User {username} authenticated successfully for client {client_config.client_id} in realm {client_config.realm}")

            # === STEP 4: RETURN AUTHENTICATION RESULT ===
            return {
                "access_token": token_response['access_token'],
                "refresh_token": token_response['refresh_token'],
                "token_type": "bearer",
                "expires_in": token_response['expires_in'],
                "user_info": user_info,
                "token_info": token_info,
                "client_info": {
                    "client_id": client_config.client_id,
                    "realm": client_config.realm
                }
            }

        except KeycloakError as e:
            logger.warning(
                f"Authentication failed for user {username} in client {client_config.client_id}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )
        except Exception as e:
            logger.error(
                f"Unexpected error during authentication for client {client_config.client_id}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Authentication service error"
            )

    async def refresh_token(self, refresh_token: str, client_config: ClientConfig) -> Dict[str, Any]:
        """
        Refresh access token using refresh token for a specific client.

        Args:
            refresh_token: Valid refresh token
            client_config: Client configuration

        Returns:
            Dict containing new access token and refresh token

        Raises:
            HTTPException: If token refresh fails
        """
        try:
            keycloak_openid = self._get_openid_client(client_config)
            token_response = keycloak_openid.refresh_token(refresh_token)

            logger.info(
                f"Token refreshed successfully for client {client_config.client_id}")

            return {
                "access_token": token_response['access_token'],
                "refresh_token": token_response['refresh_token'],
                "token_type": "bearer",
                "expires_in": token_response['expires_in'],
                "client_info": {
                    "client_id": client_config.client_id,
                    "realm": client_config.realm
                }
            }

        except KeycloakError as e:
            logger.warning(
                f"Token refresh failed for client {client_config.client_id}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token"
            )

    async def validate_token(self, token: str, client_config: ClientConfig) -> Dict[str, Any]:
        """
        Validate and decode access token for a specific client.

        Args:
            token: JWT access token
            client_config: Client configuration

        Returns:
            Dict containing token information and user data

        Raises:
            HTTPException: If token is invalid or expired
        """
        try:
            keycloak_openid = self._get_openid_client(client_config)

            # Introspect token with Keycloak
            token_info = keycloak_openid.introspect(token)

            if not token_info.get('active', False):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token is not active"
                )

            # Get user info from token
            user_info = keycloak_openid.userinfo(token)

            # Extract roles safely
            realm_access = token_info.get('realm_access')
            roles = []
            if isinstance(realm_access, dict):
                roles = realm_access.get('roles', [])

            return {
                "token_info": token_info,
                "user_info": user_info,
                "user_id": token_info.get('sub'),
                "username": token_info.get('preferred_username'),
                "email": token_info.get('email'),
                "roles": roles,
                "client_info": {
                    "client_id": client_config.client_id,
                    "realm": client_config.realm
                }
            }

        except KeycloakError as e:
            logger.warning(
                f"Token validation failed for client {client_config.client_id}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token"
            )
        except Exception as e:
            logger.error(
                f"Unexpected error during token validation for client {client_config.client_id}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Token validation service error"
            )

    async def logout_user(self, refresh_token: str, client_config: ClientConfig) -> bool:
        """
        Logout user by invalidating refresh token for a specific client.

        Args:
            refresh_token: User's refresh token
            client_config: Client configuration

        Returns:
            True if logout successful, False otherwise
        """
        try:
            keycloak_openid = self._get_openid_client(client_config)
            keycloak_openid.logout(refresh_token)
            logger.info(
                f"User logged out successfully for client {client_config.client_id}")
            return True

        except KeycloakError as e:
            logger.warning(
                f"Logout failed for client {client_config.client_id}: {str(e)}")
            return False

    async def create_user(self, user_data: Dict[str, Any], client_config: ClientConfig) -> Dict[str, Any]:
        """
        Create a new user in Keycloak for a specific client.

        Args:
            user_data: Dictionary containing user information
            client_config: Client configuration

        Returns:
            Dict containing created user information

        Raises:
            HTTPException: If user creation fails or admin client not available
        """
        keycloak_admin = self._get_admin_client(client_config)

        if not keycloak_admin:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "error": "User registration service unavailable",
                    "message": f"Keycloak admin access not configured for client {client_config.client_id}",
                    "solutions": [
                        f"Enable 'Service Accounts' in Keycloak client '{client_config.client_id}' settings",
                        "Ensure the service account has realm-admin or user management roles",
                        "Or provide admin credentials via KEYCLOAK_ADMIN_USERNAME and KEYCLOAK_ADMIN_PASSWORD"
                    ],
                    "client_info": {
                        "client_id": client_config.client_id,
                        "realm": client_config.realm
                    }
                }
            )

        try:
            user_id = keycloak_admin.create_user(user_data)
            user_details = keycloak_admin.get_user(user_id)

            logger.info(
                f"User created successfully with ID: {user_id} for client {client_config.client_id}")

            return {
                "user_id": user_id,
                "user_details": user_details,
                "client_info": {
                    "client_id": client_config.client_id,
                    "realm": client_config.realm
                }
            }

        except KeycloakError as e:
            error_str = str(e)
            logger.error(
                f"User creation failed for client {client_config.client_id}: {error_str}")

            # Handle specific error cases
            if "403" in error_str or "Forbidden" in error_str:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "error": "Permission denied for user creation",
                        "message": f"The service account for client '{client_config.client_id}' lacks permission to create users",
                        "keycloak_error": error_str,
                        "solutions": [
                            f"Go to Keycloak Admin Console → Clients → '{client_config.client_id}' → Service Account Roles",
                            "Add the following roles to the service account:",
                            "  - realm-admin (for full realm management)",
                            "  - manage-users (for user management only)",
                            "  - create-client (if creating client-specific roles)",
                            "Alternative: Enable 'Service Accounts' and configure proper role mappings",
                            "Or provide admin credentials via KEYCLOAK_ADMIN_USERNAME and KEYCLOAK_ADMIN_PASSWORD"
                        ],
                        "client_info": {
                            "client_id": client_config.client_id,
                            "realm": client_config.realm,
                            "server_url": client_config.server_url
                        }
                    }
                )
            elif "409" in error_str or "exists" in error_str.lower():
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail={
                        "error": "User already exists",
                        "message": "A user with this username or email already exists",
                        "keycloak_error": error_str,
                        "solutions": [
                            "Choose a different username",
                            "Check if the email is already registered",
                            "Use the login endpoint instead of registration"
                        ]
                    }
                )
            else:
                # Generic error handling
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "error": "User creation failed",
                        "message": f"Failed to create user in Keycloak",
                        "keycloak_error": error_str,
                        "client_info": {
                            "client_id": client_config.client_id,
                            "realm": client_config.realm
                        }
                    }
                )

    async def get_user_roles(self, user_id: str, client_config: ClientConfig) -> List[str]:
        """
        Get user roles from Keycloak for a specific client.

        Args:
            user_id: Keycloak user ID
            client_config: Client configuration

        Returns:
            List of user roles
        """
        keycloak_admin = self._get_admin_client(client_config)

        if not keycloak_admin:
            logger.warning(
                f"Admin client not available for role retrieval for client {client_config.client_id}")
            return []

        try:
            roles = keycloak_admin.get_realm_roles_of_user(user_id)
            return [role['name'] for role in roles if isinstance(role, dict) and 'name' in role]

        except KeycloakError as e:
            logger.warning(
                f"Failed to retrieve user roles for client {client_config.client_id}: {str(e)}")
            return []

    def get_client_status(self, client_config: ClientConfig) -> Dict[str, Any]:
        """
        Get the status of operations for a specific client.

        Args:
            client_config: Client configuration

        Returns:
            Dict containing client status information
        """
        openid_available = True
        admin_available = self._get_admin_client(client_config) is not None

        return {
            "client_id": client_config.client_id,
            "realm": client_config.realm,
            "openid_available": openid_available,
            "admin_available": admin_available,
            "features_enabled": {
                "user_authentication": openid_available,
                "token_validation": openid_available,
                "user_registration": admin_available,
                "user_management": admin_available,
                "role_management": admin_available
            },
            "message": "All operations available" if admin_available
            else "Admin operations unavailable - authentication only"
        }

    def check_admin_permissions(self, client_config: ClientConfig) -> Dict[str, Any]:
        """
        Check admin permissions and provide detailed guidance for setup.

        Args:
            client_config: Client configuration

        Returns:
            Dict containing permission status and setup guidance
        """
        admin_client = self._get_admin_client(client_config)

        result = {
            "client_id": client_config.client_id,
            "realm": client_config.realm,
            "server_url": client_config.server_url,
            "admin_client_available": admin_client is not None,
            "permissions_status": "unknown",
            "required_permissions": [
                "realm-admin (full realm management)",
                "manage-users (user creation and management)",
                "view-users (user information access)"
            ],
            "setup_instructions": []
        }

        if not admin_client:
            result.update({
                "permissions_status": "no_admin_access",
                "message": "No admin client available - service account not configured",
                "setup_instructions": [
                    f"1. Go to Keycloak Admin Console → Clients → '{client_config.client_id}'",
                    "2. Settings tab → Enable 'Service Accounts'",
                    "3. Save the configuration",
                    "4. Go to 'Service Account Roles' tab",
                    "5. In 'Client Roles' dropdown, select 'realm-management'",
                    "6. Add the following roles:",
                    "   - realm-admin (recommended for full access)",
                    "   - OR manage-users + view-users (minimal for user management)",
                    "7. Alternative: Set KEYCLOAK_ADMIN_USERNAME and KEYCLOAK_ADMIN_PASSWORD in environment"
                ]
            })
            return result

        # Test permissions by trying to get realm info
        try:
            # Try a simple admin operation
            realm_info = admin_client.get_realm(client_config.realm)
            result.update({
                "permissions_status": "full_access",
                "message": "Service account has admin access to the realm",
                "realm_info": {
                    "realm_name": realm_info.get("realm"),
                    "enabled": realm_info.get("enabled"),
                    "registration_allowed": realm_info.get("registrationAllowed")
                }
            })
        except Exception as e:
            error_str = str(e)
            if "403" in error_str or "Forbidden" in error_str:
                result.update({
                    "permissions_status": "insufficient_permissions",
                    "message": "Service account exists but lacks necessary permissions",
                    "error": error_str,
                    "setup_instructions": [
                        f"1. Go to Keycloak Admin Console → Clients → '{client_config.client_id}' → Service Account Roles",
                        "2. In 'Client Roles' dropdown, select 'realm-management'",
                        "3. Add the following roles to the service account:",
                        "   - realm-admin (for full realm management)",
                        "   - OR manage-users + view-users (for user management only)",
                        "4. Save and try again",
                        "5. Verify the client has 'Service Accounts Enabled' in Settings"
                    ]
                })
            else:
                result.update({
                    "permissions_status": "connection_error",
                    "message": "Unable to connect to Keycloak admin API",
                    "error": error_str,
                    "setup_instructions": [
                        "1. Verify Keycloak server is running and accessible",
                        "2. Check client credentials (client_id and client_secret)",
                        "3. Verify realm name is correct",
                        "4. Check network connectivity to Keycloak server"
                    ]
                })

        return result

    async def exchange_code_for_tokens(self, code: str, redirect_uri: str, client_config: ClientConfig) -> Dict[str, Any]:
        """
        Exchange Authorization Code for Tokens - OAuth2 Authorization Code Flow

        USECASE:
        This method handles the OAuth2 Authorization Code Flow where:
        1. User is redirected to Keycloak login page
        2. User authenticates with Keycloak
        3. Keycloak redirects back to application with authorization code
        4. Application exchanges code for access token, refresh token, and ID token

        FLOW:
        Frontend -> Keycloak Login -> User Auth -> Redirect with Code -> Backend calls this method

        Args:
            code: Authorization code received from Keycloak redirect
            redirect_uri: The redirect URI used in the original authorization request (must match)
            client_config: Client configuration for the specific application

        Returns:
            Dict containing:
            - access_token: JWT token for API authentication
            - refresh_token: Token for refreshing access token
            - id_token: OIDC ID token with user information
            - token_type: Always "bearer"
            - expires_in: Token expiration time in seconds
            - user_info: User profile information from userinfo endpoint
            - token_info: Token metadata and claims
            - client_info: Information about the client used

        Raises:
            HTTPException: 400 for invalid code/redirect_uri, 500 for service errors
        """
        try:
            # Get KeycloakOpenID client for this tenant
            keycloak_openid = self._get_openid_client(client_config)

            # === STEP 1: EXCHANGE AUTHORIZATION CODE FOR TOKENS ===
            token_response = keycloak_openid.token(
                grant_type='authorization_code',
                code=code,
                redirect_uri=redirect_uri
            )

            # === STEP 2: INTROSPECT ACCESS TOKEN ===
            token_info = keycloak_openid.introspect(
                token_response['access_token'])

            # === STEP 3: RETRIEVE USER PROFILE ===
            user_info = keycloak_openid.userinfo(
                token_response['access_token'])

            logger.info(
                f"Authorization code exchanged successfully for client {client_config.client_id} in realm {client_config.realm}")

            # === STEP 4: RETURN TOKEN EXCHANGE RESULT ===
            return {
                "access_token": token_response['access_token'],
                "refresh_token": token_response['refresh_token'],
                # OIDC ID token (may not always be present)
                "id_token": token_response.get('id_token'),
                "token_type": "bearer",
                "expires_in": token_response['expires_in'],
                "user_info": user_info,
                "token_info": token_info,
                "client_info": {
                    "client_id": client_config.client_id,
                    "realm": client_config.realm
                },
                "flow_type": "authorization_code"
            }

        except KeycloakError as e:
            logger.warning(
                f"Authorization code exchange failed for client {client_config.client_id}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid authorization code or redirect URI: {str(e)}"
            )
        except Exception as e:
            logger.error(
                f"Unexpected error during code exchange for client {client_config.client_id}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Token exchange service error"
            )

    def get_auth_url(self, redirect_uri: str, client_config: ClientConfig, state: Optional[str] = None) -> str:
        """
        Generate Authorization URL for OAuth2 Authorization Code Flow

        USECASE:
        This method generates the URL where users should be redirected to authenticate
        with Keycloak. After authentication, Keycloak will redirect back to redirect_uri
        with an authorization code.

        Args:
            redirect_uri: URI where Keycloak should redirect after authentication
            client_config: Client configuration for the specific application
            state: Optional state parameter for CSRF protection

        Returns:
            Authorization URL for redirecting users to Keycloak login

        Example:
            auth_url = keycloak_client.get_auth_url(
                redirect_uri="http://localhost:3000/callback",
                client_config=client_config,
                state="random-csrf-token"
            )
            # Redirect user to auth_url
        """
        try:
            keycloak_openid = self._get_openid_client(client_config)

            # Build auth_url parameters
            auth_params = {
                "redirect_uri": redirect_uri,
                "scope": "openid email profile"
            }

            # Add state parameter only if provided
            if state:
                auth_params["state"] = state

            auth_url = keycloak_openid.auth_url(**auth_params)

            logger.debug(
                f"Generated auth URL for client {client_config.client_id} in realm {client_config.realm}")

            return auth_url

        except Exception as e:
            logger.error(
                f"Failed to generate auth URL for client {client_config.client_id}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate authorization URL"
            )


# Global Multi-Tenant Keycloak client instance
keycloak_client = MultiTenantKeycloakClient()
