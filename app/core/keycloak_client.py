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
from app.utils.error_handler import AuthErrorHandler

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
        # Remove trailing slash and use root endpoint for basic connectivity check
        base_url = server_url.rstrip('/')
        # Use root endpoint - Keycloak typically returns 302 redirect when running
        health_url = base_url

        start_time = asyncio.get_event_loop().time()

        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            response = await client.get(health_url)

        end_time = asyncio.get_event_loop().time()
        response_time = int((end_time - start_time) * 1000)

        health_status["response_time_ms"] = response_time

        # Accept both 200 (OK) and 302 (redirect) as healthy responses
        if response.status_code in [200, 302]:
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
        self._openid_clients: Dict[str, Any] = {}
        self._admin_clients: Dict[str, Any] = {}

        logger.info("Multi-tenant Keycloak client initialized successfully")

    def _get_client_key(self, config: ClientConfig) -> str:
        """Generate a unique key for client caching"""
        return f"{config.server_url}:{config.realm}:{config.client_id}"

    def _get_openid_client(self, config: ClientConfig) -> Any:
        """Get or create KeycloakOpenID client for the given configuration"""
        client_key = self._get_client_key(config)
        server_url = config.server_url or settings.keycloak_server_url

        if client_key not in self._openid_clients:
            self._openid_clients[client_key] = KeycloakOpenID(
                server_url=server_url,
                client_id=config.client_id,
                realm_name=config.realm,
                client_secret_key=config.client_secret
            )
            logger.debug(
                f"Created new OpenID client for {config.client_id} in realm {config.realm}")

        return self._openid_clients[client_key]

    def _get_admin_client(self, config: ClientConfig, use_service_account: bool = True) -> Optional[Any]:
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
                        verify=True
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

    def _get_master_admin_client(self, admin_username: str, admin_password: str, server_url: Optional[str] = None) -> Any:
        """
        Get KeycloakAdmin client using direct admin credentials for realm/client management.

        This method is used for administrative operations that require master realm access
        or when creating new realms/clients.

        Args:
            admin_username: Keycloak admin username
            admin_password: Keycloak admin password  
            server_url: Keycloak server URL (optional, uses default if not provided)

        Returns:
            KeycloakAdmin client with master realm access

        Raises:
            HTTPException: If admin authentication fails
        """
        try:
            admin_client = KeycloakAdmin(
                server_url=server_url or settings.keycloak_server_url,
                username=admin_username,
                password=admin_password,
                realm_name="master",  # Always use master realm for admin operations
                verify=True
            )

            # Test the connection
            admin_client.get_realm("master")

            logger.debug("Created master admin client successfully")
            return admin_client

        except Exception as e:
            logger.error(f"Failed to create master admin client: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": "Admin authentication failed",
                    "message": "Invalid admin credentials or Keycloak server unreachable",
                    "keycloak_error": str(e)
                }
            )

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
            
            # Use standardized error handler
            raise AuthErrorHandler.handle_keycloak_error(
                keycloak_error=str(e),
                operation="login",
                client_id=client_config.client_id,
                realm=client_config.realm
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
            
            # Use standardized error handler
            raise AuthErrorHandler.handle_keycloak_error(
                keycloak_error=str(e),
                operation="refresh_token",
                client_id=client_config.client_id,
                realm=client_config.realm
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
            
            # Use standardized error handler
            raise AuthErrorHandler.handle_keycloak_error(
                keycloak_error=str(e),
                operation="validate_token",
                client_id=client_config.client_id,
                realm=client_config.realm
            )
        except Exception as e:
            logger.error(
                f"Unexpected error during token validation for client {client_config.client_id}: {str(e)}")
            
            # Classify the error type based on the exception
            error_str = str(e).lower()
            
            if any(token_error in error_str for token_error in [
                "jwt", "token", "expired", "invalid", "malformed", "decode"
            ]):
                # Token-related errors should be 401 Unauthorized
                raise AuthErrorHandler.create_simplified_error(
                    message="Invalid or expired token",
                    operation="validate_token", 
                    suggestions=["Check if the token format is correct", "Try refreshing your token"],
                    status_code=status.HTTP_401_UNAUTHORIZED
                )
            elif any(network_error in error_str for network_error in [
                "connection", "timeout", "network", "unreachable"
            ]):
                # Network/connectivity issues should be 503 Service Unavailable
                raise AuthErrorHandler.create_simplified_error(
                    message="Authentication service temporarily unavailable",
                    operation="validate_token",
                    suggestions=["Try again in a few moments", "Contact support if the issue persists"],
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE
                )
            else:
                # Unknown/unexpected errors should be 500 Internal Server Error
                raise AuthErrorHandler.create_simplified_error(
                    message="Token validation failed due to an unexpected error",
                    operation="validate_token",
                    suggestions=["Try again later", "Contact support if the issue persists"],
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
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

    async def create_user(self, user_data: Dict[str, Any], client_config: ClientConfig, roles: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Create a new user in Keycloak for a specific client with optional role assignment.

        Args:
            user_data: Dictionary containing user information
            client_config: Client configuration
            roles: Optional list of role names to assign to the user

        Returns:
            Dict containing created user information and role assignment status

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
            # Create the user
            user_id = keycloak_admin.create_user(user_data)
            user_details = keycloak_admin.get_user(user_id)

            # Role assignment status
            role_assignment_status = {
                "roles_requested": roles or [],
                "roles_assigned": [],
                "role_assignment_errors": []
            }

            # Assign roles if provided
            if roles:
                try:
                    # Get available realm roles
                    available_roles = keycloak_admin.get_realm_roles()
                    available_role_names = [role['name']
                                            for role in available_roles]

                    # Prepare roles to assign
                    roles_to_assign = []
                    for role_name in roles:
                        if role_name in available_role_names:
                            role_obj = next(
                                role for role in available_roles if role['name'] == role_name)
                            roles_to_assign.append(role_obj)
                            role_assignment_status["roles_assigned"].append(
                                role_name)
                        else:
                            role_assignment_status["role_assignment_errors"].append(
                                f"Role '{role_name}' not found in realm")

                    # Assign the roles
                    if roles_to_assign:
                        keycloak_admin.assign_realm_roles(
                            user_id=user_id, roles=roles_to_assign)
                        logger.info(
                            f"✅ Assigned roles {[r['name'] for r in roles_to_assign]} to user {user_data.get('username')}")

                except Exception as role_error:
                    error_msg = f"Failed to assign roles: {str(role_error)}"
                    role_assignment_status["role_assignment_errors"].append(
                        error_msg)
                    logger.warning(
                        f"⚠️ Role assignment failed for user {user_data.get('username')}: {error_msg}")

            logger.info(
                f"User created successfully with ID: {user_id} for client {client_config.client_id}")

            return {
                "user_id": user_id,
                "user_details": user_details,
                "role_assignment": role_assignment_status,
                "client_info": {
                    "client_id": client_config.client_id,
                    "realm": client_config.realm
                }
            }

        except KeycloakError as e:
            error_str = str(e)
            logger.error(
                f"User creation failed for client {client_config.client_id}: {error_str}")

            # Use standardized error handler
            raise AuthErrorHandler.handle_keycloak_error(
                keycloak_error=error_str,
                operation="register",
                client_id=client_config.client_id,
                realm=client_config.realm
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

    async def create_realm(self, realm_data: Dict[str, Any], admin_username: str, admin_password: str) -> Dict[str, Any]:
        """
        Create a new realm in Keycloak.

        Args:
            realm_data: Dictionary containing realm configuration
            admin_username: Keycloak admin username
            admin_password: Keycloak admin password

        Returns:
            Dict containing created realm information

        Raises:
            HTTPException: If realm creation fails
        """
        try:
            admin_client = self._get_master_admin_client(
                admin_username, admin_password)

            # Create the realm
            realm_id = admin_client.create_realm(
                payload=realm_data, skip_exists=False)

            # Get the created realm info
            realm_info = admin_client.get_realm(realm_data["realm"])

            logger.info(f"Realm '{realm_data['realm']}' created successfully")

            return {
                "realm_id": realm_id,
                "realm_info": realm_info,
                "message": f"Realm '{realm_data['realm']}' created successfully"
            }

        except Exception as e:
            error_str = str(e)
            logger.error(f"Realm creation failed: {error_str}")

            if "409" in error_str or "exists" in error_str.lower():
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail={
                        "error": "Realm already exists",
                        "message": f"Realm '{realm_data['realm']}' already exists",
                        "keycloak_error": error_str
                    }
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "error": "Realm creation failed",
                        "message": "Failed to create realm in Keycloak",
                        "keycloak_error": error_str
                    }
                )

    async def create_client(self, client_data: Dict[str, Any], realm_name: str, admin_username: str, admin_password: str) -> Dict[str, Any]:
        """
        Create a new client in a specific realm with automatic service account role assignment.

        Args:
            client_data: Dictionary containing client configuration
            realm_name: Name of the realm where client should be created
            admin_username: Keycloak admin username
            admin_password: Keycloak admin password

        Returns:
            Dict containing created client information and role assignment status

        Raises:
            HTTPException: If client creation fails
        """
        try:
            admin_client = self._get_master_admin_client(
                admin_username, admin_password)
            admin_client.connection.realm_name = realm_name  # Switch to target realm

            # Create the client
            client_id = admin_client.create_client(
                payload=client_data, skip_exists=False)

            # Get the created client info
            clients = admin_client.get_clients()
            client_info = next(
                (c for c in clients if c["clientId"] == client_data["clientId"]), None)

            # Get client secret if it's a confidential client
            client_secret = None
            if client_info and client_info.get("publicClient") is False:
                client_secret = admin_client.get_client_secrets(
                    client_info["id"])

            # Initialize role assignment status
            role_assignment_status = {
                "service_account_enabled": client_data.get("serviceAccountsEnabled", False),
                "roles_assigned": False,
                "assigned_roles": [],
                "role_assignment_error": None
            }

            # If service accounts are enabled, automatically assign required roles
            if client_data.get("serviceAccountsEnabled", False) and client_info:
                try:
                    # Get the service account user for this client
                    service_account_user = admin_client.get_client_service_account_user(
                        client_info["id"])

                    if service_account_user:
                        # Get the realm-management client in this realm
                        realm_mgmt_clients = [
                            c for c in clients if c["clientId"] == "realm-management"]

                        if realm_mgmt_clients:
                            realm_mgmt_client = realm_mgmt_clients[0]

                            # Get available roles from realm-management client
                            available_roles = admin_client.get_client_roles(
                                realm_mgmt_client["id"])

                            # Define required roles for user management
                            required_role_names = [
                                "manage-users", "view-users"]
                            roles_to_assign = []

                            # Find the required roles
                            for role_name in required_role_names:
                                role = next(
                                    (r for r in available_roles if r["name"] == role_name), None)
                                if role:
                                    roles_to_assign.append(role)

                            # Assign the roles to the service account
                            if roles_to_assign:
                                admin_client.assign_client_role(
                                    user_id=service_account_user["id"],
                                    client_id=realm_mgmt_client["id"],
                                    roles=roles_to_assign
                                )

                                role_assignment_status.update({
                                    "roles_assigned": True,
                                    "assigned_roles": [role["name"] for role in roles_to_assign],
                                    "service_account_user_id": service_account_user["id"]
                                })

                                logger.info(
                                    f"✅ Assigned roles {[r['name'] for r in roles_to_assign]} to service account for client '{client_data['clientId']}'")
                            else:
                                role_assignment_status[
                                    "role_assignment_error"] = "Required roles (manage-users, view-users) not found in realm-management client"
                        else:
                            role_assignment_status["role_assignment_error"] = "realm-management client not found in realm"
                    else:
                        role_assignment_status["role_assignment_error"] = "Service account user not found for client"

                except Exception as role_error:
                    role_assignment_status[
                        "role_assignment_error"] = f"Failed to assign roles: {str(role_error)}"
                    logger.warning(
                        f"⚠️ Role assignment failed for client '{client_data['clientId']}': {str(role_error)}")

            logger.info(
                f"Client '{client_data['clientId']}' created successfully in realm '{realm_name}'")

            return {
                "client_id": client_id,
                "client_info": client_info,
                "client_secret": client_secret,
                "realm": realm_name,
                "message": f"Client '{client_data['clientId']}' created successfully",
                "role_assignment": role_assignment_status
            }

        except Exception as e:
            error_str = str(e)
            logger.error(f"Client creation failed: {error_str}")

            if "409" in error_str or "exists" in error_str.lower():
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail={
                        "error": "Client already exists",
                        "message": f"Client '{client_data['clientId']}' already exists in realm '{realm_name}'",
                        "keycloak_error": error_str
                    }
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "error": "Client creation failed",
                        "message": "Failed to create client in Keycloak",
                        "keycloak_error": error_str,
                        "realm": realm_name
                    }
                )

    async def get_realm_info(self, realm_name: str, admin_username: str, admin_password: str) -> Dict[str, Any]:
        """
        Get detailed information about a realm.

        Args:
            realm_name: Name of the realm
            admin_username: Keycloak admin username
            admin_password: Keycloak admin password

        Returns:
            Dict containing realm information

        Raises:
            HTTPException: If realm retrieval fails
        """
        try:
            admin_client = self._get_master_admin_client(
                admin_username, admin_password)

            # Get realm info
            realm_info = admin_client.get_realm(realm_name)

            # Get realm clients
            admin_client.connection.realm_name = realm_name
            clients = admin_client.get_clients()

            # Get realm users count
            users_count = admin_client.users_count()

            logger.info(f"Retrieved information for realm '{realm_name}'")

            return {
                "realm_info": realm_info,
                "clients": clients,
                "users_count": users_count,
                "realm_name": realm_name
            }

        except Exception as e:
            error_str = str(e)
            logger.error(
                f"Failed to get realm info for '{realm_name}': {error_str}")

            if "404" in error_str or "not found" in error_str.lower():
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail={
                        "error": "Realm not found",
                        "message": f"Realm '{realm_name}' does not exist",
                        "keycloak_error": error_str
                    }
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "error": "Failed to retrieve realm information",
                        "message": f"Could not get information for realm '{realm_name}'",
                        "keycloak_error": error_str
                    }
                )

    async def get_client_info(self, realm_name: str, client_id: str, admin_username: str, admin_password: str) -> Dict[str, Any]:
        """
        Get detailed information about a client in a specific realm.

        Args:
            realm_name: Name of the realm
            client_id: Client ID to retrieve information for
            admin_username: Keycloak admin username
            admin_password: Keycloak admin password

        Returns:
            Dict containing client information

        Raises:
            HTTPException: If client retrieval fails
        """
        try:
            admin_client = self._get_master_admin_client(
                admin_username, admin_password)
            admin_client.connection.realm_name = realm_name

            # Get all clients and find the specific one
            clients = admin_client.get_clients()
            client_info = next(
                (c for c in clients if c["clientId"] == client_id), None)

            if not client_info:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail={
                        "error": "Client not found",
                        "message": f"Client '{client_id}' not found in realm '{realm_name}'"
                    }
                )

            # Get client secret if it's a confidential client
            client_secret = None
            if client_info.get("publicClient") is False:
                try:
                    client_secret = admin_client.get_client_secrets(
                        client_info["id"])
                except:
                    logger.warning(
                        f"Could not retrieve client secret for {client_id}")

            # Get client roles
            client_roles = admin_client.get_client_roles(client_info["id"])

            logger.info(
                f"Retrieved information for client '{client_id}' in realm '{realm_name}'")

            return {
                "client_info": client_info,
                "client_secret": client_secret,
                "client_roles": client_roles,
                "realm_name": realm_name,
                "client_id": client_id
            }

        except HTTPException:
            raise
        except Exception as e:
            error_str = str(e)
            logger.error(
                f"Failed to get client info for '{client_id}' in realm '{realm_name}': {error_str}")

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "Failed to retrieve client information",
                    "message": f"Could not get information for client '{client_id}' in realm '{realm_name}'",
                    "keycloak_error": error_str
                }
            )

    async def delete_realm(self, realm_name: str, admin_username: str, admin_password: str) -> Dict[str, Any]:
        """
        Delete a Keycloak realm.

        Args:
            realm_name: Name of the realm to delete
            admin_username: Keycloak admin username  
            admin_password: Keycloak admin password

        Returns:
            Dict containing deletion confirmation

        Raises:
            HTTPException: If realm deletion fails
        """
        try:
            admin_client = self._get_master_admin_client(
                admin_username, admin_password)

            # Check if realm exists first
            try:
                realm_info = admin_client.get_realm(realm_name)
                if not realm_info:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail={
                            "error": "Realm not found",
                            "message": f"Realm '{realm_name}' does not exist"
                        }
                    )
            except Exception as e:
                if "404" in str(e) or "not found" in str(e).lower():
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail={
                            "error": "Realm not found",
                            "message": f"Realm '{realm_name}' does not exist"
                        }
                    )
                raise

            # Delete the realm
            admin_client.delete_realm(realm_name)

            logger.info(f"✅ Realm '{realm_name}' deleted successfully")

            return {
                "realm_name": realm_name,
                "message": f"Realm '{realm_name}' deleted successfully",
                "deleted": True,
                "timestamp": __import__('datetime').datetime.now().isoformat()
            }

        except HTTPException:
            raise
        except Exception as e:
            error_str = str(e)
            logger.error(f"Failed to delete realm '{realm_name}': {error_str}")

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "Failed to delete realm",
                    "message": f"Could not delete realm '{realm_name}'",
                    "keycloak_error": error_str
                }
            )

    async def delete_client(self, realm_name: str, client_id: str, admin_username: str, admin_password: str) -> Dict[str, Any]:
        """
        Delete a Keycloak client from a specific realm.

        Args:
            realm_name: Name of the realm containing the client
            client_id: Client ID to delete
            admin_username: Keycloak admin username
            admin_password: Keycloak admin password

        Returns:
            Dict containing deletion confirmation

        Raises:
            HTTPException: If client deletion fails
        """
        try:
            admin_client = self._get_master_admin_client(
                admin_username, admin_password)
            admin_client.connection.realm_name = realm_name

            # Get all clients and find the specific one
            clients = admin_client.get_clients()
            client_info = next(
                (c for c in clients if c["clientId"] == client_id), None)

            if not client_info:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail={
                        "error": "Client not found",
                        "message": f"Client '{client_id}' not found in realm '{realm_name}'"
                    }
                )

            # Delete the client using its internal ID
            client_uuid = client_info["id"]
            admin_client.delete_client(client_uuid)

            logger.info(
                f"✅ Client '{client_id}' deleted successfully from realm '{realm_name}'")

            return {
                "realm_name": realm_name,
                "client_id": client_id,
                "message": f"Client '{client_id}' deleted successfully from realm '{realm_name}'",
                "deleted": True,
                "timestamp": __import__('datetime').datetime.now().isoformat()
            }

        except HTTPException:
            raise
        except Exception as e:
            error_str = str(e)
            logger.error(
                f"Failed to delete client '{client_id}' from realm '{realm_name}': {error_str}")

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "Failed to delete client",
                    "message": f"Could not delete client '{client_id}' from realm '{realm_name}'",
                    "keycloak_error": error_str
                }
            )

    async def create_realm_role(self, realm_name: str, role_name: str, role_description: Optional[str], admin_username: str, admin_password: str) -> Dict[str, Any]:
        """
        Create a new realm role.

        Args:
            realm_name: Name of the realm
            role_name: Name of the role to create
            role_description: Description of the role
            admin_username: Keycloak admin username
            admin_password: Keycloak admin password

        Returns:
            Dict containing created role information

        Raises:
            HTTPException: If role creation fails
        """
        try:
            admin_client = self._get_master_admin_client(
                admin_username, admin_password)
            admin_client.connection.realm_name = realm_name

            # Prepare role data
            role_data = {
                "name": role_name,
                "description": role_description or f"Role: {role_name}",
                "composite": False,
                "clientRole": False
            }

            # Create the role
            admin_client.create_realm_role(
                payload=role_data, skip_exists=False)

            # Get the created role info
            role_info = admin_client.get_realm_role(role_name)

            logger.info(
                f"✅ Realm role '{role_name}' created successfully in realm '{realm_name}'")

            return {
                "role_name": role_name,
                "role_info": role_info,
                "realm_name": realm_name,
                "message": f"Role '{role_name}' created successfully in realm '{realm_name}'"
            }

        except Exception as e:
            error_str = str(e)
            logger.error(
                f"Failed to create role '{role_name}' in realm '{realm_name}': {error_str}")

            if "409" in error_str or "exists" in error_str.lower():
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail={
                        "error": "Role already exists",
                        "message": f"Role '{role_name}' already exists in realm '{realm_name}'",
                        "keycloak_error": error_str
                    }
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "error": "Role creation failed",
                        "message": f"Failed to create role '{role_name}' in realm '{realm_name}'",
                        "keycloak_error": error_str
                    }
                )

    async def assign_user_roles(self, realm_name: str, username: str, roles: List[str], admin_username: str, admin_password: str) -> Dict[str, Any]:
        """
        Assign realm roles to a user.

        Args:
            realm_name: Name of the realm
            username: Username of the user
            roles: List of role names to assign
            admin_username: Keycloak admin username
            admin_password: Keycloak admin password

        Returns:
            Dict containing role assignment status

        Raises:
            HTTPException: If role assignment fails
        """
        try:
            admin_client = self._get_master_admin_client(
                admin_username, admin_password)
            admin_client.connection.realm_name = realm_name

            # Find the user
            users = admin_client.get_users({"username": username})
            if not users:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail={
                        "error": "User not found",
                        "message": f"User '{username}' not found in realm '{realm_name}'"
                    }
                )

            user_id = users[0]["id"]

            # Get available realm roles
            available_roles = admin_client.get_realm_roles()
            available_role_names = [role['name'] for role in available_roles]

            # Prepare roles to assign
            roles_to_assign = []
            assignment_status = {
                "roles_requested": roles,
                "roles_assigned": [],
                "role_assignment_errors": []
            }

            for role_name in roles:
                if role_name in available_role_names:
                    role_obj = next(
                        role for role in available_roles if role['name'] == role_name)
                    roles_to_assign.append(role_obj)
                    assignment_status["roles_assigned"].append(role_name)
                else:
                    assignment_status["role_assignment_errors"].append(
                        f"Role '{role_name}' not found in realm")

            # Assign the roles
            if roles_to_assign:
                admin_client.assign_realm_roles(
                    user_id=user_id, roles=roles_to_assign)
                logger.info(
                    f"✅ Assigned roles {[r['name'] for r in roles_to_assign]} to user '{username}' in realm '{realm_name}'")

            return {
                "username": username,
                "realm_name": realm_name,
                "assignment_status": assignment_status,
                "message": f"Role assignment completed for user '{username}'"
            }

        except HTTPException:
            raise
        except Exception as e:
            error_str = str(e)
            logger.error(
                f"Failed to assign roles to user '{username}' in realm '{realm_name}': {error_str}")

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "Role assignment failed",
                    "message": f"Failed to assign roles to user '{username}' in realm '{realm_name}'",
                    "keycloak_error": error_str
                }
            )

    async def get_user_roles_info(self, realm_name: str, username: str, admin_username: str, admin_password: str) -> Dict[str, Any]:
        """
        Get roles assigned to a user.

        Args:
            realm_name: Name of the realm
            username: Username of the user
            admin_username: Keycloak admin username
            admin_password: Keycloak admin password

        Returns:
            Dict containing user roles

        Raises:
            HTTPException: If user role retrieval fails
        """
        try:
            admin_client = self._get_master_admin_client(
                admin_username, admin_password)
            admin_client.connection.realm_name = realm_name

            # Find the user
            users = admin_client.get_users({"username": username})
            if not users:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail={
                        "error": "User not found",
                        "message": f"User '{username}' not found in realm '{realm_name}'"
                    }
                )

            user_id = users[0]["id"]

            # Get user's realm roles
            user_realm_roles = admin_client.get_realm_roles_of_user(user_id)

            return {
                "username": username,
                "realm_name": realm_name,
                "user_id": user_id,
                "realm_roles": [role["name"] for role in user_realm_roles],
                "role_details": user_realm_roles
            }

        except HTTPException:
            raise
        except Exception as e:
            error_str = str(e)
            logger.error(
                f"Failed to get roles for user '{username}' in realm '{realm_name}': {error_str}")

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "Failed to retrieve user roles",
                    "message": f"Could not get roles for user '{username}' in realm '{realm_name}'",
                    "keycloak_error": error_str
                }
            )

    async def send_verification_email(self, username_or_email: str, client_config: ClientConfig) -> Dict[str, Any]:
        """
        Send email verification to a user.

        Args:
            username_or_email: Username or email address
            client_config: Client configuration

        Returns:
            Dict containing verification status

        Raises:
            HTTPException: If verification email sending fails
        """
        keycloak_admin = self._get_admin_client(client_config)

        if not keycloak_admin:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "error": "Email verification service unavailable",
                    "message": f"Admin access not configured for client {client_config.client_id}",
                    "solutions": [
                        "Configure admin credentials or service account",
                        "Ensure email verification is enabled in realm settings"
                    ]
                }
            )

        try:
            # Find user by username or email
            users = keycloak_admin.get_users({
                "username": username_or_email
            }) or keycloak_admin.get_users({
                "email": username_or_email
            })

            if not users:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )

            user_id = users[0]["id"]
            user = users[0]

            # Send verification email
            keycloak_admin.send_verify_email(user_id)

            logger.info(
                f"✅ Verification email sent to user {username_or_email}")

            return {
                "message": "Verification email sent successfully",
                "user_id": user_id,
                "email": user.get("email"),
                "email_verified": user.get("emailVerified", False),
                "client_info": {
                    "client_id": client_config.client_id,
                    "realm": client_config.realm
                }
            }

        except HTTPException:
            raise
        except KeycloakError as e:
            error_str = str(e)
            logger.error(
                f"Failed to send verification email to {username_or_email}: {error_str}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "Failed to send verification email",
                    "message": "Could not send verification email. Check realm email settings.",
                    "keycloak_error": error_str,
                    "solutions": [
                        "Configure SMTP settings in Keycloak realm",
                        "Verify email templates are configured",
                        "Check if user email address is valid"
                    ]
                }
            )

    async def send_reset_password_email(self, username_or_email: str, client_config: ClientConfig) -> Dict[str, Any]:
        """
        Send password reset email to a user.

        Args:
            username_or_email: Username or email address
            client_config: Client configuration

        Returns:
            Dict containing reset email status

        Raises:
            HTTPException: If password reset email sending fails
        """
        keycloak_admin = self._get_admin_client(client_config)

        if not keycloak_admin:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "error": "Password reset service unavailable",
                    "message": f"Admin access not configured for client {client_config.client_id}",
                    "solutions": [
                        "Configure admin credentials or service account",
                        "Ensure password reset is enabled in realm settings"
                    ]
                }
            )

        try:
            # Find user by username or email
            users = keycloak_admin.get_users({
                "username": username_or_email
            }) or keycloak_admin.get_users({
                "email": username_or_email
            })

            if not users:
                # For security reasons, don't reveal if user exists or not
                return {
                    "message": "If the user exists, a password reset email has been sent",
                    "client_info": {
                        "client_id": client_config.client_id,
                        "realm": client_config.realm
                    }
                }

            user_id = users[0]["id"]
            user = users[0]

            # Send password reset email
            keycloak_admin.send_update_account(
                user_id=user_id,
                payload=["UPDATE_PASSWORD"]
            )

            logger.info(
                f"✅ Password reset email sent to user {username_or_email}")

            return {
                "message": "Password reset email sent successfully",
                "user_id": user_id,
                "email": user.get("email"),
                "client_info": {
                    "client_id": client_config.client_id,
                    "realm": client_config.realm
                }
            }

        except HTTPException:
            raise
        except KeycloakError as e:
            error_str = str(e)
            logger.error(
                f"Failed to send password reset email to {username_or_email}: {error_str}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "Failed to send password reset email",
                    "message": "Could not send password reset email. Check realm email settings.",
                    "keycloak_error": error_str,
                    "solutions": [
                        "Configure SMTP settings in Keycloak realm",
                        "Verify email templates are configured",
                        "Enable 'Forgot Password' in realm login settings"
                    ]
                }
            )

    async def update_user_password(self, user_id: str, new_password: str, client_config: ClientConfig, temporary: bool = False) -> Dict[str, Any]:
        """
        Update user password (for admin operations).

        Args:
            user_id: User ID in Keycloak
            new_password: New password to set
            client_config: Client configuration
            temporary: Whether password is temporary (user must change on next login)

        Returns:
            Dict containing password update status

        Raises:
            HTTPException: If password update fails
        """
        keycloak_admin = self._get_admin_client(client_config)

        if not keycloak_admin:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "error": "Password update service unavailable",
                    "message": f"Admin access not configured for client {client_config.client_id}"
                }
            )

        try:
            # Set new password
            keycloak_admin.set_user_password(
                user_id=user_id,
                password=new_password,
                temporary=temporary
            )

            logger.info(f"✅ Password updated for user {user_id}")

            return {
                "message": "Password updated successfully",
                "user_id": user_id,
                "temporary": temporary,
                "client_info": {
                    "client_id": client_config.client_id,
                    "realm": client_config.realm
                }
            }

        except KeycloakError as e:
            error_str = str(e)
            logger.error(
                f"Failed to update password for user {user_id}: {error_str}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "Failed to update password",
                    "message": "Could not update user password",
                    "keycloak_error": error_str
                }
            )

    async def configure_smtp(self, smtp_config: Dict[str, Any], realm_name: str, admin_username: str, admin_password: str) -> Dict[str, Any]:
        """
        Configure SMTP settings for a Keycloak realm.

        Args:
            smtp_config: Dictionary containing SMTP configuration
            realm_name: Name of the realm to configure
            admin_username: Admin username for authentication
            admin_password: Admin password for authentication

        Returns:
            Dict containing configuration status

        Raises:
            HTTPException: If SMTP configuration fails
        """
        try:
            # Create admin client for this specific operation
            admin_client = KeycloakAdmin(
                server_url=settings.keycloak_server_url,
                username=admin_username,
                password=admin_password,
                realm_name="master",  # Admin operations are done from master realm
                verify=True
            )

            # Get current realm configuration
            realm_config = admin_client.get_realm(realm_name)

            # Update SMTP server configuration
            # Ensure all required fields are present and properly formatted
            smtp_server_config = {
                "host": smtp_config["host"],
                "port": str(smtp_config["port"]),
                "from": smtp_config["from_email"],
                "fromDisplayName": smtp_config.get("from_display_name", ""),
                "replyTo": smtp_config.get("reply_to", smtp_config["from_email"]),
                "starttls": str(smtp_config.get("starttls", True)).lower(),
                "ssl": str(smtp_config.get("ssl", False)).lower(),
                "auth": str(smtp_config.get("auth_enabled", True)).lower(),
                "user": smtp_config.get("username", ""),
                "password": smtp_config.get("password", "")
            }

            # Add envelopeFrom only if it's not empty
            envelope_from = smtp_config.get("envelope_from", "")
            if envelope_from:
                smtp_server_config["envelopeFrom"] = envelope_from

            realm_config["smtpServer"] = smtp_server_config

            # Update the realm
            admin_client.update_realm(realm_name, realm_config)

            logger.info(f"✅ SMTP configuration updated for realm {realm_name}")

            return {
                "message": "SMTP configuration updated successfully",
                "realm_name": realm_name,
                "smtp_host": smtp_config["host"],
                "smtp_port": smtp_config["port"],
                "from_email": smtp_config["from_email"],
                "auth_enabled": smtp_config.get("auth_enabled", True),
                "starttls": smtp_config.get("starttls", True),
                "ssl": smtp_config.get("ssl", False),
                "status": "configured"
            }

        except KeycloakError as e:
            error_str = str(e)
            logger.error(
                f"Failed to configure SMTP for realm {realm_name}: {error_str}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "Failed to configure SMTP settings",
                    "message": f"Could not update SMTP configuration for realm '{realm_name}'",
                    "keycloak_error": error_str,
                    "solutions": [
                        "Verify admin credentials are correct",
                        "Ensure the realm exists",
                        "Check SMTP server details are valid",
                        "Verify network connectivity to SMTP server"
                    ]
                }
            )
        except Exception as e:
            error_str = str(e)
            logger.error(
                f"Unexpected error configuring SMTP for realm {realm_name}: {error_str}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "error": "SMTP configuration error",
                    "message": "Unexpected error during SMTP configuration",
                    "keycloak_error": error_str
                }
            )

    async def get_smtp_config(self, realm_name: str, admin_username: str, admin_password: str) -> Dict[str, Any]:
        """
        Get current SMTP configuration for a Keycloak realm.

        Args:
            realm_name: Name of the realm
            admin_username: Admin username for authentication
            admin_password: Admin password for authentication

        Returns:
            Dict containing current SMTP configuration

        Raises:
            HTTPException: If retrieval fails
        """
        try:
            # Create admin client
            admin_client = KeycloakAdmin(
                server_url=settings.keycloak_server_url,
                username=admin_username,
                password=admin_password,
                realm_name="master",
                verify=True
            ) # type: ignore

            # Get realm configuration
            realm_config = admin_client.get_realm(realm_name)
            smtp_server = realm_config.get("smtpServer", {})

            # Format response (hide sensitive data)
            smtp_config = {
                "realm_name": realm_name,
                "smtp_configured": bool(smtp_server),
                "host": smtp_server.get("host", ""),
                "port": int(smtp_server.get("port", 587)) if smtp_server.get("port") else 587,
                "from_email": smtp_server.get("from", ""),
                "from_display_name": smtp_server.get("fromDisplayName", ""),
                "reply_to": smtp_server.get("replyTo", ""),
                "auth_enabled": smtp_server.get("auth", "true").lower() == "true",
                "starttls": smtp_server.get("starttls", "true").lower() == "true",
                "ssl": smtp_server.get("ssl", "false").lower() == "true",
                "username": smtp_server.get("user", ""),
                # Don't return actual password
                "password_configured": bool(smtp_server.get("password")),
                "envelope_from": smtp_server.get("envelopeFrom", "")
            }

            logger.info(
                f"✅ Retrieved SMTP configuration for realm {realm_name}")

            return smtp_config

        except KeycloakError as e:
            error_str = str(e)
            logger.error(
                f"Failed to get SMTP config for realm {realm_name}: {error_str}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "Failed to retrieve SMTP configuration",
                    "message": f"Could not get SMTP configuration for realm '{realm_name}'",
                    "keycloak_error": error_str
                }
            )

    async def test_smtp_connection(self, realm_name: str, test_email: str, admin_username: str, admin_password: str) -> Dict[str, Any]:
        """
        Test SMTP configuration by sending a test email.

        Args:
            realm_name: Name of the realm
            test_email: Email address to send test email to
            admin_username: Admin username for authentication
            admin_password: Admin password for authentication

        Returns:
            Dict containing test results

        Raises:
            HTTPException: If test fails
        """
        try:
            # Create admin client
            admin_client = KeycloakAdmin(
                server_url=settings.keycloak_server_url,
                username=admin_username,
                password=admin_password,
                realm_name="master",
                verify=True
            )

            # Get realm configuration to check if SMTP is configured
            realm_config = admin_client.get_realm(realm_name)
            smtp_server = realm_config.get("smtpServer", {})

            if not smtp_server:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "error": "SMTP not configured",
                        "message": f"No SMTP configuration found for realm '{realm_name}'",
                        "solutions": [
                            "Configure SMTP settings first using /admin/smtp/configure",
                            "Verify realm name is correct"
                        ]
                    }
                )

            # Test SMTP by sending a test email using Keycloak's admin API
            # Note: Keycloak doesn't have a direct "test SMTP" endpoint, but we can
            # create a temporary user and send them a verification email as a test

            test_user_data = {
                "username": f"smtp-test-{int(asyncio.get_event_loop().time())}",
                "email": test_email,
                "enabled": True,
                "emailVerified": False
            }

            # Create temporary test user
            temp_user_id = admin_client.create_user(test_user_data)

            try:
                # Try to send verification email to test SMTP
                admin_client.send_verify_email(user_id=temp_user_id)

                # If we get here, email sending worked
                result = {
                    "message": "SMTP test successful",
                    "realm_name": realm_name,
                    "test_email": test_email,
                    "smtp_host": smtp_server.get("host"),
                    "smtp_port": smtp_server.get("port"),
                    "test_status": "passed",
                    "details": "Test verification email sent successfully"
                }

                logger.info(f"✅ SMTP test passed for realm {realm_name}")

            finally:
                # Clean up: delete the temporary test user
                try:
                    admin_client.delete_user(user_id=temp_user_id)
                except:
                    logger.warning(
                        f"Could not delete temporary test user {temp_user_id}")

            return result

        except HTTPException:
            raise
        except KeycloakError as e:
            error_str = str(e)
            logger.error(
                f"SMTP test failed for realm {realm_name}: {error_str}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "SMTP test failed",
                    "message": f"SMTP test failed for realm '{realm_name}'",
                    "keycloak_error": error_str,
                    "test_status": "failed",
                    "solutions": [
                        "Verify SMTP server settings are correct",
                        "Check SMTP server credentials",
                        "Ensure network connectivity to SMTP server",
                        "Check firewall settings for SMTP ports"
                    ]
                }
            )
        except Exception as e:
            error_str = str(e)
            logger.error(
                f"Unexpected error during SMTP test for realm {realm_name}: {error_str}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "error": "SMTP test error",
                    "message": "Unexpected error during SMTP test",
                    "keycloak_error": error_str,
                    "test_status": "error"
                }
            )


# Global Multi-Tenant Keycloak client instance
keycloak_client = MultiTenantKeycloakClient()
