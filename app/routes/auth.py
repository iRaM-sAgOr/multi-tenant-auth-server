"""
Authentication Routes

This module contains all authentication-related API endpoints including:
- User login and registration
- Token validation and refresh
- OAuth2 authorization code flow
- User logout
"""

import logging
from fastapi import APIRouter, HTTPException, Depends

from app.models.auth import (
    LoginRequest,
    RegisterRequest,
    TokenValidationRequest,
    RefreshTokenRequest,
    CodeExchangeRequest,
    AuthUrlRequest,
    EmailVerificationRequest,
    PasswordResetRequest,
    ResendVerificationEmailRequest
)
from app.dependencies import get_client_config
from app.core.keycloak_client import keycloak_client, ClientConfig
from app.core.logging import get_structured_logger, log_keycloak_operation

# Get structured logger
logger = get_structured_logger(__name__)

# Create router
router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login")
async def login(
    request: LoginRequest,
    client_config: ClientConfig = Depends(get_client_config)
):
    """
    Authenticate user for a specific client application

    Required headers:
    - X-Client-Id: Your application's client ID
    - X-Client-Secret: Your application's client secret
    - X-Realm: Keycloak realm name
    """
    try:
        result = await keycloak_client.authenticate_user(
            username=request.username,
            password=request.password,
            client_config=client_config
        )
        logger.info(
            "✅ User login successful",
            **log_keycloak_operation(
                operation="login",
                client_id=client_config.client_id,
                realm=client_config.realm,
                username=request.username,
                success=True
            )
        )
        return result
    except HTTPException:
        logger.warning(
            "❌ User login failed",
            **log_keycloak_operation(
                operation="login",
                client_id=client_config.client_id,
                realm=client_config.realm,
                username=request.username,
                success=False
            )
        )
        raise
    except Exception as e:
        logger.error(
            "❌ Login error",
            **log_keycloak_operation(
                operation="login",
                client_id=client_config.client_id,
                realm=client_config.realm,
                username=request.username,
                error=str(e),
                success=False
            )
        )
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/register")
async def register(
    request: RegisterRequest,
    client_config: ClientConfig = Depends(get_client_config)
):
    """
    Register new user for a specific client application with automatic role assignment and optional email verification

    🆕 NEW FEATURES:
    - Automatic Role Assignment: Default role 'user' (customizable via roles parameter)
    - Automatic Email Verification: Sends verification email after successful registration
    - Supports multiple roles: ['user', 'paid-user', 'lawyer', etc.]
    - Roles must exist in the realm before assignment

    Required headers:
    - X-Client-Id: Your application's client ID
    - X-Client-Secret: Your application's client secret
    - X-Realm: Keycloak realm name

    Body Parameters:
    - username: Username for the new user
    - email: Email address
    - password: Password for the user
    - firstName: First name (optional)
    - lastName: Last name (optional)
    - roles: List of roles to assign (default: ['user'])
    - send_verification_email: Whether to automatically send verification email (default: true)

    Flow:
    1. Create user account in Keycloak
    2. Assign specified roles
    3. Send verification email (if enabled and SMTP configured)
    4. Return registration status with email verification info
    """
    try:
        user_data = {
            "username": request.username,
            "email": request.email,
            "firstName": request.firstName,
            "lastName": request.lastName,
            "enabled": True,
            "emailVerified": False,  # Set to False initially - user must verify
            "credentials": [{
                "type": "password",
                "value": request.password,
                "temporary": False
            }]
        }

        # Step 1: Create user and assign roles
        result = await keycloak_client.create_user(
            user_data=user_data,
            client_config=client_config,
            roles=request.roles  # Pass roles for automatic assignment
        )

        # Step 2: Attempt to send verification email automatically
        verification_status = {
            "verification_email_sent": False,
            "verification_email_error": None,
            "verification_required": True
        }

        # Check if we should send verification email (default: True unless specified otherwise)
        send_verification = getattr(request, 'send_verification_email', True)

        if send_verification:
            try:
                verification_result = await keycloak_client.send_verification_email(
                    username_or_email=request.email,
                    client_config=client_config
                )
                verification_status.update({
                    "verification_email_sent": True,
                    "verification_email_error": None,
                    "message": "Registration successful. Please check your email to verify your account."
                })
                logger.info(
                    f"✅ Verification email sent automatically to {request.email}")

            except Exception as email_error:
                # Don't fail registration if email sending fails
                verification_status.update({
                    "verification_email_sent": False,
                    "verification_email_error": str(email_error),
                    "message": "Registration successful, but verification email could not be sent. You can request it later."
                })
                logger.warning(
                    f"⚠️ Auto-verification email failed for {request.email}: {str(email_error)}")

        # Step 3: Combine results
        combined_result = {
            **result,  # User creation and role assignment results
            "email_verification": verification_status,
            "next_steps": [
                "Check your email for verification link" if verification_status[
                    "verification_email_sent"] else "Request verification email via /auth/send-verification-email",
                "Click the verification link to activate your account",
                "Login using /auth/login after verification"
            ]
        }

        logger.info(
            "✅ User registration successful",
            **log_keycloak_operation(
                operation="register",
                client_id=client_config.client_id,
                realm=client_config.realm,
                username=request.username,
                success=True,
                extra_info={
                    "verification_email_sent": verification_status["verification_email_sent"]}
            )
        )
        return combined_result

    except HTTPException as he:
        logger.warning(
            "❌ User registration failed",
            **log_keycloak_operation(
                operation="register",
                client_id=client_config.client_id,
                realm=client_config.realm,
                username=request.username,
                error=str(he.detail),
                success=False
            )
        )
        raise
    except Exception as e:
        logger.error(
            "❌ Registration error",
            **log_keycloak_operation(
                operation="register",
                client_id=client_config.client_id,
                realm=client_config.realm,
                username=request.username,
                error=str(e),
                success=False
            )
        )
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/validate")
async def validate_token(
    request: TokenValidationRequest,
    client_config: ClientConfig = Depends(get_client_config)
):
    """
    Validate access token for a specific client application

    This endpoint is typically called by backend services to validate
    tokens received from frontend applications.

    Required headers:
    - X-Client-Id: Your application's client ID
    - X-Client-Secret: Your application's client secret
    - X-Realm: Keycloak realm name
    """
    try:
        result = await keycloak_client.validate_token(
            token=request.token,
            client_config=client_config
        )
        logger.info(
            f"✅ Token validated successfully for client {client_config.client_id}")
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"❌ Token validation error for client {client_config.client_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/refresh")
async def refresh_token(
    request: RefreshTokenRequest,
    client_config: ClientConfig = Depends(get_client_config)
):
    """
    Refresh access token for a specific client application

    Required headers:
    - X-Client-Id: Your application's client ID
    - X-Client-Secret: Your application's client secret
    - X-Realm: Keycloak realm name
    """
    try:
        result = await keycloak_client.refresh_token(
            refresh_token=request.refresh_token,
            client_config=client_config
        )
        logger.info(
            f"✅ Token refreshed successfully for client {client_config.client_id}")
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"❌ Token refresh error for client {client_config.client_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/logout")
async def logout(
    request: RefreshTokenRequest,
    client_config: ClientConfig = Depends(get_client_config)
):
    """
    Logout user by invalidating refresh token

    Required headers:
    - X-Client-Id: Your application's client ID
    - X-Client-Secret: Your application's client secret
    - X-Realm: Keycloak realm name
    """
    try:
        result = await keycloak_client.logout_user(
            refresh_token=request.refresh_token,
            client_config=client_config
        )
        logger.info(
            f"✅ User logged out successfully for client {client_config.client_id}")
        return {"success": result, "message": "Logout successful" if result else "Logout failed"}
    except Exception as e:
        logger.error(
            f"❌ Logout error for client {client_config.client_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/status")
async def get_client_status(
    client_config: ClientConfig = Depends(get_client_config)
):
    """
    Get authentication service status for a specific client

    Required headers:
    - X-Client-Id: Your application's client ID
    - X-Client-Secret: Your application's client secret
    - X-Realm: Keycloak realm name
    """
    try:
        result = keycloak_client.get_client_status(client_config)
        logger.info(f"✅ Status checked for client {client_config.client_id}")
        return result
    except Exception as e:
        logger.error(
            f"❌ Status check error for client {client_config.client_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/permissions")
async def check_permissions(
    client_config: ClientConfig = Depends(get_client_config)
):
    """
    Check if the client has proper permissions for user management operations

    Required headers:
    - X-Client-Id: Your application's client ID
    - X-Client-Secret: Your application's client secret
    - X-Realm: Keycloak realm name

    Returns information about:
    - Service account availability
    - User management permissions
    - Admin client configuration
    """
    try:
        result = keycloak_client.check_admin_permissions(client_config)
        logger.info(
            f"✅ Permissions checked for client {client_config.client_id}")
        return result
    except Exception as e:
        logger.error(
            f"❌ Permission check error for client {client_config.client_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/exchange-code")
async def exchange_code_for_tokens(
    request: CodeExchangeRequest,
    client_config: ClientConfig = Depends(get_client_config)
):
    """
    Exchange Authorization Code for Tokens - OAuth2 Authorization Code Flow

    This endpoint handles the standard OAuth2/OIDC Authorization Code Flow where:
    1. User was redirected to Keycloak login page
    2. User authenticated with Keycloak
    3. Keycloak redirected back with authorization code
    4. Frontend calls this endpoint to exchange code for tokens

    Required headers:
    - X-Client-Id: Your application's client ID
    - X-Client-Secret: Your application's client secret
    - X-Realm: Keycloak realm name

    Request body:
    - code: Authorization code from Keycloak redirect
    - redirect_uri: The same redirect URI used in the auth request
    """
    try:
        result = await keycloak_client.exchange_code_for_tokens(
            code=request.code,
            redirect_uri=request.redirect_uri,
            client_config=client_config
        )
        logger.info(
            f"✅ Authorization code exchanged successfully for client {client_config.client_id}")
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"❌ Code exchange error for client {client_config.client_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/auth-url")
async def get_authorization_url(
    request: AuthUrlRequest,
    client_config: ClientConfig = Depends(get_client_config)
):
    """
    Generate Authorization URL for OAuth2 Authorization Code Flow

    This endpoint generates the URL where users should be redirected to authenticate
    with Keycloak. After authentication, Keycloak will redirect back to your
    redirect_uri with an authorization code.

    Required headers:
    - X-Client-Id: Your application's client ID
    - X-Client-Secret: Your application's client secret
    - X-Realm: Keycloak realm name

    Request body:
    - redirect_uri: Where Keycloak should redirect after authentication
    - state: Optional CSRF protection parameter

    Returns:
    - auth_url: URL to redirect users for Keycloak authentication
    """
    try:
        auth_url = keycloak_client.get_auth_url(
            redirect_uri=request.redirect_uri,
            client_config=client_config,
            state=request.state
        )
        logger.info(
            f"✅ Authorization URL generated for client {client_config.client_id}")
        return {
            "auth_url": auth_url,
            "client_info": {
                "client_id": client_config.client_id,
                "realm": client_config.realm
            },
            "flow": "authorization_code",
            "instructions": {
                "step1": "Redirect user to the auth_url",
                "step2": "User authenticates with Keycloak",
                "step3": "Keycloak redirects to your redirect_uri with 'code' parameter",
                "step4": "Use /auth/exchange-code endpoint to exchange code for tokens"
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"❌ Auth URL generation error for client {client_config.client_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/send-verification-email")
async def send_verification_email(
    request: EmailVerificationRequest,
    client_config: ClientConfig = Depends(get_client_config)
):
    """
    Send email verification to a user

    This endpoint triggers Keycloak to send a verification email to the user.
    The user must click the link in the email to verify their email address.

    Required headers:
    - X-Client-Id: Your application's client ID
    - X-Client-Secret: Your application's client secret
    - X-Realm: Keycloak realm name

    Body Parameters:
    - username_or_email: Username or email address of the user

    Prerequisites:
    - Realm must have email verification enabled
    - SMTP settings must be configured in Keycloak
    - Email templates must be properly configured
    """
    try:
        result = await keycloak_client.send_verification_email(
            username_or_email=request.username_or_email,
            client_config=client_config
        )
        logger.info(
            "✅ Verification email sent successfully",
            **log_keycloak_operation(
                operation="send_verification_email",
                client_id=client_config.client_id,
                realm=client_config.realm,
                username=request.username_or_email,
                success=True
            )
        )
        return result
    except HTTPException:
        logger.warning(
            "❌ Verification email sending failed",
            **log_keycloak_operation(
                operation="send_verification_email",
                client_id=client_config.client_id,
                realm=client_config.realm,
                username=request.username_or_email,
                success=False
            )
        )
        raise
    except Exception as e:
        logger.error(
            "❌ Verification email error",
            **log_keycloak_operation(
                operation="send_verification_email",
                client_id=client_config.client_id,
                realm=client_config.realm,
                username=request.username_or_email,
                error=str(e),
                success=False
            )
        )
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/forgot-password")
async def forgot_password(
    request: PasswordResetRequest,
    client_config: ClientConfig = Depends(get_client_config)
):
    """
    Send password reset email to a user

    This endpoint triggers Keycloak to send a password reset email to the user.
    The user can then click the link to reset their password.

    Required headers:
    - X-Client-Id: Your application's client ID
    - X-Client-Secret: Your application's client secret
    - X-Realm: Keycloak realm name

    Body Parameters:
    - username_or_email: Username or email address of the user

    Prerequisites:
    - Realm must have "Forgot Password" enabled in login settings
    - SMTP settings must be configured in Keycloak
    - Email templates must be properly configured

    Security Note:
    - This endpoint will not reveal whether the user exists or not
    - Always returns success message for security purposes
    """
    try:
        result = await keycloak_client.send_reset_password_email(
            username_or_email=request.username_or_email,
            client_config=client_config
        )
        logger.info(
            "✅ Password reset email sent successfully",
            **log_keycloak_operation(
                operation="forgot_password",
                client_id=client_config.client_id,
                realm=client_config.realm,
                username=request.username_or_email,
                success=True
            )
        )
        return result
    except HTTPException:
        logger.warning(
            "❌ Password reset email sending failed",
            **log_keycloak_operation(
                operation="forgot_password",
                client_id=client_config.client_id,
                realm=client_config.realm,
                username=request.username_or_email,
                success=False
            )
        )
        raise
    except Exception as e:
        logger.error(
            "❌ Password reset email error",
            **log_keycloak_operation(
                operation="forgot_password",
                client_id=client_config.client_id,
                realm=client_config.realm,
                username=request.username_or_email,
                error=str(e),
                success=False
            )
        )
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/resend-verification")
async def resend_verification_email(
    request: ResendVerificationEmailRequest,
    client_config: ClientConfig = Depends(get_client_config)
):
    """
    Resend verification email to a user

    This endpoint allows users to request another verification email if they
    didn't receive the first one or if it expired.

    Required headers:
    - X-Client-Id: Your application's client ID
    - X-Client-Secret: Your application's client secret
    - X-Realm: Keycloak realm name

    Body Parameters:
    - username_or_email: Username or email address of the user
    """
    try:
        result = await keycloak_client.send_verification_email(
            username_or_email=request.username_or_email,
            client_config=client_config
        )
        logger.info(
            "✅ Verification email resent successfully",
            **log_keycloak_operation(
                operation="resend_verification",
                client_id=client_config.client_id,
                realm=client_config.realm,
                username=request.username_or_email,
                success=True
            )
        )
        return result
    except HTTPException:
        logger.warning(
            "❌ Verification email resend failed",
            **log_keycloak_operation(
                operation="resend_verification",
                client_id=client_config.client_id,
                realm=client_config.realm,
                username=request.username_or_email,
                success=False
            )
        )
        raise
    except Exception as e:
        logger.error(
            "❌ Verification email resend error",
            **log_keycloak_operation(
                operation="resend_verification",
                client_id=client_config.client_id,
                realm=client_config.realm,
                username=request.username_or_email,
                error=str(e),
                success=False
            )
        )
        raise HTTPException(status_code=500, detail="Internal server error")
