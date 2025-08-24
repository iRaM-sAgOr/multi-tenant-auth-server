"""
Authentication Request/Response Models

This module contains all Pydantic models used for authentication-related
API endpoints including login, registration, token operations, and OAuth2 flows.
"""

from pydantic import BaseModel
from typing import Optional, Dict, Any, List


class LoginRequest(BaseModel):
    """Request model for user login endpoint"""
    username: str
    password: str


class RegisterRequest(BaseModel):
    """Request model for user registration endpoint"""
    username: str
    email: str
    password: str
    firstName: Optional[str] = None
    lastName: Optional[str] = None
    roles: Optional[List[str]] = ["user"]  # Default role assignment
    # Auto-send verification email
    send_verification_email: Optional[bool] = True


class TokenValidationRequest(BaseModel):
    """Request model for token validation endpoint"""
    token: str


class RefreshTokenRequest(BaseModel):
    """Request model for token refresh endpoint"""
    refresh_token: str


class CodeExchangeRequest(BaseModel):
    """Request model for OAuth2 authorization code exchange"""
    code: str
    redirect_uri: str


class AuthUrlRequest(BaseModel):
    """Request model for OAuth2 authorization URL generation"""
    redirect_uri: str
    state: Optional[str] = None


class CreateRealmRequest(BaseModel):
    """Request model for realm creation endpoint"""
    realm_name: str
    display_name: Optional[str] = None
    enabled: bool = True
    registration_allowed: bool = True
    registration_email_as_username: bool = True
    login_with_email_allowed: bool = True
    duplicate_emails_allowed: bool = False
    verify_email: bool = False
    reset_password_allowed: bool = True
    remember_me: bool = True
    admin_username: str
    admin_password: str


class CreateClientRequest(BaseModel):
    """Request model for client creation endpoint"""
    client_id: str
    client_name: Optional[str] = None
    realm_name: str
    redirect_uris: List[str] = ["http://localhost:3000/*"]
    web_origins: List[str] = ["http://localhost:3000"]
    # Enable service account for programmatic access
    service_accounts_enabled: bool = False
    admin_username: str
    admin_password: str


class RealmInfoRequest(BaseModel):
    """Request model for realm information endpoint"""
    realm_name: str
    admin_username: str
    admin_password: str


class ClientInfoRequest(BaseModel):
    """Request model for client information endpoint"""
    realm_name: str
    client_id: str
    admin_username: str
    admin_password: str


class DeleteRealmRequest(BaseModel):
    """Request model for realm deletion endpoint"""
    realm_name: str
    admin_username: str
    admin_password: str


class DeleteClientRequest(BaseModel):
    """Request model for client deletion endpoint"""
    realm_name: str
    client_id: str
    admin_username: str
    admin_password: str


class CreateRoleRequest(BaseModel):
    """Request model for creating realm roles"""
    realm_name: str
    role_name: str
    role_description: Optional[str] = None
    admin_username: str
    admin_password: str


class AssignRoleRequest(BaseModel):
    """Request model for assigning roles to users"""
    realm_name: str
    username: str
    roles: List[str]  # List of role names to assign
    admin_username: str
    admin_password: str


class UserRoleRequest(BaseModel):
    """Request model for getting user roles"""
    realm_name: str
    username: str
    admin_username: str
    admin_password: str


class RegistrationStatusResponse(BaseModel):
    """Response model for registration status endpoint"""
    client_id: str
    realm: str
    server_url: str
    registration_enabled: bool
    service_account_configured: bool
    admin_access: bool
    permissions: Dict[str, Any]
    setup_required: Optional[Dict[str, Any]] = None


class EmailVerificationRequest(BaseModel):
    """Request model for sending email verification"""
    username_or_email: str


class PasswordResetRequest(BaseModel):
    """Request model for initiating password reset"""
    username_or_email: str


class PasswordResetConfirmRequest(BaseModel):
    """Request model for confirming password reset with new password"""
    username: str
    reset_token: str
    new_password: str


class ResendVerificationEmailRequest(BaseModel):
    """Request model for resending verification email"""
    username_or_email: str


class SMTPConfigRequest(BaseModel):
    """Request model for configuring SMTP settings"""
    realm_name: str
    admin_username: str
    admin_password: str

    # SMTP Server Settings
    host: str
    port: int = 587
    from_email: str
    from_display_name: Optional[str] = None
    reply_to: Optional[str] = None

    # Authentication Settings
    auth_enabled: bool = True
    username: Optional[str] = None
    password: Optional[str] = None

    # Encryption Settings
    starttls: bool = True
    ssl: bool = False

    # Additional Settings
    envelope_from: Optional[str] = None


class SMTPTestRequest(BaseModel):
    """Request model for testing SMTP configuration"""
    realm_name: str
    admin_username: str
    admin_password: str
    test_email: str


class GetSMTPConfigRequest(BaseModel):
    """Request model for retrieving SMTP configuration"""
    realm_name: str
    admin_username: str
    admin_password: str


class ErrorResponse(BaseModel):
    """Standard error response model"""
    error: str
    message: str
    keycloak_error: Optional[str] = None
    solutions: Optional[List[str]] = None
    client_info: Optional[Dict[str, str]] = None
