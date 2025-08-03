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
    service_accounts_enabled: bool = False  # Enable service account for programmatic access
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


class ErrorResponse(BaseModel):
    """Standard error response model"""
    error: str
    message: str
    keycloak_error: Optional[str] = None
    solutions: Optional[List[str]] = None
    client_info: Optional[Dict[str, str]] = None
