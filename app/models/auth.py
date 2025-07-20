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
