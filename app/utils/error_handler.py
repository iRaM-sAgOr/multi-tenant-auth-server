"""
Simplified Error Handler for Authentication APIs

This module provides utilities for creating consistent, simplified error responses
across all authentication endpoints.
"""

import re
from datetime import datetime
from typing import Dict, Any, List, Optional
from fastapi import HTTPException, status
from uuid import uuid4

from app.models.auth import (
    StandardizedErrorResponse,
    AuthErrorCode,
    PasswordRequirement
)


class AuthErrorHandler:
    """Handles simplified standardized error responses for authentication operations"""
    
    @staticmethod
    def get_password_suggestions(keycloak_error: str) -> List[str]:
        """
        Get actionable password suggestions based on Keycloak error
        
        Args:
            keycloak_error: Raw Keycloak error message
            
        Returns:
            List of suggestions to fix password issues
        """
        suggestions = []
        
        if "invalidPasswordMinUpperCaseCharsMessage" in keycloak_error:
            suggestions.append("Add at least one uppercase letter (A-Z)")
        if "invalidPasswordMinLowerCaseCharsMessage" in keycloak_error:
            suggestions.append("Add at least one lowercase letter (a-z)")
        if "invalidPasswordMinDigitsMessage" in keycloak_error:
            suggestions.append("Add at least one number (0-9)")
        if "invalidPasswordMinSpecialCharsMessage" in keycloak_error:
            suggestions.append("Add at least one special character (!@#$%^&*)")
        if "invalidPasswordMinLengthMessage" in keycloak_error:
            suggestions.append("Use a longer password (minimum 8 characters recommended)")
        if "invalidPasswordMaxLengthMessage" in keycloak_error:
            suggestions.append("Use a shorter password")
        if "invalidPasswordNotUsernameMessage" in keycloak_error:
            suggestions.append("Choose a password different from your username")
        
        # If no specific suggestions found, provide general ones
        if not suggestions:
            suggestions = [
                "Use a password with at least 8 characters",
                "Include uppercase and lowercase letters",
                "Include at least one number",
                "Include at least one special character"
            ]
        
        return suggestions
    
    @staticmethod
    def create_simplified_error(
        message: str,
        operation: str,
        suggestions: List[str],
        status_code: int = status.HTTP_400_BAD_REQUEST
    ) -> HTTPException:
        """
        Create a simplified HTTP exception for authentication errors
        
        Args:
            message: User-friendly error message
            operation: Operation that failed (login, register, etc.)
            suggestions: List of actionable suggestions
            status_code: HTTP status code
            
        Returns:
            HTTPException with simplified error format
        """
        error_response = StandardizedErrorResponse(
            message=message,
            operation=operation,
            suggestions=suggestions
        )
        
        return HTTPException(
            status_code=status_code,
            detail=error_response.dict()
        )
    
    @staticmethod
    def handle_keycloak_error(
        keycloak_error: str,
        operation: str,
        client_id: Optional[str] = None,
        realm: Optional[str] = None
    ) -> HTTPException:
        """
        Parse and handle Keycloak errors with simplified responses
        
        Args:
            keycloak_error: Raw Keycloak error string
            operation: Operation that failed
            client_id: Client ID context (not used in response but for logging)
            realm: Realm context (not used in response but for logging)
            
        Returns:
            HTTPException with simplified error details
        """
        error_str = str(keycloak_error).lower()
        
        # Password validation errors
        if any(pwd_error in keycloak_error for pwd_error in [
            "invalidPasswordMinUpperCaseCharsMessage",
            "invalidPasswordMinLowerCaseCharsMessage", 
            "invalidPasswordMinDigitsMessage",
            "invalidPasswordMinSpecialCharsMessage",
            "invalidPasswordMinLengthMessage",
            "invalidPasswordMaxLengthMessage",
            "invalidPasswordNotUsernameMessage"
        ]):
            suggestions = AuthErrorHandler.get_password_suggestions(keycloak_error)
            return AuthErrorHandler.create_simplified_error(
                message="Your password doesn't meet the security requirements",
                operation=operation,
                suggestions=suggestions,
                status_code=status.HTTP_400_BAD_REQUEST
            )
        
        # User already exists
        elif "409" in error_str or "exists" in error_str or "conflict" in error_str:
            return AuthErrorHandler.create_simplified_error(
                message="An account with this username or email already exists",
                operation=operation,
                suggestions=[
                    "Try logging in instead of registering",
                    "Use a different username or email address",
                    "Reset your password if you forgot it"
                ],
                status_code=status.HTTP_409_CONFLICT
            )
        
        # Permission denied / Forbidden
        elif "403" in error_str or "forbidden" in error_str:
            return AuthErrorHandler.create_simplified_error(
                message="Access denied for this operation",
                operation=operation,
                suggestions=[
                    "Check your account permissions",
                    "Contact system administrator",
                    "Verify client configuration"
                ],
                status_code=status.HTTP_403_FORBIDDEN
            )
        
        # Invalid credentials / Unauthorized
        elif "401" in error_str or "unauthorized" in error_str or "invalid_grant" in error_str:
            # Customize message based on operation
            if operation == "refresh_token":
                return AuthErrorHandler.create_simplified_error(
                    message="Invalid or expired refresh token",
                    operation=operation,
                    suggestions=[
                        "Your session has expired",
                        "Please log in again"
                    ],
                    status_code=status.HTTP_401_UNAUTHORIZED
                )
            elif operation == "validate_token":
                return AuthErrorHandler.create_simplified_error(
                    message="Invalid or expired access token",
                    operation=operation,
                    suggestions=[
                        "Check your token format",
                        "Try refreshing your token",
                        "Log in again if needed"
                    ],
                    status_code=status.HTTP_401_UNAUTHORIZED
                )
            else:  # login or other authentication operations
                return AuthErrorHandler.create_simplified_error(
                    message="Invalid username or password",
                    operation=operation,
                    suggestions=[
                        "Check your username and password",
                        "Ensure your account is activated",
                        "Reset your password if needed"
                    ],
                    status_code=status.HTTP_401_UNAUTHORIZED
                )
        
        # Email/Username validation
        elif "email" in error_str and "invalid" in error_str:
            return AuthErrorHandler.create_simplified_error(
                message="Please provide a valid email address",
                operation=operation,
                suggestions=[
                    "Use a valid email format (e.g., user@example.com)",
                    "Check for typos in the email address"
                ],
                status_code=status.HTTP_400_BAD_REQUEST
            )
        
        # Account disabled
        elif "disabled" in error_str or "account_disabled" in error_str:
            return AuthErrorHandler.create_simplified_error(
                message="Your account has been disabled",
                operation=operation,
                suggestions=[
                    "Contact system administrator",
                    "Check your email for account status updates"
                ],
                status_code=status.HTTP_403_FORBIDDEN
            )
        
        # Token expired
        elif "expired" in error_str or "token" in error_str:
            # Customize message based on operation
            if operation == "refresh_token":
                return AuthErrorHandler.create_simplified_error(
                    message="Refresh token has expired",
                    operation=operation,
                    suggestions=[
                        "Your session has completely expired",
                        "Please log in again to get a new session"
                    ],
                    status_code=status.HTTP_401_UNAUTHORIZED
                )
            elif operation == "validate_token":
                return AuthErrorHandler.create_simplified_error(
                    message="Access token has expired",
                    operation=operation,
                    suggestions=[
                        "Use your refresh token to get a new access token",
                        "Log in again if your refresh token has also expired"
                    ],
                    status_code=status.HTTP_401_UNAUTHORIZED
                )
            else:
                return AuthErrorHandler.create_simplified_error(
                    message="Your session has expired",
                    operation=operation,
                    suggestions=[
                        "Please login again",
                        "Use refresh token if available"
                    ],
                    status_code=status.HTTP_401_UNAUTHORIZED
                )
        
        # Generic error fallback
        else:
            return AuthErrorHandler.create_simplified_error(
                message="Something went wrong. Please try again.",
                operation=operation,
                suggestions=[
                    "Try again in a few moments",
                    "Contact support if the problem persists"
                ],
                status_code=status.HTTP_400_BAD_REQUEST
            )


def create_success_response(
    message: str,
    data: Optional[Dict[str, Any]] = None,
    operation: Optional[str] = None,
    client_id: Optional[str] = None,
    realm: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create a simplified success response
    
    Args:
        message: Success message
        data: Response data
        operation: Operation that succeeded (not included in response for simplicity)
        client_id: Client ID context (not included in response for simplicity)
        realm: Realm context (not included in response for simplicity)
        
    Returns:
        Simplified success response
    """
    response = {
        "success": True,
        "message": message,
        "data": data or {}
    }
    
    return response
