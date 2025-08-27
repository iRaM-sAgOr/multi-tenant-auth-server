"""
Route Error Handler Utility

This module provides clean, reusable error handling for authentication routes.
It wraps complex error classification logic into simple, readable functions.
"""

from typing import Callable, Any
from functools import wraps
from fastapi import HTTPException

from app.core.logging import get_structured_logger, log_keycloak_operation
from app.utils.error_handler import AuthErrorHandler, create_success_response
from app.core.keycloak_client import ClientConfig

logger = get_structured_logger(__name__)


def handle_auth_operation(operation_name: str):
    """
    Decorator to handle authentication operation errors with proper classification
    
    Args:
        operation_name: Name of the operation (login, register, validate_token, etc.)
        
    Returns:
        Decorated function with error handling
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                result = await func(*args, **kwargs)
                
                # If it's a success response, wrap it properly
                if isinstance(result, dict) and "access_token" in result:
                    # Token response - wrap with success format
                    return create_success_response(
                        message=f"{operation_name.title()} successful",
                        data=result,
                        operation=operation_name
                    )
                elif isinstance(result, dict) and "success" not in result:
                    # Regular response - wrap with success format  
                    return create_success_response(
                        message=f"{operation_name.title()} completed successfully",
                        data=result,
                        operation=operation_name
                    )
                else:
                    # Already formatted response
                    return result
                    
            except HTTPException:
                # Re-raise HTTPExceptions (they're already properly formatted)
                raise
            except Exception as e:
                # Handle unexpected errors with classification
                return await _handle_operation_error(e, operation_name, *args, **kwargs)
        
        return wrapper
    return decorator


async def _handle_operation_error(
    error: Exception, 
    operation: str, 
    *args, 
    **kwargs
) -> HTTPException:
    """
    Handle and classify operation errors
    
    Args:
        error: The exception that occurred
        operation: Operation name
        *args, **kwargs: Function arguments to extract context
        
    Returns:
        Properly classified HTTPException
    """
    # Extract client config and other context from args/kwargs
    client_config = None
    username = None
    
    # Try to find client_config and username from function parameters
    for arg in args:
        if isinstance(arg, ClientConfig):
            client_config = arg
        elif hasattr(arg, 'username'):
            username = getattr(arg, 'username')
    
    for value in kwargs.values():
        if isinstance(value, ClientConfig):
            client_config = value
        elif hasattr(value, 'username'):
            username = getattr(value, 'username')
    
    # Log the error
    log_context = {
        "operation": operation,
        "error": str(error),
        "success": False
    }
    
    if client_config:
        log_context.update({
            "client_id": client_config.client_id,
            "realm": client_config.realm
        })
    
    if username:
        log_context["username"] = username
        
    logger.error(f"❌ {operation.title()} error", **log_context)
    
    # Classify and handle the error
    error_str = str(error).lower()
    
    if operation == "login":
        return _handle_login_error(error_str)
    elif operation == "register":
        return _handle_register_error(error_str)
    elif operation == "validate_token":
        return _handle_token_validation_error(error_str)
    elif operation == "refresh_token":
        return _handle_token_refresh_error(error_str)
    else:
        return _handle_generic_error(error_str, operation)


def _handle_login_error(error_str: str) -> HTTPException:
    """Handle login-specific errors"""
    if any(auth_error in error_str for auth_error in [
        "authentication", "credentials", "login", "password", "username", "invalid_grant"
    ]):
        raise AuthErrorHandler.create_simplified_error(
            message="Invalid username or password",
            operation="login",
            suggestions=["Check your username and password", "Ensure your account is not locked"],
            status_code=401
        )
    elif any(network_error in error_str for network_error in [
        "connection", "timeout", "network", "unavailable"
    ]):
        raise AuthErrorHandler.create_simplified_error(
            message="Authentication service temporarily unavailable",
            operation="login", 
            suggestions=["Try again in a few moments", "Contact support if the issue persists"],
            status_code=503
        )
    else:
        raise AuthErrorHandler.create_simplified_error(
            message="Login failed due to a system error",
            operation="login",
            suggestions=["Try again later", "Contact support if the issue persists"],
            status_code=500
        )


def _handle_register_error(error_str: str) -> HTTPException:
    """Handle registration-specific errors"""
    if any(validation_error in error_str for validation_error in [
        "validation", "password", "email", "username", "duplicate"
    ]):
        raise AuthErrorHandler.create_simplified_error(
            message="Registration failed due to validation errors",
            operation="register",
            suggestions=["Check your input data", "Ensure email format is correct", "Use a stronger password"],
            status_code=400
        )
    elif any(conflict_error in error_str for conflict_error in [
        "already exists", "conflict", "duplicate"
    ]):
        raise AuthErrorHandler.create_simplified_error(
            message="An account with this email or username already exists",
            operation="register",
            suggestions=["Try logging in instead", "Use a different email or username"],
            status_code=409
        )
    elif any(network_error in error_str for network_error in [
        "connection", "timeout", "network", "unavailable"
    ]):
        raise AuthErrorHandler.create_simplified_error(
            message="Registration service temporarily unavailable",
            operation="register",
            suggestions=["Try again in a few moments", "Contact support if the issue persists"],
            status_code=503
        )
    else:
        raise AuthErrorHandler.create_simplified_error(
            message="Registration failed due to a system error",
            operation="register",
            suggestions=["Try again later", "Contact support if the issue persists"],
            status_code=500
        )


def _handle_token_validation_error(error_str: str) -> HTTPException:
    """Handle token validation errors"""
    if any(token_error in error_str for token_error in [
        "jwt", "token", "expired", "invalid", "malformed", "decode"
    ]):
        raise AuthErrorHandler.create_simplified_error(
            message="Invalid or expired token",
            operation="validate_token",
            suggestions=["Check your token format", "Try refreshing your token", "Log in again if needed"],
            status_code=401
        )
    elif any(network_error in error_str for network_error in [
        "connection", "timeout", "network", "unreachable"
    ]):
        raise AuthErrorHandler.create_simplified_error(
            message="Token validation service temporarily unavailable",
            operation="validate_token",
            suggestions=["Try again in a few moments", "Contact support if the issue persists"],
            status_code=503
        )
    else:
        raise AuthErrorHandler.create_simplified_error(
            message="Token validation failed due to a system error",
            operation="validate_token",
            suggestions=["Try again in a few moments", "Contact support if the issue persists"],
            status_code=500
        )


def _handle_token_refresh_error(error_str: str) -> HTTPException:
    """Handle token refresh errors"""
    if any(token_error in error_str for token_error in [
        "refresh_token", "token", "expired", "invalid", "unauthorized"
    ]):
        raise AuthErrorHandler.create_simplified_error(
            message="Invalid or expired refresh token",
            operation="refresh_token",
            suggestions=["Your session has expired", "Please log in again"],
            status_code=401
        )
    elif any(network_error in error_str for network_error in [
        "connection", "timeout", "network", "unavailable"
    ]):
        raise AuthErrorHandler.create_simplified_error(
            message="Token refresh service temporarily unavailable",
            operation="refresh_token",
            suggestions=["Try again in a few moments", "Log in again if the issue persists"],
            status_code=503
        )
    else:
        raise AuthErrorHandler.create_simplified_error(
            message="Token refresh failed due to a system error",
            operation="refresh_token",
            suggestions=["Try again in a few moments", "Log in again if the issue persists"],
            status_code=500
        )


def _handle_generic_error(error_str: str, operation: str) -> HTTPException:
    """Handle generic operation errors"""
    if any(auth_error in error_str for auth_error in [
        "authentication", "unauthorized", "forbidden"
    ]):
        raise AuthErrorHandler.create_simplified_error(
            message=f"{operation.title()} failed due to authentication error",
            operation=operation,
            suggestions=["Check your credentials", "Ensure you have proper access"],
            status_code=401
        )
    elif any(network_error in error_str for network_error in [
        "connection", "timeout", "network", "unavailable"
    ]):
        raise AuthErrorHandler.create_simplified_error(
            message=f"{operation.title()} service temporarily unavailable",
            operation=operation,
            suggestions=["Try again in a few moments", "Contact support if the issue persists"],
            status_code=503
        )
    else:
        raise AuthErrorHandler.create_simplified_error(
            message=f"{operation.title()} failed due to a system error",
            operation=operation,
            suggestions=["Try again later", "Contact support if the issue persists"],
            status_code=500
        )
