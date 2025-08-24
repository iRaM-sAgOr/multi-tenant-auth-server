"""
SMTP Configuration Admin Routes

This module contains admin API endpoints for configuring SMTP settings in Keycloak realms.
Allows programmatic configuration of email settings without accessing the Keycloak admin console.
"""

import logging
from fastapi import APIRouter, HTTPException

from app.models.auth import (
    SMTPConfigRequest,
    SMTPTestRequest,
    GetSMTPConfigRequest
)
from app.core.keycloak import keycloak_client
from app.core.logging import get_structured_logger

# Get structured logger
logger = get_structured_logger(__name__)

# Create router
router = APIRouter(prefix="/admin/smtp", tags=["SMTP Configuration"])


@router.post("/configure")
async def configure_smtp(request: SMTPConfigRequest):
    """
    Configure SMTP settings for a Keycloak realm

    This endpoint allows you to programmatically configure SMTP settings for email
    verification and password reset functionality without accessing the Keycloak admin console.

    Body Parameters:
    - realm_name: Name of the Keycloak realm to configure
    - admin_username: Keycloak admin username
    - admin_password: Keycloak admin password

    SMTP Server Settings:
    - host: SMTP server hostname (e.g., smtp.gmail.com)
    - port: SMTP server port (default: 587 for TLS, 465 for SSL)
    - from_email: Email address to send emails from
    - from_display_name: Display name for the sender (optional)
    - reply_to: Reply-to email address (optional)

    Authentication Settings:
    - auth_enabled: Whether SMTP authentication is required (default: true)
    - username: SMTP username (usually email address)
    - password: SMTP password (use app-specific password for Gmail)

    Encryption Settings:
    - starttls: Enable STARTTLS encryption (default: true)
    - ssl: Enable SSL encryption (default: false)

    Common SMTP Configurations:

    Gmail:
    - host: smtp.gmail.com
    - port: 587
    - starttls: true
    - auth_enabled: true
    - username: your-email@gmail.com
    - password: your-app-password

    SendGrid:
    - host: smtp.sendgrid.net
    - port: 587
    - starttls: true
    - auth_enabled: true
    - username: apikey
    - password: SG.your-sendgrid-api-key

    AWS SES:
    - host: email-smtp.us-east-1.amazonaws.com
    - port: 587
    - starttls: true
    - auth_enabled: true
    - username: your-ses-username
    - password: your-ses-password
    """
    try:
        # Prepare SMTP configuration
        smtp_config = {
            "host": request.host,
            "port": request.port,
            "from_email": request.from_email,
            "from_display_name": request.from_display_name or "",
            "reply_to": request.reply_to or "",
            "auth_enabled": request.auth_enabled,
            "username": request.username or "",
            "password": request.password or "",
            "starttls": request.starttls,
            "ssl": request.ssl,
            "envelope_from": request.envelope_from or ""
        }

        result = await keycloak_client.configure_smtp(
            smtp_config=smtp_config,
            realm_name=request.realm_name,
            admin_username=request.admin_username,
            admin_password=request.admin_password
        )

        logger.info(
            f"✅ SMTP configuration successful for realm {request.realm_name}",
            extra={
                "operation": "configure_smtp",
                "realm": request.realm_name,
                "smtp_host": request.host,
                "smtp_port": request.port,
                "success": True
            }
        )

        return result

    except HTTPException:
        logger.warning(
            f"❌ SMTP configuration failed for realm {request.realm_name}",
            extra={
                "operation": "configure_smtp",
                "realm": request.realm_name,
                "success": False
            }
        )
        raise
    except Exception as e:
        logger.error(
            f"❌ SMTP configuration error for realm {request.realm_name}: {str(e)}",
            extra={
                "operation": "configure_smtp",
                "realm": request.realm_name,
                "error": str(e),
                "success": False
            }
        )
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/config")
async def get_smtp_config(request: GetSMTPConfigRequest):
    """
    Get current SMTP configuration for a Keycloak realm

    This endpoint retrieves the current SMTP configuration for a realm.
    Sensitive information like passwords are not returned for security.

    Body Parameters:
    - realm_name: Name of the Keycloak realm
    - admin_username: Keycloak admin username
    - admin_password: Keycloak admin password

    Returns:
    - Current SMTP configuration (passwords are masked)
    - Configuration status
    - SMTP settings details
    """
    try:
        result = await keycloak_client.get_smtp_config(
            realm_name=request.realm_name,
            admin_username=request.admin_username,
            admin_password=request.admin_password
        )

        logger.info(
            f"✅ SMTP configuration retrieved for realm {request.realm_name}",
            extra={
                "operation": "get_smtp_config",
                "realm": request.realm_name,
                "smtp_configured": result.get("smtp_configured", False),
                "success": True
            }
        )

        return result

    except HTTPException:
        logger.warning(
            f"❌ SMTP configuration retrieval failed for realm {request.realm_name}",
            extra={
                "operation": "get_smtp_config",
                "realm": request.realm_name,
                "success": False
            }
        )
        raise
    except Exception as e:
        logger.error(
            f"❌ SMTP configuration retrieval error for realm {request.realm_name}: {str(e)}",
            extra={
                "operation": "get_smtp_config",
                "realm": request.realm_name,
                "error": str(e),
                "success": False
            }
        )
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/test")
async def test_smtp(request: SMTPTestRequest):
    """
    Test SMTP configuration by sending a test email

    This endpoint tests the current SMTP configuration by creating a temporary user
    and sending them a verification email. The temporary user is automatically deleted
    after the test.

    Body Parameters:
    - realm_name: Name of the Keycloak realm
    - admin_username: Keycloak admin username
    - admin_password: Keycloak admin password
    - test_email: Email address to send the test email to

    Test Process:
    1. Creates a temporary test user with the provided email
    2. Attempts to send a verification email using current SMTP settings
    3. Reports success/failure of the email sending
    4. Automatically deletes the temporary test user

    Returns:
    - Test status (passed/failed)
    - SMTP configuration details used for the test
    - Error details if test failed
    """
    try:
        result = await keycloak_client.test_smtp_connection(
            realm_name=request.realm_name,
            test_email=request.test_email,
            admin_username=request.admin_username,
            admin_password=request.admin_password
        )

        logger.info(
            f"✅ SMTP test successful for realm {request.realm_name}",
            extra={
                "operation": "test_smtp",
                "realm": request.realm_name,
                "test_email": request.test_email,
                "test_status": result.get("test_status", "unknown"),
                "success": True
            }
        )

        return result

    except HTTPException:
        logger.warning(
            f"❌ SMTP test failed for realm {request.realm_name}",
            extra={
                "operation": "test_smtp",
                "realm": request.realm_name,
                "test_email": request.test_email,
                "success": False
            }
        )
        raise
    except Exception as e:
        logger.error(
            f"❌ SMTP test error for realm {request.realm_name}: {str(e)}",
            extra={
                "operation": "test_smtp",
                "realm": request.realm_name,
                "test_email": request.test_email,
                "error": str(e),
                "success": False
            }
        )
        raise HTTPException(status_code=500, detail="Internal server error")
