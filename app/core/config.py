"""
Configuration Settings Module - Centralized Application Configuration

USECASE:
This module provides centralized configuration management for the FastAPI Keycloak 
authentication microservice. It handles all environment-specific settings including:
- Application metadata and server configuration
- Keycloak integration settings
- Database connection parameters
- Security and JWT token settings
- CORS (Cross-Origin Resource Sharing) configuration
- Logging configuration

ARCHITECTURE:
Uses Pydantic Settings for:
- Automatic environment variable loading
- Type validation and conversion
- Default value management
- Configuration validation

FLOW:
1. Load settings from environment variables or .env file
2. Validate all configuration values
3. Apply defaults where appropriate
4. Provide global settings instance for application use
"""

from typing import List, Optional
from pydantic import validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Application Settings Configuration Class

    USECASE:
    This class defines all configuration parameters needed by the authentication service.
    It automatically loads values from environment variables, validates them, and provides
    defaults for development environments.

    CONFIGURATION CATEGORIES:
    1. Application Settings - Basic app metadata and server configuration
    2. Keycloak Integration - Identity provider connection settings
    3. Database Configuration - Database connection and behavior settings
    4. Security Settings - JWT tokens and cryptographic configuration
    5. CORS Settings - Cross-origin request handling
    6. Logging Configuration - Logging behavior and formats

    ENVIRONMENT VARIABLES:
    All settings can be configured via environment variables with the same names.
    For example: APP_NAME, KEYCLOAK_SERVER_URL, DATABASE_URL, etc.
    """

    # === APPLICATION SETTINGS ===
    # Basic application metadata and server configuration
    # Service name for identification
    app_name: str = "FastAPI Keycloak Auth Service"
    # Version for API documentation
    app_version: str = "1.0.0"
    # Environment identifier (dev/staging/prod)
    environment: str = "development"
    # Enable debug mode for development
    debug: bool = True
    host: str = "0.0.0.0"                             # Server bind address
    port: int = 8000                                   # Server port

    # === KEYCLOAK CONFIGURATION ===
    # Settings for connecting to Keycloak server
    # Keycloak server base URL (default for development)
    keycloak_server_url: str = "http://localhost:8080"

    # Startup health check configuration
    # Whether to verify Keycloak connectivity during startup
    keycloak_startup_check_enabled: bool = True
    # Number of retry attempts for Keycloak connectivity check
    keycloak_startup_check_retries: int = 3
    # Delay between retry attempts in seconds
    keycloak_startup_check_retry_delay: int = 5
    # Whether to exit application if Keycloak is unavailable (production behavior)
    keycloak_startup_check_exit_on_failure: bool = False

    # Admin access configuration (legacy fallback - deprecated for security)
    # SECURITY NOTE: Admin credentials are now passed per-request in admin APIs
    # These settings are kept for backward compatibility with existing service account fallback
    # Admin username for fallback (optional - deprecated)
    keycloak_admin_username: Optional[str] = None
    # Admin password for fallback (optional - deprecated)
    keycloak_admin_password: Optional[str] = None

    # === SECURITY SETTINGS ===
    # JWT token configuration and cryptographic settings
    # Secret key for JWT operations (can be any string for multi-tenant)
    secret_key: str = "your-secret-key-here"
    algorithm: str = "HS256"                           # JWT signing algorithm
    # Access token lifespan in minutes
    access_token_expire_minutes: int = 30
    # Refresh token lifespan in days
    refresh_token_expire_days: int = 7

    # === CORS SETTINGS ===
    # Cross-Origin Resource Sharing configuration for web clients
    # Allowed origins for CORS
    cors_origins: List[str] = ["http://localhost:3000"]
    # Allow credentials in CORS requests
    cors_allow_credentials: bool = True
    cors_allow_methods: List[str] = ["*"]                # Allowed HTTP methods
    # Allowed request headers
    cors_allow_headers: List[str] = ["*"]

    # === TRUSTED HOSTS SETTINGS ===
    # Security middleware configuration for trusted hosts
    # List of allowed host headers (domains that can access the API)
    trusted_hosts: List[str] = ["localhost",
                                "127.0.0.1", "*"]  # Configure for production

    # === LOGGING CONFIGURATION ===
    # Logging behavior and output format settings
    # Minimum log level (DEBUG/INFO/WARNING/ERROR)
    log_level: str = "INFO"
    # Log output format (json/console)
    log_format: str = "json"

    @validator('keycloak_server_url')
    def validate_keycloak_url(cls, v):
        """
        Validate and normalize Keycloak server URL.

        USECASE:
        Ensures the Keycloak server URL is properly formatted by removing
        trailing slashes that could cause connection issues.

        Args:
            v: The Keycloak server URL value

        Returns:
            Normalized URL without trailing slash
        """
        return v.rstrip('/')

    @validator('cors_origins', pre=True)
    def parse_cors_origins(cls, v):
        """
        Parse CORS origins from string or list format.

        USECASE:
        Allows CORS origins to be specified either as a comma-separated string
        (convenient for environment variables) or as a list (convenient for config files).

        Example:
            Environment variable: CORS_ORIGINS="http://localhost:3000,https://myapp.com"
            Config file: cors_origins = ["http://localhost:3000", "https://myapp.com"]

        Args:
            v: CORS origins value (string or list)

        Returns:
            List of origin URLs
        """
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v

    @validator('trusted_hosts', pre=True)
    def parse_trusted_hosts(cls, v):
        """
        Parse trusted hosts from string or list format.

        USECASE:
        Allows trusted hosts to be specified either as a comma-separated string
        (convenient for environment variables) or as a list (convenient for config files).

        Example:
            Environment variable: TRUSTED_HOSTS="localhost,127.0.0.1,myapp.com"
            Config file: trusted_hosts = ["localhost", "127.0.0.1", "myapp.com"]

        Args:
            v: Trusted hosts value (string or list)

        Returns:
            List of trusted host domains
        """
        if isinstance(v, str):
            return [host.strip() for host in v.split(",")]
        return v

    class Config:
        """
        Pydantic Configuration for Settings Class

        USECASE:
        Configures how Pydantic loads and processes environment variables:
        - Specifies .env file location for local development
        - Sets encoding for environment file
        - Makes environment variable names case-insensitive
        """
        env_file = ".env"                    # Load from .env file if present
        env_file_encoding = "utf-8"          # Use UTF-8 encoding
        case_sensitive = False               # Environment variables are case-insensitive


# === GLOBAL SETTINGS INSTANCE ===
# Create singleton settings instance that's imported throughout the application
# This ensures consistent configuration across all modules
settings = Settings()
