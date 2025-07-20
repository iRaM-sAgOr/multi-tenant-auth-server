# Multi-Tenant Authentication Service

A FastAPI-based authentication service that provides multi-tenant support with Keycloak as the identity provider. This service includes comprehensive health checking and startup verification to ensure reliable operation.

## Features

### 🔐 Authentication & Authorization
- Multi-tenant authentication with Keycloak integration
- JWT token generation and validation
- User management and role-based access control
- Session management across multiple applications

### 🏥 Health Monitoring & Startup Verification
- **Startup Health Check**: Verifies Keycloak connectivity during application startup
- **Real-time Health Monitoring**: Continuous health monitoring endpoints
- **Configurable Behavior**: Control startup behavior when dependencies are unavailable
- **Retry Logic**: Automatic retry mechanism for transient connection issues

### 🌐 Multi-Tenant Support
- Support for multiple applications with different Keycloak configurations
- Dynamic client configuration based on request context
- Realm and client isolation per tenant

## Health Check Configuration

The service includes robust health checking functionality to ensure reliable operation:

### 1. 🚀 Install and Start Keycloak

#### Option A: Docker (Recommended)
```bash
docker run -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest \
  start-dev
```

### Environment Variables

```bash
# Enable/disable startup health check
KEYCLOAK_STARTUP_CHECK_ENABLED=true

# Number of retry attempts during startup
KEYCLOAK_STARTUP_CHECK_RETRIES=3

# Delay between retry attempts (seconds)
KEYCLOAK_STARTUP_CHECK_RETRY_DELAY=5

# Whether to exit on health check failure (production behavior)
KEYCLOAK_STARTUP_CHECK_EXIT_ON_FAILURE=false
```

### Health Endpoints

#### Main Health Check: `GET /health`
Returns comprehensive service health information:
```json
{
  "status": "healthy",
  "service": "Multi-Tenant Authentication Service",
  "version": "1.0.0",
  "dependencies": {
    "keycloak": {
      "status": "healthy",
      "server_url": "http://localhost:8080",
      "response_time_ms": 45,
      "error": null
    }
  }
}
```

#### Dedicated Keycloak Health: `GET /health/keycloak`
Returns detailed Keycloak connectivity information:
```json
{
  "keycloak_available": true,
  "server_url": "http://localhost:8080",
  "response_time_ms": 45,
  "error": null
}
```

### Startup Behavior

The application performs the following health checks during startup:

1. **Keycloak Connectivity Check** (if enabled)
   - Attempts to connect to the configured Keycloak server
   - Retries connection with configurable attempts and delays
   - Logs detailed connectivity status

2. **Failure Handling**
   - **Production Mode**: Application exits if health checks fail (when `KEYCLOAK_STARTUP_CHECK_EXIT_ON_FAILURE=true`)
   - **Development Mode**: Application continues with warnings (when `DEBUG=true`)
   - **Configurable**: Behavior can be customized via environment variables

## Quick Start

### 1. Environment Setup

Create a `.env` file:
```env
# Application Settings
APP_NAME=Multi-Tenant Authentication Service
DEBUG=true
HOST=0.0.0.0
PORT=8000

# Keycloak Configuration
KEYCLOAK_SERVER_URL=http://localhost:8080
KEYCLOAK_STARTUP_CHECK_ENABLED=true
KEYCLOAK_STARTUP_CHECK_RETRIES=3
KEYCLOAK_STARTUP_CHECK_RETRY_DELAY=5

# Security Settings
SECRET_KEY=your-super-secret-key-change-this-in-production
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Start the Service

```bash
# Development
python main.py

# Production
uvicorn server:app_server --host 0.0.0.0 --port 8000
```

### 4. Verify Health

```bash
# Check overall service health
curl http://localhost:8000/health

# Check Keycloak connectivity specifically  
curl http://localhost:8000/health/keycloak
```

## Production Deployment

For production deployments, consider these health check configurations:

```env
# Production health check settings
KEYCLOAK_STARTUP_CHECK_ENABLED=true
KEYCLOAK_STARTUP_CHECK_RETRIES=5
KEYCLOAK_STARTUP_CHECK_RETRY_DELAY=10
KEYCLOAK_STARTUP_CHECK_EXIT_ON_FAILURE=true
DEBUG=false
```

This ensures the application won't start if critical dependencies are unavailable, preventing cascade failures in production environments.

## API Documentation

When the service is running, visit:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

## Architecture

The service is built with a modular architecture:
- `app/core/` - Core business logic and configuration
- `app/routes/` - API endpoints organized by domain
- `app/models/` - Pydantic request/response models
- `app/utils/` - Utility functions and helpers

The health check functionality is implemented in `app/core/keycloak.py` and integrated into the application lifecycle in `server.py`.