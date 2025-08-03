# Multi-Tenant Authentication Service

A FastAPI-based authentication service that provides multi-tenant support with Keycloak as the identity provider. This service includes comprehensive health checking, startup verification, and complete administrative APIs for Keycloak management without console access.

## 🌟 Features Overview

### 🔐 Authentication & Authorization
- Multi-tenant authentication with Keycloak integration
- JWT token generation and validation
- User management and role-based access control
- Session management across multiple applications

### 🔧 Administrative Operations
- **Realm Management**: Create and configure new Keycloak realms
- **Client Management**: Create clients with proper authentication settings
- **Information Retrieval**: Get detailed realm and client information
- **Security Optimized**: Admin credentials passed per-request, not stored in environment
- **Console-Free Management**: Complete Keycloak administration through APIs

### 🏥 Health Monitoring & Startup Verification
- **Startup Health Check**: Verifies Keycloak connectivity during application startup
- **Real-time Health Monitoring**: Continuous health monitoring endpoints
- **Configurable Behavior**: Control startup behavior when dependencies are unavailable
- **Retry Logic**: Automatic retry mechanism for transient connection issues

### 🌐 Multi-Tenant Support
- Support for multiple applications with different Keycloak configurations
- Dynamic client configuration based on request context
- Realm and client isolation per tenant

### 🔒 Enhanced Security
- Admin credentials no longer stored in environment variables
- Per-request admin authentication for administrative operations
- Service account authentication preferred for regular operations
- Comprehensive audit logging for admin operations

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

## Production Deployment with Docker

### 🐳 Docker Production Setup

The service includes production-ready Docker configurations for scalable deployment with Keycloak.

#### 1. **Environment Configuration**

Create a production environment file (`.env.production`):

```env
# === SECURITY SETTINGS (CHANGE THESE!) ===
SECRET_KEY=your-super-secure-secret-key-minimum-32-characters-for-production
CORS_ORIGINS=["https://your-frontend-domain.com"]

# === KEYCLOAK CONFIGURATION ===
KEYCLOAK_SERVER_URL=http://keycloak:8080
KEYCLOAK_STARTUP_CHECK_ENABLED=true
KEYCLOAK_STARTUP_CHECK_RETRIES=5
KEYCLOAK_STARTUP_CHECK_RETRY_DELAY=10
KEYCLOAK_STARTUP_CHECK_EXIT_ON_FAILURE=true

# === APPLICATION SETTINGS ===
APP_ENVIRONMENT=production
APP_DEBUG=false
HOST=0.0.0.0
PORT=8000

# === DATABASE CONFIGURATION ===
# For managed database (e.g., AWS RDS, Google Cloud SQL)
KC_DB_URL=postgresql://username:password@your-db-host:5432/keycloak?sslmode=require
KC_DB_USERNAME=your_db_username
KC_DB_PASSWORD=your_db_password
KC_HOSTNAME=your-keycloak-domain.com

# === KEYCLOAK ADMIN SETUP ===
KEYCLOAK_ADMIN_USER=keycloak-admin
KEYCLOAK_ADMIN_PASSWORD=secure-admin-password-change-this
```

#### 2. **Production Docker Deployment**

##### Option A: With Managed Database (Recommended)

```bash
# 1. Build and deploy with external database
docker-compose -f docker-compose.production.yml --env-file .env.production up -d

# 2. Check service health
curl https://your-auth-service-domain.com/health
```

##### Option B: Complete Stack (Database + Keycloak + Auth Service)

```bash
# 1. Deploy complete stack locally or on single server
docker-compose -f docker-compose.yml --env-file .env.production up -d

# 2. Verify all services are running
docker-compose ps
```

##### Option C: AWS Deployment

```bash
# 1. Deploy on AWS with AWS-specific configuration
docker-compose -f docker-compose.aws.yml --env-file .env.production.aws up -d

# 2. Stop AWS deployment
docker-compose -f docker-compose.aws.yml --env-file .env.production.aws down

# 3. Check service health on AWS
curl https://your-aws-auth-service-domain.com/health
```

#### 3. **Production Build Commands**

```bash
# Build production image
docker build -t multi-tenant-auth:production .

# Tag for registry
docker tag multi-tenant-auth:production your-registry.com/multi-tenant-auth:latest

# Push to registry
docker push your-registry.com/multi-tenant-auth:latest

# Deploy on production server
docker run -d \
  --name auth-service \
  --env-file .env.production \
  -p 8000:8000 \
  your-registry.com/multi-tenant-auth:latest
```

#### 4. **Kubernetes Deployment** (Optional)

```yaml
# k8s-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: multi-tenant-auth
spec:
  replicas: 3
  selector:
    matchLabels:
      app: multi-tenant-auth
  template:
    metadata:
      labels:
        app: multi-tenant-auth
    spec:
      containers:
      - name: auth-service
        image: your-registry.com/multi-tenant-auth:latest
        ports:
        - containerPort: 8000
        envFrom:
        - configMapRef:
            name: auth-config
        - secretRef:
            name: auth-secrets
```

#### 5. **Production Health Checks**

```bash
# Kubernetes health check
curl https://your-auth-service/health

# Docker health check
docker exec auth-service curl http://localhost:8000/health

# Service monitoring
curl https://your-auth-service/health/keycloak
```

### 📊 Production Monitoring

Monitor these endpoints in production:

- **`/health`** - Overall service health
- **`/health/keycloak`** - Keycloak connectivity
- **`/docs`** - API documentation (restrict access in production)

This ensures the application won't start if critical dependencies are unavailable, preventing cascade failures in production environments.

## API Documentation

When the service is running, visit:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

## Admin APIs - Complete Keycloak Management Without Console

The service provides comprehensive administrative APIs for managing Keycloak realms and clients **entirely through APIs**, eliminating the need for Keycloak console access.

### 🔑 **Admin Privilege Model**

- **Admin credentials are passed per-request** (not stored in environment)
- **Direct master realm access** for administrative operations
- **Secure credential handling** with no environment exposure
- **Complete console replacement** for realm and client management

### 🚀 **Available Admin Operations**

#### 1. **Realm Management** - `POST /admin/realms`

**Purpose**: Create new Keycloak realms with production-ready configurations

```bash
curl -X POST "https://your-auth-service.com/admin/realms" \
  -H "Content-Type: application/json" \
  -d '{
    "realm_name": "production-app",
    "display_name": "Production Application",
    "enabled": true,
    "registration_allowed": true,
    "registration_email_as_username": true,
    "login_with_email_allowed": true,
    "verify_email": false,
    "reset_password_allowed": true,
    "admin_username": "keycloak-admin",
    "admin_password": "secure-admin-password"
  }'
```

**Auto-configured Security Features**:
- Password policy: 8+ chars, mixed case, digits
- Session timeout: 30 minutes idle, 10 hours max
- SSL required for external connections
- CSRF protection enabled

#### 2. **Client Creation** - `POST /admin/clients`

**Purpose**: Create clients for user authentication with automatic service account role assignment

```bash
curl -X POST "https://your-auth-service.com/admin/clients" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "mobile-app-client",
    "client_name": "Mobile Application",
    "realm_name": "production-app",
    "redirect_uris": [
      "https://your-app.com/callback",
      "https://your-app.com/silent-refresh"
    ],
    "web_origins": ["https://your-app.com"],
    "service_accounts_enabled": true,
    "admin_username": "keycloak-admin",
    "admin_password": "secure-admin-password"
  }'
```

**🆕 NEW FEATURE: Automatic Role Assignment**
When `service_accounts_enabled: true`, the API now automatically:
- ✅ Creates the client with service account enabled
- ✅ Finds the service account user for the client
- ✅ Assigns `manage-users` and `view-users` roles from `realm-management`
- ✅ Returns role assignment status in the response

**Client Security Configuration**:
- ✅ Confidential client (requires client secret)
- ✅ PKCE enabled for enhanced security
- ✅ Authorization Code Flow enabled
- ✅ Direct Grant Flow enabled
- ✅ Service accounts with automatic role assignment
- ❌ Authorization services disabled
- ❌ Implicit flow disabled

**Enhanced Response includes**:
```json
{
  "client_secret": {
    "type": "secret",
    "value": "generated-client-secret-use-this-in-your-app"
  },
  "client_configuration": {
    "features_enabled": {
      "user_login": true,
      "user_registration": false,
      "admin_access": false,
      "service_account": true,
      "automatic_role_assignment": true
    },
    "service_account_configuration": {
      "enabled": true,
      "automatic_role_assignment": true,
      "assigned_roles": ["manage-users", "view-users"],
      "role_assignment_status": "Success"
    }
  },
  "role_assignment": {
    "service_account_enabled": true,
    "roles_assigned": true,
    "assigned_roles": ["manage-users", "view-users"],
    "service_account_user_id": "uuid-of-service-account"
  }
}
```

#### 3. **Realm Information** - `POST /admin/realms/info`

**Purpose**: Get comprehensive realm status and statistics

```bash
curl -X POST "https://your-auth-service.com/admin/realms/info" \
  -H "Content-Type: application/json" \
  -d '{
    "realm_name": "production-app",
    "admin_username": "keycloak-admin",
    "admin_password": "secure-admin-password"
  }'
```

**Response includes**:
```json
{
  "realm_summary": {
    "realm_name": "production-app",
    "enabled": true,
    "registration_allowed": true,
    "total_users": 1547,
    "total_clients": 3,
    "client_categories": {
      "authentication_clients": 2,
      "service_account_clients": 0,
      "public_clients": 1
    }
  }
}
```

#### 4. **Client Information** - `POST /admin/clients/info`

**Purpose**: Get detailed client configuration and credentials

```bash
curl -X POST "https://your-auth-service.com/admin/clients/info" \
  -H "Content-Type: application/json" \
  -d '{
    "realm_name": "production-app",
    "client_id": "mobile-app-client",
    "admin_username": "keycloak-admin",
    "admin_password": "secure-admin-password"
  }'
```

#### 5. **Realm Deletion** - `DELETE /admin/realms`

**Purpose**: Permanently delete a Keycloak realm and ALL its data

⚠️ **WARNING**: This operation is irreversible and will delete ALL data in the realm including users, clients, roles, and configurations.

```bash
curl -X DELETE "https://your-auth-service.com/admin/realms" \
  -H "Content-Type: application/json" \
  -d '{
    "realm_name": "test-realm",
    "admin_username": "keycloak-admin",
    "admin_password": "secure-admin-password"
  }'
```

**Response includes**:
```json
{
  "realm_name": "test-realm",
  "message": "Realm 'test-realm' deleted successfully",
  "deleted": true,
  "warning": "Realm and all its data have been permanently deleted",
  "affected_resources": [
    "All users in the realm",
    "All clients in the realm",
    "All roles and permissions",
    "All realm configurations"
  ]
}
```

#### 6. **Client Deletion** - `DELETE /admin/clients`

**Purpose**: Permanently delete a specific client from a realm

```bash
curl -X DELETE "https://your-auth-service.com/admin/clients" \
  -H "Content-Type: application/json" \
  -d '{
    "realm_name": "production-app",
    "client_id": "mobile-app-client",
    "admin_username": "keycloak-admin",
    "admin_password": "secure-admin-password"
  }'
```

**Response includes**:
```json
{
  "realm_name": "production-app",
  "client_id": "mobile-app-client",
  "message": "Client 'mobile-app-client' deleted successfully",
  "deleted": true,
  "warning": "Client has been permanently deleted",
  "affected_resources": [
    "Client configuration and settings",
    "Client roles and permissions",
    "Client secret (if any)",
    "All active sessions for this client"
  ],
  "next_steps": [
    "Update your applications to use a different client",
    "Users will need to re-authenticate with the new client configuration"
  ]
}
```

### 🔄 **Complete Workflow - Console-Free Setup**

#### Step 1: Create Production Realm

```bash
# Create realm for your application
curl -X POST "https://your-auth-service.com/admin/realms" \
  -H "Content-Type: application/json" \
  -d '{
    "realm_name": "mycompany-prod",
    "display_name": "MyCompany Production",
    "registration_allowed": true,
    "admin_username": "admin",
    "admin_password": "admin-password"
  }'
```

#### Step 2: Create Authentication Client

```bash
# Create client for your frontend application
curl -X POST "https://your-auth-service.com/admin/clients" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "mycompany-frontend",
    "realm_name": "mycompany-prod",
    "redirect_uris": ["https://myapp.com/*"],
    "web_origins": ["https://myapp.com"],
    "admin_username": "admin",
    "admin_password": "admin-password"
  }'

# Save the returned client_secret for your application
```

#### Step 3: Configure Your Application

Use the created realm and client in your application:

```javascript
// Frontend configuration
const keycloakConfig = {
  url: 'https://your-keycloak-domain.com',
  realm: 'mycompany-prod',
  clientId: 'mycompany-frontend',
  clientSecret: 'client-secret-from-step-2' // For server-side
};
```

#### Step 4: Test User Authentication

```bash
# Register a new user
curl -X POST "https://your-auth-service.com/auth/register" \
  -H "Content-Type: application/json" \
  -H "X-Client-Id: mycompany-frontend" \
  -H "X-Client-Secret: client-secret-from-step-2" \
  -H "X-Realm: mycompany-prod" \
  -d '{
    "username": "john.doe",
    "email": "john@mycompany.com",
    "password": "SecurePass123!",
    "firstName": "John",
    "lastName": "Doe"
  }'

# Login user
curl -X POST "https://your-auth-service.com/auth/login" \
  -H "Content-Type: application/json" \
  -H "X-Client-Id: mycompany-frontend" \
  -H "X-Client-Secret: client-secret-from-step-2" \
  -H "X-Realm: mycompany-prod" \
  -d '{
    "username": "john.doe",
    "password": "SecurePass123!"
  }'
```

### 🛡️ **Security Benefits of API-Only Management**

1. **No Console Access Required**: Complete Keycloak management through APIs
2. **Credential Security**: Admin credentials never stored in environment variables
3. **Audit Trail**: All administrative actions logged and traceable
4. **Least Privilege**: Created clients have minimal required permissions
5. **Automation Ready**: Perfect for CI/CD and infrastructure as code

## 🔧 **Service Account Permissions Setup**

🆕 **AUTOMATED SOLUTION AVAILABLE**: As of the latest update, when creating clients with `service_accounts_enabled=true`, the API **automatically assigns** the required `manage-users` and `view-users` roles. Manual setup is now **optional** for most use cases.

### 📖 **Understanding Service Account Permissions**

**What are Service Accounts?**
- Service accounts allow applications to authenticate and perform operations on behalf of the application itself
- When enabled, Keycloak creates a special user for the client that can be assigned roles
- **NEW**: Our API now automatically assigns required roles for user management

**Why This Enhancement Matters:**
- ✅ **Before**: Manual role assignment via Keycloak console required
- ✅ **Now**: Automatic role assignment during client creation
- ✅ **Benefit**: Immediate user management capabilities without console access

### 🚀 **Method 1: Automated Role Assignment (RECOMMENDED)**

**Step 1: Create Client with Automatic Role Assignment**
```bash
# Create client with service accounts enabled - roles assigned automatically
curl -X POST "http://YOUR-EC2-PUBLIC-IP:8000/admin/clients" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "petition-pro-client",
    "client_name": "Petition Pro Client with Auto-Roles",
    "realm_name": "petition-pro-realm",
    "redirect_uris": ["http://YOUR-EC2-PUBLIC-IP:3000/*"],
    "web_origins": ["http://YOUR-EC2-PUBLIC-IP:3000"],
    "service_accounts_enabled": true,
    "admin_username": "petiton_admin",
    "admin_password": "usa_ai_solution2025"
  }'
```

**Expected Response:**
```json
{
  "client_secret": {
    "value": "abc123-generated-secret-xyz789"
  },
  "role_assignment": {
    "service_account_enabled": true,
    "roles_assigned": true,
    "assigned_roles": ["manage-users", "view-users"],
    "service_account_user_id": "uuid-of-service-account"
  },
  "client_configuration": {
    "service_account_configuration": {
      "automatic_role_assignment": true,
      "role_assignment_status": "Success"
    }
  }
}
```

**Step 2: Immediate User Operations**
```bash
# User registration works immediately - no manual setup required
curl -X POST "http://YOUR-EC2-PUBLIC-IP:8000/auth/register" \
  -H "Content-Type: application/json" \
  -H "X-Client-Id: petition-pro-client" \
  -H "X-Client-Secret: abc123-generated-secret-xyz789" \
  -H "X-Realm: petition-pro-realm" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "TestPass123!",
    "firstName": "Test",
    "lastName": "User"
  }'
```

### 🔄 **Method 2: Manual Permission Setup (FALLBACK)**

**Use this method only if automatic role assignment fails or for troubleshooting purposes.**

**Step 1: Access Keycloak Admin Console**
```bash
# Access your Keycloak instance
URL: http://YOUR-EC2-PUBLIC-IP:8080
Username: petiton_admin
Password: usa_ai_solution2025
```

**Step 2: Navigate to Client Service Account**
1. Go to **Clients** in the left sidebar
2. Find and click on your client (e.g., `petition-pro-client`)
3. Click on the **Service Account Roles** tab

**Step 3: Assign Required Roles**
1. In the **Client Roles** dropdown, select `realm-management`
2. From **Available Roles**, move these to **Assigned Roles**:
   ```
   ✅ manage-users     # Required for user creation/modification
   ✅ view-users       # Required for user queries
   ✅ manage-clients   # Optional: for client management
   ✅ view-clients     # Optional: for client information
   ```
3. Click **Add selected** to assign the roles

**Step 4: Verify Permissions**
```bash
# Test user registration after role assignment
curl -X POST "http://YOUR-EC2-PUBLIC-IP:8000/auth/register" \
  -H "Content-Type: application/json" \
  -H "X-Client-Id: petition-pro-client" \
  -H "X-Client-Secret: your-client-secret" \
  -H "X-Realm: petition-pro-realm" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "TestPass123!",
    "firstName": "Test",
    "lastName": "User"
  }'
```

### 🚀 **Method 3: Legacy Manual API Setup (DEPRECATED)**

**⚠️ This method is now deprecated since automatic role assignment is available.**

**Step 1: Delete Existing Client (if needed)**
```bash
# Remove client with insufficient permissions
curl -X DELETE "http://YOUR-EC2-PUBLIC-IP:8000/admin/clients" \
  -H "Content-Type: application/json" \
  -d '{
    "realm_name": "petition-pro-realm",
    "client_id": "petition-pro-client",
    "admin_username": "petiton_admin",
    "admin_password": "usa_ai_solution2025"
  }'
```

**Step 2: Create Client with Service Accounts Enabled**
```bash
# Create new client with service account capabilities
curl -X POST "http://YOUR-EC2-PUBLIC-IP:8000/admin/clients" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "petition-pro-client",
    "client_name": "Petition Pro Client with Service Account",
    "realm_name": "petition-pro-realm",
    "redirect_uris": ["http://YOUR-EC2-PUBLIC-IP:3000/*"],
    "web_origins": ["http://YOUR-EC2-PUBLIC-IP:3000"],
    "service_accounts_enabled": true,
    "admin_username": "petiton_admin",
    "admin_password": "usa_ai_solution2025"
  }'
```

**Response Example:**
```json
{
  "client_secret": {
    "type": "secret",
    "value": "abc123-generated-secret-xyz789"
  },
  "client_configuration": {
    "features_enabled": {
      "user_login": true,
      "service_account": true
    }
  },
  "message": "Client 'petition-pro-client' created successfully"
}
```

**Step 3: Manual Role Assignment Still Required**
```bash
# Note: After API creation, you still need to manually assign roles via console
# This is because role assignment requires realm-management permissions
# Future enhancement: Add role assignment to the API
```

### ⚠️ **Important Notes About Service Account Permissions**

**🆕 Automatic Role Assignment (Current)**:
- ✅ `manage-users` and `view-users` roles automatically assigned during client creation
- ✅ Service account immediately ready for user management operations
- ✅ No manual console access required for basic setup
- ✅ Role assignment status included in API response

**Security Considerations:**
- `manage-users` role allows creating, updating, and deleting users
- `view-users` role allows querying user information
- Only assign minimum required permissions
- Service account credentials are tied to the client secret
- Automatic assignment only includes user management roles (not full realm-admin)

**Troubleshooting Common Issues:**
```bash
# Issue 1: "Role assignment failed" in API response
# Solution: Check admin credentials and ensure realm exists

# Issue 2: "Service account user not found"
# Solution: Verify service_accounts_enabled: true in request

# Issue 3: "realm-management client not found"
# Solution: Ensure realm is properly configured and accessible

# Issue 4: Legacy "HTTP 403 Forbidden" during user operations
# Solution: Use new API with service_accounts_enabled: true for automatic roles
```

**Fallback to Manual Setup:**
If automatic role assignment fails, the API response will include:
```json
{
  "role_assignment": {
    "roles_assigned": false,
    "role_assignment_error": "Detailed error message"
  }
}
```
In this case, use Method 2 (Manual Console Setup) above.

### 🔄 **Complete User Management Workflow**

**🆕 NEW AUTOMATED APPROACH (Recommended)**

**1. Setup (One-time) - Fully Automated**
```bash
# Create realm
curl -X POST "http://YOUR-EC2-PUBLIC-IP:8000/admin/realms" \
  -H "Content-Type: application/json" \
  -d '{
    "realm_name": "my-app-realm",
    "display_name": "My Application",
    "registration_allowed": true,
    "admin_username": "petiton_admin",
    "admin_password": "usa_ai_solution2025"
  }'

# Create client with automatic role assignment
curl -X POST "http://YOUR-EC2-PUBLIC-IP:8000/admin/clients" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "my-app-client",
    "realm_name": "my-app-realm",
    "service_accounts_enabled": true,
    "admin_username": "petiton_admin",
    "admin_password": "usa_ai_solution2025"
  }'

# ✅ Roles automatically assigned - no manual console access needed!
```

**2. User Operations (Runtime) - Immediate Use**
```bash
# Register new user - works immediately after client creation
curl -X POST "http://YOUR-EC2-PUBLIC-IP:8000/auth/register" \
  -H "Content-Type: application/json" \
  -H "X-Client-Id: my-app-client" \
  -H "X-Client-Secret: client-secret-from-setup" \
  -H "X-Realm: my-app-realm" \
  -d '{
    "username": "newuser",
    "email": "user@example.com",
    "password": "SecurePassword123!",
    "firstName": "John",
    "lastName": "Doe"
  }'

# Login user
curl -X POST "http://YOUR-EC2-PUBLIC-IP:8000/auth/login" \
  -H "Content-Type: application/json" \
  -H "X-Client-Id: my-app-client" \
  -H "X-Client-Secret: client-secret-from-setup" \
  -H "X-Realm: my-app-realm" \
  -d '{
    "username": "newuser",
    "password": "SecurePassword123!"
  }'
```

**📋 Legacy Manual Approach (Fallback Only)**

Use this only if automatic role assignment fails:

**1. Setup (One-time)**
```bash
# Create realm and client as above
# Then manually assign roles via Keycloak console (see Method 2 above)
```

### 📋 **Production Checklist**

- [ ] Create production realm with company-specific naming
- [ ] Create clients for each application with `service_accounts_enabled: true` for automatic role assignment
- [ ] Verify automatic role assignment succeeded in API response
- [ ] Configure appropriate redirect URIs for each environment
- [ ] Store client secrets securely (e.g., AWS Secrets Manager, Kubernetes secrets)
- [ ] Set up monitoring for realm and client health
- [ ] Document client credentials for development teams
- [ ] Rotate admin credentials regularly
- [ ] Monitor admin API usage for security auditing
- [ ] Test user registration/login immediately after client creation (should work without manual setup)

**🆕 Enhanced Production Benefits:**
- ✅ Zero manual console configuration required for user management
- ✅ Immediate service account functionality after client creation
- ✅ Automated role assignment eliminates human error
- ✅ Faster deployment and setup processes
- ✅ API-driven infrastructure suitable for CI/CD pipelines

For detailed API documentation and examples, see [ADMIN_APIS.md](./ADMIN_APIS.md).

## 📖 Complete Admin API Documentation

### 🔑 **Admin Privilege Model**

⚠️ **SECURITY NOTICE**: Admin credentials are no longer stored in environment variables for security. They must be provided with each admin API request.

- **Admin credentials are passed per-request** (not stored in environment)
- **Direct master realm access** for administrative operations
- **Secure credential handling** with no environment exposure
- **Complete console replacement** for realm and client management

### 🚀 **Available Admin API Endpoints**

#### 1. **Create Realm API** - `POST /admin/realms`

Creates a new Keycloak realm with sensible defaults for user authentication.

**Example Request**:
```bash
curl -X POST "http://localhost:8000/admin/realms" \
  -H "Content-Type: application/json" \
  -d '{
    "realm_name": "my-app-realm",
    "display_name": "My Application Realm",
    "enabled": true,
    "registration_allowed": true,
    "registration_email_as_username": true,
    "login_with_email_allowed": true,
    "duplicate_emails_allowed": false,
    "verify_email": false,
    "reset_password_allowed": true,
    "remember_me": true,
    "admin_username": "your-keycloak-admin",
    "admin_password": "your-keycloak-admin-password"
  }'
```

**Response Example**:
```json
{
  "realm_id": "...",
  "realm_info": { ... },
  "message": "Realm 'my-app-realm' created successfully",
  "realm_configuration": {
    "realm_name": "my-app-realm",
    "features_enabled": {
      "user_registration": true,
      "email_login": true,
      "password_reset": true,
      "remember_me": true
    },
    "security_settings": {
      "ssl_required": "external",
      "password_policy": "Strong password required (8+ chars, mixed case, digits)",
      "session_timeout": "30 minutes idle, 10 hours max"
    }
  }
}
```

#### 2. **Create Client API** - `POST /admin/clients`

Creates a new client configured for user authentication without admin capabilities.

**Example Request**:
```bash
curl -X POST "http://localhost:8000/admin/clients" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "my-app-client",
    "client_name": "My Application Client",
    "realm_name": "my-app-realm",
    "redirect_uris": ["http://localhost:3000/*", "http://localhost:3000/callback"],
    "web_origins": ["http://localhost:3000"],
    "admin_username": "your-keycloak-admin",
    "admin_password": "your-keycloak-admin-password"
  }'
```

**Response Example**:
```json
{
  "client_id": "...",
  "client_info": { ... },
  "client_secret": {
    "type": "secret",
    "value": "generated-client-secret"
  },
  "realm": "my-app-realm",
  "message": "Client 'my-app-client' created successfully",
  "client_configuration": {
    "client_id": "my-app-client",
    "realm": "my-app-realm",
    "features_enabled": {
      "user_login": true,
      "user_registration": false,
      "authorization_code_flow": true,
      "direct_grant_flow": true,
      "admin_access": false,
      "service_account": false
    },
    "security_features": {
      "confidential_client": true,
      "pkce_enabled": true,
      "implicit_flow_disabled": true,
      "client_secret_required": true
    }
  }
}
```

#### 3. **Get Realm Information API** - `POST /admin/realms/info`

Retrieves detailed information about a realm.

**Example Request**:
```bash
curl -X POST "http://localhost:8000/admin/realms/info" \
  -H "Content-Type: application/json" \
  -d '{
    "realm_name": "my-app-realm",
    "admin_username": "your-keycloak-admin",
    "admin_password": "your-keycloak-admin-password"
  }'
```

**Response Example**:
```json
{
  "realm_info": { ... },
  "clients": [ ... ],
  "users_count": 42,
  "realm_name": "my-app-realm",
  "realm_summary": {
    "realm_name": "my-app-realm",
    "enabled": true,
    "registration_allowed": true,
    "login_with_email": true,
    "total_users": 42,
    "total_clients": 5,
    "client_categories": {
      "authentication_clients": 3,
      "service_account_clients": 1,
      "public_clients": 1
    }
  }
}
```

#### 4. **Get Client Information API** - `POST /admin/clients/info`

Retrieves detailed information about a specific client.

**Example Request**:
```bash
curl -X POST "http://localhost:8000/admin/clients/info" \
  -H "Content-Type: application/json" \
  -d '{
    "realm_name": "my-app-realm",
    "client_id": "my-app-client",
    "admin_username": "your-keycloak-admin",
    "admin_password": "your-keycloak-admin-password"
  }'
```

**Response Example**:
```json
{
  "client_info": { ... },
  "client_secret": {
    "type": "secret",
    "value": "client-secret-value"
  },
  "client_roles": [ ... ],
  "realm_name": "my-app-realm",
  "client_id": "my-app-client",
  "client_summary": {
    "client_id": "my-app-client",
    "realm_name": "my-app-realm",
    "enabled": true,
    "capabilities": {
      "user_authentication": true,
      "direct_grant": true,
      "service_account": false,
      "authorization_services": false,
      "public_client": false,
      "bearer_only": false
    },
    "redirect_uris": ["http://localhost:3000/*"],
    "web_origins": ["http://localhost:3000"],
    "has_secret": true,
    "total_roles": 2
  }
}
```

### 🔄 **Using Created Clients for Authentication**

After creating a realm and client, you can use the existing authentication APIs:

#### User Login
```bash
curl -X POST "http://localhost:8000/auth/login" \
  -H "Content-Type: application/json" \
  -H "X-Client-Id: my-app-client" \
  -H "X-Client-Secret: generated-client-secret" \
  -H "X-Realm: my-app-realm" \
  -d '{
    "username": "user@example.com",
    "password": "userpassword"
  }'
```

#### User Registration
```bash
curl -X POST "http://localhost:8000/auth/register" \
  -H "Content-Type: application/json" \
  -H "X-Client-Id: my-app-client" \
  -H "X-Client-Secret: generated-client-secret" \
  -H "X-Realm: my-app-realm" \
  -d '{
    "username": "newuser",
    "email": "newuser@example.com",
    "password": "newpassword",
    "firstName": "New",
    "lastName": "User"
  }'
```

### 🔒 **Admin API Security Best Practices**

1. **Admin Credentials**: Never store admin credentials in environment variables or config files
2. **Secure Transmission**: Always use HTTPS in production
3. **Limited Access**: Restrict access to admin APIs to authorized personnel only
4. **Credential Rotation**: Regularly rotate Keycloak admin passwords
5. **Audit Logging**: Monitor admin API usage for security auditing

### 📋 **Common Admin Workflows**

#### Complete Setup Workflow
1. **Create Realm** → Get realm configuration
2. **Create Client** → Get client credentials (client_id, client_secret)
3. **Configure Frontend** → Use client credentials for authentication
4. **Test Authentication** → Verify login/registration works
5. **Monitor Usage** → Use info APIs to check realm/client status

#### Development vs Production
**Development**:
- Use local Keycloak instance
- Simple redirect URIs (localhost)
- Basic security settings

**Production**:
- Use managed Keycloak service
- HTTPS redirect URIs
- Enhanced security policies
- Proper SSL configuration

### ⚠️ **Error Handling**

All admin APIs return detailed error information:

```json
{
  "detail": {
    "error": "Realm already exists",
    "message": "Realm 'my-app-realm' already exists",
    "keycloak_error": "409 Conflict: realm already exists"
  }
}
```

Common HTTP status codes:
- `200`: Success
- `400`: Bad Request (invalid parameters)
- `401`: Unauthorized (invalid admin credentials)
- `404`: Not Found (realm/client doesn't exist)
- `409`: Conflict (resource already exists)
- `500`: Internal Server Error

## 📋 Implementation Summary

### 🆕 **New Features Added**

#### 1. **Realm Management API**
- **Endpoint**: `POST /admin/realms`
- **Purpose**: Create new Keycloak realms with default configurations
- **Features**: Automatic security settings, password policies, session management

#### 2. **Client Management API**
- **Endpoint**: `POST /admin/clients`  
- **Purpose**: Create clients configured for user authentication WITHOUT admin facilities
- **Features**: Confidential client, PKCE enabled, no service account, proper CORS settings

#### 3. **Realm Information API**
- **Endpoint**: `POST /admin/realms/info`
- **Purpose**: Retrieve detailed realm information including users, clients, settings
- **Features**: Comprehensive realm statistics and client categorization

#### 4. **Client Information API**
- **Endpoint**: `POST /admin/clients/info`
- **Purpose**: Get detailed client information including credentials and capabilities
- **Features**: Client secret retrieval, role information, capability analysis

#### 5. **Realm Deletion API**
- **Endpoint**: `DELETE /admin/realms`
- **Purpose**: Permanently delete Keycloak realms and all associated data
- **Features**: Comprehensive data cleanup, detailed warnings, affected resource listing

#### 6. **Client Deletion API**
- **Endpoint**: `DELETE /admin/clients`
- **Purpose**: Permanently delete clients from specific realms
- **Features**: Client cleanup, session invalidation, migration guidance

### 🔒 **Security Enhancements**

#### **Admin Credentials Removed from Environment**
- ❌ **Before**: Admin credentials stored in `.env`, `docker-compose.yml`
- ✅ **After**: Admin credentials passed per-request in API body
- **Benefit**: No risk of credential exposure in environment variables

#### **Enhanced Authentication Strategy**
- **Primary**: Service account authentication (for regular operations)
- **Fallback**: Direct admin authentication (only when needed)
- **Admin APIs**: Always use direct admin credentials (passed in request)

#### **Client Security Configuration**
- Created clients have **NO admin access** by default
- Service accounts **disabled** for authentication-only clients
- PKCE enabled for enhanced OAuth security
- Implicit flow disabled for security

### 📁 **Files Modified**

#### Core Application Files
1. **`app/core/keycloak.py`**
   - Added `_get_master_admin_client()` method
   - Added `create_realm()` method
   - Added `create_client()` method
   - Added `get_realm_info()` method
   - Added `get_client_info()` method

2. **`app/models/auth.py`**
   - Added `CreateRealmRequest` model
   - Added `CreateClientRequest` model
   - Added `RealmInfoRequest` model
   - Added `ClientInfoRequest` model

3. **`app/routes/admin.py`** (NEW FILE)
   - Complete admin API implementation
   - Comprehensive error handling
   - Detailed response formatting

4. **`server.py`**
   - Imported and registered admin router
   - Added admin routes to application

#### Configuration Files
1. **`.env`**
   - Removed `KEYCLOAK_ADMIN_USERNAME`
   - Removed `KEYCLOAK_ADMIN_PASSWORD`
   - Added security comments

2. **`app/core/config.py`**
   - Updated admin credential settings comments
   - Marked as deprecated for security

3. **`docker-compose.yml`**
   - Commented out admin credential environment variables
   - Added security notices

4. **`docker-compose.production.yml`**
   - Commented out admin credential environment variables
   - Enhanced security for production

### ✅ **Security Benefits Achieved**

1. **No Environment Exposure**: Admin credentials never stored in environment
2. **Per-Request Authentication**: Admin access only when explicitly provided
3. **Limited Client Privileges**: Created clients have no admin capabilities
4. **Audit Trail**: All admin operations logged with credentials context
5. **Principle of Least Privilege**: Clients get only necessary permissions

### 🔄 **Migration from Old System**

#### Before (Insecure)
```env
KEYCLOAK_ADMIN_USERNAME=admin
KEYCLOAK_ADMIN_PASSWORD=admin123
```

#### After (Secure)
```bash
# Admin credentials passed in API requests
{
  "admin_username": "admin",
  "admin_password": "admin123"
}
```

### 🎯 **Requirements Fulfilled**

✅ **Realm Creation API**: Creates realms with necessary configurations  
✅ **Client Creation API**: Creates clients for user login/registration without admin facilities  
✅ **Information Retrieval APIs**: Get realm and client information using admin credentials  
✅ **Security Optimization**: Admin credentials no longer exposed in environment variables  
✅ **Comprehensive Documentation**: Complete usage guide and examples provided

## Testing & Validation

### 🧪 **Automated Testing Suite**

Run the comprehensive test suite to verify all admin API functionality:

```bash
# 1. Update credentials in test file
nano test_admin_apis.py
# Change KEYCLOAK_ADMIN_USER and KEYCLOAK_ADMIN_PASSWORD

# 2. Run complete workflow test
python test_admin_apis.py
```

**Test Coverage**:
- ✅ Realm creation with security policies
- ✅ Client creation without admin privileges  
- ✅ Information retrieval APIs
- ✅ User registration and authentication flow
- ✅ Error handling and validation

### 🔍 **Manual API Validation**

#### Test 1: Service Health
```bash
curl https://your-auth-service.com/health
# Expected: 200 OK with Keycloak connectivity status
```

#### Test 2: Admin API Access
```bash
# Test realm creation
curl -X POST "https://your-auth-service.com/admin/realms" \
  -H "Content-Type: application/json" \
  -d '{"realm_name": "test-realm", "admin_username": "admin", "admin_password": "password"}'
# Expected: 200 OK with realm configuration details
```

#### Test 3: User Authentication Flow
```bash
# After creating realm and client, test user operations
curl -X POST "https://your-auth-service.com/auth/register" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "X-Realm: your-realm" \
  -d '{"username": "testuser", "email": "test@example.com", "password": "TestPass123!"}'
# Expected: 200 OK with user creation confirmation
```

## Architecture

The service is built with a modular architecture:
- `app/core/` - Core business logic and configuration
- `app/routes/` - API endpoints organized by domain
- `app/models/` - Pydantic request/response models
- `app/utils/` - Utility functions and helpers

The health check functionality is implemented in `app/core/keycloak.py` and integrated into the application lifecycle in `server.py`.

## Quick Reference

### 🐳 **Production Deployment Commands**
```bash
# Build and deploy with managed database
docker-compose -f docker-compose.production.yml --env-file .env.production up -d

# AWS deployment with AWS-specific configuration
docker-compose -f docker-compose.aws.yml --env-file .env.production.aws up -d

# Stop AWS deployment
docker-compose -f docker-compose.aws.yml --env-file .env.production.aws down

# Check service health
curl https://your-auth-service.com/health

# View service logs
docker-compose logs -f auth-service
```

### 🔑 **Essential Admin API Endpoints**
- **Create Realm**: `POST /admin/realms`
- **Create Client**: `POST /admin/clients`
- **Realm Info**: `POST /admin/realms/info`
- **Client Info**: `POST /admin/clients/info`
- **Delete Realm**: `DELETE /admin/realms` ⚠️
- **Delete Client**: `DELETE /admin/clients` ⚠️

### 🛡️ **Security Checklist**
- [ ] Admin credentials passed per-request (not in environment)
- [ ] Clients created without admin privileges
- [ ] HTTPS enabled for all production endpoints
- [ ] Client secrets stored securely
- [ ] Regular credential rotation implemented
- [ ] API access monitoring enabled

### 📚 **Documentation Sections**
- **API Documentation**: `/docs` (when service is running)
- **Admin API Examples**: See "Complete Admin API Documentation" section above
- **Implementation Details**: See "Implementation Summary" section above
- **Docker Setup**: [DOCKER.md](./DOCKER.md)