# Multi-Tenant Authentication Service - Docker Setup

This directory contains production-ready Docker configurations for the Multi-Tenant Authentication Service with Keycloak.

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Nginx Proxy   │────│  Auth Service    │────│   Keycloak      │
│   (Port 80/443) │    │   (Port 8000)    │    │  (Port 8080)    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                         │
                                                ┌─────────────────┐
                                                │  PostgreSQL DB  │
                                                │   (Managed)     │
                                                └─────────────────┘
```

## 📁 Files Overview

- **`Dockerfile`** - Multi-stage build for the FastAPI application
- **`docker-compose.yml`** - Development setup with local PostgreSQL
- **`docker-compose.production.yml`** - Production setup with managed database
- **`nginx.conf`** - Reverse proxy configuration with rate limiting
- **`.env.docker`** - Environment variables template

## 🚀 Quick Start

### Development Setup (with local PostgreSQL)

1. **Copy environment file:**
   ```bash
   cp .env.docker .env
   ```

2. **Edit `.env` file with your settings:**
   ```bash
   nano .env  # Update passwords and secrets
   ```

3. **Start all services:**
   ```bash
   docker-compose up -d
   ```

4. **Access the services:**
   - Auth Service: http://localhost:8000
   - API Docs: http://localhost:8000/docs
   - Keycloak Admin: http://localhost:8080 (admin/admin123)

### Production Setup (with managed database)

1. **Set up your managed database** (Render/AWS RDS/etc.)

2. **Configure environment variables:**
   ```bash
   export SECRET_KEY="your-super-secure-secret-key"
   export KEYCLOAK_ADMIN_PASSWORD="secure-admin-password"
   export KC_DB_URL="jdbc:postgresql://your-db-host:5432/keycloak?sslmode=require"
   export KC_DB_USERNAME="your-db-user"
   export KC_DB_PASSWORD="your-db-password"
   export KC_HOSTNAME="your-domain.com"
   ```

3. **Start production services:**
   ```bash
   docker-compose -f docker-compose.production.yml up -d
   ```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Application secret key | `change-this-in-production` |
| `KEYCLOAK_ADMIN_USER` | Keycloak admin username | `admin` |
| `KEYCLOAK_ADMIN_PASSWORD` | Keycloak admin password | `admin123` |
| `KC_DB_URL` | PostgreSQL connection URL | Local container |
| `KC_DB_USERNAME` | Database username | `keycloak` |
| `KC_DB_PASSWORD` | Database password | `keycloak123` |
| `KC_HOSTNAME` | Keycloak hostname | `localhost` |

### Database Configuration

#### For Render PostgreSQL:
```bash
KC_DB_URL="jdbc:postgresql://dpg-xxxxx-a.oregon-postgres.render.com:5432/your_db?sslmode=require"
KC_DB_USERNAME="your_user"
KC_DB_PASSWORD="your_password"
```

#### For AWS RDS:
```bash
KC_DB_URL="jdbc:postgresql://your-db.region.rds.amazonaws.com:5432/keycloak?sslmode=require"
KC_DB_USERNAME="your_user"
KC_DB_PASSWORD="your_password"
```

## 🔒 Security Features

### Network Security
- **Internal Communication**: Keycloak only accessible from auth-service
- **Rate Limiting**: Configured in Nginx
- **CORS Protection**: Configurable origins

### Container Security
- **Non-root User**: Application runs as non-root user
- **Security Headers**: Configured in Nginx
- **Health Checks**: All services have health monitoring

### Database Security
- **SSL Connections**: Required for managed databases
- **Environment Variables**: Sensitive data in env vars
- **Access Control**: Database isolated from external access

## 📊 Monitoring & Health Checks

### Health Endpoints
- **Auth Service**: `GET /health`
- **Keycloak Health**: `GET /health/keycloak`
- **Overall Status**: `GET /health` (includes Keycloak status)

### Container Health Checks
- **Auth Service**: HTTP health check every 30s
- **Keycloak**: HTTP connectivity check every 30s
- **PostgreSQL**: Database connection check every 30s

## 🚦 Deployment Commands

### Development
```bash
# Start services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down

# Rebuild and restart
docker-compose up -d --build
```

### Production
```bash
# Start with production config
docker-compose -f docker-compose.production.yml up -d

# Check status
docker-compose -f docker-compose.production.yml ps

# Update application only
docker-compose -f docker-compose.production.yml up -d --no-deps auth-service

# View application logs
docker-compose -f docker-compose.production.yml logs -f auth-service
```

### With Nginx (Production)
```bash
# Start with reverse proxy
docker-compose -f docker-compose.production.yml --profile production up -d

# SSL setup (after obtaining certificates)
mkdir ssl
# Copy your SSL certificates to ./ssl/
docker-compose -f docker-compose.production.yml restart nginx
```

## 🔍 Troubleshooting

### Common Issues

1. **Keycloak startup fails:**
   ```bash
   # Check database connectivity
   docker-compose logs keycloak
   
   # Verify database credentials
   echo $KC_DB_URL
   ```

2. **Auth service can't connect to Keycloak:**
   ```bash
   # Check network connectivity
   docker-compose exec auth-service curl http://keycloak:8080
   
   # Verify Keycloak is healthy
   docker-compose exec keycloak curl http://localhost:8080
   ```

3. **Database connection issues:**
   ```bash
   # Test database connection
   docker-compose exec keycloak pg_isready -h your-db-host -U your-user
   ```

### Logs and Debugging
```bash
# View all logs
docker-compose logs

# Follow specific service logs
docker-compose logs -f auth-service
docker-compose logs -f keycloak

# Check container status
docker-compose ps

# Execute commands in containers
docker-compose exec auth-service /bin/bash
docker-compose exec keycloak /bin/bash
```

## 🌐 Production Checklist

### Before Deployment
- [ ] Update all default passwords
- [ ] Configure proper domain names
- [ ] Set up SSL certificates
- [ ] Configure managed database
- [ ] Update CORS origins
- [ ] Set strong SECRET_KEY
- [ ] Review Nginx security headers
- [ ] Configure backup strategy

### After Deployment
- [ ] Test health endpoints
- [ ] Verify Keycloak admin access
- [ ] Test authentication flow
- [ ] Monitor logs for errors
- [ ] Set up monitoring/alerting
- [ ] Configure log aggregation

## 📈 Scaling

### Horizontal Scaling
```yaml
# In docker-compose.yml
auth-service:
  deploy:
    replicas: 3
```

### Load Balancing
- Configure Nginx upstream with multiple auth-service instances
- Use external load balancer for multiple Docker hosts

### Database Scaling
- Use managed database read replicas
- Configure connection pooling
- Monitor database performance

## 🔐 Backup Strategy

### Application Data
- Keycloak configuration: Stored in managed database
- Application logs: Configure log rotation
- SSL certificates: Backup from `./ssl/` directory

### Database Backup
- Use managed database backup features
- Set up automated daily backups
- Test restore procedures regularly
