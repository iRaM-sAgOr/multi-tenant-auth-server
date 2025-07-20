"""
Multi-Tenant FastAPI Authentication Service - Main Entry Point

REFACTORED ARCHITECTURE:
This main.py file now serves as the primary entry point and imports the 
modularized application from app.py. The code has been split into:

MODULES:
- app/models/ - Pydantic request/response models
- app/routes/ - API endpoint handlers organized by domain
- app/dependencies.py - FastAPI dependency functions
- app/exceptions.py - Global exception handlers
- app/app.py - Application factory and configuration
- app/core/ - Core business logic (config, keycloak client)

BENEFITS:
- Separation of concerns
- Better code organization
- Easier testing and maintenance
- Cleaner imports and dependencies
- Reusable components
"""

from server import app_server
from app.core.config import settings

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "server:app_server",  # Updated to point to the app factory
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level="info"
    )
