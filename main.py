#!/usr/bin/env python3
"""
Azure Permission Analyzer Web Application
In-house Custom Built Tool by Razvan Duda v1.1
FastAPI-based web interface for analyzing Azure permissions
"""

import asyncio
import json
import logging
import tempfile
from datetime import datetime
import json
from pathlib import Path
from typing import Dict, List, Optional
import os

from fastapi import FastAPI, Request, Form, File, UploadFile, HTTPException, BackgroundTasks, Depends
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, StreamingResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import uvicorn

# Import only non-Azure dependent modules at startup
from database import initialize_database, DatabaseConfig
from config import get_config

# Lazy loading for Azure-dependent modules
credential_manager = None
analysis_repo = None
credential_repo = None

def get_security_module():
    """Lazy load security module to avoid Azure imports at startup"""
    try:
        import security
        return security
    except (ImportError, ModuleNotFoundError):
        return None

def get_analysis_repo():
    """Get analysis repository with lazy initialization"""
    global analysis_repo
    if analysis_repo is None:
        try:
            from repositories import get_analysis_repository
            analysis_repo = get_analysis_repository(db_manager)
        except (ImportError, ModuleNotFoundError):
            return None
    return analysis_repo

def get_credential_repo():
    """Get credential repository with lazy initialization"""
    global credential_repo
    if credential_repo is None:
        try:
            from repositories import get_credential_repository
            credential_repo = get_credential_repository(db_manager)
        except (ImportError, ModuleNotFoundError):
            return None
    return credential_repo

def get_migrations_module():
    """Lazy load migrations module"""
    import migrations
    return migrations

# Setup logging
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Azure Permission Analyzer - In-house Custom Built Tool",
    description="Web-based Azure Permission Analyzer for System Administrators and Cloud Engineers\nDeveloped by Razvan Duda",
    version="1.1"
)

# Startup and shutdown event handlers
@app.on_event("startup")
async def startup_event():
    """Configure logging and exception handling on startup"""
    logger.info("Azure Permission Analyzer starting up...")
    
    # Load configuration
    config = get_config()
    logger.info(f"Configuration loaded: debug={config.debug}, port={config.port}")
    
    # Initialize database with configuration
    try:
        db_stats = db_manager.get_database_stats()
        logger.info(f"Database initialized: {db_stats}")
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
        raise

@app.on_event("shutdown")
async def shutdown_event():
    """Clean shutdown handler"""
    logger.info("Azure Permission Analyzer shutting down...")
    
    # Cancel any remaining background tasks
    try:
        tasks = [task for task in asyncio.all_tasks() if not task.done()]
        if tasks:
            logger.info(f"Cancelling {len(tasks)} remaining tasks...")
            for task in tasks:
                if not task.cancelled():
                    task.cancel()
    except Exception as e:
        logger.warning(f"Error during shutdown cleanup: {e}")

# Setup templates and static files
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Initialize database and repositories
db_manager = initialize_database()
def get_credential_manager():
    """Get credential manager with lazy initialization"""
    global credential_manager
    if credential_manager is None:
        security = get_security_module()
        if security is None:
            return None
        repo = get_credential_repo()
        if repo is None:
            return None
        credential_manager = security.SecureCredentialManager(repo)
    return credential_manager

# Session storage (still in-memory for now)
active_sessions: Dict[str, Dict] = {}

# Security models
class CredentialRequest(BaseModel):
    master_password: str
    tenant_id: str
    client_id: str
    client_secret: str

class TestConnectionRequest(BaseModel):
    master_password: str

class PasswordRequest(BaseModel):
    master_password: str

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Home page with analysis form"""
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/config", response_class=HTMLResponse)
async def config_page(request: Request):
    """Secure configuration page"""
    return templates.TemplateResponse("config.html", {"request": request})

@app.get("/results", response_class=HTMLResponse)
async def results_page(request: Request):
    """Results page showing completed analyses"""
    # Get analyses directly from database to avoid Azure import issues
    try:
        query = "SELECT analysis_id, analysis_data FROM analysis_results ORDER BY created_at DESC LIMIT 50"
        results = db_manager.execute_query(query)
        
        # Handle empty database case
        analyses_with_keys = []
        if results:
            # Create a list of analyses with their actual analysis IDs
            for row in results:
                try:
                    analysis_id = row[0]
                    analysis_data = json.loads(row[1])
                    # Use the actual analysis_id from database as the analysis_key
                    analysis_data['analysis_key'] = analysis_id

                    # Parse analyzed_at string to datetime object for template rendering
                    if 'analyzed_at' in analysis_data and isinstance(analysis_data['analyzed_at'], str):
                        analysis_data['analyzed_at'] = datetime.fromisoformat(analysis_data['analyzed_at'])

                    analyses_with_keys.append(analysis_data)
                except Exception as e:
                    logger.warning(f"Failed to parse analysis data: {e}")
                    continue
            
            logger.info(f"Loaded {len(analyses_with_keys)} analysis results for results page")
        else:
            logger.info("No analysis results found in database")

        return templates.TemplateResponse("results.html", {
            "request": request,
            "analyses": analyses_with_keys
        })
        
    except Exception as e:
        logger.error(f"Failed to load results page: {e}")
        # Return empty results instead of error to show proper UI
        return templates.TemplateResponse("results.html", {
            "request": request,
            "analyses": []
        })


@app.post("/analyze")
async def analyze_permissions(
    background_tasks: BackgroundTasks,
    subscription_id: str = Form(...),
    user_id: Optional[str] = Form(None),
    security_group_id: Optional[str] = Form(None),
    user_list_file: Optional[UploadFile] = File(None),
    master_password: str = Form(...),
    generate_diagram: bool = Form(False)
):
    """Start permission analysis"""

    # Validate input
    if not user_id and not security_group_id and not user_list_file:
        raise HTTPException(status_code=400, detail="Must provide either user_id, security_group_id, or user_list_file")

    # Get user IDs
    user_ids = []
    if user_id:
        user_ids = [user_id.strip()]
    elif security_group_id:
        # Security group ID will be resolved to user IDs in the background task
        user_ids = [f"GROUP:{security_group_id.strip()}"]
    elif user_list_file:
        content = await user_list_file.read()
        raw_user_ids = [line.strip() for line in content.decode().split('\n') if line.strip()]
        
        # Deduplicate and validate user IDs from file
        before_dedup = len(raw_user_ids)
        user_ids = list(set(raw_user_ids))  # Remove duplicates
        after_dedup = len(user_ids)
        
        if before_dedup > after_dedup:
            logger.info(f"Removed {before_dedup - after_dedup} duplicate user ID(s) from uploaded file. "
                       f"Processing {after_dedup} unique users instead of {before_dedup}")
        
        # Validate user ID format (basic validation)
        valid_user_ids = []
        invalid_count = 0
        for uid in user_ids:
            if uid and len(uid) > 0 and not uid.isspace():
                # Basic validation - not empty or just whitespace
                valid_user_ids.append(uid)
            else:
                invalid_count += 1
        
        if invalid_count > 0:
            logger.warning(f"Filtered out {invalid_count} invalid/empty user ID(s) from file")
        
        user_ids = valid_user_ids

    if not user_ids:
        raise HTTPException(status_code=400, detail="No valid user IDs or security group ID provided")

    # Create analysis ID
    analysis_id = f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    # Initialize status in database
    status_data = {
        "status": "running",
        "total_users": len(user_ids),
        "completed_users": 0,
        "current_user": "",
        "started_at": datetime.now(),
        "error": None
    }
    get_analysis_repo().save_analysis_status(analysis_id, status_data)

    # Validate that encrypted credentials exist
    if not get_credential_manager().credentials_exist():
        raise HTTPException(status_code=400, detail="No encrypted service principal credentials found. Please configure credentials first.")

    # Start background analysis
    background_tasks.add_task(
        run_analysis,
        analysis_id,
        subscription_id,
        user_ids,
        master_password,
        generate_diagram
    )

    return JSONResponse({
        "analysis_id": analysis_id,
        "status": "started",
        "total_users": len(user_ids)
    })

@app.get("/status/{analysis_id}")
async def get_analysis_status(analysis_id: str):
    """Get analysis status"""
    status_data = get_analysis_repo().get_analysis_status(analysis_id)
    if not status_data:
        raise HTTPException(status_code=404, detail="Analysis not found")

    # Convert datetime objects to ISO format strings for JSON serialization
    for key in ['started_at', 'updated_at', 'completed_at']:
        if key in status_data and status_data[key]:
            if hasattr(status_data[key], 'isoformat'):
                status_data[key] = status_data[key].isoformat()

    return JSONResponse(status_data)

def serialize_datetime(obj):
    """JSON serializer function that handles datetime objects"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")

@app.get("/result/{analysis_id}")
async def get_analysis_result(analysis_id: str):
    """Get analysis result"""
    result = get_analysis_repo().get_analysis_result_raw(analysis_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis result not found")

    # Result is already a dict from the repository
    return JSONResponse(content=result)

@app.get("/download/{analysis_id}/{format}")
async def download_result(analysis_id: str, format: str):
    """Download analysis result in JSON format"""
    from permissions import OutputFormatter

    # Only support JSON format
    if format != "json":
        raise HTTPException(status_code=400, detail="Only JSON format is supported")

    result = get_analysis_repo().get_analysis_result(analysis_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis result not found")

    # Create temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp_file:
        tmp_path = Path(tmp_file.name)

    try:
        OutputFormatter.to_json(result, tmp_path)
        filename = f"permissions_{result.user_principal_name}_{analysis_id}.json"

        return FileResponse(
            path=tmp_path,
            media_type="application/json",
            filename=filename
        )

    except Exception as e:
        # Clean up temp file on error
        if tmp_path.exists():
            tmp_path.unlink()
        raise HTTPException(status_code=500, detail=f"Error generating file: {str(e)}")

@app.get("/diagram/{analysis_id}")
async def get_diagram(analysis_id: str):
    """Get Mermaid diagram for analysis"""
    from permissions import OutputFormatter
    
    result = get_analysis_repo().get_analysis_result(analysis_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis result not found")

    try:
        mermaid_code = await OutputFormatter.generate_mermaid_diagram(result)
        return JSONResponse({
            "mermaid_code": mermaid_code,
            "user_name": result.display_name,
            "user_principal_name": result.user_principal_name
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating diagram: {str(e)}")

@app.delete("/result/{analysis_id}")
async def delete_result(analysis_id: str):
    """Delete analysis result"""
    success = get_analysis_repo().delete_analysis_result(analysis_id)
    if success:
        return JSONResponse({"status": "deleted"})
    else:
        raise HTTPException(status_code=404, detail="Analysis not found")

@app.post("/api/results/remove-duplicates")
async def remove_duplicate_results():
    """Remove duplicate user analyses, keeping only the most recent scan for each user"""
    try:
        repo = get_analysis_repo()

        # Find duplicates - keep most recent scan per user_id
        query = """
            WITH RankedResults AS (
                SELECT
                    analysis_id,
                    user_id,
                    created_at,
                    ROW_NUMBER() OVER (
                        PARTITION BY user_id
                        ORDER BY created_at DESC
                    ) as rn
                FROM analysis_results
            )
            SELECT analysis_id
            FROM RankedResults
            WHERE rn > 1
        """

        duplicates = db_manager.execute_query(query)

        if not duplicates:
            return JSONResponse({
                "status": "success",
                "message": "No duplicates found",
                "deleted_count": 0
            })

        # Delete duplicates
        deleted_count = 0
        for (analysis_id,) in duplicates:
            if repo.delete_analysis_result(analysis_id):
                deleted_count += 1

        return JSONResponse({
            "status": "success",
            "message": f"Removed {deleted_count} duplicate analyses",
            "deleted_count": deleted_count
        })

    except Exception as e:
        logger.error(f"Error removing duplicates: {e}")
        raise HTTPException(status_code=500, detail=f"Error removing duplicates: {str(e)}")

@app.get("/api/report/generate")
async def generate_comprehensive_report(organization_name: str = "Organization"):
    """Generate comprehensive HTML report for all analyzed users"""
    try:
        from permissions import OutputFormatter
        import tempfile
        import os
        from pathlib import Path
        
        # Get all analysis results from database
        analysis_repo = get_analysis_repo()
        analyses = analysis_repo.get_all_analysis_results()
        
        if not analyses:
            raise HTTPException(status_code=404, detail="No analysis results found")
        
        # Create temporary file for the HTML report
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.html', prefix='azure_permissions_report_') as tmp_file:
            tmp_path = Path(tmp_file.name)
        
        try:
            # Generate the HTML report
            OutputFormatter.to_html_report(analyses, tmp_path, organization_name)
            
            # Create filename with timestamp
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"azure_permissions_report_{organization_name}_{timestamp}.html"
            
            return FileResponse(
                path=tmp_path,
                media_type="text/html",
                filename=filename,
                headers={"Content-Disposition": f"attachment; filename={filename}"}
            )
            
        except Exception as e:
            # Clean up temp file on error
            if tmp_path.exists():
                os.unlink(tmp_path)
            raise HTTPException(status_code=500, detail=f"Error generating report: {str(e)}")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating comprehensive report: {str(e)}")

# Secure credential management endpoints
@app.get("/api/credentials/status")
async def get_credential_status():
    """Get credential configuration status"""
    try:
        info = get_credential_manager().get_credential_info()
        return JSONResponse({
            "exists": info is not None,
            **(info or {})
        })
    except Exception as e:
        return JSONResponse({
            "exists": False,
            "error": str(e)
        })

@app.post("/api/credentials/store")
async def store_credentials(
    master_password: str = Form(...),
    tenant_id: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    organization_name: str = Form(...)
):
    """Store encrypted Azure credentials"""
    try:
        # Validate credential format
        validation_errors = get_credential_manager().validate_credentials_format(
            tenant_id, client_id, client_secret
        )

        if validation_errors:
            raise HTTPException(status_code=400, detail=validation_errors)

        # Store credentials with encryption
        success = get_credential_manager().store_credentials(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            organization_name=organization_name,
            master_password=master_password
        )

        if success:
            return JSONResponse({
                "status": "success",
                "message": "Credentials encrypted and stored successfully"
            })
        else:
            raise HTTPException(status_code=500, detail="Failed to store credentials")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error storing credentials: {str(e)}")

@app.post("/api/credentials/test")
async def test_connection(request: TestConnectionRequest):
    """Test Azure connection with stored credentials"""
    from permissions import AzureAuthManager
    
    try:
        # Retrieve and decrypt credentials
        credentials = get_credential_manager().retrieve_credentials(request.master_password)

        if not credentials:
            raise HTTPException(status_code=401, detail="Invalid master password or no credentials found")

        # Test Azure connection
        auth_manager = AzureAuthManager(
            tenant_id=credentials.tenant_id,
            client_id=credentials.client_id,
            client_secret=credentials.client_secret
        )

        # Try to get a token to validate credentials
        try:
            management_token = auth_manager.get_token("https://management.azure.com/.default")
            graph_token = auth_manager.get_token("https://graph.microsoft.com/.default")

            return JSONResponse({
                "status": "success",
                "message": "Connection successful",
                "details": {
                    "management_api": "accessible",
                    "graph_api": "accessible",
                    "credentials_valid": True
                }
            })

        except Exception as auth_error:
            raise HTTPException(
                status_code=401,
                detail=f"Authentication failed: {str(auth_error)}"
            )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error testing connection: {str(e)}")

@app.delete("/api/credentials/delete")
async def delete_credentials():
    """Delete stored credentials"""
    try:
        success = get_credential_manager().delete_credentials()

        if success:
            return JSONResponse({
                "status": "success",
                "message": "Credentials deleted successfully"
            })
        else:
            raise HTTPException(status_code=500, detail="Failed to delete credentials")

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deleting credentials: {str(e)}")

@app.post("/api/demo/load")
async def load_demo_data_endpoint():
    """Load comprehensive Contoso demo data for testing and demonstration"""
    try:
        # Generate demo data without Azure dependencies using JSON approach
        from demo_data import create_demo_data_json
        demo_data = create_demo_data_json()
        
        # Save demo data to database
        demo_ids = []
        for analysis_id, analysis_data in demo_data.items():
            try:
                query = """
                    INSERT INTO analysis_results (
                        analysis_id, user_id, user_principal_name, display_name,
                        tenant_id, tenant_name, subscription_id, subscription_name,
                        organization_name, analysis_data, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (analysis_id) DO UPDATE SET
                        user_id = EXCLUDED.user_id,
                        user_principal_name = EXCLUDED.user_principal_name,
                        display_name = EXCLUDED.display_name,
                        tenant_id = EXCLUDED.tenant_id,
                        tenant_name = EXCLUDED.tenant_name,
                        subscription_id = EXCLUDED.subscription_id,
                        subscription_name = EXCLUDED.subscription_name,
                        organization_name = EXCLUDED.organization_name,
                        analysis_data = EXCLUDED.analysis_data,
                        created_at = EXCLUDED.created_at,
                        updated_at = EXCLUDED.updated_at
                """
                
                parameters = (
                    analysis_id,
                    analysis_data["user_id"],
                    analysis_data["user_principal_name"],
                    analysis_data["display_name"],
                    analysis_data["tenant_id"],
                    analysis_data["tenant_name"],
                    analysis_data["subscription_id"],
                    analysis_data["subscription_name"],
                    analysis_data["organization_name"],
                    json.dumps(analysis_data),
                    datetime.utcnow(),
                    datetime.utcnow()
                )
                
                db_manager.execute_update(query, parameters)
                
                # Also create analysis status
                status_query = """
                    INSERT INTO analysis_status (
                        analysis_id, status, current_user, completed_users, total_users,
                        error_message, started_at, updated_at, completed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (analysis_id) DO UPDATE SET
                        status = EXCLUDED.status,
                        current_user = EXCLUDED.current_user,
                        completed_users = EXCLUDED.completed_users,
                        total_users = EXCLUDED.total_users,
                        error_message = EXCLUDED.error_message,
                        started_at = EXCLUDED.started_at,
                        updated_at = EXCLUDED.updated_at,
                        completed_at = EXCLUDED.completed_at
                """
                
                analyzed_at = datetime.fromisoformat(analysis_data["analyzed_at"])
                status_params = (
                    analysis_id,
                    "completed",
                    "",
                    1,
                    1,
                    None,
                    analyzed_at,
                    datetime.utcnow(),
                    analyzed_at
                )
                
                db_manager.execute_update(status_query, status_params)
                demo_ids.append(analysis_id)
                
            except Exception as e:
                logger.warning(f"Failed to save demo record {analysis_id}: {e}")
                continue
        
        return JSONResponse({
            "status": "success", 
            "message": f"Loaded {len(demo_ids)} comprehensive Contoso demo analysis results",
            "demo_ids": demo_ids,
            "organization": "Contoso Corporation",
            "users_generated": len(demo_data)
        })
        
    except Exception as e:
        logger.error(f"Error loading demo data: {e}")
        return JSONResponse({
            "status": "error",
            "message": f"Failed to load demo data: {str(e)}"
        }, status_code=500)

@app.delete("/api/demo/clear")
async def clear_demo_data():
    """Clear all analysis results including Contoso demo data"""
    try:
        # Get count before clearing using direct database access
        db_stats = db_manager.get_database_stats()
        count = db_stats.get('analysis_results_count', 0)
        
        # Clear all data using direct database operations
        with db_manager.get_connection() as conn:
            conn.execute("DELETE FROM analysis_results")
            conn.execute("DELETE FROM analysis_status")
        
        return JSONResponse({
            "status": "success",
            "message": f"Cleared {count} analysis results"
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error clearing data: {str(e)}")

@app.get("/health")
async def health_check(request: Request):
    """Health check endpoint with UI template"""
    
    # Get database statistics without Azure dependencies
    db_stats = db_manager.get_database_stats()
    
    health_data = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "active_analyses": 0,  # Simplified for demo mode
        "total_results": db_stats.get('analysis_results_count', 0),
        "credentials_configured": False,  # Simplified for demo mode
        "database_size_mb": db_stats.get('database_size_mb', 0),
        "total_status_records": db_stats.get('analysis_status_count', 0)
    }
    
    # Check if request wants JSON (for API calls)
    if request.headers.get("accept") == "application/json":
        return JSONResponse(health_data)
    
    # Return HTML template by default
    return templates.TemplateResponse("health.html", {
        "request": request,
        "health_data": health_data
    })

@app.get("/api/database/status")
async def get_database_status():
    """Get comprehensive database status information"""
    try:
        migrations = get_migrations_module()
        status = migrations.get_database_status()
        return JSONResponse(status)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving database status: {str(e)}")

@app.post("/api/database/backup")
async def create_database_backup(background_tasks: BackgroundTasks):
    """Create a database backup"""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        config = get_config()
        backup_dir = Path(config.database.backup_directory)
        backup_dir.mkdir(parents=True, exist_ok=True)  # Create backup directory lazily
        backup_path = str(backup_dir / f"azure_analyzer_backup_{timestamp}")
        
        # Run backup in background
        migrations = get_migrations_module()
        background_tasks.add_task(migrations.backup_database, backup_path)
        
        return JSONResponse({
            "status": "backup_started",
            "backup_path": backup_path,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error starting backup: {str(e)}")

@app.post("/api/database/cleanup")
async def cleanup_database(
    background_tasks: BackgroundTasks,
    days_to_keep: int = 30
):
    """Clean up old analysis data"""
    try:
        # Run cleanup in background
        migrations = get_migrations_module()
        background_tasks.add_task(migrations.cleanup_old_data, days_to_keep)
        
        return JSONResponse({
            "status": "cleanup_started", 
            "days_to_keep": days_to_keep,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error starting cleanup: {str(e)}")

@app.post("/api/database/optimize")
async def optimize_database_endpoint(background_tasks: BackgroundTasks):
    """Optimize database performance"""
    try:
        # Run optimization in background
        migrations = get_migrations_module()
        background_tasks.add_task(migrations.optimize_database)
        
        return JSONResponse({
            "status": "optimization_started",
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error starting optimization: {str(e)}")

@app.get("/api/config")
async def get_application_config():
    """Get current application configuration (non-sensitive parts only)"""
    try:
        config = get_config()
        
        # Return non-sensitive configuration
        return JSONResponse({
            "database": {
                "connection_timeout": config.database.connection_timeout,
                "max_connections": config.database.max_connections,
                "enable_wal": config.database.enable_wal,
                "auto_backup_enabled": config.database.auto_backup_enabled,
                "auto_backup_interval_hours": config.database.auto_backup_interval_hours,
                "cleanup_enabled": config.database.cleanup_enabled,
                "cleanup_interval_days": config.database.cleanup_interval_days,
                "data_retention_days": config.database.data_retention_days
            },
            "application": {
                "debug": config.debug,
                "host": config.host,
                "port": config.port,
                "workers": config.workers,
                "log_level": config.log_level,
                "max_concurrent_analyses": config.max_concurrent_analyses,
                "analysis_timeout_minutes": config.analysis_timeout_minutes
            },
            "security": {
                "credential_expiry_hours": config.security.credential_expiry_hours,
                "session_timeout_hours": config.security.session_timeout_hours,
                "max_login_attempts": config.security.max_login_attempts,
                "lockout_duration_minutes": config.security.lockout_duration_minutes
            }
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving configuration: {str(e)}")

async def run_analysis(
    analysis_id: str,
    subscription_id: str,
    user_ids: List[str],
    master_password: str,
    generate_diagram: bool
):
    """Run the actual analysis in background"""
    from permissions import AzureAuthManager, AzurePermissionAnalyzer
    
    try:
        # Initialize authentication using only encrypted service principal credentials
        stored_credentials = get_credential_manager().retrieve_credentials(master_password)
        if not stored_credentials:
            raise ValueError("Invalid master password or encrypted service principal credentials not found")

        auth_manager = AzureAuthManager(
            tenant_id=stored_credentials.tenant_id,
            client_id=stored_credentials.client_id,
            client_secret=stored_credentials.client_secret
        )

        # Fetch subscription name from Azure
        subscription_name = subscription_id  # Default to ID if name fetch fails
        try:
            from azure.identity import ClientSecretCredential
            from azure.mgmt.resource.subscriptions import SubscriptionClient

            credential = ClientSecretCredential(
                tenant_id=stored_credentials.tenant_id,
                client_id=stored_credentials.client_id,
                client_secret=stored_credentials.client_secret
            )

            subscription_client = SubscriptionClient(credential)
            subscription = subscription_client.subscriptions.get(subscription_id)
            subscription_name = subscription.display_name
            logger.info(f"Fetched subscription name: {subscription_name} for ID: {subscription_id}")
        except Exception as e:
            logger.warning(f"Failed to fetch subscription name for ID {subscription_id}: {e}")
            subscription_name = subscription_id

        # Update analysis status with subscription info
        status_data = get_analysis_repo().get_analysis_status(analysis_id)
        if status_data:
            status_data["subscription_name"] = subscription_name
            status_data["subscription_id"] = subscription_id
            get_analysis_repo().save_analysis_status(analysis_id, status_data)

        async with AzurePermissionAnalyzer(subscription_id, auth_manager, subscription_name, stored_credentials.organization_name) as analyzer:
            # Resolve group members if needed
            actual_user_ids_set = set()  # Use set for automatic deduplication
            initial_user_count = len(user_ids)
            
            for user_id in user_ids:
                if user_id.startswith("GROUP:"):
                    group_id = user_id[6:]  # Remove "GROUP:" prefix
                    try:
                        # Update status to show group resolution
                        status_data = get_analysis_repo().get_analysis_status(analysis_id)
                        if status_data:
                            status_data["current_user"] = f"Resolving group {group_id}..."
                            status_data["completed_users"] = len(actual_user_ids_set)
                            get_analysis_repo().save_analysis_status(analysis_id, status_data)
                        
                        group_members = await analyzer._get_group_members(group_id)
                        # Use set update to add all members while preventing duplicates
                        before_add = len(actual_user_ids_set)
                        actual_user_ids_set.update(group_members)
                        after_add = len(actual_user_ids_set)
                        new_unique_members = after_add - before_add
                        
                        logger.info(f"Resolved group {group_id} to {len(group_members)} users "
                                   f"({new_unique_members} new unique users added)")
                    except Exception as e:
                        logger.error(f"Error resolving group {group_id}: {e}")
                        continue
                else:
                    actual_user_ids_set.add(user_id)
            
            # Convert set to list for processing (deduplication already done by set)
            actual_user_ids = list(actual_user_ids_set)
            
            # Log final user count
            logger.info(f"Final user list contains {len(actual_user_ids)} unique users for analysis")
            
            # Update total count after group resolution and deduplication
            total_users = len(actual_user_ids)
            status_data = get_analysis_repo().get_analysis_status(analysis_id)
            if status_data:
                status_data["total_users"] = total_users
                get_analysis_repo().save_analysis_status(analysis_id, status_data)
            
            for i, user_id in enumerate(actual_user_ids):
                # Update status
                status_data = get_analysis_repo().get_analysis_status(analysis_id)
                if status_data:
                    status_data["current_user"] = user_id
                    status_data["completed_users"] = i
                    get_analysis_repo().save_analysis_status(analysis_id, status_data)

                try:
                    # Analyze user
                    result = await analyzer.analyze_user_permissions(user_id)

                    # Store result in database
                    if total_users == 1:
                        # For single user, use the analysis_id
                        success = get_analysis_repo().save_analysis_result(result)
                    else:
                        # For multiple users, save each result individually
                        success = get_analysis_repo().save_analysis_result(result)

                except Exception as e:
                    # Log error but continue with other users
                    print(f"Error analyzing user {user_id}: {e}")
                    continue

        # Update final status
        status_data = get_analysis_repo().get_analysis_status(analysis_id)
        if status_data:
            status_data["status"] = "completed"
            status_data["completed_users"] = len(actual_user_ids)
            status_data["current_user"] = ""
            status_data["completed_at"] = datetime.now()
            get_analysis_repo().save_analysis_status(analysis_id, status_data)

    except Exception as e:
        # Update error status
        status_data = get_analysis_repo().get_analysis_status(analysis_id)
        if status_data:
            status_data["status"] = "error"
            status_data["error"] = str(e)
            status_data["completed_at"] = datetime.now()
            get_analysis_repo().save_analysis_status(analysis_id, status_data)

if __name__ == "__main__":
    # Only create essential directories that must exist at startup
    Path("templates").mkdir(exist_ok=True)
    Path("static").mkdir(exist_ok=True)

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
