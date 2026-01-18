#!/usr/bin/env python3
"""
Configuration module for Azure Permission Analyzer
Provides centralized configuration management for database and application settings
"""

import os
from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field

class DatabaseConfig(BaseModel):
    """Database configuration settings"""
    database_path: str = Field(default="./data/azure_analyzer.db", description="Path to DuckDB database file")
    connection_timeout: int = Field(default=60, description="Database connection timeout in seconds")
    max_connections: int = Field(default=10, description="Maximum number of database connections")
    enable_wal: bool = Field(default=True, description="Enable Write-Ahead Logging for better concurrency")
    backup_directory: str = Field(default="./backups", description="Directory for database backups")
    auto_backup_enabled: bool = Field(default=True, description="Enable automatic database backups")
    auto_backup_interval_hours: int = Field(default=24, description="Backup interval in hours")
    cleanup_enabled: bool = Field(default=True, description="Enable automatic cleanup of old data")
    cleanup_interval_days: int = Field(default=7, description="Cleanup interval in days")
    data_retention_days: int = Field(default=30, description="Number of days to retain analysis data")
    
class SecurityConfig(BaseModel):
    """Security configuration settings"""
    credential_expiry_hours: int = Field(default=24, description="Credential expiry time in hours")
    session_timeout_hours: int = Field(default=8, description="Session timeout in hours")
    max_login_attempts: int = Field(default=5, description="Maximum login attempts before lockout")
    lockout_duration_minutes: int = Field(default=15, description="Account lockout duration in minutes")
    
class ApplicationConfig(BaseModel):
    """Main application configuration"""
    debug: bool = Field(default=False, description="Enable debug mode")
    host: str = Field(default="0.0.0.0", description="Host to bind the application to")
    port: int = Field(default=8000, description="Port to run the application on")
    workers: int = Field(default=1, description="Number of worker processes")
    log_level: str = Field(default="INFO", description="Logging level")
    max_concurrent_analyses: int = Field(default=5, description="Maximum concurrent analysis operations")
    analysis_timeout_minutes: int = Field(default=60, description="Analysis timeout in minutes")
    
    # Database configuration
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    
    # Security configuration  
    security: SecurityConfig = Field(default_factory=SecurityConfig)

def load_config_from_env() -> ApplicationConfig:
    """Load configuration from environment variables"""
    
    # Database configuration
    db_config = DatabaseConfig(
        database_path=os.getenv("DB_PATH", "./data/azure_analyzer.db"),
        connection_timeout=int(os.getenv("DB_CONNECTION_TIMEOUT", "60")),
        max_connections=int(os.getenv("DB_MAX_CONNECTIONS", "10")),
        enable_wal=os.getenv("DB_ENABLE_WAL", "true").lower() == "true",
        backup_directory=os.getenv("DB_BACKUP_DIR", "./backups"),
        auto_backup_enabled=os.getenv("DB_AUTO_BACKUP", "true").lower() == "true",
        auto_backup_interval_hours=int(os.getenv("DB_BACKUP_INTERVAL_HOURS", "24")),
        cleanup_enabled=os.getenv("DB_CLEANUP_ENABLED", "true").lower() == "true",
        cleanup_interval_days=int(os.getenv("DB_CLEANUP_INTERVAL_DAYS", "7")),
        data_retention_days=int(os.getenv("DB_DATA_RETENTION_DAYS", "30"))
    )
    
    # Security configuration
    security_config = SecurityConfig(
        credential_expiry_hours=int(os.getenv("CREDENTIAL_EXPIRY_HOURS", "24")),
        session_timeout_hours=int(os.getenv("SESSION_TIMEOUT_HOURS", "8")),
        max_login_attempts=int(os.getenv("MAX_LOGIN_ATTEMPTS", "5")),
        lockout_duration_minutes=int(os.getenv("LOCKOUT_DURATION_MINUTES", "15"))
    )
    
    # Application configuration
    app_config = ApplicationConfig(
        debug=os.getenv("DEBUG", "false").lower() == "true",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        workers=int(os.getenv("WORKERS", "1")),
        log_level=os.getenv("LOG_LEVEL", "INFO"),
        max_concurrent_analyses=int(os.getenv("MAX_CONCURRENT_ANALYSES", "5")),
        analysis_timeout_minutes=int(os.getenv("ANALYSIS_TIMEOUT_MINUTES", "60")),
        database=db_config,
        security=security_config
    )
    
    return app_config

def load_config_from_file(config_path: str) -> Optional[ApplicationConfig]:
    """Load configuration from a JSON file"""
    try:
        config_file = Path(config_path)
        if not config_file.exists():
            return None
        
        import json
        with open(config_file, 'r') as f:
            config_data = json.load(f)
        
        return ApplicationConfig.parse_obj(config_data)
    
    except Exception as e:
        print(f"Error loading config from file: {e}")
        return None

def save_config_to_file(config: ApplicationConfig, config_path: str) -> bool:
    """Save configuration to a JSON file"""
    try:
        config_file = Path(config_path)
        config_file.parent.mkdir(parents=True, exist_ok=True)
        
        import json
        with open(config_file, 'w') as f:
            json.dump(config.dict(), f, indent=2)
        
        return True
    
    except Exception as e:
        print(f"Error saving config to file: {e}")
        return False

def get_application_config() -> ApplicationConfig:
    """
    Get application configuration with the following precedence:
    1. Configuration file (if exists)
    2. Environment variables
    3. Default values
    """
    
    # Try to load from config file first
    config_file = os.getenv("CONFIG_FILE", "./config/app_config.json")
    config = load_config_from_file(config_file)
    
    if config is None:
        # Fall back to environment variables and defaults
        config = load_config_from_env()
    
    # Ensure database directory exists (required for app to function)
    Path(config.database.database_path).parent.mkdir(parents=True, exist_ok=True)
    # Note: backup_directory will be created lazily when backup functionality is used
    
    return config

# Global configuration instance
_app_config: Optional[ApplicationConfig] = None

def get_config() -> ApplicationConfig:
    """Get or create the global configuration instance"""
    global _app_config
    if _app_config is None:
        _app_config = get_application_config()
    return _app_config

def reload_config() -> ApplicationConfig:
    """Reload configuration from sources"""
    global _app_config
    _app_config = get_application_config()
    return _app_config