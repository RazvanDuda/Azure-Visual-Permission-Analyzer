#!/usr/bin/env python3
"""
Database migration scripts for Azure Permission Analyzer
Handles database schema updates and data migrations
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from database import DatabaseManager, get_database_manager
from permissions import UserPermissionAnalysis

logger = logging.getLogger(__name__)

class MigrationManager:
    """Manages database migrations and schema updates"""
    
    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        self.db = db_manager or get_database_manager()
        self.migration_history_table = "migration_history"
    
    def initialize_migration_tracking(self):
        """Create migration history table"""
        try:
            with self.db.get_connection() as conn:
                conn.execute(f"""
                    CREATE TABLE IF NOT EXISTS {self.migration_history_table} (
                        migration_id VARCHAR PRIMARY KEY,
                        migration_name VARCHAR NOT NULL,
                        executed_at TIMESTAMP DEFAULT NOW(),
                        execution_time_ms INTEGER,
                        status VARCHAR DEFAULT 'completed'
                    )
                """)
                logger.info("Migration history table initialized")
        except Exception as e:
            logger.error(f"Failed to initialize migration tracking: {e}")
            raise
    
    def record_migration(self, migration_id: str, migration_name: str, execution_time_ms: int, status: str = 'completed'):
        """Record a migration execution"""
        try:
            query = f"""
                INSERT INTO {self.migration_history_table} 
                (migration_id, migration_name, executed_at, execution_time_ms, status)
                VALUES (?, ?, ?, ?, ?)
            """
            self.db.execute_update(query, (
                migration_id, 
                migration_name, 
                datetime.utcnow(), 
                execution_time_ms, 
                status
            ))
        except Exception as e:
            logger.error(f"Failed to record migration {migration_id}: {e}")
    
    def is_migration_executed(self, migration_id: str) -> bool:
        """Check if a migration has already been executed"""
        try:
            query = f"SELECT COUNT(*) FROM {self.migration_history_table} WHERE migration_id = ? AND status = 'completed'"
            result = self.db.execute_query(query, (migration_id,))
            return result[0][0] > 0 if result else False
        except Exception:
            # If migration history doesn't exist yet, assume no migrations have been run
            return False
    
    def get_migration_history(self) -> List[Dict[str, Any]]:
        """Get migration execution history"""
        try:
            query = f"""
                SELECT migration_id, migration_name, executed_at, execution_time_ms, status 
                FROM {self.migration_history_table} 
                ORDER BY executed_at DESC
            """
            results = self.db.execute_query(query)
            
            migrations = []
            for row in results:
                migrations.append({
                    'migration_id': row[0],
                    'migration_name': row[1],
                    'executed_at': row[2],
                    'execution_time_ms': row[3],
                    'status': row[4]
                })
            
            return migrations
        except Exception as e:
            logger.error(f"Failed to get migration history: {e}")
            return []

def migrate_from_memory_to_database(analysis_results: Dict[str, UserPermissionAnalysis], 
                                   analysis_status: Dict[str, Dict[str, Any]]) -> Dict[str, int]:
    """
    Migrate existing in-memory data to database
    
    Args:
        analysis_results: Dictionary of analysis results
        analysis_status: Dictionary of analysis status data
    
    Returns:
        Dictionary with migration statistics
    """
    migration_manager = MigrationManager()
    migration_id = "memory_to_db_001"
    migration_name = "Migrate in-memory data to database"
    
    # Check if migration already executed
    if migration_manager.is_migration_executed(migration_id):
        logger.info(f"Migration {migration_id} already executed, skipping")
        return {"skipped": True, "reason": "already_executed"}
    
    start_time = datetime.utcnow()
    stats = {"migrated_results": 0, "migrated_status": 0, "errors": 0}
    
    try:
        # Initialize migration tracking
        migration_manager.initialize_migration_tracking()
        
        from repositories import get_analysis_repository
        analysis_repo = get_analysis_repository()
        
        # Migrate analysis results
        for analysis_id, result in analysis_results.items():
            try:
                success = analysis_repo.save_analysis_result(result)
                if success:
                    stats["migrated_results"] += 1
                else:
                    stats["errors"] += 1
                    logger.warning(f"Failed to migrate result {analysis_id}")
            except Exception as e:
                stats["errors"] += 1
                logger.error(f"Error migrating result {analysis_id}: {e}")
        
        # Migrate analysis status
        for analysis_id, status_data in analysis_status.items():
            try:
                success = analysis_repo.save_analysis_status(analysis_id, status_data)
                if success:
                    stats["migrated_status"] += 1
                else:
                    stats["errors"] += 1
                    logger.warning(f"Failed to migrate status {analysis_id}")
            except Exception as e:
                stats["errors"] += 1
                logger.error(f"Error migrating status {analysis_id}: {e}")
        
        # Record successful migration
        execution_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        migration_manager.record_migration(migration_id, migration_name, execution_time)
        
        logger.info(f"Memory to database migration completed: {stats}")
        return stats
        
    except Exception as e:
        # Record failed migration
        execution_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        migration_manager.record_migration(migration_id, migration_name, execution_time, 'failed')
        logger.error(f"Memory to database migration failed: {e}")
        stats["migration_error"] = str(e)
        return stats

def migrate_from_file_credentials() -> Dict[str, Any]:
    """
    Migrate existing file-based credentials to database
    
    Returns:
        Dictionary with migration results
    """
    migration_manager = MigrationManager()
    migration_id = "file_to_db_creds_001"
    migration_name = "Migrate file-based credentials to database"
    
    # Check if migration already executed
    if migration_manager.is_migration_executed(migration_id):
        logger.info(f"Migration {migration_id} already executed, skipping")
        return {"skipped": True, "reason": "already_executed"}
    
    start_time = datetime.utcnow()
    result = {"migrated": False, "error": None, "found_file": False}
    
    try:
        # Initialize migration tracking
        migration_manager.initialize_migration_tracking()
        
        # Look for existing credential files
        possible_paths = [
            Path("./secure_storage/encrypted_credentials.json"),
            Path("./encrypted_credentials.json"),
            Path("credentials.enc")
        ]
        
        credential_file = None
        for path in possible_paths:
            if path.exists():
                credential_file = path
                result["found_file"] = True
                result["file_path"] = str(path)
                break
        
        if not credential_file:
            logger.info("No existing credential files found, skipping migration")
            result["skipped_reason"] = "no_files_found"
        else:
            # If we found a file, we would need the user's master password to decrypt and migrate
            # For now, just log that the file exists and needs manual migration
            logger.info(f"Found credential file: {credential_file}")
            result["manual_migration_needed"] = True
            result["message"] = "Credential file found, but migration requires user's master password"
        
        # Record migration attempt
        execution_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        migration_manager.record_migration(migration_id, migration_name, execution_time)
        
        return result
        
    except Exception as e:
        # Record failed migration
        execution_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        migration_manager.record_migration(migration_id, migration_name, execution_time, 'failed')
        logger.error(f"File credential migration failed: {e}")
        result["error"] = str(e)
        return result

def backup_database(backup_path: Optional[str] = None) -> bool:
    """
    Create a backup of the entire database
    
    Args:
        backup_path: Optional custom backup path
    
    Returns:
        True if backup successful, False otherwise
    """
    try:
        db_manager = get_database_manager()
        
        if not backup_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            from config import get_config
            config = get_config()
            backup_dir = Path(config.database.backup_directory)
            backup_dir.mkdir(parents=True, exist_ok=True)  # Create backup directory lazily
            backup_path = str(backup_dir / f"azure_analyzer_backup_{timestamp}")
        
        success = db_manager.backup_database(backup_path)
        
        if success:
            logger.info(f"Database backup created: {backup_path}")
        else:
            logger.error("Database backup failed")
        
        return success
        
    except Exception as e:
        logger.error(f"Backup operation failed: {e}")
        return False

def restore_database_from_backup(backup_path: str) -> bool:
    """
    Restore database from a backup
    
    Args:
        backup_path: Path to backup directory
    
    Returns:
        True if restore successful, False otherwise
    """
    try:
        db_manager = get_database_manager()
        
        backup_path_obj = Path(backup_path)
        if not backup_path_obj.exists():
            logger.error(f"Backup path does not exist: {backup_path}")
            return False
        
        # Note: DuckDB restore would need to be implemented based on specific backup format
        logger.info(f"Database restore from {backup_path} - implementation needed")
        return False
        
    except Exception as e:
        logger.error(f"Restore operation failed: {e}")
        return False

def cleanup_old_data(days_to_keep: int = 30) -> Dict[str, int]:
    """
    Clean up old analysis data
    
    Args:
        days_to_keep: Number of days of data to keep
    
    Returns:
        Dictionary with cleanup statistics
    """
    try:
        from repositories import get_analysis_repository
        analysis_repo = get_analysis_repository()
        
        deleted_count = analysis_repo.delete_old_analysis_results(days_to_keep)
        
        db_manager = get_database_manager()
        cleanup_stats = db_manager.cleanup_expired_data()
        cleanup_stats['old_analyses_deleted'] = deleted_count
        
        logger.info(f"Data cleanup completed: {cleanup_stats}")
        return cleanup_stats
        
    except Exception as e:
        logger.error(f"Data cleanup failed: {e}")
        return {"error": str(e)}

def optimize_database() -> bool:
    """
    Optimize database performance
    
    Returns:
        True if optimization successful, False otherwise
    """
    try:
        db_manager = get_database_manager()
        
        # Run vacuum to reclaim space
        success = db_manager.vacuum_database()
        
        if success:
            logger.info("Database optimization completed")
        
        return success
        
    except Exception as e:
        logger.error(f"Database optimization failed: {e}")
        return False

def get_database_status() -> Dict[str, Any]:
    """
    Get comprehensive database status information
    
    Returns:
        Dictionary with database status
    """
    try:
        db_manager = get_database_manager()
        migration_manager = MigrationManager()
        
        # Get basic stats
        stats = db_manager.get_database_stats()
        
        # Get migration history
        try:
            migration_history = migration_manager.get_migration_history()
            stats['migrations'] = {
                'total_migrations': len(migration_history),
                'last_migration': migration_history[0] if migration_history else None,
                'failed_migrations': len([m for m in migration_history if m['status'] == 'failed'])
            }
        except Exception:
            stats['migrations'] = {"error": "migration history not available"}
        
        return stats
        
    except Exception as e:
        return {"error": str(e)}

# Available migrations
AVAILABLE_MIGRATIONS = {
    "memory_to_db": {
        "function": migrate_from_memory_to_database,
        "description": "Migrate in-memory data to database",
        "requires_data": True
    },
    "file_creds_to_db": {
        "function": migrate_from_file_credentials,
        "description": "Migrate file-based credentials to database",
        "requires_data": False
    }
}