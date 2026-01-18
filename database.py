#!/usr/bin/env python3
"""
Database module for Azure Permission Analyzer
Provides DuckDB-based storage for analysis results and encrypted credentials
"""

import json
import logging
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from contextlib import contextmanager

import duckdb
from pydantic import BaseModel

logger = logging.getLogger(__name__)

class DatabaseConfig(BaseModel):
    """Database configuration settings"""
    database_path: str = "./data/azure_analyzer.db"
    connection_timeout: int = 60
    max_connections: int = 10
    enable_wal: bool = True
    
class DatabaseManager:
    """
    Manages DuckDB database connections and operations for Azure Permission Analyzer
    
    Features:
    - Thread-safe connection management
    - Automatic schema initialization
    - JSON column support for complex data structures
    - Transaction management
    - Connection pooling
    """
    
    def __init__(self, config: Optional[DatabaseConfig] = None):
        """Initialize database manager"""
        self.config = config or DatabaseConfig()
        self._connection_lock = threading.Lock()
        self._initialized = False
        
        # Ensure database directory exists
        db_path = Path(self.config.database_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize database on first access
        self._initialize_database()
    
    def _initialize_database(self):
        """Initialize database schema if not exists"""
        with self._connection_lock:
            if self._initialized:
                return
                
            try:
                with self.get_connection() as conn:
                    # DuckDB doesn't support SQLite PRAGMA statements
                    # WAL mode is not applicable to DuckDB
                    
                    # Create tables
                    self._create_tables(conn)
                    
                    # Create indexes
                    self._create_indexes(conn)
                    
                    self._initialized = True
                    logger.info("Database initialized successfully")
                    
            except Exception as e:
                logger.error(f"Failed to initialize database: {e}")
                raise
    
    def _create_tables(self, conn: duckdb.DuckDBPyConnection):
        """Create database tables"""
        
        # Analysis Results Table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analysis_results (
                analysis_id VARCHAR PRIMARY KEY,
                user_id VARCHAR NOT NULL,
                user_principal_name VARCHAR,
                display_name VARCHAR,
                tenant_id VARCHAR,
                tenant_name VARCHAR,
                subscription_id VARCHAR,
                subscription_name VARCHAR,
                organization_name VARCHAR,
                analysis_data JSON NOT NULL,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            )
        """)
        
        # Analysis Status Table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analysis_status (
                analysis_id VARCHAR PRIMARY KEY,
                status VARCHAR NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'error')),
                current_user VARCHAR,
                completed_users INTEGER DEFAULT 0,
                total_users INTEGER DEFAULT 0,
                error_message TEXT,
                started_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW(),
                completed_at TIMESTAMP
            )
        """)
        
        # Encrypted Credentials Table
        # First create a sequence for auto-increment if it doesn't exist
        try:
            conn.execute("CREATE SEQUENCE IF NOT EXISTS encrypted_credentials_id_seq START 1")
        except:
            pass  # Sequence might already exist
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS encrypted_credentials (
                id INTEGER PRIMARY KEY DEFAULT nextval('encrypted_credentials_id_seq'),
                tenant_id VARCHAR NOT NULL,
                encrypted_data JSON NOT NULL,
                salt VARCHAR NOT NULL,
                nonce VARCHAR NOT NULL,
                created_at TIMESTAMP DEFAULT NOW(),
                expires_at TIMESTAMP NOT NULL,
                is_active BOOLEAN DEFAULT TRUE
            )
        """)
        
        # Sessions Table (optional for future use)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_sessions (
                session_id VARCHAR PRIMARY KEY,
                user_data JSON,
                created_at TIMESTAMP DEFAULT NOW(),
                expires_at TIMESTAMP NOT NULL,
                last_accessed TIMESTAMP DEFAULT NOW()
            )
        """)
        
        logger.info("Database tables created successfully")
    
    def _create_indexes(self, conn: duckdb.DuckDBPyConnection):
        """Create database indexes for performance"""
        
        indexes = [
            # Analysis Results indexes
            "CREATE INDEX IF NOT EXISTS idx_analysis_results_user_id ON analysis_results(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_analysis_results_tenant_id ON analysis_results(tenant_id)",
            "CREATE INDEX IF NOT EXISTS idx_analysis_results_subscription_id ON analysis_results(subscription_id)",
            "CREATE INDEX IF NOT EXISTS idx_analysis_results_created_at ON analysis_results(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_analysis_results_organization ON analysis_results(organization_name)",
            
            # Analysis Status indexes
            "CREATE INDEX IF NOT EXISTS idx_analysis_status_status ON analysis_status(status)",
            "CREATE INDEX IF NOT EXISTS idx_analysis_status_started_at ON analysis_status(started_at)",
            
            # Credentials indexes
            "CREATE INDEX IF NOT EXISTS idx_encrypted_credentials_tenant_id ON encrypted_credentials(tenant_id)",
            "CREATE INDEX IF NOT EXISTS idx_encrypted_credentials_active ON encrypted_credentials(is_active)",
            "CREATE INDEX IF NOT EXISTS idx_encrypted_credentials_expires_at ON encrypted_credentials(expires_at)",
            
            # Sessions indexes
            "CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at ON user_sessions(expires_at)",
            
            # Unique constraint to prevent duplicate users within the same analysis session
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_analysis_results_unique_user_per_session ON analysis_results(analysis_id, user_id)",
        ]
        
        for index_sql in indexes:
            try:
                conn.execute(index_sql)
            except Exception as e:
                logger.warning(f"Failed to create index: {e}")
        
        logger.info("Database indexes created successfully")
    
    @contextmanager
    def get_connection(self):
        """Get a database connection with automatic cleanup"""
        conn = None
        try:
            conn = duckdb.connect(
                self.config.database_path,
                read_only=False,
                config={'threads': 4}
            )
            yield conn
        finally:
            if conn:
                conn.close()
    
    def execute_query(self, query: str, parameters: Optional[Tuple] = None) -> List[Tuple]:
        """Execute a SELECT query and return results"""
        with self.get_connection() as conn:
            if parameters:
                return conn.execute(query, parameters).fetchall()
            else:
                return conn.execute(query).fetchall()
    
    def execute_update(self, query: str, parameters: Optional[Tuple] = None) -> int:
        """Execute an INSERT/UPDATE/DELETE query and return affected rows"""
        with self.get_connection() as conn:
            if parameters:
                result = conn.execute(query, parameters)
            else:
                result = conn.execute(query)
            return result.rowcount if hasattr(result, 'rowcount') else 0
    
    def execute_transaction(self, queries: List[Tuple[str, Optional[Tuple]]]) -> bool:
        """Execute multiple queries in a transaction"""
        with self.get_connection() as conn:
            try:
                conn.begin()
                for query, parameters in queries:
                    if parameters:
                        conn.execute(query, parameters)
                    else:
                        conn.execute(query)
                conn.commit()
                return True
            except Exception as e:
                conn.rollback()
                logger.error(f"Transaction failed: {e}")
                raise
    
    def get_table_info(self, table_name: str) -> List[Dict]:
        """Get information about a table"""
        with self.get_connection() as conn:
            result = conn.execute(f"DESCRIBE {table_name}").fetchall()
            columns = [desc[0] for desc in conn.description]
            return [dict(zip(columns, row)) for row in result]
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        stats = {}
        
        with self.get_connection() as conn:
            # Table counts
            tables = ['analysis_results', 'analysis_status', 'encrypted_credentials', 'user_sessions']
            
            for table in tables:
                try:
                    count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    stats[f"{table}_count"] = count
                except Exception as e:
                    logger.warning(f"Failed to get count for {table}: {e}")
                    stats[f"{table}_count"] = 0
            
            # Database size
            try:
                db_path = Path(self.config.database_path)
                if db_path.exists():
                    stats['database_size_bytes'] = db_path.stat().st_size
                    stats['database_size_mb'] = round(stats['database_size_bytes'] / (1024 * 1024), 2)
                else:
                    stats['database_size_bytes'] = 0
                    stats['database_size_mb'] = 0
            except Exception as e:
                logger.warning(f"Failed to get database size: {e}")
                stats['database_size_bytes'] = 0
                stats['database_size_mb'] = 0
        
        return stats
    
    def cleanup_expired_data(self) -> Dict[str, int]:
        """Clean up expired data from all tables"""
        cleanup_stats = {}
        current_time = datetime.utcnow()
        
        with self.get_connection() as conn:
            try:
                conn.begin()
                
                # Clean up expired credentials
                expired_creds = conn.execute(
                    "DELETE FROM encrypted_credentials WHERE expires_at < ?",
                    (current_time,)
                ).rowcount
                cleanup_stats['expired_credentials'] = expired_creds
                
                # Clean up expired sessions
                expired_sessions = conn.execute(
                    "DELETE FROM user_sessions WHERE expires_at < ?",
                    (current_time,)
                ).rowcount
                cleanup_stats['expired_sessions'] = expired_sessions
                
                # Clean up old analysis results (older than 30 days)
                old_cutoff = current_time - timedelta(days=30)
                old_analyses = conn.execute(
                    "DELETE FROM analysis_results WHERE created_at < ?",
                    (old_cutoff,)
                ).rowcount
                cleanup_stats['old_analyses'] = old_analyses
                
                # Clean up orphaned analysis status records
                orphaned_status = conn.execute("""
                    DELETE FROM analysis_status 
                    WHERE analysis_id NOT IN (SELECT analysis_id FROM analysis_results)
                """).rowcount
                cleanup_stats['orphaned_status'] = orphaned_status
                
                conn.commit()
                logger.info(f"Cleanup completed: {cleanup_stats}")
                
            except Exception as e:
                conn.rollback()
                logger.error(f"Cleanup failed: {e}")
                raise
        
        return cleanup_stats
    
    def backup_database(self, backup_path: str) -> bool:
        """Create a backup of the database"""
        try:
            with self.get_connection() as conn:
                conn.execute(f"EXPORT DATABASE '{backup_path}'")
            logger.info(f"Database backup created: {backup_path}")
            return True
        except Exception as e:
            logger.error(f"Backup failed: {e}")
            return False
    
    def vacuum_database(self) -> bool:
        """Optimize database by reclaiming space"""
        try:
            with self.get_connection() as conn:
                conn.execute("VACUUM")
            logger.info("Database vacuum completed")
            return True
        except Exception as e:
            logger.error(f"Vacuum failed: {e}")
            return False

# Global database manager instance
_db_manager: Optional[DatabaseManager] = None

def get_database_manager(config: Optional[DatabaseConfig] = None) -> DatabaseManager:
    """Get or create the global database manager instance"""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager(config)
    return _db_manager

def initialize_database(config: Optional[DatabaseConfig] = None) -> DatabaseManager:
    """Initialize the database and return the manager"""
    return get_database_manager(config)