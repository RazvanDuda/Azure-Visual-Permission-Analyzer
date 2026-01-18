#!/usr/bin/env python3
"""
Repository classes for Azure Permission Analyzer
Provides data access layer for analysis results, status, and credentials
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import asdict

from permissions import UserPermissionAnalysis
from database import DatabaseManager, get_database_manager

logger = logging.getLogger(__name__)

class AnalysisRepository:
    """Repository for managing analysis results and status"""
    
    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        self.db = db_manager or get_database_manager()
    
    # Analysis Results Methods
    
    def save_analysis_result(self, analysis: UserPermissionAnalysis, analysis_id: Optional[str] = None) -> bool:
        """Save or update an analysis result"""
        try:
            # Convert analysis to JSON-serializable format
            analysis_data = analysis.dict()
            # Convert datetime objects to ISO format strings for JSON serialization
            if 'analyzed_at' in analysis_data and analysis_data['analyzed_at']:
                analysis_data['analyzed_at'] = analysis_data['analyzed_at'].isoformat()
            
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
            
            # Use provided analysis_id, or generate one if not provided
            if analysis_id is None:
                analysis_id = getattr(analysis, 'analysis_key', None) or f"{analysis.user_id}_{int(datetime.utcnow().timestamp())}"
            
            parameters = (
                analysis_id,
                analysis.user_id,
                analysis.user_principal_name,
                analysis.display_name,
                analysis.tenant_id,
                analysis.tenant_name,
                analysis.subscription_id,
                analysis.subscription_name,
                analysis.organization_name,
                json.dumps(analysis_data),
                analysis.analyzed_at,
                datetime.utcnow()
            )
            
            self.db.execute_update(query, parameters)
            logger.info(f"Saved analysis result for user {analysis.user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save analysis result: {e}")
            return False
    
    def get_analysis_result(self, analysis_id: str) -> Optional[UserPermissionAnalysis]:
        """Get an analysis result by ID"""
        try:
            query = "SELECT analysis_data FROM analysis_results WHERE analysis_id = ?"
            results = self.db.execute_query(query, (analysis_id,))
            
            if not results:
                logger.warning(f"No analysis result found for ID: {analysis_id}")
                return None
            
            analysis_data = json.loads(results[0][0])
            # Use model_validate instead of deprecated parse_obj
            try:
                return UserPermissionAnalysis.model_validate(analysis_data)
            except AttributeError:
                # Fallback for older Pydantic versions
                return UserPermissionAnalysis.parse_obj(analysis_data)
            
        except Exception as e:
            logger.error(f"Failed to get analysis result {analysis_id}: {e}")
            return None
    
    def get_analysis_result_raw(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """Get an analysis result as raw dict by ID"""
        try:
            query = "SELECT analysis_data FROM analysis_results WHERE analysis_id = ?"
            results = self.db.execute_query(query, (analysis_id,))
            
            if not results:
                logger.warning(f"No analysis result found for ID: {analysis_id}")
                return None
            
            analysis_data = json.loads(results[0][0])
            return analysis_data
            
        except Exception as e:
            logger.error(f"Failed to get analysis result {analysis_id}: {e}")
            return None
    
    def get_all_analysis_results(self, 
                                limit: Optional[int] = None,
                                offset: int = 0,
                                user_id: Optional[str] = None,
                                tenant_id: Optional[str] = None,
                                organization_name: Optional[str] = None) -> List[UserPermissionAnalysis]:
        """Get all analysis results with optional filtering and pagination"""
        try:
            query = "SELECT analysis_data FROM analysis_results"
            conditions = []
            parameters = []
            
            # Add filters
            if user_id:
                conditions.append("user_id = ?")
                parameters.append(user_id)
            
            if tenant_id:
                conditions.append("tenant_id = ?")
                parameters.append(tenant_id)
            
            if organization_name:
                conditions.append("organization_name = ?")
                parameters.append(organization_name)
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            
            query += " ORDER BY created_at DESC"
            
            # Add pagination
            if limit:
                query += f" LIMIT {limit}"
                if offset > 0:
                    query += f" OFFSET {offset}"
            
            results = self.db.execute_query(query, tuple(parameters))
            
            analyses = []
            for row in results:
                try:
                    analysis_data = json.loads(row[0])
                    # Use model_validate instead of deprecated parse_obj
                    try:
                        analysis = UserPermissionAnalysis.model_validate(analysis_data)
                    except AttributeError:
                        # Fallback for older Pydantic versions
                        analysis = UserPermissionAnalysis.parse_obj(analysis_data)
                    analyses.append(analysis)
                except Exception as e:
                    logger.warning(f"Failed to parse analysis data: {e}")
                    continue
            
            return analyses
            
        except Exception as e:
            logger.error(f"Failed to get analysis results: {e}")
            return []
    
    def get_all_analysis_results_with_ids(self, 
                                        limit: Optional[int] = None,
                                        offset: int = 0,
                                        user_id: Optional[str] = None,
                                        tenant_id: Optional[str] = None,
                                        organization_name: Optional[str] = None) -> List[Tuple[str, Dict[str, Any]]]:
        """Get all analysis results with their analysis IDs"""
        try:
            query = "SELECT analysis_id, analysis_data FROM analysis_results"
            conditions = []
            parameters = []
            
            # Add filters
            if user_id:
                conditions.append("user_id = ?")
                parameters.append(user_id)
            
            if tenant_id:
                conditions.append("tenant_id = ?")
                parameters.append(tenant_id)
            
            if organization_name:
                conditions.append("organization_name = ?")
                parameters.append(organization_name)
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            
            query += " ORDER BY created_at DESC"
            
            # Add pagination
            if limit:
                query += f" LIMIT {limit}"
                if offset > 0:
                    query += f" OFFSET {offset}"
            
            results = self.db.execute_query(query, tuple(parameters))
            
            analyses = []
            for row in results:
                try:
                    analysis_id = row[0]
                    analysis_data = json.loads(row[1])
                    analyses.append((analysis_id, analysis_data))
                except Exception as e:
                    logger.warning(f"Failed to parse analysis data: {e}")
                    continue
            
            return analyses
            
        except Exception as e:
            logger.error(f"Failed to get analysis results with IDs: {e}")
            return []
    
    def get_analysis_results_summary(self) -> Dict[str, Any]:
        """Get summary statistics of analysis results"""
        try:
            query = """
                SELECT 
                    COUNT(*) as total_count,
                    COUNT(DISTINCT user_id) as unique_users,
                    COUNT(DISTINCT tenant_id) as unique_tenants,
                    COUNT(DISTINCT organization_name) as unique_organizations,
                    MIN(created_at) as oldest_analysis,
                    MAX(created_at) as newest_analysis
                FROM analysis_results
            """
            
            results = self.db.execute_query(query)
            if results:
                columns = ['total_count', 'unique_users', 'unique_tenants', 'unique_organizations', 'oldest_analysis', 'newest_analysis']
                return dict(zip(columns, results[0]))
            
            return {}
            
        except Exception as e:
            logger.error(f"Failed to get analysis summary: {e}")
            return {}
    
    def delete_analysis_result(self, analysis_id: str) -> bool:
        """Delete an analysis result"""
        try:
            queries = [
                ("DELETE FROM analysis_results WHERE analysis_id = ?", (analysis_id,)),
                ("DELETE FROM analysis_status WHERE analysis_id = ?", (analysis_id,))
            ]
            
            self.db.execute_transaction(queries)
            logger.info(f"Deleted analysis result {analysis_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete analysis result {analysis_id}: {e}")
            return False
    
    def delete_old_analysis_results(self, days_old: int = 30) -> int:
        """Delete analysis results older than specified days"""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days_old)
            
            queries = [
                ("DELETE FROM analysis_status WHERE analysis_id IN (SELECT analysis_id FROM analysis_results WHERE created_at < ?)", (cutoff_date,)),
                ("DELETE FROM analysis_results WHERE created_at < ?", (cutoff_date,))
            ]
            
            self.db.execute_transaction(queries)
            
            # Get count of deleted records
            count_query = "SELECT changes()"
            result = self.db.execute_query(count_query)
            deleted_count = result[0][0] if result else 0
            
            logger.info(f"Deleted {deleted_count} old analysis results")
            return deleted_count
            
        except Exception as e:
            logger.error(f"Failed to delete old analysis results: {e}")
            return 0
    
    # Analysis Status Methods
    
    def save_analysis_status(self, analysis_id: str, status_data: Dict[str, Any]) -> bool:
        """Save or update analysis status"""
        try:
            query = """
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
            
            parameters = (
                analysis_id,
                status_data.get('status', 'pending'),
                status_data.get('current_user'),
                status_data.get('completed_users', 0),
                status_data.get('total_users', 0),
                status_data.get('error'),
                status_data.get('started_at', datetime.utcnow()),
                datetime.utcnow(),
                status_data.get('completed_at')
            )
            
            self.db.execute_update(query, parameters)
            return True
            
        except Exception as e:
            logger.error(f"Failed to save analysis status: {e}")
            return False
    
    def get_analysis_status(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """Get analysis status by ID"""
        try:
            query = """
                SELECT status, current_user, completed_users, total_users,
                       error_message, started_at, updated_at, completed_at
                FROM analysis_status 
                WHERE analysis_id = ?
            """
            
            results = self.db.execute_query(query, (analysis_id,))
            
            if not results:
                return None
            
            row = results[0]
            return {
                'status': row[0],
                'current_user': row[1],
                'completed_users': row[2],
                'total_users': row[3],
                'error': row[4],
                'started_at': row[5],
                'updated_at': row[6],
                'completed_at': row[7]
            }
            
        except Exception as e:
            logger.error(f"Failed to get analysis status {analysis_id}: {e}")
            return None
    
    def get_all_analysis_status(self, status_filter: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
        """Get all analysis statuses with optional status filter"""
        try:
            query = """
                SELECT analysis_id, status, current_user, completed_users, total_users,
                       error_message, started_at, updated_at, completed_at
                FROM analysis_status
            """
            
            parameters = []
            if status_filter:
                query += " WHERE status = ?"
                parameters.append(status_filter)
            
            query += " ORDER BY started_at DESC"
            
            results = self.db.execute_query(query, tuple(parameters) if parameters else None)
            
            status_dict = {}
            for row in results:
                analysis_id = row[0]
                status_dict[analysis_id] = {
                    'status': row[1],
                    'current_user': row[2],
                    'completed_users': row[3],
                    'total_users': row[4],
                    'error': row[5],
                    'started_at': row[6],
                    'updated_at': row[7],
                    'completed_at': row[8]
                }
            
            return status_dict
            
        except Exception as e:
            logger.error(f"Failed to get analysis statuses: {e}")
            return {}
    
    def delete_analysis_status(self, analysis_id: str) -> bool:
        """Delete analysis status"""
        try:
            query = "DELETE FROM analysis_status WHERE analysis_id = ?"
            self.db.execute_update(query, (analysis_id,))
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete analysis status {analysis_id}: {e}")
            return False
    
    def clear_all_data(self) -> bool:
        """Clear all analysis data (for demo purposes)"""
        try:
            queries = [
                ("DELETE FROM analysis_status", None),
                ("DELETE FROM analysis_results", None)
            ]
            
            self.db.execute_transaction(queries)
            logger.info("Cleared all analysis data")
            return True
            
        except Exception as e:
            logger.error(f"Failed to clear all data: {e}")
            return False

class CredentialRepository:
    """Repository for managing encrypted credentials"""
    
    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        self.db = db_manager or get_database_manager()
    
    def save_encrypted_credentials(self, 
                                  tenant_id: str,
                                  encrypted_data: Dict[str, Any],
                                  salt: str,
                                  nonce: str,
                                  expires_at: datetime) -> bool:
        """Save encrypted credentials"""
        try:
            # Deactivate any existing credentials for this tenant
            self.db.execute_update(
                "UPDATE encrypted_credentials SET is_active = FALSE WHERE tenant_id = ? AND is_active = TRUE",
                (tenant_id,)
            )
            
            # Insert new credentials
            query = """
                INSERT INTO encrypted_credentials (
                    tenant_id, encrypted_data, salt, nonce, expires_at, is_active
                ) VALUES (?, ?, ?, ?, ?, TRUE)
            """
            
            parameters = (
                tenant_id,
                json.dumps(encrypted_data),
                salt,
                nonce,
                expires_at
            )
            
            self.db.execute_update(query, parameters)
            logger.info(f"Saved encrypted credentials for tenant {tenant_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save encrypted credentials: {e}")
            return False
    
    def get_encrypted_credentials(self, tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Get active encrypted credentials"""
        try:
            if tenant_id:
                query = """
                    SELECT encrypted_data, salt, nonce, created_at, expires_at
                    FROM encrypted_credentials 
                    WHERE tenant_id = ? AND is_active = TRUE AND expires_at > ?
                    ORDER BY created_at DESC 
                    LIMIT 1
                """
                parameters = (tenant_id, datetime.utcnow())
            else:
                query = """
                    SELECT encrypted_data, salt, nonce, created_at, expires_at
                    FROM encrypted_credentials 
                    WHERE is_active = TRUE AND expires_at > ?
                    ORDER BY created_at DESC 
                    LIMIT 1
                """
                parameters = (datetime.utcnow(),)
            
            results = self.db.execute_query(query, parameters)
            
            if not results:
                return None
            
            row = results[0]
            return {
                'encrypted_data': json.loads(row[0]),
                'salt': row[1],
                'nonce': row[2],
                'created_at': row[3],
                'expires_at': row[4]
            }
            
        except Exception as e:
            logger.error(f"Failed to get encrypted credentials: {e}")
            return None
    
    def credentials_exist(self, tenant_id: Optional[str] = None) -> bool:
        """Check if credentials exist"""
        try:
            if tenant_id:
                query = """
                    SELECT COUNT(*) FROM encrypted_credentials 
                    WHERE tenant_id = ? AND is_active = TRUE AND expires_at > ?
                """
                parameters = (tenant_id, datetime.utcnow())
            else:
                query = """
                    SELECT COUNT(*) FROM encrypted_credentials 
                    WHERE is_active = TRUE AND expires_at > ?
                """
                parameters = (datetime.utcnow(),)
            
            results = self.db.execute_query(query, parameters)
            return results[0][0] > 0 if results else False
            
        except Exception as e:
            logger.error(f"Failed to check credentials existence: {e}")
            return False
    
    def delete_credentials(self, tenant_id: Optional[str] = None) -> bool:
        """Delete credentials (mark as inactive)"""
        try:
            if tenant_id:
                query = "UPDATE encrypted_credentials SET is_active = FALSE WHERE tenant_id = ?"
                parameters = (tenant_id,)
            else:
                query = "UPDATE encrypted_credentials SET is_active = FALSE WHERE is_active = TRUE"
                parameters = None
            
            self.db.execute_update(query, parameters)
            logger.info(f"Deleted credentials for tenant {tenant_id or 'all'}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete credentials: {e}")
            return False
    
    def cleanup_expired_credentials(self) -> int:
        """Remove expired credentials"""
        try:
            query = "DELETE FROM encrypted_credentials WHERE expires_at < ?"
            count = self.db.execute_update(query, (datetime.utcnow(),))
            logger.info(f"Cleaned up {count} expired credentials")
            return count
            
        except Exception as e:
            logger.error(f"Failed to cleanup expired credentials: {e}")
            return 0
    
    def get_credential_info(self, tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Get credential metadata without sensitive data"""
        try:
            if tenant_id:
                query = """
                    SELECT tenant_id, created_at, expires_at
                    FROM encrypted_credentials 
                    WHERE tenant_id = ? AND is_active = TRUE AND expires_at > ?
                    ORDER BY created_at DESC 
                    LIMIT 1
                """
                parameters = (tenant_id, datetime.utcnow())
            else:
                query = """
                    SELECT tenant_id, created_at, expires_at
                    FROM encrypted_credentials 
                    WHERE is_active = TRUE AND expires_at > ?
                    ORDER BY created_at DESC 
                    LIMIT 1
                """
                parameters = (datetime.utcnow(),)
            
            results = self.db.execute_query(query, parameters)
            
            if not results:
                return None
            
            row = results[0]
            return {
                'tenant_id': row[0],
                'created_at': row[1],
                'expires_at': row[2],
                'is_expired': row[2] < datetime.utcnow() if row[2] else True
            }
            
        except Exception as e:
            logger.error(f"Failed to get credential info: {e}")
            return None

# Global repository instances
_analysis_repo: Optional[AnalysisRepository] = None
_credential_repo: Optional[CredentialRepository] = None

def get_analysis_repository(db_manager: Optional[DatabaseManager] = None) -> AnalysisRepository:
    """Get or create the global analysis repository instance"""
    global _analysis_repo
    if _analysis_repo is None:
        _analysis_repo = AnalysisRepository(db_manager)
    return _analysis_repo

def get_credential_repository(db_manager: Optional[DatabaseManager] = None) -> CredentialRepository:
    """Get or create the global credential repository instance"""
    global _credential_repo
    if _credential_repo is None:
        _credential_repo = CredentialRepository(db_manager)
    return _credential_repo