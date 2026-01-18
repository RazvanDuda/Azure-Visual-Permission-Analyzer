#!/usr/bin/env python3
"""
Azure Permission Analyzer - Production-Ready Implementation
Analyzes all resources and permissions for users in Azure subscriptions
Version: 1.0.0
"""

import asyncio
import json
import csv
import logging
import os
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, field, asdict
from pathlib import Path
from functools import lru_cache
import hashlib
import subprocess
import tempfile
import base64
import urllib.parse
import time
from io import BytesIO

import click
import aiohttp
from azure.identity import ClientSecretCredential
from azure.core.exceptions import (
    ClientAuthenticationError,
    HttpResponseError,
    ResourceNotFoundError
)
from pydantic import BaseModel, Field, validator
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type
)
import pandas as pd
from tqdm.asyncio import tqdm
import requests
from PIL import Image

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('azure_permissions.log')
    ]
)
logger = logging.getLogger(__name__)

# Constants for Azure APIs
AZURE_MANAGEMENT_URL = "https://management.azure.com"
GRAPH_API_URL = "https://graph.microsoft.com/v1.0"
RBAC_API_VERSION = "2022-04-01"
RESOURCE_GRAPH_API_VERSION = "2024-04-01"

# Rate limiting configuration
MAX_CONCURRENT_REQUESTS = 50
RATE_LIMIT_DELAY = 0.1
MAX_RETRIES = 5
BACKOFF_FACTOR = 2

# Pagination defaults
DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 999

# Cache configuration
CACHE_TTL_SECONDS = 900  # 15 minutes

@dataclass
class RoleAssignment:
    """Represents an Azure RBAC role assignment"""
    id: str
    principal_id: str
    principal_type: str
    role_definition_id: str
    role_name: str = ""
    scope: str = ""
    created_on: Optional[datetime] = None
    created_by: Optional[str] = None
    condition: Optional[str] = None
    group_name: Optional[str] = None  # Added to track group name for group assignments
    group_id: Optional[str] = None    # Added to track group ID for group assignments

    def to_dict(self) -> Dict:
        return {k: str(v) if v else None for k, v in asdict(self).items()}

@dataclass
class Permission:
    """Represents a permission action"""
    actions: List[str] = field(default_factory=list)
    not_actions: List[str] = field(default_factory=list)
    data_actions: List[str] = field(default_factory=list)
    not_data_actions: List[str] = field(default_factory=list)

    def is_allowed(self, action: str) -> bool:
        """Check if an action is allowed by this permission"""
        # Check if action matches any allowed pattern
        for allowed in self.actions + self.data_actions:
            if self._matches_pattern(action, allowed):
                # Check if it's not explicitly denied
                for denied in self.not_actions + self.not_data_actions:
                    if self._matches_pattern(action, denied):
                        return False
                return True
        return False

    @staticmethod
    def _matches_pattern(action: str, pattern: str) -> bool:
        """Check if action matches a pattern (supports wildcards)"""
        if pattern == "*":
            return True
        if pattern.endswith("/*"):
            prefix = pattern[:-2]
            return action.startswith(prefix + "/")
        return action == pattern

class UserPermissionAnalysis(BaseModel):
    """Complete permission analysis for a user"""
    user_id: str
    user_principal_name: str
    display_name: str
    tenant_id: str = ""
    tenant_name: str = ""
    subscription_id: str = ""
    subscription_name: str = ""
    organization_name: str = ""
    direct_assignments: List[Dict] = Field(default_factory=list)
    group_assignments: List[Dict] = Field(default_factory=list)
    all_permissions: Dict[str, List[str]] = Field(default_factory=dict)
    key_vault_permissions: List[Dict] = Field(default_factory=list)
    storage_account_permissions: List[Dict] = Field(default_factory=list)
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)

    @validator('analyzed_at', pre=True)
    def parse_analyzed_at(cls, v):
        if isinstance(v, str):
            # Parse ISO format string to datetime
            return datetime.fromisoformat(v.replace('Z', '+00:00'))
        return v

    class Config:
        arbitrary_types_allowed = True

class AzureAuthManager:
    """Manages Azure authentication and token refresh"""

    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        """Initialize Azure Auth Manager with required service principal credentials"""
        if not all([tenant_id, client_id, client_secret]):
            raise ValueError("tenant_id, client_id, and client_secret are required for secure authentication")
        
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret

        # Initialize service principal credentials only
        self.credential = ClientSecretCredential(
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            client_secret=self.client_secret
        )
        self.async_credential = None  # Will be created when needed

        # Token cache
        self._token_cache: Dict[str, Tuple[str, datetime]] = {}

    def get_token(self, scope: str) -> str:
        """Get access token for a specific scope with caching"""
        # Check cache first
        if scope in self._token_cache:
            token, expires_on = self._token_cache[scope]
            if datetime.utcnow() < expires_on - timedelta(minutes=5):
                return token

        # Get new token
        token_response = self.credential.get_token(scope)
        self._token_cache[scope] = (
            token_response.token,
            datetime.fromtimestamp(token_response.expires_on)
        )
        return token_response.token

    async def get_token_async(self, scope: str) -> str:
        """Async version of get_token"""
        if not self.async_credential:
            # Create async service principal credential
            from azure.identity.aio import ClientSecretCredential as AsyncClientSecretCredential
            self.async_credential = AsyncClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret
            )

        # Check cache first
        if scope in self._token_cache:
            token, expires_on = self._token_cache[scope]
            if datetime.utcnow() < expires_on - timedelta(minutes=5):
                return token

        # Get new token
        token_response = await self.async_credential.get_token(scope)
        self._token_cache[scope] = (
            token_response.token,
            datetime.fromtimestamp(token_response.expires_on)
        )
        return token_response.token

class AzureAPIClient:
    """Async client for Azure REST APIs with rate limiting and retry logic"""

    def __init__(self, auth_manager: AzureAuthManager,
                 max_concurrent: int = MAX_CONCURRENT_REQUESTS):
        self.auth_manager = auth_manager
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.session: Optional[aiohttp.ClientSession] = None
        self._request_count = 0
        self._last_request_time = datetime.utcnow()

    async def __aenter__(self):
        """Async context manager entry"""
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=20,  # Reduce per-host connections to help with cleanup
            ttl_dns_cache=300,
            enable_cleanup_closed=True,
            force_close=False,  # Allow keepalive for better performance
            ssl=True,  # Keep SSL but with better timeout handling
            keepalive_timeout=30  # Close idle connections after 30 seconds
        )
        timeout = aiohttp.ClientTimeout(
            total=60,
            connect=30,
            sock_read=30,
            sock_connect=30
        )
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            connector_owner=True
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            try:
                # Close the session first (this should handle the connector)
                if not self.session.closed:
                    try:
                        await asyncio.wait_for(self.session.close(), timeout=3.0)
                    except asyncio.TimeoutError:
                        logger.debug("Session close timed out")
                    except Exception as e:
                        logger.debug(f"Error closing session: {e}")
                
                # Ensure connector is explicitly closed if session close didn't handle it
                if hasattr(self.session, '_connector') and self.session._connector:
                    connector = self.session._connector
                    if not connector.closed:
                        try:
                            await asyncio.wait_for(connector.close(), timeout=2.0)
                        except (asyncio.TimeoutError, Exception) as e:
                            logger.debug(f"Error closing connector: {e}")
                        
                        # Wait a moment for the connector to fully close
                        try:
                            await asyncio.sleep(0.1)
                        except Exception:
                            pass
                        
            except Exception as e:
                logger.debug(f"Error in session cleanup: {e}")
            finally:
                self.session = None

    @retry(
        stop=stop_after_attempt(MAX_RETRIES),
        wait=wait_exponential(multiplier=BACKOFF_FACTOR, min=1, max=60),
        retry=retry_if_exception_type((
            aiohttp.ClientError, 
            asyncio.TimeoutError,
            aiohttp.ClientConnectionError,
            aiohttp.ServerTimeoutError
        ))
    )
    async def make_request(self, method: str, url: str,
                          scope: str, **kwargs) -> Dict:
        """Make an authenticated request with retry logic"""
        async with self.semaphore:
            # Rate limiting
            await self._apply_rate_limit()

            # Get token for the appropriate scope
            token = await self.auth_manager.get_token_async(scope)

            headers = kwargs.get('headers', {})
            headers['Authorization'] = f'Bearer {token}'
            headers['Content-Type'] = 'application/json'
            kwargs['headers'] = headers

            try:
                async with self.session.request(method, url, **kwargs) as response:
                    self._request_count += 1

                    # Handle rate limiting (429)
                    if response.status == 429:
                        retry_after = int(response.headers.get('Retry-After', 30))
                        logger.warning(f"Rate limited. Waiting {retry_after} seconds")
                        await asyncio.sleep(retry_after)
                        raise aiohttp.ClientError("Rate limited")

                    response.raise_for_status()
                    return await response.json()

            except aiohttp.ClientConnectionError as e:
                logger.warning(f"Connection error: {e}. Will retry...")
                raise
            except aiohttp.ServerTimeoutError as e:
                logger.warning(f"Server timeout: {e}. Will retry...")
                raise
            except asyncio.TimeoutError as e:
                logger.warning(f"Request timeout: {e}. Will retry...")
                raise
            except aiohttp.ClientResponseError as e:
                logger.error(f"API request failed: {e.status} - {e.message}")
                if e.status == 404:
                    return {}
                raise
            except Exception as e:
                logger.error(f"Unexpected error in make_request: {e}")
                raise

    async def _apply_rate_limit(self):
        """Apply rate limiting between requests"""
        now = datetime.utcnow()
        time_since_last = (now - self._last_request_time).total_seconds()
        if time_since_last < RATE_LIMIT_DELAY:
            await asyncio.sleep(RATE_LIMIT_DELAY - time_since_last)
        self._last_request_time = datetime.utcnow()


    def suppress_future_exceptions(self):
        """Suppress unhandled future exceptions by setting up an exception handler"""
        def exception_handler(loop, context):
            exception = context.get('exception')
            message = context.get('message', '')
            
            # Suppress common connection/cleanup errors
            if isinstance(exception, (aiohttp.ClientConnectionError, asyncio.TimeoutError, ConnectionResetError)):
                logger.debug(f"Suppressed connection error: {exception}")
            elif 'Unclosed client session' in message:
                logger.debug(f"Suppressed unclosed session warning: {message}")
            elif 'Unclosed connector' in message:
                logger.debug(f"Suppressed unclosed connector warning: {message}")
            elif 'Task was destroyed but it is pending' in message:
                logger.debug(f"Suppressed pending task warning: {message}")
            elif isinstance(exception, RecursionError):
                logger.warning(f"Recursion error detected: {exception}")
            else:
                # For other exceptions, log as warning instead of error
                logger.warning(f"Async exception: {context}")
        
        try:
            loop = asyncio.get_event_loop()
            loop.set_exception_handler(exception_handler)
        except RuntimeError:
            # Event loop might not be available
            pass

class AzurePermissionAnalyzer:
    """Main class for analyzing Azure permissions"""

    def __init__(self, subscription_id: str, auth_manager: AzureAuthManager, subscription_name: Optional[str] = None, organization_name: Optional[str] = None):
        self.subscription_id = subscription_id
        self.subscription_name = subscription_name or subscription_id
        self.auth_manager = auth_manager
        self.tenant_id = auth_manager.tenant_id  # Add tenant_id from auth_manager
        self.organization_name = organization_name or "Organization"  # Add organization_name
        self.api_client: Optional[AzureAPIClient] = None

        # Caches
        self._role_definitions_cache: Dict[str, Dict] = {}
        self._group_members_cache: Dict[str, Set[str]] = {}
        self._user_cache: Dict[str, Dict] = {}
        self._group_cache: Dict[str, Dict] = {}  # Added cache for group information

    async def __aenter__(self):
        """Async context manager entry"""
        self.api_client = await AzureAPIClient(self.auth_manager).__aenter__()
        # Set up exception handler for SSL/connection errors
        self.api_client.suppress_future_exceptions()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.api_client:
            await self.api_client.__aexit__(exc_type, exc_val, exc_tb)

    async def _get_tenant_info(self) -> Dict[str, str]:
        """Get tenant information including display name"""
        try:
            logger.info(f"Fetching tenant information for tenant ID: {self.tenant_id}")
            
            # Use Microsoft Graph API to get organization information
            url = "https://graph.microsoft.com/v1.0/organization"
            
            response = await self.api_client.get(url, api_type='graph')
            
            if response and 'value' in response and len(response['value']) > 0:
                org_info = response['value'][0]
                tenant_name = org_info.get('displayName', f'Tenant-{self.tenant_id[:8]}')
                logger.info(f"Retrieved tenant name: {tenant_name}")
                return {
                    'tenant_id': self.tenant_id,
                    'tenant_name': tenant_name
                }
            else:
                logger.warning("Could not retrieve tenant display name from Graph API")
                return {
                    'tenant_id': self.tenant_id,
                    'tenant_name': f'Tenant-{self.tenant_id[:8]}...'  # Fallback name
                }
                
        except Exception as e:
            logger.warning(f"Failed to fetch tenant display name: {e}")
            return {
                'tenant_id': self.tenant_id,
                'tenant_name': f'Tenant-{self.tenant_id[:8]}...'  # Fallback name
            }

    async def analyze_user_permissions(self, user_id: str) -> UserPermissionAnalysis:
        """Analyze all permissions for a specific user"""
        logger.info(f"Starting permission analysis for user {user_id}")

        # Get user details
        user_info = await self._get_user_info(user_id)
        if not user_info:
            raise ValueError(f"User {user_id} not found")
        
        # Get tenant information
        tenant_info = await self._get_tenant_info()

        # Get direct role assignments
        direct_assignments = await self._get_user_role_assignments(user_id)

        # Get group memberships and their role assignments
        group_assignments = await self._get_group_role_assignments(user_id)

        # Resolve all role definitions
        all_assignments = direct_assignments + group_assignments
        await self._resolve_role_definitions(all_assignments)

        # Compile all permissions
        all_permissions = await self._compile_permissions(all_assignments)

        # Get Key Vault permissions from subscriptions where user has assignments
        key_vault_permissions = await self._get_key_vault_permissions(user_id, all_assignments)

        # Get Storage Account permissions from subscriptions where user has assignments
        storage_account_permissions = await self._get_storage_account_permissions(user_id, all_assignments)

        # Create analysis result
        analysis = UserPermissionAnalysis(
            user_id=user_id,
            user_principal_name=user_info.get('userPrincipalName', ''),
            display_name=user_info.get('displayName', ''),
            tenant_id=self.tenant_id,
            tenant_name=tenant_info.get('tenant_name', f'Tenant-{self.tenant_id[:8]}...'),
            subscription_id=self.subscription_id,
            subscription_name=self.subscription_name,
            organization_name=self.organization_name,
            direct_assignments=[self._format_assignment(a) for a in direct_assignments],
            group_assignments=[self._format_assignment(a) for a in group_assignments],
            all_permissions=all_permissions,
            key_vault_permissions=key_vault_permissions,
            storage_account_permissions=storage_account_permissions
        )

        logger.info(f"Completed permission analysis for user {user_id}")
        return analysis

    async def _get_user_info(self, user_id: str) -> Dict:
        """Get user information from Microsoft Graph"""
        if user_id in self._user_cache:
            return self._user_cache[user_id]

        url = f"{GRAPH_API_URL}/users/{user_id}"
        scope = "https://graph.microsoft.com/.default"

        try:
            user_info = await self.api_client.make_request("GET", url, scope)
            self._user_cache[user_id] = user_info
            return user_info
        except Exception as e:
            logger.error(f"Failed to get user info for {user_id}: {e}")
            return {}

    async def _get_user_role_assignments(self, user_id: str) -> List[RoleAssignment]:
        """Get direct role assignments for a user"""
        url = f"{AZURE_MANAGEMENT_URL}/subscriptions/{self.subscription_id}"
        url += f"/providers/Microsoft.Authorization/roleAssignments"
        url += f"?api-version={RBAC_API_VERSION}"
        url += f"&$filter=principalId eq '{user_id}'"

        scope = f"{AZURE_MANAGEMENT_URL}/.default"
        assignments = []

        while url:
            response = await self.api_client.make_request("GET", url, scope)

            for item in response.get('value', []):
                assignment = RoleAssignment(
                    id=item['id'],
                    principal_id=item['properties']['principalId'],
                    principal_type=item['properties'].get('principalType', ''),
                    role_definition_id=item['properties']['roleDefinitionId'],
                    scope=item['properties']['scope'],
                    created_on=self._parse_datetime(item['properties'].get('createdOn')),
                    created_by=item['properties'].get('createdBy'),
                    condition=item['properties'].get('condition')
                )
                assignments.append(assignment)

            # Handle pagination
            url = response.get('nextLink')

        return assignments

    async def _get_group_role_assignments(self, user_id: str) -> List[RoleAssignment]:
        """Get role assignments through group memberships"""
        # First, get user's group memberships (including transitive)
        groups = await self._get_user_groups_with_details(user_id)

        # Get role assignments for each group
        assignments = []
        tasks = []

        for group_id, group_info in groups.items():
            tasks.append(self._get_group_assignments_with_info(group_id, group_info))

        if tasks:
            group_assignments_lists = await asyncio.gather(*tasks, return_exceptions=True)
            for group_assignments in group_assignments_lists:
                if isinstance(group_assignments, list):
                    assignments.extend(group_assignments)
                elif isinstance(group_assignments, Exception):
                    logger.error(f"Failed to get group assignments: {group_assignments}")

        return assignments

    async def _get_user_groups(self, user_id: str) -> Set[str]:
        """Get all groups a user belongs to (including transitive)"""
        url = f"{GRAPH_API_URL}/users/{user_id}/transitiveMemberOf"
        scope = "https://graph.microsoft.com/.default"

        groups = set()

        while url:
            try:
                response = await self.api_client.make_request("GET", url, scope)

                for group in response.get('value', []):
                    if group.get('@odata.type') == '#microsoft.graph.group':
                        groups.add(group['id'])

                url = response.get('@odata.nextLink')
            except Exception as e:
                logger.error(f"Failed to get user groups: {e}")
                break

        return groups

    async def _get_user_groups_with_details(self, user_id: str) -> Dict[str, Dict]:
        """Get all groups a user belongs to with their details (including transitive)"""
        url = f"{GRAPH_API_URL}/users/{user_id}/transitiveMemberOf"
        scope = "https://graph.microsoft.com/.default"

        groups = {}

        while url:
            try:
                response = await self.api_client.make_request("GET", url, scope)

                for group in response.get('value', []):
                    if group.get('@odata.type') == '#microsoft.graph.group':
                        group_id = group['id']
                        groups[group_id] = {
                            'id': group_id,
                            'displayName': group.get('displayName', 'Unknown Group'),
                            'description': group.get('description', ''),
                            'mail': group.get('mail', '')
                        }
                        # Cache the group information
                        self._group_cache[group_id] = groups[group_id]

                url = response.get('@odata.nextLink')
            except Exception as e:
                logger.error(f"Failed to get user groups: {e}")
                break

        return groups

    async def _get_group_assignments_with_info(self, group_id: str, group_info: Dict) -> List[RoleAssignment]:
        """Get role assignments for a group and attach group information"""
        assignments = await self._get_user_role_assignments(group_id)

        # Add group information to each assignment
        for assignment in assignments:
            assignment.group_name = group_info.get('displayName', 'Unknown Group')
            assignment.group_id = group_id

        return assignments

    async def _resolve_role_definitions(self, assignments: List[RoleAssignment]):
        """Resolve role definitions for assignments"""
        tasks = []

        for assignment in assignments:
            if assignment.role_definition_id not in self._role_definitions_cache:
                tasks.append(self._get_role_definition(assignment.role_definition_id))

        if tasks:
            definitions = await asyncio.gather(*tasks, return_exceptions=True)

            for definition in definitions:
                if isinstance(definition, dict) and 'id' in definition:
                    self._role_definitions_cache[definition['id']] = definition

        # Update assignments with role names
        for assignment in assignments:
            if assignment.role_definition_id in self._role_definitions_cache:
                role_def = self._role_definitions_cache[assignment.role_definition_id]
                assignment.role_name = role_def.get('properties', {}).get('roleName', '')

    async def _get_role_definition(self, role_definition_id: str) -> Dict:
        """Get a specific role definition"""
        url = f"{AZURE_MANAGEMENT_URL}{role_definition_id}?api-version={RBAC_API_VERSION}"
        scope = f"{AZURE_MANAGEMENT_URL}/.default"

        try:
            return await self.api_client.make_request("GET", url, scope)
        except Exception as e:
            logger.error(f"Failed to get role definition {role_definition_id}: {e}")
            return {}

    @staticmethod
    def _get_scope_type(scope: str) -> str:
        """Determine the type of scope from the scope string"""
        if not scope:
            return "Unknown"

        scope_parts = scope.lower().split('/')

        # Root scope
        if scope == '/':
            return "Root"

        # Subscription scope: /subscriptions/{id}
        if len(scope_parts) == 3 and scope_parts[1] == 'subscriptions':
            return "Subscription"

        # Resource Group scope: /subscriptions/{id}/resourceGroups/{name}
        if len(scope_parts) == 5 and scope_parts[1] == 'subscriptions' and scope_parts[3] == 'resourcegroups':
            return "Resource Group"

        # Management Group scope: /providers/Microsoft.Management/managementGroups/{id}
        if 'managementgroups' in scope.lower():
            return "Management Group"

        # Resource scope: has providers after resource group
        if len(scope_parts) > 5 and 'providers' in scope_parts:
            # Extract resource type
            provider_index = scope_parts.index('providers')
            if provider_index + 2 < len(scope_parts):
                provider = scope_parts[provider_index + 1]
                resource_type = scope_parts[provider_index + 2]
                return f"Resource ({provider}/{resource_type})"
            return "Resource"

        return "Custom"

    async def _compile_permissions(self, assignments: List[RoleAssignment]) -> Dict[str, List[str]]:
        """Compile all unique permissions from assignments"""
        permissions_by_scope = {}

        for assignment in assignments:
            scope = assignment.scope
            if scope not in permissions_by_scope:
                permissions_by_scope[scope] = set()

            if assignment.role_definition_id in self._role_definitions_cache:
                role_def = self._role_definitions_cache[assignment.role_definition_id]
                permissions = role_def.get('properties', {}).get('permissions', [])

                for perm in permissions:
                    actions = perm.get('actions', [])
                    data_actions = perm.get('dataActions', [])
                    permissions_by_scope[scope].update(actions)
                    permissions_by_scope[scope].update(data_actions)

        # Convert sets to lists for JSON serialization
        return {scope: list(perms) for scope, perms in permissions_by_scope.items()}

    async def _get_key_vault_permissions(self, user_id: str, assignments: List[RoleAssignment]) -> List[Dict]:
        """Get Key Vault access policies for the user from the analyzed subscription"""
        key_vault_permissions = []

        try:
            # Use only the subscription ID that was provided to the analyzer
            # This ensures we only check Key Vaults in the subscription being analyzed
            subscriptions = [self.subscription_id]
            
            logger.info(f"Checking Key Vaults in subscription: {self.subscription_id}")
            
            # Check if user has any assignments in this subscription
            has_subscription_access = any(
                self.subscription_id in assignment.scope 
                for assignment in assignments
            )
            
            if not has_subscription_access:
                logger.warning(f"User has no role assignments in subscription {self.subscription_id} - skipping Key Vault check")
                return key_vault_permissions

            for subscription_id in subscriptions:
                try:
                    # List Key Vaults in subscription
                    key_vaults = await self._list_key_vaults_in_subscription(subscription_id)

                    for kv in key_vaults:
                        kv_name = kv.get('name', '')
                        kv_id = kv.get('id', '')
                        resource_group = self._extract_resource_group_from_id(kv_id)

                        # Get access policies for this Key Vault
                        access_policies = await self._get_key_vault_access_policies(subscription_id, resource_group, kv_name, user_id)

                        if access_policies:
                            key_vault_permissions.append({
                                'key_vault_name': kv_name,
                                'key_vault_id': kv_id,
                                'subscription_id': subscription_id,
                                'subscription_name': self.subscription_name,
                                'resource_group': resource_group,
                                'location': kv.get('location', ''),
                                'access_policies': access_policies
                            })

                except Exception as e:
                    logger.warning(f"Failed to get Key Vault permissions for subscription {subscription_id}: {str(e)}")
                    continue

        except Exception as e:
            logger.error(f"Failed to get Key Vault permissions for user {user_id}: {str(e)}")

        return key_vault_permissions

    async def _list_key_vaults_in_subscription(self, subscription_id: str) -> List[Dict]:
        """List all Key Vaults in a subscription"""
        url = f"{AZURE_MANAGEMENT_URL}/subscriptions/{subscription_id}/providers/Microsoft.KeyVault/vaults"
        params = {"api-version": "2021-10-01"}

        try:
            data = await self._make_management_api_request(url, params)
            return data.get('value', [])
        except Exception as e:
            logger.warning(f"Failed to list Key Vaults in subscription {subscription_id}: {str(e)}")
            return []

    async def _get_key_vault_access_policies(self, subscription_id: str, resource_group: str, kv_name: str, user_id: str) -> List[Dict]:
        """Get access policies for a specific Key Vault and user"""
        url = f"{AZURE_MANAGEMENT_URL}/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.KeyVault/vaults/{kv_name}"
        params = {"api-version": "2021-10-01"}

        try:
            data = await self._make_management_api_request(url, params)
            properties = data.get('properties', {})
            access_policies = properties.get('accessPolicies', [])

            user_policies = []
            for policy in access_policies:
                object_id = policy.get('objectId', '')

                # Check if this policy applies to the user (direct or through group)
                if object_id == user_id or await self._is_user_in_group(user_id, object_id):
                    permissions = policy.get('permissions', {})
                    user_policies.append({
                        'object_id': object_id,
                        'tenant_id': policy.get('tenantId', ''),
                        'permissions': {
                            'keys': permissions.get('keys', []),
                            'secrets': permissions.get('secrets', []),
                            'certificates': permissions.get('certificates', []),
                            'storage': permissions.get('storage', [])
                        }
                    })

            return user_policies

        except Exception as e:
            logger.warning(f"Failed to get Key Vault access policies for {kv_name}: {str(e)}")
            return []

    async def _get_storage_account_permissions(self, user_id: str, assignments: List[RoleAssignment]) -> List[Dict]:
        """Get storage account permissions for a user based on role assignments"""
        storage_permissions = []
        
        # Use only the subscription ID that was provided to the analyzer
        # This ensures we only check storage accounts in the subscription being analyzed
        subscription_ids = [self.subscription_id]
        
        logger.info(f"Checking storage accounts in subscription: {self.subscription_id}")
        
        # Check if user has any assignments in this subscription
        has_subscription_access = any(
            self.subscription_id in assignment.scope 
            for assignment in assignments
        )
        
        if not has_subscription_access:
            logger.warning(f"User has no role assignments in subscription {self.subscription_id}")
            return storage_permissions
        
        # Storage-related permissions to check for
        storage_permissions_to_check = [
            "Microsoft.Storage/storageAccounts/listKeys/action",
            "Microsoft.Storage/storageAccounts/regenerateKey/action", 
            "Microsoft.Storage/storageAccounts/read",
            "Microsoft.Storage/storageAccounts/write",
            "Microsoft.Storage/storageAccounts/delete",
            "Microsoft.Storage/storageAccounts/blobServices/containers/read",
            "Microsoft.Storage/storageAccounts/blobServices/containers/write",
            "Microsoft.Storage/storageAccounts/fileServices/shares/read",
            "Microsoft.Storage/storageAccounts/fileServices/shares/write",
            "Microsoft.Storage/storageAccounts/queueServices/queues/read",
            "Microsoft.Storage/storageAccounts/queueServices/queues/write",
            "Microsoft.Storage/storageAccounts/tableServices/tables/read",
            "Microsoft.Storage/storageAccounts/tableServices/tables/write"
        ]
        
        # Check which storage permissions the user has from role definitions
        user_storage_permissions = set()
        logger.info(f"Checking storage permissions for {len(assignments)} role assignments")
        
        for assignment in assignments:
            # Get permissions from the role definition cache
            if assignment.role_definition_id in self._role_definitions_cache:
                role_def = self._role_definitions_cache[assignment.role_definition_id]
                role_name = assignment.role_name or role_def.get('properties', {}).get('roleName', 'Unknown')
                logger.debug(f"Checking role: {role_name} (ID: {assignment.role_definition_id})")
                
                permissions = role_def.get('properties', {}).get('permissions', [])
                
                # Log Owner role details for debugging
                if 'owner' in role_name.lower():
                    logger.info(f"Owner role detected: {role_name}")
                    logger.info(f"Owner role permissions structure: {permissions}")
                
                for perm in permissions:
                    actions = perm.get('actions', [])
                    data_actions = perm.get('dataActions', [])
                    
                    # Check each action against storage permissions
                    for action in actions + data_actions:
                        # Check for wildcard permissions that grant storage access
                        if action == "*" or action == "Microsoft.Storage/*":
                            user_storage_permissions.update(storage_permissions_to_check)
                            logger.info(f"User has wildcard permission: {action} via role {role_name}")
                        # Check for specific storage permissions
                        elif any(self._action_matches_pattern(action, perm) for perm in storage_permissions_to_check):
                            user_storage_permissions.add(action)
                            logger.debug(f"User has storage permission: {action} via role {role_name}")
            else:
                logger.warning(f"Role definition {assignment.role_definition_id} not found in cache")
        
        # Special check for Owner, Contributor roles that should have storage access
        for assignment in assignments:
            role_name = assignment.role_name
            if role_name and ('owner' in role_name.lower() or 'contributor' in role_name.lower()):
                logger.info(f"User has {role_name} role - granting storage permissions")
                # Owner and Contributor should have these permissions
                if 'owner' in role_name.lower():
                    user_storage_permissions.update(storage_permissions_to_check)
                elif 'contributor' in role_name.lower():
                    # Contributor has all except delete
                    user_storage_permissions.update([p for p in storage_permissions_to_check if 'delete' not in p.lower()])
        
        logger.info(f"Found {len(user_storage_permissions)} storage-related permissions for user")
        
        # If user has any storage permissions, get storage accounts in their subscriptions
        if user_storage_permissions:
            for subscription_id in subscription_ids:
                try:
                    storage_accounts = await self._get_storage_accounts_in_subscription(subscription_id)
                    
                    for storage_account in storage_accounts:
                        storage_account_name = storage_account.get('name', '')
                        resource_group = self._extract_resource_group_from_id(storage_account.get('id', ''))
                        
                        # Determine specific permissions for this storage account
                        can_list_keys = any(
                            perm in user_storage_permissions 
                            for perm in ["Microsoft.Storage/storageAccounts/listKeys/action", "*", "Microsoft.Storage/*"]
                        )
                        
                        can_regenerate_keys = any(
                            perm in user_storage_permissions 
                            for perm in ["Microsoft.Storage/storageAccounts/regenerateKey/action", "*", "Microsoft.Storage/*"]
                        )
                        
                        effective_permissions = []
                        if can_list_keys:
                            effective_permissions.append("List Storage Keys")
                        if can_regenerate_keys:
                            effective_permissions.append("Regenerate Storage Keys")
                        
                        # Add other permissions
                        if "Microsoft.Storage/storageAccounts/read" in user_storage_permissions or "*" in user_storage_permissions:
                            effective_permissions.append("Read Storage Account")
                        if "Microsoft.Storage/storageAccounts/write" in user_storage_permissions or "*" in user_storage_permissions:
                            effective_permissions.append("Write Storage Account")
                        if "Microsoft.Storage/storageAccounts/delete" in user_storage_permissions or "*" in user_storage_permissions:
                            effective_permissions.append("Delete Storage Account")
                        
                        storage_permission = {
                            'storage_account_name': storage_account_name,
                            'resource_group': resource_group,
                            'subscription_id': subscription_id,
                            'subscription_name': self.subscription_name,
                            'location': storage_account.get('location', ''),
                            'sku': storage_account.get('sku', {}).get('name', ''),
                            'kind': storage_account.get('kind', ''),
                            'can_list_keys': can_list_keys,
                            'can_regenerate_keys': can_regenerate_keys,
                            'effective_permissions': effective_permissions,
                            'security_level': 'High' if can_list_keys or can_regenerate_keys else 'Medium' if effective_permissions else 'Low'
                        }
                        
                        storage_permissions.append(storage_permission)
                        
                except Exception as e:
                    logger.warning(f"Failed to get storage accounts for subscription {subscription_id}: {str(e)}")
                    continue
        
        logger.info(f"Found {len(storage_permissions)} storage account permissions for user {user_id}")
        return storage_permissions

    async def _get_storage_accounts_in_subscription(self, subscription_id: str) -> List[Dict]:
        """Get all storage accounts in a subscription"""
        url = f"{AZURE_MANAGEMENT_URL}/subscriptions/{subscription_id}/providers/Microsoft.Storage/storageAccounts"
        scope = "https://management.azure.com/.default"
        params = {"api-version": "2023-01-01"}
        
        storage_accounts = []
        
        try:
            response = await self.api_client.make_request("GET", url, scope, params=params)
            storage_accounts = response.get('value', [])
            
            logger.info(f"Found {len(storage_accounts)} storage accounts in subscription {subscription_id}")
            
        except Exception as e:
            logger.warning(f"Failed to get storage accounts for subscription {subscription_id}: {str(e)}")
        
        return storage_accounts

    async def _get_group_members(self, group_id: str) -> List[str]:
        """Get all user members of a security group"""
        url = f"{GRAPH_API_URL}/groups/{group_id}/members"
        scope = "https://graph.microsoft.com/.default"
        
        # Use set to automatically prevent duplicates during collection
        members_set = set()
        
        while url:
            try:
                response = await self.api_client.make_request("GET", url, scope)
                
                for member in response.get('value', []):
                    # Only include users (not groups or other object types)
                    if member.get('@odata.type') == '#microsoft.graph.user':
                        member_id = member.get('id')
                        if member_id:  # Ensure member ID is valid
                            members_set.add(member_id)
                
                url = response.get('@odata.nextLink')
            except Exception as e:
                logger.error(f"Failed to get group members for group {group_id}: {e}")
                break
        
        # Convert set back to list
        members = list(members_set)
        logger.info(f"Found {len(members)} unique user members in group {group_id}")
        return members

    async def _is_user_in_group(self, user_id: str, group_id: str) -> bool:
        """Check if user is member of a specific group"""
        try:
            # Get user's group memberships
            url = f"{GRAPH_API_URL}/users/{user_id}/memberOf"
            scope = "https://graph.microsoft.com/.default"
            data = await self._make_graph_api_request(url, scope)

            group_ids = [group.get('id', '') for group in data.get('value', [])]
            return group_id in group_ids

        except Exception as e:
            logger.warning(f"Failed to check group membership for user {user_id}, group {group_id}: {str(e)}")
            return False

    def _extract_subscriptions_from_assignments(self, assignments: List[RoleAssignment]) -> List[str]:
        """Extract unique subscription IDs from role assignments"""
        subscription_ids = set()

        for assignment in assignments:
            scope = assignment.scope
            if '/subscriptions/' in scope:
                # Extract subscription ID from scope path
                parts = scope.split('/')
                try:
                    sub_index = parts.index('subscriptions')
                    if sub_index + 1 < len(parts):
                        sub_id = parts[sub_index + 1]
                        subscription_ids.add(sub_id)
                except (ValueError, IndexError):
                    continue

        return list(subscription_ids)

    def _extract_resource_group_from_id(self, resource_id: str) -> str:
        """Extract resource group name from Azure resource ID"""
        try:
            parts = resource_id.split('/')
            rg_index = parts.index('resourceGroups')
            return parts[rg_index + 1]
        except (ValueError, IndexError):
            return ''
    
    @staticmethod
    def _action_matches_pattern(action: str, pattern: str) -> bool:
        """Check if action matches a pattern (supports wildcards)"""
        if pattern == "*":
            return True
        if pattern.endswith("/*"):
            prefix = pattern[:-2]
            return action.startswith(prefix + "/")
        return action == pattern

    async def _make_management_api_request(self, url: str, params: Dict) -> Dict:
        """Make a request to Azure Management API"""
        scope = "https://management.azure.com/.default"
        return await self.api_client.make_request("GET", url, scope, params=params)

    async def _make_graph_api_request(self, url: str, scope: str) -> Dict:
        """Make a request to Microsoft Graph API"""
        return await self.api_client.make_request("GET", url, scope)

    def _format_assignment(self, assignment: RoleAssignment) -> Dict:
        """Format assignment for output"""
        result = {
            'role_name': assignment.role_name,
            'scope': assignment.scope,
            'scope_type': self._get_scope_type(assignment.scope),
            'principal_type': assignment.principal_type,
            'created_on': assignment.created_on.isoformat() if assignment.created_on else None,
            'condition': assignment.condition
        }

        # Add group information if this is a group assignment
        if assignment.group_name:
            result['group_name'] = assignment.group_name
            result['group_id'] = assignment.group_id

        return result

    @staticmethod
    def _parse_datetime(date_str: Optional[str]) -> Optional[datetime]:
        """Parse datetime string from Azure API"""
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            return None

class OutputFormatter:
    """Format analysis results for different output types"""

    @staticmethod
    def to_json(analysis: UserPermissionAnalysis, file_path: Path):
        """Export analysis to JSON"""
        with file_path.open('w') as f:
            json.dump(analysis.dict(), f, indent=2, default=str)
        logger.info(f"Exported JSON to {file_path}")

    @staticmethod
    def to_csv(analysis: UserPermissionAnalysis, file_path: Path):
        """Export analysis to CSV"""
        # Flatten the data for CSV
        rows = []

        # Direct assignments
        for assignment in analysis.direct_assignments:
            row = {
                'user_id': analysis.user_id,
                'user_principal_name': analysis.user_principal_name,
                'assignment_type': 'direct',
                **assignment
            }
            rows.append(row)

        # Group assignments
        for assignment in analysis.group_assignments:
            row = {
                'user_id': analysis.user_id,
                'user_principal_name': analysis.user_principal_name,
                'assignment_type': 'group',
                **assignment
            }
            rows.append(row)

        df = pd.DataFrame(rows)
        df.to_csv(file_path, index=False)
        logger.info(f"Exported CSV to {file_path}")

    @staticmethod
    def to_excel(analyses: List[UserPermissionAnalysis], file_path: Path):
        """Export multiple analyses to Excel with multiple sheets"""
        with pd.ExcelWriter(file_path, engine='openpyxl') as writer:
            # Summary sheet
            summary_data = []
            for analysis in analyses:
                summary_data.append({
                    'User ID': analysis.user_id,
                    'Principal Name': analysis.user_principal_name,
                    'Display Name': analysis.display_name,
                    'Direct Assignments': len(analysis.direct_assignments),
                    'Group Assignments': len(analysis.group_assignments),
                    'Total Unique Scopes': len(analysis.all_permissions),
                    'Analyzed At': analysis.analyzed_at
                })

            pd.DataFrame(summary_data).to_excel(writer, sheet_name='Summary', index=False)

            # Detailed assignments sheet
            all_assignments = []
            for analysis in analyses:
                for assignment in analysis.direct_assignments:
                    assignment_data = {
                        'User': analysis.user_principal_name,
                        'Assignment Type': 'Direct',
                        'Role': assignment['role_name'],
                        'Scope Type': assignment.get('scope_type', 'Unknown'),
                        'Scope': assignment['scope'],
                        'Created On': assignment.get('created_on'),
                        'Condition': assignment.get('condition')
                    }
                    all_assignments.append(assignment_data)

                for assignment in analysis.group_assignments:
                    assignment_data = {
                        'User': analysis.user_principal_name,
                        'Assignment Type': 'Group',
                        'Group Name': assignment.get('group_name', 'Unknown Group'),
                        'Role': assignment['role_name'],
                        'Scope Type': assignment.get('scope_type', 'Unknown'),
                        'Scope': assignment['scope'],
                        'Created On': assignment.get('created_on'),
                        'Condition': assignment.get('condition')
                    }
                    all_assignments.append(assignment_data)

            if all_assignments:
                pd.DataFrame(all_assignments).to_excel(writer, sheet_name='Assignments', index=False)

        logger.info(f"Exported Excel to {file_path}")

    @staticmethod
    def to_html_report(analyses: List[UserPermissionAnalysis], output_path: Path, organization_name: str = "Organization"):
        """Generate comprehensive HTML report for all analyzed users"""
        from jinja2 import Template
        from datetime import datetime
        from collections import Counter
        import json
        import os
        
        # Get the template path
        template_path = Path(__file__).parent / "templates" / "report_template.html"
        
        # Read the template
        with template_path.open('r', encoding='utf-8') as f:
            template_content = f.read()
        
        template = Template(template_content)
        
        # Calculate summary statistics
        total_users = len(analyses)
        total_role_assignments = sum(len(analysis.direct_assignments) + len(analysis.group_assignments) for analysis in analyses)
        
        # Count unique roles
        all_roles = []
        for analysis in analyses:
            all_roles.extend([assignment['role_name'] for assignment in analysis.direct_assignments])
            all_roles.extend([assignment['role_name'] for assignment in analysis.group_assignments])
        
        role_counts = Counter(all_roles)
        unique_roles = len(role_counts)
        
        # Identify high-risk users (those with Owner, Contributor, or administrative roles)
        high_risk_roles = {'Owner', 'Contributor', 'User Access Administrator', 'Global Administrator', 'Security Administrator'}
        high_risk_users = 0
        critical_permissions_count = 0
        
        for analysis in analyses:
            user_roles = set()
            user_roles.update([assignment['role_name'] for assignment in analysis.direct_assignments])
            user_roles.update([assignment['role_name'] for assignment in analysis.group_assignments])
            
            if any(role in high_risk_roles for role in user_roles):
                high_risk_users += 1
                critical_permissions_count += len([role for role in user_roles if role in high_risk_roles])
        
        # Get subscription info from first analysis
        subscription_name = analyses[0].subscription_name if analyses else "Unknown"
        
        # Generate common roles table
        common_roles_table = ""
        for role, count in role_counts.most_common(10):
            risk_level = "High" if role in high_risk_roles else "Medium" if "Admin" in role else "Low"
            risk_class = "danger" if risk_level == "High" else "warning" if risk_level == "Medium" else "success"
            common_roles_table += f"""
                <tr>
                    <td><strong>{role}</strong></td>
                    <td>{count}</td>
                    <td><span class="badge badge-{risk_class}">{risk_level}</span></td>
                </tr>
            """
        
        # Generate user details
        user_details = ""
        for analysis in analyses:
            # Calculate user risk score
            user_roles = [assignment['role_name'] for assignment in analysis.direct_assignments + analysis.group_assignments]
            risk_score = sum(3 if role in high_risk_roles else 1 for role in user_roles)
            risk_level = "High" if risk_score >= 5 else "Medium" if risk_score >= 2 else "Low"
            risk_class = "danger" if risk_level == "High" else "warning" if risk_level == "Medium" else "success"
            
            direct_count = len(analysis.direct_assignments)
            group_count = len(analysis.group_assignments)
            
            user_details += f"""
                <div class="user-card">
                    <div class="user-header">
                        <div class="user-info">
                            <h3>{analysis.display_name}</h3>
                            <p>{analysis.user_principal_name}</p>
                            <p><strong>User ID:</strong> {analysis.user_id}</p>
                        </div>
                        <div>
                            <span class="badge badge-{risk_class}">Risk: {risk_level}</span>
                            <span class="badge badge-primary">{direct_count} Direct</span>
                            <span class="badge badge-info">{group_count} Group</span>
                        </div>
                    </div>
                    
                    <button class="collapsible">Direct Role Assignments ({direct_count})</button>
                    <div class="collapsible-content">
                        <div class="permission-group">
            """
            
            for assignment in analysis.direct_assignments:
                scope_type = assignment.get('scope_type', 'Unknown')
                scope_name = assignment['scope'].split('/')[-1] if assignment['scope'] else 'Unknown'
                user_details += f"""
                    <div class="permission-item">
                        <strong>{assignment['role_name']}</strong> on {scope_name} ({scope_type})
                    </div>
                """
            
            user_details += f"""
                        </div>
                    </div>
                    
                    <button class="collapsible">Group-Based Assignments ({group_count})</button>
                    <div class="collapsible-content">
                        <div class="permission-group">
            """
            
            for assignment in analysis.group_assignments:
                scope_type = assignment.get('scope_type', 'Unknown')
                scope_name = assignment['scope'].split('/')[-1] if assignment['scope'] else 'Unknown'
                group_name = assignment.get('group_name', 'Unknown Group')
                user_details += f"""
                    <div class="permission-item">
                        <strong>{assignment['role_name']}</strong> on {scope_name} ({scope_type}) via <em>{group_name}</em>
                    </div>
                """
            
            # Add Key Vault and Storage permissions if any
            kv_count = len(analysis.key_vault_permissions)
            storage_count = len(analysis.storage_account_permissions)
            
            if kv_count > 0:
                user_details += f"""
                        </div>
                    </div>
                    
                    <button class="collapsible">Key Vault Access ({kv_count})</button>
                    <div class="collapsible-content">
                        <div class="permission-group">
                """
                
                for kv in analysis.key_vault_permissions:
                    policy_count = len(kv.get('access_policies', []))
                    user_details += f"""
                        <div class="permission-item">
                            <strong>{kv.get('key_vault_name', 'Unknown')}</strong> - {policy_count} policies
                        </div>
                    """
            
            if storage_count > 0:
                user_details += f"""
                        </div>
                    </div>
                    
                    <button class="collapsible">Storage Account Access ({storage_count})</button>
                    <div class="collapsible-content">
                        <div class="permission-group">
                """
                
                for sa in analysis.storage_account_permissions:
                    critical_access = " (CRITICAL)" if sa.get('can_list_keys') or sa.get('can_regenerate_keys') else ""
                    perm_count = len(sa.get('effective_permissions', []))
                    user_details += f"""
                        <div class="permission-item">
                            <strong>{sa.get('storage_account_name', 'Unknown')}</strong> - {perm_count} permissions{critical_access}
                        </div>
                    """
            
            user_details += """
                        </div>
                    </div>
                </div>
            """
        
        # Generate comprehensive chart data for enhanced visualizations
        chart_labels = json.dumps([role for role, _ in role_counts.most_common(5)])
        chart_data = json.dumps([count for _, count in role_counts.most_common(5)])
        
        # Advanced Security Insights Data
        security_insights = {
            'privileged_users': [],
            'stale_assignments': [],
            'excessive_permissions': [],
            'cross_subscription_access': [],
            'anomalies': []
        }
        
        # Risk assessment data
        risk_distribution = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        permission_trends = []
        compliance_gaps = []
        
        # Timeline data for analysis
        timeline_events = []
        
        # Process each user for advanced analytics
        for analysis in analyses:
            user_roles = [assignment['role_name'] for assignment in analysis.direct_assignments + analysis.group_assignments]
            total_permissions = len(analysis.direct_assignments) + len(analysis.group_assignments) + len(analysis.key_vault_permissions) + len(analysis.storage_account_permissions)
            
            # Calculate comprehensive risk score
            base_risk = sum(3 if role in high_risk_roles else 1 for role in user_roles)
            kv_risk = len(analysis.key_vault_permissions) * 2
            storage_risk = sum(2 if sa.get('can_list_keys') or sa.get('can_regenerate_keys') else 1 for sa in analysis.storage_account_permissions)
            comprehensive_risk = base_risk + kv_risk + storage_risk
            
            # Classify risk level
            if comprehensive_risk >= 15:
                risk_level = 'Critical'
                risk_distribution['Critical'] += 1
            elif comprehensive_risk >= 8:
                risk_level = 'High'
                risk_distribution['High'] += 1
            elif comprehensive_risk >= 3:
                risk_level = 'Medium'
                risk_distribution['Medium'] += 1
            else:
                risk_level = 'Low'
                risk_distribution['Low'] += 1
            
            # Identify privileged users
            if any(role in high_risk_roles for role in user_roles):
                security_insights['privileged_users'].append({
                    'name': analysis.display_name,
                    'email': analysis.user_principal_name,
                    'risk_score': comprehensive_risk,
                    'high_risk_roles': [role for role in user_roles if role in high_risk_roles],
                    'total_permissions': total_permissions
                })
            
            # Detect excessive permissions (users with >10 direct assignments)
            if len(analysis.direct_assignments) > 10:
                security_insights['excessive_permissions'].append({
                    'name': analysis.display_name,
                    'email': analysis.user_principal_name,
                    'direct_count': len(analysis.direct_assignments),
                    'group_count': len(analysis.group_assignments),
                    'total_count': total_permissions
                })
            
            # Detect cross-subscription patterns (simplified - based on scope diversity)
            unique_scopes = set()
            for assignment in analysis.direct_assignments + analysis.group_assignments:
                if assignment.get('scope'):
                    scope_parts = assignment['scope'].split('/')
                    if len(scope_parts) >= 3:
                        unique_scopes.add(scope_parts[2])  # subscription level
            
            if len(unique_scopes) > 1:
                security_insights['cross_subscription_access'].append({
                    'name': analysis.display_name,
                    'email': analysis.user_principal_name,
                    'scope_count': len(unique_scopes),
                    'scopes': list(unique_scopes)[:3]  # First 3 for display
                })
            
            # Add to timeline
            timeline_events.append({
                'date': analysis.analyzed_at.strftime('%Y-%m-%d') if hasattr(analysis.analyzed_at, 'strftime') else datetime.now().strftime('%Y-%m-%d'),
                'user': analysis.display_name,
                'event': 'Permission Analysis',
                'risk_level': risk_level,
                'details': f"{total_permissions} total permissions assigned"
            })
        
        # Generate anomaly detection results
        avg_permissions = total_role_assignments / total_users if total_users > 0 else 0
        for analysis in analyses:
            user_permissions = len(analysis.direct_assignments) + len(analysis.group_assignments)
            if user_permissions > avg_permissions * 2:  # More than 2x average
                security_insights['anomalies'].append({
                    'type': 'Excessive Permissions',
                    'user': analysis.display_name,
                    'value': user_permissions,
                    'threshold': avg_permissions * 2,
                    'severity': 'High'
                })
        
        # Comprehensive Compliance and Audit Trail Analysis
        compliance_frameworks = {
            'SOC 2': {'score': 0, 'max_score': 0, 'findings': []},
            'ISO 27001': {'score': 0, 'max_score': 0, 'findings': []},
            'GDPR': {'score': 0, 'max_score': 0, 'findings': []},
            'PCI DSS': {'score': 0, 'max_score': 0, 'findings': []},
            'NIST': {'score': 0, 'max_score': 0, 'findings': []}
        }
        
        # SOC 2 Type II Compliance Assessment
        compliance_frameworks['SOC 2']['max_score'] = 10
        
        # CC6.1 - Logical and physical access controls
        if len(security_insights['privileged_users']) / total_users <= 0.1:  # ≤10% privileged
            compliance_frameworks['SOC 2']['score'] += 2
        else:
            compliance_frameworks['SOC 2']['findings'].append('CC6.1: Excessive privileged access detected')
        
        # CC6.2 - Access control design and implementation
        if len(security_insights['excessive_permissions']) == 0:
            compliance_frameworks['SOC 2']['score'] += 2
        else:
            compliance_frameworks['SOC 2']['findings'].append('CC6.2: Users with excessive direct permissions')
        
        # CC6.3 - Network access controls
        if len(security_insights['cross_subscription_access']) / total_users <= 0.05:  # ≤5% cross-sub
            compliance_frameworks['SOC 2']['score'] += 2
        else:
            compliance_frameworks['SOC 2']['findings'].append('CC6.3: Cross-subscription access requires review')
        
        # CC6.6 - Privileged access management
        high_risk_storage = [u for u in analyses if any(sa.get('can_list_keys') for sa in u.storage_account_permissions)]
        if len(high_risk_storage) <= 2:  # Minimal storage key access
            compliance_frameworks['SOC 2']['score'] += 2
        else:
            compliance_frameworks['SOC 2']['findings'].append('CC6.6: Storage key access requires stricter controls')
        
        # CC6.7 - Access control monitoring
        compliance_frameworks['SOC 2']['score'] += 2  # Assuming monitoring is in place via this analysis
        
        # ISO 27001 Compliance Assessment
        compliance_frameworks['ISO 27001']['max_score'] = 8
        
        # A.9.1.2 - Access to networks and network services
        if avg_permissions <= 3:  # Reasonable permission level
            compliance_frameworks['ISO 27001']['score'] += 2
        else:
            compliance_frameworks['ISO 27001']['findings'].append('A.9.1.2: High average permissions per user')
        
        # A.9.2.1 - User registration and de-registration
        if len(security_insights['anomalies']) == 0:
            compliance_frameworks['ISO 27001']['score'] += 2
        else:
            compliance_frameworks['ISO 27001']['findings'].append('A.9.2.1: Permission anomalies detected')
        
        # A.9.2.3 - Management of privileged access rights
        if risk_distribution['Critical'] == 0:
            compliance_frameworks['ISO 27001']['score'] += 2
        else:
            compliance_frameworks['ISO 27001']['findings'].append('A.9.2.3: Critical risk users require immediate review')
        
        # A.9.4.2 - Secure log-on procedures
        compliance_frameworks['ISO 27001']['score'] += 2  # Assuming secure logon via Azure AD
        
        # GDPR Compliance Assessment (Data Protection Officer requirements)
        compliance_frameworks['GDPR']['max_score'] = 6
        
        # Article 32 - Security of processing
        if len(security_insights['privileged_users']) <= total_users * 0.15:
            compliance_frameworks['GDPR']['score'] += 2
        else:
            compliance_frameworks['GDPR']['findings'].append('Art.32: Excessive data access permissions')
        
        # Article 25 - Data protection by design and by default
        if len(security_insights['excessive_permissions']) == 0:
            compliance_frameworks['GDPR']['score'] += 2
        else:
            compliance_frameworks['GDPR']['findings'].append('Art.25: Principle of data minimization violated')
        
        # Article 30 - Records of processing activities
        compliance_frameworks['GDPR']['score'] += 2  # Assuming this analysis serves as records
        
        # PCI DSS Compliance Assessment
        compliance_frameworks['PCI DSS']['max_score'] = 8
        
        # Requirement 7 - Restrict access to cardholder data
        if len([u for u in security_insights['privileged_users'] if u['risk_score'] >= 10]) <= 1:
            compliance_frameworks['PCI DSS']['score'] += 2
        else:
            compliance_frameworks['PCI DSS']['findings'].append('Req.7: High-risk access to sensitive data')
        
        # Requirement 8 - Identify and authenticate access
        compliance_frameworks['PCI DSS']['score'] += 2  # Assuming Azure AD authentication
        
        # Requirement 10 - Log and monitor access
        compliance_frameworks['PCI DSS']['score'] += 2  # Assuming logging is enabled
        
        # Requirement 11 - Regular security testing
        compliance_frameworks['PCI DSS']['score'] += 2  # This analysis counts as testing
        
        # NIST Cybersecurity Framework Assessment
        compliance_frameworks['NIST']['max_score'] = 10
        
        # PR.AC-1: Identities and credentials are issued, managed, verified, revoked, and audited
        if len(security_insights['anomalies']) / total_users <= 0.05:
            compliance_frameworks['NIST']['score'] += 2
        else:
            compliance_frameworks['NIST']['findings'].append('PR.AC-1: Identity management anomalies detected')
        
        # PR.AC-3: Remote access is managed
        if len(security_insights['cross_subscription_access']) == 0:
            compliance_frameworks['NIST']['score'] += 2
        else:
            compliance_frameworks['NIST']['findings'].append('PR.AC-3: Remote access patterns require review')
        
        # PR.AC-4: Access permissions and authorizations are managed
        if avg_permissions <= 4:
            compliance_frameworks['NIST']['score'] += 2
        else:
            compliance_frameworks['NIST']['findings'].append('PR.AC-4: Access permissions may be over-provisioned')
        
        # DE.CM-3: Personnel activity is monitored
        compliance_frameworks['NIST']['score'] += 2  # This analysis provides monitoring
        
        # RS.RP-1: Response plan is executed
        compliance_frameworks['NIST']['score'] += 2  # Assuming response procedures exist
        
        # Audit Trail Generation
        audit_events = []
        current_time = datetime.now().isoformat()
        
        # Generate audit events for high-risk findings
        for user_data in security_insights['privileged_users']:
            audit_events.append({
                'timestamp': current_time,
                'event_type': 'PRIVILEGED_ACCESS_DETECTED',
                'user': user_data['email'],
                'details': f"User has {len(user_data['high_risk_roles'])} high-risk roles",
                'risk_score': user_data['risk_score'],
                'requires_review': user_data['risk_score'] >= 10
            })
        
        for anomaly in security_insights['anomalies']:
            audit_events.append({
                'timestamp': current_time,
                'event_type': 'PERMISSION_ANOMALY',
                'user': anomaly['user'],
                'details': f"{anomaly['type']}: {anomaly['value']} (threshold: {anomaly['threshold']})",
                'severity': anomaly['severity'],
                'requires_action': True
            })
        
        # Add compliance gap events
        admin_users_without_mfa = [user for user in security_insights['privileged_users']]  # Simplified
        if len(admin_users_without_mfa) > 0:
            compliance_gaps.append({
                'category': 'Multi-Factor Authentication',
                'severity': 'Critical',
                'affected_users': len(admin_users_without_mfa),
                'description': 'Privileged users should have MFA enforced'
            })
            
            audit_events.append({
                'timestamp': current_time,
                'event_type': 'COMPLIANCE_GAP',
                'category': 'MFA_ENFORCEMENT',
                'details': f"{len(admin_users_without_mfa)} privileged users without verified MFA",
                'severity': 'Critical',
                'compliance_frameworks': ['SOC 2', 'ISO 27001', 'PCI DSS']
            })
        
        # Calculate overall compliance scores
        overall_compliance_score = sum(
            (framework['score'] / framework['max_score']) * 100 
            for framework in compliance_frameworks.values()
        ) / len(compliance_frameworks)
        
        compliance_summary = {
            'overall_score': round(overall_compliance_score, 1),
            'frameworks': compliance_frameworks,
            'total_findings': sum(len(framework['findings']) for framework in compliance_frameworks.values()),
            'critical_gaps': len([gap for gap in compliance_gaps if gap['severity'] == 'Critical']),
            'audit_events': audit_events[:50]  # Last 50 events
        }
        
        # Role distribution for radar chart
        role_categories = {
            'Administrative': ['Owner', 'Contributor', 'User Access Administrator'],
            'Security': ['Security Administrator', 'Security Reader', 'Key Vault Administrator'],
            'Developer': ['Developer', 'DevTest Labs User', 'Application Developer'],
            'Reader': ['Reader', 'Monitoring Reader', 'Log Analytics Reader'],
            'Network': ['Network Contributor', 'DNS Zone Contributor', 'Traffic Manager Contributor']
        }
        
        role_distribution_data = {}
        for category, roles in role_categories.items():
            count = sum(role_counts.get(role, 0) for role in roles)
            role_distribution_data[category] = count
        
        # Permission matrix for heatmap
        permission_matrix = []
        for analysis in analyses[:10]:  # Top 10 users for matrix
            user_data = {
                'user': analysis.display_name[:20] + '...' if len(analysis.display_name) > 20 else analysis.display_name,
                'owner': 1 if 'Owner' in [a['role_name'] for a in analysis.direct_assignments + analysis.group_assignments] else 0,
                'contributor': 1 if 'Contributor' in [a['role_name'] for a in analysis.direct_assignments + analysis.group_assignments] else 0,
                'reader': 1 if 'Reader' in [a['role_name'] for a in analysis.direct_assignments + analysis.group_assignments] else 0,
                'admin': 1 if any(role in high_risk_roles for role in [a['role_name'] for a in analysis.direct_assignments + analysis.group_assignments]) else 0,
                'keyvault': len(analysis.key_vault_permissions),
                'storage': len(analysis.storage_account_permissions)
            }
            permission_matrix.append(user_data)
        
        # Advanced Recommendations Engine
        recommendations = []
        
        # Analyze patterns and generate recommendations
        if len(security_insights['privileged_users']) > total_users * 0.2:  # >20% have privileged access
            recommendations.append({
                'priority': 'Critical',
                'category': 'Access Governance',
                'title': 'Excessive Privileged Access Detected',
                'description': f'{len(security_insights["privileged_users"])} users ({round(len(security_insights["privileged_users"])/total_users*100, 1)}%) have privileged access. Consider implementing just-in-time access.',
                'action_items': [
                    'Review necessity of each privileged role assignment',
                    'Implement Azure AD Privileged Identity Management (PIM)',
                    'Establish regular access reviews for privileged accounts',
                    'Consider role-based access with least privilege principle'
                ],
                'compliance_impact': 'High - affects SOC 2 and ISO 27001 compliance'
            })
        
        if len(security_insights['excessive_permissions']) > 0:
            recommendations.append({
                'priority': 'High',
                'category': 'Permission Optimization',
                'title': 'Users with Excessive Direct Permissions',
                'description': f'{len(security_insights["excessive_permissions"])} users have more than 10 direct role assignments. This indicates potential permission sprawl.',
                'action_items': [
                    'Consolidate permissions using Azure AD groups',
                    'Review and remove unnecessary direct assignments',
                    'Implement automated permission lifecycle management',
                    'Create standardized permission templates for common roles'
                ],
                'compliance_impact': 'Medium - improves access management efficiency'
            })
        
        if len(security_insights['cross_subscription_access']) > 0:
            recommendations.append({
                'priority': 'High',
                'category': 'Cross-Subscription Security',
                'title': 'Cross-Subscription Access Patterns',
                'description': f'{len(security_insights["cross_subscription_access"])} users have access across multiple subscriptions. This requires careful monitoring.',
                'action_items': [
                    'Document legitimate cross-subscription access requirements',
                    'Implement subscription-level access policies',
                    'Review and validate each cross-subscription permission',
                    'Consider using management groups for better governance'
                ],
                'compliance_impact': 'High - critical for data segregation and compliance'
            })
        
        # Storage and Key Vault specific recommendations
        critical_storage_users = [user for user in analyses if any(sa.get('can_list_keys') or sa.get('can_regenerate_keys') for sa in user.storage_account_permissions)]
        if len(critical_storage_users) > 0:
            recommendations.append({
                'priority': 'Critical',
                'category': 'Data Security',
                'title': 'Critical Storage Account Access',
                'description': f'{len(critical_storage_users)} users can list or regenerate storage account keys. This is highly sensitive access.',
                'action_items': [
                    'Audit all users with storage key access',
                    'Implement storage account access policies',
                    'Use Azure AD authentication for storage where possible',
                    'Enable storage account logging and monitoring'
                ],
                'compliance_impact': 'Critical - affects data protection and PCI compliance'
            })
        
        # Risk-based recommendations
        if risk_distribution['Critical'] > 0:
            recommendations.append({
                'priority': 'Critical',
                'category': 'Risk Management',
                'title': 'Critical Risk Users Identified',
                'description': f'{risk_distribution["Critical"]} users classified as critical risk. Immediate review required.',
                'action_items': [
                    'Immediate review of all critical risk users',
                    'Implement enhanced monitoring for high-risk accounts',
                    'Consider temporary access restrictions pending review',
                    'Establish incident response procedures for privileged account misuse'
                ],
                'compliance_impact': 'Critical - immediate action required for compliance'
            })
        
        # Compliance-specific recommendations
        if len(compliance_gaps) > 0:
            recommendations.append({
                'priority': 'High',
                'category': 'Compliance',
                'title': 'Compliance Gaps Identified',
                'description': f'{len(compliance_gaps)} compliance gaps detected that require attention.',
                'action_items': [
                    'Address identified compliance gaps',
                    'Implement automated compliance monitoring',
                    'Establish regular compliance reporting',
                    'Train administrators on compliance requirements'
                ],
                'compliance_impact': 'High - required for regulatory compliance'
            })
        
        # General security recommendations based on analysis
        if avg_permissions > 5:  # If average permissions per user is high
            recommendations.append({
                'priority': 'Medium',
                'category': 'Security Optimization',
                'title': 'High Average Permission Count',
                'description': f'Average of {round(avg_permissions, 1)} permissions per user suggests potential over-provisioning.',
                'action_items': [
                    'Review permission assignment patterns',
                    'Implement principle of least privilege',
                    'Create role-based permission templates',
                    'Establish regular permission audits'
                ],
                'compliance_impact': 'Medium - improves security posture'
            })
        
        # Generate additional chart data for enhanced visualizations
        risk_distribution_data = [
            risk_distribution['Critical'],
            risk_distribution['High'], 
            risk_distribution['Medium'],
            risk_distribution['Low']
        ]
        
        # Security posture scoring (simplified calculation)
        access_control_score = 85 if len(security_insights['excessive_permissions']) == 0 else 65
        privilege_mgmt_score = 90 if len(security_insights['privileged_users']) <= total_users * 0.1 else 70
        monitoring_score = 80  # Assuming monitoring is in place
        compliance_score = compliance_summary['overall_score']
        identity_security_score = 85 if len(security_insights['anomalies']) == 0 else 70
        data_protection_score = 75 if len([u for u in analyses if len(u.storage_account_permissions) > 0]) <= 3 else 60
        
        security_posture_scores = [
            access_control_score, privilege_mgmt_score, monitoring_score,
            compliance_score, identity_security_score, data_protection_score
        ]
        
        # Generate risk score histogram data
        all_risk_scores = []
        for analysis in analyses:
            user_roles = [assignment['role_name'] for assignment in analysis.direct_assignments + analysis.group_assignments]
            base_risk = sum(3 if role in high_risk_roles else 1 for role in user_roles)
            kv_risk = len(analysis.key_vault_permissions) * 2
            storage_risk = sum(2 if sa.get('can_list_keys') or sa.get('can_regenerate_keys') else 1 for sa in analysis.storage_account_permissions)
            comprehensive_risk = base_risk + kv_risk + storage_risk
            all_risk_scores.append(comprehensive_risk)
        
        # Create histogram bins
        max_score = max(all_risk_scores) if all_risk_scores else 0
        bins = list(range(0, max_score + 5, 2))  # 2-point bins
        risk_score_histogram_data = []
        for i in range(len(bins) - 1):
            count = len([score for score in all_risk_scores if bins[i] <= score < bins[i + 1]])
            risk_score_histogram_data.append({'x': bins[i], 'y': count})
        
        # Timeline data for charts (simplified - based on analysis dates)
        from collections import defaultdict
        timeline_data = defaultdict(int)
        permission_grants_data = []
        permission_revokes_data = []
        timeline_labels = []
        
        # Generate mock timeline data based on analysis dates
        for i, analysis in enumerate(analyses):
            date_str = analysis.analyzed_at.strftime('%Y-%m-%d') if hasattr(analysis.analyzed_at, 'strftime') else datetime.now().strftime('%Y-%m-%d')
            timeline_data[date_str] += 1
        
        sorted_dates = sorted(timeline_data.keys())
        for date in sorted_dates[-30:]:  # Last 30 days
            timeline_labels.append(date)
            permission_grants_data.append(timeline_data[date])
            permission_revokes_data.append(max(0, timeline_data[date] - 1))  # Mock revoke data
        
        # Convert data to JSON for JavaScript
        recommendations_json = json.dumps(recommendations)
        security_insights_json = json.dumps(security_insights)
        risk_distribution_json = json.dumps(risk_distribution)
        role_distribution_json = json.dumps(role_distribution_data)
        permission_matrix_json = json.dumps(permission_matrix)
        timeline_events_json = json.dumps(timeline_events[:20])  # Last 20 events
        compliance_gaps_json = json.dumps(compliance_gaps)
        compliance_summary_json = json.dumps(compliance_summary)
        audit_events_json = json.dumps(audit_events[:30])  # Last 30 audit events
        
        # Additional chart data for JavaScript
        security_posture_scores_json = json.dumps(security_posture_scores)
        risk_distribution_data_json = json.dumps(risk_distribution_data)
        risk_score_histogram_data_json = json.dumps(risk_score_histogram_data)
        timeline_labels_json = json.dumps(timeline_labels)
        permission_grants_data_json = json.dumps(permission_grants_data)
        permission_revokes_data_json = json.dumps(permission_revokes_data)
        
        # Generate critical users table
        critical_users_table = ""
        for analysis in analyses:
            # Get all roles for this user
            direct_roles = [assignment['role_name'] for assignment in analysis.direct_assignments]
            group_roles = [assignment['role_name'] for assignment in analysis.group_assignments]
            all_user_roles = direct_roles + group_roles

            # Find critical roles
            critical_roles = [role for role in all_user_roles if role in high_risk_roles]

            if critical_roles:
                # Get unique critical roles
                unique_critical_roles = list(set(critical_roles))

                # Format critical roles as badges
                critical_roles_html = " ".join([f'<span class="badge badge-danger">{role}</span>' for role in unique_critical_roles])

                critical_users_table += f"""
                    <tr>
                        <td><strong>{analysis.display_name}</strong></td>
                        <td>{analysis.user_principal_name}</td>
                        <td>{critical_roles_html}</td>
                        <td>{len(analysis.direct_assignments)}</td>
                        <td>{len(analysis.group_assignments)}</td>
                    </tr>
                """

        # Generate high-risk users table (sorted by risk score) for Executive Summary
        high_risk_users_list = []
        for analysis in analyses:
            # Get all roles for this user
            user_roles = [assignment['role_name'] for assignment in analysis.direct_assignments + analysis.group_assignments]

            # Find high-risk roles
            user_high_risk_roles = [role for role in user_roles if role in high_risk_roles]

            # Calculate risk score (3 points for high-risk roles, 1 for others)
            risk_score = sum(3 if role in high_risk_roles else 1 for role in user_roles)

            # Only include users with high-risk roles
            if user_high_risk_roles:
                high_risk_users_list.append({
                    'name': analysis.display_name,
                    'email': analysis.user_principal_name,
                    'risk_score': risk_score,
                    'high_risk_roles': list(set(user_high_risk_roles)),  # Unique roles
                    'total_permissions': len(analysis.direct_assignments) + len(analysis.group_assignments)
                })

        # Sort by risk score (descending)
        high_risk_users_list.sort(key=lambda x: x['risk_score'], reverse=True)

        # Generate HTML table for high-risk users
        high_risk_users_table = ""
        for rank, user in enumerate(high_risk_users_list, start=1):
            # Format risk score badge
            risk_badge_color = "danger" if user['risk_score'] >= 9 else "warning" if user['risk_score'] >= 5 else "info"

            # Format high-risk roles as badges
            roles_html = " ".join([f'<span class="badge badge-danger">{role}</span>' for role in user['high_risk_roles']])

            high_risk_users_table += f"""
                <tr>
                    <td><strong>#{rank}</strong></td>
                    <td><strong>{user['name']}</strong></td>
                    <td>{user['email']}</td>
                    <td><span class="badge badge-{risk_badge_color}" style="font-size: 1.1em;">{user['risk_score']}</span></td>
                    <td>{roles_html}</td>
                    <td>{user['total_permissions']}</td>
                </tr>
            """

        # Calculate resource access counts
        total_key_vaults = sum(len(a.key_vault_permissions) for a in analyses)
        total_storage_accounts = sum(len(a.storage_account_permissions) for a in analyses)
        total_resources_accessed = total_key_vaults + total_storage_accounts
        unique_scopes = len(set(scope for a in analyses for scope in a.all_permissions.keys()))

        # Calculate privileged user count (needed before using it in template strings)
        total_privileged_users = len(security_insights['privileged_users'])

        # Generate other sections
        resource_access_summary = f"""
            <div class="summary-cards">
                <div class="summary-card">
                    <h3>{total_key_vaults}</h3>
                    <p>Key Vaults Accessed</p>
                </div>
                <div class="summary-card">
                    <h3>{total_storage_accounts}</h3>
                    <p>Storage Accounts Accessed</p>
                </div>
                <div class="summary-card">
                    <h3>{unique_scopes}</h3>
                    <p>Unique Scopes</p>
                </div>
            </div>
        """

        # Generate privileged access details
        privileged_roles = [role for role in role_counts.keys() if any(hr in role for hr in ['Owner', 'Administrator', 'Contributor', 'Manager'])]
        privileged_access_details = f"""
            <div class="alert alert-info">
                <h6>Privileged Access Summary</h6>
                <ul>
                    <li><strong>{total_privileged_users}</strong> users have privileged access</li>
                    <li><strong>{len(privileged_roles)}</strong> privileged role types in use</li>
                    <li><strong>{high_risk_users}</strong> users with high-risk permissions</li>
                    <li>Most common privileged role: <strong>{role_counts.most_common(1)[0][0] if role_counts else 'None'}</strong></li>
                </ul>
            </div>
            <p>Privileged users have elevated permissions that grant access to critical resources and administrative functions. Regular review and monitoring of these accounts is essential for maintaining security posture.</p>
        """
        
        high_risk_summary = f"""
            <strong>{high_risk_users}</strong> users have been identified with high-risk permissions that require immediate review.
            Critical administrative roles detected across {len(role_counts)} unique role types.
        """
        
        security_concerns = """
            <ul>
                <li>Users with Owner-level access to subscription resources</li>
                <li>Accounts with Key Vault administrative permissions</li>
                <li>Storage account key management access</li>
                <li>Cross-subscription access patterns</li>
            </ul>
        """
        
        immediate_actions = """
            <ul>
                <li>Review all users with Owner or Contributor roles</li>
                <li>Audit Key Vault access policies</li>
                <li>Implement just-in-time access for administrative operations</li>
                <li>Enable conditional access policies for privileged accounts</li>
            </ul>
        """
        
        compliance_notes = """
            <p>This analysis helps support compliance with:</p>
            <ul>
                <li>SOC 2 Type II access control requirements</li>
                <li>ISO 27001 access management standards</li>
                <li>GDPR data protection officer requirements</li>
                <li>PCI DSS privileged access controls</li>
            </ul>
        """
        
        # Render the template with comprehensive data
        html_content = template.render(
            organization_name=organization_name,
            report_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_users=total_users,
            high_risk_users=high_risk_users,
            total_role_assignments=total_role_assignments,
            unique_roles=unique_roles,
            critical_permissions_count=critical_permissions_count,
            subscription_name=subscription_name,
            common_roles_table=common_roles_table,
            user_details=user_details,
            chart_labels=chart_labels,
            chart_data=chart_data,
            critical_users_table=critical_users_table,
            high_risk_users_table=high_risk_users_table,
            resource_access_summary=resource_access_summary,
            privileged_access_details=privileged_access_details,
            high_risk_summary=high_risk_summary,
            security_concerns=security_concerns,
            immediate_actions=immediate_actions,
            compliance_notes=compliance_notes,
            # New enhanced data for advanced sections
            security_insights_json=security_insights_json,
            risk_distribution_json=risk_distribution_json,
            role_distribution_json=role_distribution_json,
            permission_matrix_json=permission_matrix_json,
            timeline_events_json=timeline_events_json,
            compliance_gaps_json=compliance_gaps_json,
            compliance_summary_json=compliance_summary_json,
            audit_events_json=audit_events_json,
            recommendations_json=recommendations_json,
            # Chart data for JavaScript
            security_posture_scores=security_posture_scores_json,
            risk_distribution_data=risk_distribution_data_json,
            risk_score_histogram_data=risk_score_histogram_data_json,
            timeline_labels=timeline_labels_json,
            permission_grants_data=permission_grants_data_json,
            permission_revokes_data=permission_revokes_data_json,
            # Summary statistics
            total_privileged_users=total_privileged_users,
            total_anomalies=len(security_insights['anomalies']),
            total_compliance_gaps=len(compliance_gaps),
            total_recommendations=len(recommendations),
            total_audit_events=len(audit_events),
            overall_compliance_score=compliance_summary['overall_score'],
            avg_permissions_per_user=round(avg_permissions, 1),
            critical_risk_count=risk_distribution['Critical'],
            high_risk_count=risk_distribution['High'],
            medium_risk_count=risk_distribution['Medium'],
            low_risk_count=risk_distribution['Low'],
            # Resource access counts for Permission Analysis tab
            total_key_vaults=total_key_vaults,
            total_storage_accounts=total_storage_accounts,
            total_resources_accessed=total_resources_accessed,
            unique_scopes=unique_scopes
        )
        
        # Write the HTML file
        with output_path.open('w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"Generated comprehensive HTML report: {output_path}")

    @staticmethod
    def print_summary(analysis: UserPermissionAnalysis):
        """Print a summary to console"""
        print(f"\n{'='*60}")
        print(f"Permission Analysis for {analysis.display_name}")
        print(f"{'='*60}")
        print(f"User ID: {analysis.user_id}")
        print(f"Principal Name: {analysis.user_principal_name}")
        print(f"Analysis Time: {analysis.analyzed_at}")
        print(f"\nDirect Role Assignments: {len(analysis.direct_assignments)}")

        for assignment in analysis.direct_assignments[:5]:  # Show first 5
            scope_type = assignment.get('scope_type', 'Unknown')
            scope_name = assignment['scope'].split('/')[-1] if '/' in assignment['scope'] else assignment['scope']
            print(f"  - {assignment['role_name']} on {scope_type}: {scope_name}")

        if len(analysis.direct_assignments) > 5:
            print(f"  ... and {len(analysis.direct_assignments) - 5} more")

        print(f"\nGroup-based Assignments: {len(analysis.group_assignments)}")
        for assignment in analysis.group_assignments[:5]:  # Show first 5
            scope_type = assignment.get('scope_type', 'Unknown')
            scope_name = assignment['scope'].split('/')[-1] if '/' in assignment['scope'] else assignment['scope']
            group_info = f" (via {assignment.get('group_name', 'Unknown Group')})" if 'group_name' in assignment else ""
            print(f"  - {assignment['role_name']} on {scope_type}: {scope_name}{group_info}")

        if len(analysis.group_assignments) > 5:
            print(f"  ... and {len(analysis.group_assignments) - 5} more")

        print(f"\nTotal Unique Scopes with Permissions: {len(analysis.all_permissions)}")
        print(f"{'='*60}\n")

    @staticmethod
    async def generate_mermaid_diagram(analysis: UserPermissionAnalysis) -> str:
        """Generate a Mermaid.js flow diagram for permissions and groups"""
        mermaid_code = ["graph TB"]  # TB for top-to-bottom layout

        # Sanitize names for Mermaid (replace special characters)
        def sanitize_id(text: str) -> str:
            # More aggressive sanitization for Mermaid compatibility
            import re
            # Keep only alphanumeric and underscores
            sanitized = re.sub(r'[^a-zA-Z0-9_]', '_', text)
            # Ensure it starts with a letter
            if sanitized and sanitized[0].isdigit():
                sanitized = 'ID_' + sanitized
            return sanitized[:50] if sanitized else 'unknown'

        def sanitize_label(text: str) -> str:
            # Remove problematic characters for labels
            return text.replace('"', "'").replace('\n', ' ').replace('\\', '/')[:100]

        def get_scope_prefix(scope_type: str) -> str:
            """Get text prefix for scope type (no emojis)"""
            prefixes = {
                'Subscription': 'SUB',
                'Resource Group': 'RG',
                'Management Group': 'MG',
                'Root': 'ROOT'
            }
            if 'Resource' in scope_type and '(' in scope_type:
                return 'RES'
            return prefixes.get(scope_type, 'SCOPE')

        def get_role_prefix(role_name: str) -> str:
            """Get text prefix for role type (no emojis)"""
            role_lower = role_name.lower()
            if 'owner' in role_lower:
                return 'OWN'
            elif 'contributor' in role_lower:
                return 'CONT'
            elif 'reader' in role_lower or 'read' in role_lower:
                return 'READ'
            elif 'admin' in role_lower:
                return 'ADMIN'
            elif 'developer' in role_lower:
                return 'DEV'
            elif 'security' in role_lower:
                return 'SEC'
            else:
                return 'ROLE'

        user_id = sanitize_id(analysis.user_principal_name)

        # Extract subscription information from assignments
        subscription_info = {}
        all_assignments = analysis.direct_assignments + analysis.group_assignments

        for assignment in all_assignments:
            scope = assignment.get('scope', '')
            if '/subscriptions/' in scope:
                # Extract subscription ID from scope path
                parts = scope.split('/')
                try:
                    sub_index = parts.index('subscriptions')
                    if sub_index + 1 < len(parts):
                        sub_id = parts[sub_index + 1]
                        if sub_id not in subscription_info:
                            subscription_info[sub_id] = {
                                'name': None,
                                'resource_groups': set(),
                                'assignment_count': 0
                            }

                        subscription_info[sub_id]['assignment_count'] += 1

                        # Try to extract resource group if present
                        if 'resourceGroups' in parts:
                            rg_index = parts.index('resourceGroups')
                            if rg_index + 1 < len(parts):
                                subscription_info[sub_id]['resource_groups'].add(parts[rg_index + 1])

                except (ValueError, IndexError):
                    continue

        # Also check all_permissions for subscription context
        for scope in analysis.all_permissions.keys():
            if '/subscriptions/' in scope:
                parts = scope.split('/')
                try:
                    sub_index = parts.index('subscriptions')
                    if sub_index + 1 < len(parts):
                        sub_id = parts[sub_index + 1]
                        if sub_id not in subscription_info:
                            subscription_info[sub_id] = {
                                'name': None,
                                'resource_groups': set(),
                                'assignment_count': 0
                            }
                except (ValueError, IndexError):
                    continue

        # Fetch subscription names from Azure API
        if subscription_info:
            try:
                # Try to get subscription names from Azure Management API
                subscription_names = await OutputFormatter._fetch_subscription_names(list(subscription_info.keys()))
                for sub_id, sub_name in subscription_names.items():
                    if sub_id in subscription_info:
                        subscription_info[sub_id]['name'] = sub_name
            except Exception as e:
                logger.warning(f"Failed to fetch subscription names from Azure API: {e}")
                # Continue without subscription names

        # Add subscription header if we have subscription information
        if subscription_info:
            # Sort by assignment count to get the most active subscription first
            sorted_subs = sorted(subscription_info.items(), key=lambda x: x[1]['assignment_count'], reverse=True)
            primary_sub_id, primary_sub_info = sorted_subs[0]
            sub_header_id = sanitize_id(f"subscription_header")

            # Create subscription header with enhanced information
            subscription_name = primary_sub_info['name'] or f"Subscription {primary_sub_id[:8]}..."
            sub_display_name = f"Name: {subscription_name}"
            sub_full_id = f"ID: {primary_sub_id}"
            rg_count = len(primary_sub_info['resource_groups'])
            assignment_count = primary_sub_info['assignment_count']

            if rg_count > 0:
                sub_stats = f"Resource Groups: {rg_count} | Assignments: {assignment_count}"
                sub_label = f"AZURE SUBSCRIPTION<br/>{sub_display_name}<br/>{sub_full_id}<br/>{sub_stats}"
            else:
                sub_label = f"AZURE SUBSCRIPTION<br/>{sub_display_name}<br/>{sub_full_id}<br/>Assignments: {assignment_count}"

            mermaid_code.append(f'    {sub_header_id}["{sub_label}"]')
            mermaid_code.append(f'    {sub_header_id}:::subscriptionStyle')

            # If multiple subscriptions, show detailed breakdown
            if len(subscription_info) > 1:
                multi_sub_id = sanitize_id(f"multi_subscriptions")
                total_assignments = sum(info['assignment_count'] for info in subscription_info.values())
                multi_label = f"MULTIPLE SUBSCRIPTIONS<br/>Count: {len(subscription_info)}<br/>Total Assignments: {total_assignments}"
                mermaid_code.append(f'    {multi_sub_id}["{multi_label}"]')
                mermaid_code.append(f'    {sub_header_id} -.-> {multi_sub_id}')
                mermaid_code.append(f'    {multi_sub_id}:::multiSubStyle')

                # Show other subscription details if not too many
                if len(subscription_info) <= 3:
                    for i, (sub_id, sub_info) in enumerate(sorted_subs[1:], 1):
                        other_sub_id = sanitize_id(f"other_sub_{i}")
                        other_sub_name = sub_info['name'] or f"Sub {sub_id[:8]}..."
                        other_label = f"{other_sub_name}<br/>ID: {sub_id[:12]}...<br/>Assignments: {sub_info['assignment_count']}"
                        mermaid_code.append(f'    {other_sub_id}["{other_label}"]')
                        mermaid_code.append(f'    {multi_sub_id} -.-> {other_sub_id}')
                        mermaid_code.append(f'    {other_sub_id}:::otherSubStyle')

        # Add user node without emojis
        user_label = f"USER: {sanitize_label(analysis.display_name)}"
        mermaid_code.append(f'    {user_id}["{user_label}"]')
        mermaid_code.append(f'    {user_id}:::userStyle')

        # Connect subscription to user if subscription info exists
        if subscription_info:
            mermaid_code.append(f'    {sub_header_id} --> {user_id}')

        # Track statistics
        total_roles = len(analysis.direct_assignments) + len(analysis.group_assignments)

        # Add statistics node
        if total_roles > 0:
            stats_id = sanitize_id(f"stats_{user_id}")
            stats_label = f"Total: {total_roles} | Direct: {len(analysis.direct_assignments)} | Groups: {len(analysis.group_assignments)}"
            mermaid_code.append(f'    {stats_id}["{stats_label}"]')
            mermaid_code.append(f'    {user_id} -.-> {stats_id}')
            mermaid_code.append(f'    {stats_id}:::statsStyle')

        # Process direct assignments
        if analysis.direct_assignments:
            direct_id = sanitize_id(f"direct_{user_id}")
            direct_label = f"DIRECT ASSIGNMENTS ({len(analysis.direct_assignments)})"
            mermaid_code.append(f'    {direct_id}["{direct_label}"]')
            mermaid_code.append(f'    {user_id} --> {direct_id}')
            mermaid_code.append(f'    {direct_id}:::directStyle')

            # Group direct assignments by scope type
            scope_groups = {}
            for assignment in analysis.direct_assignments[:10]:  # Limit for readability
                scope_type = assignment.get('scope_type', 'Unknown')
                if scope_type not in scope_groups:
                    scope_groups[scope_type] = []
                scope_groups[scope_type].append(assignment)

            for scope_idx, (scope_type, assignments) in enumerate(scope_groups.items()):
                scope_prefix = get_scope_prefix(scope_type)
                scope_group_id = sanitize_id(f"DirectScope_{scope_idx}_{scope_type}")

                # Create a node for each scope type
                scope_label = f"{scope_prefix}: {scope_type}"
                mermaid_code.append(f'    {scope_group_id}["{scope_label}"]')
                mermaid_code.append(f'    {direct_id} --> {scope_group_id}')
                mermaid_code.append(f'    {scope_group_id}:::scopeTypeStyle')

                for idx, assignment in enumerate(assignments):
                    role_id = sanitize_id(f"DirectRole_{scope_idx}_{idx}_{assignment['role_name']}")
                    role_name = sanitize_label(assignment['role_name'])
                    role_prefix = get_role_prefix(role_name)
                    scope_name = sanitize_label(assignment['scope'].split('/')[-1] if '/' in assignment['scope'] else assignment['scope'])

                    # Enhanced role label with more details
                    created_date = assignment.get('created_on', '')
                    if created_date:
                        try:
                            from datetime import datetime
                            if isinstance(created_date, str):
                                date_obj = datetime.fromisoformat(created_date.replace('Z', '+00:00'))
                            else:
                                date_obj = created_date
                            date_str = date_obj.strftime('%Y-%m-%d')
                        except:
                            date_str = str(created_date)[:10] if created_date else 'N/A'
                    else:
                        date_str = 'N/A'

                    role_label = f"{role_prefix}: {role_name}<br/>Scope: {scope_name}<br/>Created: {date_str}"
                    mermaid_code.append(f'    {role_id}["{role_label}"]')
                    mermaid_code.append(f'    {scope_group_id} --> {role_id}')

                    # Add detailed scope information as a sub-node
                    if len(scope_name) > 10 and assignment.get('scope'):  # Only for non-trivial scopes
                        scope_detail_id = sanitize_id(f"DirectScope_{scope_idx}_{idx}_detail")
                        full_scope = sanitize_label(assignment['scope'][:150])  # Truncate very long scopes
                        scope_detail_label = f"Full Path:<br/>{full_scope}"
                        mermaid_code.append(f'    {scope_detail_id}["{scope_detail_label}"]')
                        mermaid_code.append(f'    {role_id} -.-> {scope_detail_id}')
                        mermaid_code.append(f'    {scope_detail_id}:::scopeDetailStyle')

                    # Different styles based on permission level
                    if 'owner' in role_name.lower():
                        mermaid_code.append(f'    {role_id}:::ownerStyle')
                    elif 'contributor' in role_name.lower():
                        mermaid_code.append(f'    {role_id}:::contributorStyle')
                    elif 'reader' in role_name.lower() or 'read' in role_name.lower():
                        mermaid_code.append(f'    {role_id}:::readerStyle')
                    else:
                        mermaid_code.append(f'    {role_id}:::roleStyle')

        # Process group assignments
        if analysis.group_assignments:
            # Add group assignments header
            unique_groups = len(set(a.get('group_name', 'Unknown') for a in analysis.group_assignments))
            group_header_id = sanitize_id(f"GroupHeader_{user_id}")
            group_header_label = f"GROUP MEMBERSHIPS ({unique_groups} groups)"
            mermaid_code.append(f'    {group_header_id}["{group_header_label}"]')
            mermaid_code.append(f'    {user_id} --> {group_header_id}')
            mermaid_code.append(f'    {group_header_id}:::groupHeaderStyle')

            # Group assignments by group name
            groups_dict = {}
            for assignment in analysis.group_assignments:
                group_name = assignment.get('group_name', 'Unknown Group')
                if group_name not in groups_dict:
                    groups_dict[group_name] = []
                groups_dict[group_name].append(assignment)

            for group_idx, (group_name, assignments) in enumerate(list(groups_dict.items())[:5]):  # Limit to 5 groups
                group_id = sanitize_id(f"Group_{group_idx}_{group_name}")
                group_label = sanitize_label(f"GROUP: {group_name} ({len(assignments)} perms)")

                # Regular shape for groups
                mermaid_code.append(f'    {group_id}["{group_label}"]')
                mermaid_code.append(f'    {group_header_id} --> {group_id}')
                mermaid_code.append(f'    {group_id}:::groupStyle')

                # Group roles by scope type within each group
                scope_groups = {}
                for assignment in assignments[:8]:  # Limit roles per group
                    scope_type = assignment.get('scope_type', 'Unknown')
                    if scope_type not in scope_groups:
                        scope_groups[scope_type] = []
                    scope_groups[scope_type].append(assignment)

                for scope_idx, (scope_type, scope_assignments) in enumerate(scope_groups.items()):
                    for role_idx, assignment in enumerate(scope_assignments):
                        role_id = sanitize_id(f"GroupRole_{group_idx}_{scope_idx}_{role_idx}_{assignment['role_name']}")
                        role_name = sanitize_label(assignment['role_name'])
                        role_prefix = get_role_prefix(role_name)
                        scope_prefix = get_scope_prefix(scope_type)
                        scope_name = sanitize_label(assignment['scope'].split('/')[-1] if '/' in assignment['scope'] else assignment['scope'])

                        # Enhanced group role label with more details
                        created_date = assignment.get('created_on', '')
                        if created_date:
                            try:
                                from datetime import datetime
                                if isinstance(created_date, str):
                                    date_obj = datetime.fromisoformat(created_date.replace('Z', '+00:00'))
                                else:
                                    date_obj = created_date
                                date_str = date_obj.strftime('%Y-%m-%d')
                            except:
                                date_str = str(created_date)[:10] if created_date else 'N/A'
                        else:
                            date_str = 'N/A'

                        role_label = f"{role_prefix}: {role_name}<br/>{scope_prefix}: {scope_name}<br/>Created: {date_str}"
                        mermaid_code.append(f'    {role_id}["{role_label}"]')
                        mermaid_code.append(f'    {group_id} --> {role_id}')

                        # Add inheritance path information
                        principal_type = assignment.get('principal_type', '')
                        if principal_type:
                            inherit_id = sanitize_id(f"GroupInherit_{group_idx}_{scope_idx}_{role_idx}")
                            inherit_label = f"Inherited via: {principal_type}"
                            mermaid_code.append(f'    {inherit_id}["{inherit_label}"]')
                            mermaid_code.append(f'    {role_id} -.-> {inherit_id}')
                            mermaid_code.append(f'    {inherit_id}:::inheritStyle')

                        # Style based on permission level
                        if 'owner' in role_name.lower():
                            mermaid_code.append(f'    {role_id}:::ownerStyle')
                        elif 'contributor' in role_name.lower():
                            mermaid_code.append(f'    {role_id}:::contributorStyle')
                        elif 'reader' in role_name.lower() or 'read' in role_name.lower():
                            mermaid_code.append(f'    {role_id}:::readerStyle')
                        else:
                            mermaid_code.append(f'    {role_id}:::roleStyle')

        # Add permissions summary for complex assignments
        if len(analysis.all_permissions) > 0:
            perms_summary_id = sanitize_id(f"permsSummary_{user_id}")
            unique_scopes = len(analysis.all_permissions)
            total_permissions = sum(len(perms) for perms in analysis.all_permissions.values())

            perms_label = f"PERMISSIONS SUMMARY<br/>Scopes: {unique_scopes}<br/>Total Perms: {total_permissions}"
            mermaid_code.append(f'    {perms_summary_id}["{perms_label}"]')
            mermaid_code.append(f'    {user_id} -.-> {perms_summary_id}')
            mermaid_code.append(f'    {perms_summary_id}:::permsSummaryStyle')

            # Add top permission types
            all_perms = []
            for scope_perms in analysis.all_permissions.values():
                all_perms.extend(scope_perms)

            # Count permission patterns
            perm_patterns = {}
            for perm in all_perms:
                if '/' in perm:
                    pattern = '/'.join(perm.split('/')[:2])  # Take first two parts
                    perm_patterns[pattern] = perm_patterns.get(pattern, 0) + 1

            # Show top 3 permission patterns
            top_patterns = sorted(perm_patterns.items(), key=lambda x: x[1], reverse=True)[:3]
            if top_patterns:
                for i, (pattern, count) in enumerate(top_patterns):
                    pattern_id = sanitize_id(f"permPattern_{user_id}_{i}")
                    pattern_label = f"{sanitize_label(pattern)}<br/>({count} perms)"
                    mermaid_code.append(f'    {pattern_id}["{pattern_label}"]')
                    mermaid_code.append(f'    {perms_summary_id} -.-> {pattern_id}')
                    mermaid_code.append(f'    {pattern_id}:::permPatternStyle')

        # Add Key Vault permissions section
        if analysis.key_vault_permissions and len(analysis.key_vault_permissions) > 0:
            kv_header_id = sanitize_id(f"keyvaults_{user_id}")
            kv_header_label = f"KEY VAULTS ({len(analysis.key_vault_permissions)})"
            mermaid_code.append(f'    {kv_header_id}["{kv_header_label}"]')
            mermaid_code.append(f'    {user_id} --> {kv_header_id}')
            mermaid_code.append(f'    {kv_header_id}:::keyVaultHeaderStyle')

            # Process Key Vaults (limit to 5 for readability)
            for kv_idx, kv in enumerate(analysis.key_vault_permissions[:5]):
                kv_name = sanitize_label(kv.get('key_vault_name', 'Unknown'))
                kv_location = sanitize_label(kv.get('location', ''))
                policies_count = len(kv.get('access_policies', []))

                kv_id = sanitize_id(f"kv_{kv_idx}_{kv_name}")
                kv_label = f"KV: {kv_name}<br/>Location: {kv_location}<br/>Policies: {policies_count}"
                mermaid_code.append(f'    {kv_id}["{kv_label}"]')
                mermaid_code.append(f'    {kv_header_id} --> {kv_id}')
                mermaid_code.append(f'    {kv_id}:::keyVaultStyle')

                # Process access policies (limit to 3 per Key Vault)
                for policy_idx, policy in enumerate(kv.get('access_policies', [])[:3]):
                    permissions = policy.get('permissions', {})

                    # Count total permissions
                    keys_count = len(permissions.get('keys', []))
                    secrets_count = len(permissions.get('secrets', []))
                    certs_count = len(permissions.get('certificates', []))
                    storage_count = len(permissions.get('storage', []))
                    total_perms = keys_count + secrets_count + certs_count + storage_count

                    policy_id = sanitize_id(f"kvpolicy_{kv_idx}_{policy_idx}")

                    # Create policy label with breakdown
                    policy_parts = []
                    if keys_count > 0:
                        policy_parts.append(f"Keys: {keys_count}")
                    if secrets_count > 0:
                        policy_parts.append(f"Secrets: {secrets_count}")
                    if certs_count > 0:
                        policy_parts.append(f"Certs: {certs_count}")
                    if storage_count > 0:
                        policy_parts.append(f"Storage: {storage_count}")

                    policy_label = f"POLICY: {policy.get('object_id', 'Unknown')[:8]}...<br/>{' | '.join(policy_parts)}<br/>Total: {total_perms}"

                    mermaid_code.append(f'    {policy_id}["{policy_label}"]')
                    mermaid_code.append(f'    {kv_id} --> {policy_id}')
                    mermaid_code.append(f'    {policy_id}:::keyVaultPolicyStyle')

                    # Add individual permission type nodes if they have permissions
                    if keys_count > 0:
                        keys_id = sanitize_id(f"kvkeys_{kv_idx}_{policy_idx}")
                        keys_label = f"KEYS<br/>{', '.join(permissions.get('keys', [])[:3])}"
                        if len(permissions.get('keys', [])) > 3:
                            keys_label += f"<br/>+{len(permissions.get('keys', [])) - 3} more"
                        mermaid_code.append(f'    {keys_id}["{keys_label}"]')
                        mermaid_code.append(f'    {policy_id} -.-> {keys_id}')
                        mermaid_code.append(f'    {keys_id}:::keyVaultKeysStyle')

                    if secrets_count > 0:
                        secrets_id = sanitize_id(f"kvsecrets_{kv_idx}_{policy_idx}")
                        secrets_label = f"SECRETS<br/>{', '.join(permissions.get('secrets', [])[:3])}"
                        if len(permissions.get('secrets', [])) > 3:
                            secrets_label += f"<br/>+{len(permissions.get('secrets', [])) - 3} more"
                        mermaid_code.append(f'    {secrets_id}["{secrets_label}"]')
                        mermaid_code.append(f'    {policy_id} -.-> {secrets_id}')
                        mermaid_code.append(f'    {secrets_id}:::keyVaultSecretsStyle')

                    if certs_count > 0:
                        certs_id = sanitize_id(f"kvcerts_{kv_idx}_{policy_idx}")
                        certs_label = f"CERTIFICATES<br/>{', '.join(permissions.get('certificates', [])[:3])}"
                        if len(permissions.get('certificates', [])) > 3:
                            certs_label += f"<br/>+{len(permissions.get('certificates', [])) - 3} more"
                        mermaid_code.append(f'    {certs_id}["{certs_label}"]')
                        mermaid_code.append(f'    {policy_id} -.-> {certs_id}')
                        mermaid_code.append(f'    {certs_id}:::keyVaultCertsStyle')

        # Add Storage Account permissions section
        if analysis.storage_account_permissions and len(analysis.storage_account_permissions) > 0:
            sa_header_id = sanitize_id(f"storage_accounts_{user_id}")
            sa_header_label = f"STORAGE ACCOUNTS ({len(analysis.storage_account_permissions)})"
            mermaid_code.append(f'    {sa_header_id}["{sa_header_label}"]')
            mermaid_code.append(f'    {user_id} --> {sa_header_id}')
            mermaid_code.append(f'    {sa_header_id}:::storageHeaderStyle')

            # Process Storage Accounts (limit to 5 for readability)
            for sa_idx, sa in enumerate(analysis.storage_account_permissions[:5]):
                sa_name = sanitize_label(sa.get('storage_account_name', 'Unknown'))
                sa_location = sanitize_label(sa.get('location', ''))
                sa_rg = sanitize_label(sa.get('resource_group', ''))
                sa_sku = sanitize_label(sa.get('sku', ''))
                security_level = sa.get('security_level', 'Low')
                can_list_keys = sa.get('can_list_keys', False)
                can_regenerate_keys = sa.get('can_regenerate_keys', False)
                effective_perms = sa.get('effective_permissions', [])

                sa_id = sanitize_id(f"sa_{sa_idx}_{sa_name}")
                
                # Create storage account label with key information
                sa_label_parts = [f"SA: {sa_name}"]
                sa_label_parts.append(f"Location: {sa_location}")
                sa_label_parts.append(f"RG: {sa_rg}")
                if sa_sku:
                    sa_label_parts.append(f"SKU: {sa_sku}")
                sa_label_parts.append(f"Security: {security_level}")
                
                sa_label = "<br/>".join(sa_label_parts)
                mermaid_code.append(f'    {sa_id}["{sa_label}"]')
                mermaid_code.append(f'    {sa_header_id} --> {sa_id}')
                
                # Apply styling based on security level
                if security_level == 'High':
                    mermaid_code.append(f'    {sa_id}:::storageHighRiskStyle')
                elif security_level == 'Medium':
                    mermaid_code.append(f'    {sa_id}:::storageMediumRiskStyle')
                else:
                    mermaid_code.append(f'    {sa_id}:::storageLowRiskStyle')

                # Add permissions details node
                if effective_perms:
                    perms_id = sanitize_id(f"sa_perms_{sa_idx}")
                    
                    # Group permissions by type
                    critical_perms = []
                    write_perms = []
                    read_perms = []
                    
                    if can_list_keys:
                        critical_perms.append("List Keys")
                    if can_regenerate_keys:
                        critical_perms.append("Regenerate Keys")
                    
                    for perm in effective_perms:
                        perm_lower = perm.lower()
                        if 'list' in perm_lower and 'key' in perm_lower:
                            continue  # Already handled above
                        elif 'write' in perm_lower or 'delete' in perm_lower:
                            write_perms.append(perm)
                        elif 'read' in perm_lower:
                            read_perms.append(perm)
                    
                    # Create permissions label
                    perms_label_parts = []
                    if critical_perms:
                        perms_label_parts.append(f"CRITICAL: {', '.join(critical_perms)}")
                    if write_perms:
                        perms_label_parts.append(f"Write: {len(write_perms)} perms")
                    if read_perms:
                        perms_label_parts.append(f"Read: {len(read_perms)} perms")
                    
                    if perms_label_parts:
                        perms_label = "PERMISSIONS<br/>" + "<br/>".join(perms_label_parts)
                        mermaid_code.append(f'    {perms_id}["{perms_label}"]')
                        mermaid_code.append(f'    {sa_id} --> {perms_id}')
                        
                        # Style based on criticality
                        if critical_perms:
                            mermaid_code.append(f'    {perms_id}:::storageCriticalPermsStyle')
                        else:
                            mermaid_code.append(f'    {perms_id}:::storagePermsStyle')
                    
                    # Add individual critical permission nodes if they exist
                    if can_list_keys or can_regenerate_keys:
                        critical_id = sanitize_id(f"sa_critical_{sa_idx}")
                        critical_label_parts = []
                        if can_list_keys:
                            critical_label_parts.append("CAN LIST STORAGE KEYS")
                        if can_regenerate_keys:
                            critical_label_parts.append("CAN REGENERATE KEYS")
                        critical_label = "<br/>".join(critical_label_parts)
                        mermaid_code.append(f'    {critical_id}["{critical_label}"]')
                        mermaid_code.append(f'    {perms_id} -.-> {critical_id}')
                        mermaid_code.append(f'    {critical_id}:::storageDangerStyle')

            # If there are more than 5 storage accounts, indicate that
            if len(analysis.storage_account_permissions) > 5:
                more_id = sanitize_id(f"sa_more_{user_id}")
                more_count = len(analysis.storage_account_permissions) - 5
                more_label = f"... and {more_count} more storage accounts"
                mermaid_code.append(f'    {more_id}["{more_label}"]')
                mermaid_code.append(f'    {sa_header_id} -.-> {more_id}')
                mermaid_code.append(f'    {more_id}:::moreItemsStyle')

        # Enhanced styling with modern color scheme
        mermaid_code.extend([
            '',
            '    %% Subscription header styling',
            '    classDef subscriptionStyle fill:#059669,stroke:#047857,stroke-width:4px,color:#fff,font-weight:bold,font-size:16px',
            '    classDef multiSubStyle fill:#0d9488,stroke:#0f766e,stroke-width:2px,color:#fff',
            '    classDef otherSubStyle fill:#14b8a6,stroke:#0d9488,stroke-width:1px,color:#fff,font-size:12px',
            '',
            '    %% User node styling',
            '    classDef userStyle fill:#1e40af,stroke:#1e3a8a,stroke-width:3px,color:#fff,font-weight:bold',
            '',
            '    %% Statistics styling',
            '    classDef statsStyle fill:#f3f4f6,stroke:#9ca3af,stroke-width:1px,color:#111827',
            '',
            '    %% Direct assignments styling',
            '    classDef directStyle fill:#7c3aed,stroke:#6d28d9,stroke-width:2px,color:#fff,font-weight:bold',
            '',
            '    %% Group header styling',
            '    classDef groupHeaderStyle fill:#0891b2,stroke:#0e7490,stroke-width:2px,color:#fff,font-weight:bold',
            '',
            '    %% Group styling',
            '    classDef groupStyle fill:#06b6d4,stroke:#0891b2,stroke-width:2px,color:#fff',
            '',
            '    %% Scope type styling',
            '    classDef scopeTypeStyle fill:#8b5cf6,stroke:#7c3aed,stroke-width:1px,color:#fff',
            '',
            '    %% Enhanced detail styling',
            '    classDef scopeDetailStyle fill:#e5e7eb,stroke:#9ca3af,stroke-width:1px,color:#374151,font-size:12px',
            '    classDef inheritStyle fill:#fef3c7,stroke:#f59e0b,stroke-width:1px,color:#92400e',
            '    classDef permsSummaryStyle fill:#ddd6fe,stroke:#8b5cf6,stroke-width:2px,color:#5b21b6,font-weight:bold',
            '    classDef permPatternStyle fill:#fce7f3,stroke:#ec4899,stroke-width:1px,color:#be185d',
            '',
            '    %% Role permission level styling',
            '    classDef ownerStyle fill:#dc2626,stroke:#b91c1c,stroke-width:2px,color:#fff,font-weight:bold',
            '    classDef contributorStyle fill:#ea580c,stroke:#c2410c,stroke-width:2px,color:#fff',
            '    classDef readerStyle fill:#65a30d,stroke:#4d7c0f,stroke-width:2px,color:#fff',
            '    classDef roleStyle fill:#f59e0b,stroke:#d97706,stroke-width:2px,color:#fff',
            '',
            '    %% Key Vault styling',
            '    classDef keyVaultHeaderStyle fill:#1e293b,stroke:#0f172a,stroke-width:3px,color:#fff,font-weight:bold',
            '    classDef keyVaultStyle fill:#334155,stroke:#1e293b,stroke-width:2px,color:#fff',
            '    classDef keyVaultPolicyStyle fill:#475569,stroke:#334155,stroke-width:2px,color:#fff',
            '    classDef keyVaultKeysStyle fill:#3b82f6,stroke:#2563eb,stroke-width:1px,color:#fff',
            '    classDef keyVaultSecretsStyle fill:#f59e0b,stroke:#d97706,stroke-width:1px,color:#fff',
            '    classDef keyVaultCertsStyle fill:#10b981,stroke:#059669,stroke-width:1px,color:#fff',
            '    classDef keyVaultStorageStyle fill:#8b5cf6,stroke:#7c3aed,stroke-width:1px,color:#fff',
            '',
            '    %% Storage Account styling',
            '    classDef storageHeaderStyle fill:#f97316,stroke:#ea580c,stroke-width:3px,color:#fff,font-weight:bold',
            '    classDef storageHighRiskStyle fill:#dc2626,stroke:#b91c1c,stroke-width:2px,color:#fff,font-weight:bold',
            '    classDef storageMediumRiskStyle fill:#f59e0b,stroke:#d97706,stroke-width:2px,color:#fff',
            '    classDef storageLowRiskStyle fill:#22c55e,stroke:#16a34a,stroke-width:2px,color:#fff',
            '    classDef storageCriticalPermsStyle fill:#ef4444,stroke:#dc2626,stroke-width:2px,color:#fff',
            '    classDef storagePermsStyle fill:#fb923c,stroke:#f97316,stroke-width:1px,color:#fff',
            '    classDef storageDangerStyle fill:#991b1b,stroke:#7f1d1d,stroke-width:3px,color:#fff,font-weight:bold',
            '    classDef moreItemsStyle fill:#e5e7eb,stroke:#9ca3af,stroke-width:1px,color:#374151,font-style:italic'
        ])

        return '\n'.join(mermaid_code)

    @staticmethod
    async def _fetch_subscription_names(subscription_ids: List[str]) -> Dict[str, str]:
        """Fetch subscription names from Azure Management API"""
        subscription_names = {}

        try:
            from azure.identity import DefaultAzureCredential

            # Try to import azure-mgmt-resource (may not be installed)
            try:
                from azure.mgmt.resource.subscriptions import SubscriptionClient
            except ImportError:
                logger.warning("azure-mgmt-resource package not installed. Install with: pip install azure-mgmt-resource")
                return subscription_names

            # Use the same credential as the main analyzer
            credential = DefaultAzureCredential()

            # Create subscription client
            subscription_client = SubscriptionClient(credential)

            logger.info(f"Fetching names for {len(subscription_ids)} subscriptions...")

            # Fetch subscription details
            for sub_id in subscription_ids:
                try:
                    # Get subscription details
                    subscription = subscription_client.subscriptions.get(sub_id)
                    subscription_names[sub_id] = subscription.display_name or f"Subscription {sub_id[:8]}..."
                    logger.info(f"Found subscription: {subscription_names[sub_id]} ({sub_id})")
                except Exception as e:
                    logger.warning(f"Failed to fetch name for subscription {sub_id}: {e}")
                    # Use a fallback name
                    subscription_names[sub_id] = f"Subscription {sub_id[:8]}..."

        except ImportError as e:
            logger.warning(f"Azure Management SDK not available: {e}")
        except Exception as e:
            logger.warning(f"Failed to initialize Azure subscription client: {e}")

        return subscription_names

    @staticmethod
    def _convert_mermaid_to_png_web_api(mermaid_code: str, output_path: Path) -> bool:
        """Convert Mermaid code to PNG using web API service"""
        try:
            # Use mermaid.ink API for conversion
            encoded_mermaid = base64.b64encode(mermaid_code.encode('utf-8')).decode('utf-8')
            api_url = f"https://mermaid.ink/img/{encoded_mermaid}"

            logger.info("Converting Mermaid diagram using web API...")
            response = requests.get(api_url, timeout=30)

            if response.status_code == 200:
                with output_path.open('wb') as f:
                    f.write(response.content)
                logger.info(f"Successfully generated PNG via web API: {output_path}")
                return True
            else:
                logger.warning(f"Web API conversion failed with status: {response.status_code}")
                return False

        except Exception as e:
            logger.warning(f"Web API conversion failed: {e}")
            return False

    @staticmethod
    def _convert_mermaid_to_png_selenium(mermaid_code: str, output_path: Path) -> bool:
        """Convert Mermaid code to PNG using Selenium with headless browser"""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.support import expected_conditions as EC
            from webdriver_manager.chrome import ChromeDriverManager
            from selenium.webdriver.chrome.service import Service

            logger.info("Converting Mermaid diagram using headless browser...")

            # Setup Chrome options
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--window-size=1200,800")

            # Create driver
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=chrome_options)

            try:
                # Create HTML with Mermaid
                html_content = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
                    <style>
                        body {{ margin: 0; padding: 20px; background: white; }}
                        #mermaid {{ width: 100%; height: 100vh; }}
                    </style>
                </head>
                <body>
                    <div id="mermaid">
                        {mermaid_code}
                    </div>
                    <script>
                        mermaid.initialize({{ startOnLoad: true, theme: 'default' }});
                    </script>
                </body>
                </html>
                """

                # Create temp HTML file
                with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
                    f.write(html_content)
                    temp_html = f.name

                # Load page and wait for rendering
                driver.get(f"file://{temp_html}")
                WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.TAG_NAME, "svg"))
                )

                # Give extra time for rendering
                time.sleep(2)

                # Take screenshot
                driver.save_screenshot(str(output_path))
                logger.info(f"Successfully generated PNG via browser: {output_path}")

                # Cleanup
                os.unlink(temp_html)
                return True

            finally:
                driver.quit()

        except ImportError:
            logger.warning("Selenium not available for browser-based conversion")
            return False
        except Exception as e:
            logger.warning(f"Browser conversion failed: {e}")
            return False

    @staticmethod
    def _convert_mermaid_to_png_kroki(mermaid_code: str, output_path: Path) -> bool:
        """Convert Mermaid code to PNG using Kroki API"""
        try:
            import zlib

            logger.info("Converting Mermaid diagram using Kroki API...")

            # Compress and encode the mermaid code
            compressed = zlib.compress(mermaid_code.encode('utf-8'))
            encoded = base64.urlsafe_b64encode(compressed).decode('utf-8')

            # Make request to Kroki
            kroki_url = f"https://kroki.io/mermaid/png/{encoded}"
            response = requests.get(kroki_url, timeout=30)

            if response.status_code == 200:
                with output_path.open('wb') as f:
                    f.write(response.content)
                logger.info(f"Successfully generated PNG via Kroki API: {output_path}")
                return True
            else:
                logger.warning(f"Kroki API conversion failed with status: {response.status_code}")
                return False

        except Exception as e:
            logger.warning(f"Kroki API conversion failed: {e}")
            return False

    @staticmethod
    async def save_mermaid_diagram(analysis: UserPermissionAnalysis, output_path: Path, format: str = 'png', theme: str = 'dark'):
        """Save Mermaid diagram as an image file with automatic conversion"""
        mermaid_code = await OutputFormatter.generate_mermaid_diagram(analysis)

        # Save Mermaid code to a .mmd file
        mermaid_file = output_path.with_suffix('.mmd')
        with mermaid_file.open('w') as f:
            f.write(mermaid_code)
        logger.info(f"Saved Mermaid diagram code to {mermaid_file}")

        # Output image path
        output_image = output_path.with_suffix(f'.{format}')
        conversion_success = False

        # Method 1: Try mermaid-cli first (best quality)
        try:
            result = subprocess.run(['which', 'mmdc'], capture_output=True, text=True)
            if result.returncode == 0:
                cmd = [
                    'mmdc',
                    '-i', str(mermaid_file),
                    '-o', str(output_image),
                    '-t', theme,
                    '-b', 'white' if theme == 'default' else 'transparent',
                    '--width', '1200',
                    '--height', '800'
                ]

                subprocess.run(cmd, check=True)
                logger.info(f"Generated {format.upper()} diagram with mermaid-cli: {output_image}")
                conversion_success = True

                # Generate light theme version if dark was requested
                if theme == 'dark':
                    light_output = output_path.parent / f"{output_path.stem}_light.{format}"
                    light_cmd = cmd.copy()
                    light_cmd[-7] = 'default'
                    light_cmd[-5] = 'white'
                    light_cmd[-3] = str(light_output)

                    try:
                        subprocess.run(light_cmd, check=True)
                        logger.info(f"Generated light theme version: {light_output}")
                    except subprocess.CalledProcessError:
                        logger.warning("Failed to generate light theme version")

        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.info("mermaid-cli not available, trying alternative conversion methods...")

        # Method 2: Try web API services if mermaid-cli failed
        if not conversion_success:
            conversion_success = OutputFormatter._convert_mermaid_to_png_kroki(mermaid_code, output_image)

        # Method 3: Try mermaid.ink API as fallback
        if not conversion_success:
            conversion_success = OutputFormatter._convert_mermaid_to_png_web_api(mermaid_code, output_image)

        # Method 4: Try browser-based conversion as last resort
        if not conversion_success:
            conversion_success = OutputFormatter._convert_mermaid_to_png_selenium(mermaid_code, output_image)

        # If all methods failed
        if not conversion_success:
            logger.warning("All PNG conversion methods failed.")
            logger.info("Available options:")
            logger.info("  1. Install mermaid-cli: npm install -g @mermaid-js/mermaid-cli")
            logger.info("  2. Use the .mmd file with online Mermaid editors:")
            logger.info("     - https://mermaid.live")
            logger.info("     - VS Code Mermaid extension")
            logger.info("     - GitHub/GitLab markdown rendering")
        else:
            logger.info("✅ PNG diagram generated successfully!")

        return mermaid_file

@click.command()
@click.option('--subscription-id', required=True, help='Azure Subscription ID')
@click.option('--user-id', help='User object ID to analyze')
@click.option('--user-list', type=click.Path(exists=True), help='File with list of user IDs')
@click.option('--output-format', type=click.Choice(['json', 'csv', 'excel']), default='json')
@click.option('--output-dir', type=click.Path(), default='./output')
@click.option('--generate-diagram', is_flag=True, help='Generate Mermaid diagram visualization')
@click.option('--tenant-id', envvar='AZURE_TENANT_ID', help='Azure Tenant ID')
@click.option('--client-id', envvar='AZURE_CLIENT_ID', help='Service Principal Client ID')
@click.option('--client-secret', envvar='AZURE_CLIENT_SECRET', help='Service Principal Secret')
@click.option('--max-concurrent', type=int, default=50, help='Max concurrent API requests')
@click.option('--verbose', is_flag=True, help='Enable verbose logging')
def main(subscription_id, user_id, user_list, output_format, output_dir,
         generate_diagram, tenant_id, client_id, client_secret, max_concurrent, verbose):
    """Azure Permission Analyzer - Analyze user permissions across Azure resources"""

    if verbose:
        logger.setLevel(logging.DEBUG)

    # Create output directory
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Initialize authentication
    auth_manager = AzureAuthManager(tenant_id, client_id, client_secret)

    # Get list of users to analyze
    user_ids = []
    if user_id:
        user_ids.append(user_id)
    elif user_list:
        with open(user_list, 'r') as f:
            user_ids = [line.strip() for line in f if line.strip()]
    else:
        click.echo("Error: Provide either --user-id or --user-list")
        sys.exit(1)

    # Run async analysis
    asyncio.run(analyze_users(
        subscription_id,
        user_ids,
        auth_manager,
        output_format,
        output_path,
        max_concurrent,
        generate_diagram
    ))

async def analyze_users(subscription_id: str, user_ids: List[str],
                        auth_manager: AzureAuthManager, output_format: str,
                        output_path: Path, max_concurrent: int, generate_diagram: bool = False):
    """Analyze permissions for multiple users"""

    async with AzurePermissionAnalyzer(subscription_id, auth_manager) as analyzer:
        analyzer.api_client.semaphore = asyncio.Semaphore(max_concurrent)

        # Create progress bar
        progress = tqdm(total=len(user_ids), desc="Analyzing users")

        # Analyze users with limited concurrency
        analyses = []
        for user_id in user_ids:
            try:
                analysis = await analyzer.analyze_user_permissions(user_id)
                analyses.append(analysis)

                # Save individual result
                if output_format == 'json':
                    file_path = output_path / f"permissions_{user_id}.json"
                    OutputFormatter.to_json(analysis, file_path)
                elif output_format == 'csv':
                    file_path = output_path / f"permissions_{user_id}.csv"
                    OutputFormatter.to_csv(analysis, file_path)

                # Print summary
                OutputFormatter.print_summary(analysis)

                # Generate Mermaid diagram if requested
                if generate_diagram:
                    diagram_path = output_path / f"permissions_diagram_{user_id}"
                    OutputFormatter.save_mermaid_diagram(analysis, diagram_path, format='png')

            except Exception as e:
                logger.error(f"Failed to analyze user {user_id}: {e}")

            progress.update(1)

        progress.close()

        # Save combined results for Excel
        if output_format == 'excel' and analyses:
            file_path = output_path / "permissions_analysis.xlsx"
            OutputFormatter.to_excel(analyses, file_path)


        logger.info(f"Analysis complete. Results saved to {output_path}")

if __name__ == "__main__":
    main()