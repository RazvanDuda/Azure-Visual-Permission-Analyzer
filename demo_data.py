#!/usr/bin/env python3
"""
Demo Data Manager
Azure-dependency-free demo data generation for testing and demonstration
"""

import json
import logging
import random
from datetime import datetime, timedelta
from typing import Dict

logger = logging.getLogger(__name__)


def create_demo_data_json():
    """Create demo data as JSON without Azure dependencies with realistic permissions"""

    # MyTestCompany company constants
    TENANT_ID = "7c52a0b8-1234-5678-90ab-123456789abc"
    TENANT_NAME = "mytestcompany.onmicrosoft.com"
    SUBSCRIPTION_ID = "12345678-90ab-cdef-1234-567890abcdef"
    SUBSCRIPTION_NAME = "MyTestCompany Production Subscription"
    ORGANIZATION_NAME = "MyTestCompany Corporation"

    now = datetime.now()

    # Helper function to generate Key Vault permissions based on role
    def get_keyvault_permissions(role, user_type):
        """Generate realistic Key Vault permissions based on user role"""
        key_vaults = []

        if role == "Owner":
            # Owners get access to all key vaults with full permissions
            key_vaults = [
                {
                    "key_vault_name": "mytestcompany-prod-secrets-kv",
                    "location": "eastus",
                    "resource_group": "mytestcompany-prod-security-rg",
                    "subscription_name": SUBSCRIPTION_NAME,
                    "subscription_id": SUBSCRIPTION_ID,
                    "key_vault_id": f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/mytestcompany-prod-security-rg/providers/Microsoft.KeyVault/vaults/mytestcompany-prod-secrets-kv",
                    "access_policies": [
                        {
                            "object_id": user_type,
                            "tenant_id": TENANT_ID,
                            "permissions": {
                                "keys": ["Get", "List", "Update", "Create", "Import", "Delete", "Recover", "Backup", "Restore", "Decrypt", "Encrypt", "UnwrapKey", "WrapKey", "Verify", "Sign", "Purge"],
                                "secrets": ["Get", "List", "Set", "Delete", "Recover", "Backup", "Restore", "Purge"],
                                "certificates": ["Get", "List", "Update", "Create", "Import", "Delete", "Recover", "Backup", "Restore", "ManageContacts", "ManageIssuers", "GetIssuers", "ListIssuers", "SetIssuers", "DeleteIssuers", "Purge"],
                                "storage": ["get", "list", "delete", "set", "update", "regeneratekey", "getsas", "listsas", "deletesas", "setsas"]
                            }
                        }
                    ]
                },
                {
                    "key_vault_name": "mytestcompany-app-config-kv",
                    "location": "eastus",
                    "resource_group": "mytestcompany-prod-web-rg",
                    "subscription_name": SUBSCRIPTION_NAME,
                    "subscription_id": SUBSCRIPTION_ID,
                    "key_vault_id": f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/mytestcompany-prod-web-rg/providers/Microsoft.KeyVault/vaults/mytestcompany-app-config-kv",
                    "access_policies": [
                        {
                            "object_id": user_type,
                            "tenant_id": TENANT_ID,
                            "permissions": {
                                "keys": ["Get", "List", "Update", "Create", "Import", "Delete", "Recover", "Backup", "Restore"],
                                "secrets": ["Get", "List", "Set", "Delete", "Recover", "Backup", "Restore"],
                                "certificates": ["Get", "List", "Update", "Create", "Import", "Delete", "Recover"]
                            }
                        }
                    ]
                },
                {
                    "key_vault_name": "mytestcompany-certificates-kv",
                    "location": "westus",
                    "resource_group": "mytestcompany-infrastructure-rg",
                    "subscription_name": SUBSCRIPTION_NAME,
                    "subscription_id": SUBSCRIPTION_ID,
                    "key_vault_id": f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/mytestcompany-infrastructure-rg/providers/Microsoft.KeyVault/vaults/mytestcompany-certificates-kv",
                    "access_policies": [
                        {
                            "object_id": user_type,
                            "tenant_id": TENANT_ID,
                            "permissions": {
                                "certificates": ["Get", "List", "Update", "Create", "Import", "Delete", "Recover", "ManageContacts", "ManageIssuers"]
                            }
                        }
                    ]
                }
            ]
        elif role == "Security Admin":
            # Security admins get access to security-related key vaults
            key_vaults = [
                {
                    "key_vault_name": "mytestcompany-prod-secrets-kv",
                    "location": "eastus",
                    "resource_group": "mytestcompany-prod-security-rg",
                    "subscription_name": SUBSCRIPTION_NAME,
                    "subscription_id": SUBSCRIPTION_ID,
                    "key_vault_id": f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/mytestcompany-prod-security-rg/providers/Microsoft.KeyVault/vaults/mytestcompany-prod-secrets-kv",
                    "access_policies": [
                        {
                            "object_id": user_type,
                            "tenant_id": TENANT_ID,
                            "permissions": {
                                "keys": ["Get", "List", "Update", "Create", "Backup", "Restore"],
                                "secrets": ["Get", "List", "Set", "Delete", "Backup", "Restore"],
                                "certificates": ["Get", "List", "Update", "Create"]
                            }
                        }
                    ]
                },
                {
                    "key_vault_name": "mytestcompany-certificates-kv",
                    "location": "westus",
                    "resource_group": "mytestcompany-infrastructure-rg",
                    "subscription_name": SUBSCRIPTION_NAME,
                    "subscription_id": SUBSCRIPTION_ID,
                    "key_vault_id": f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/mytestcompany-infrastructure-rg/providers/Microsoft.KeyVault/vaults/mytestcompany-certificates-kv",
                    "access_policies": [
                        {
                            "object_id": user_type,
                            "tenant_id": TENANT_ID,
                            "permissions": {
                                "certificates": ["Get", "List", "Update", "Create", "ManageContacts", "ManageIssuers"]
                            }
                        }
                    ]
                }
            ]
        elif role == "Contributor":
            # Contributors get access to app configuration key vaults
            key_vaults = [
                {
                    "key_vault_name": "mytestcompany-app-config-kv",
                    "location": "eastus",
                    "resource_group": "mytestcompany-prod-web-rg",
                    "subscription_name": SUBSCRIPTION_NAME,
                    "subscription_id": SUBSCRIPTION_ID,
                    "key_vault_id": f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/mytestcompany-prod-web-rg/providers/Microsoft.KeyVault/vaults/mytestcompany-app-config-kv",
                    "access_policies": [
                        {
                            "object_id": user_type,
                            "tenant_id": TENANT_ID,
                            "permissions": {
                                "secrets": ["Get", "List", "Set"],
                                "keys": ["Get", "List"]
                            }
                        }
                    ]
                },
                {
                    "key_vault_name": "mytestcompany-dev-secrets-kv",
                    "location": "eastus",
                    "resource_group": "mytestcompany-dev-applications-rg",
                    "subscription_name": SUBSCRIPTION_NAME,
                    "subscription_id": SUBSCRIPTION_ID,
                    "key_vault_id": f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/mytestcompany-dev-applications-rg/providers/Microsoft.KeyVault/vaults/mytestcompany-dev-secrets-kv",
                    "access_policies": [
                        {
                            "object_id": user_type,
                            "tenant_id": TENANT_ID,
                            "permissions": {
                                "secrets": ["Get", "List", "Set", "Delete"],
                                "keys": ["Get", "List", "Create"]
                            }
                        }
                    ]
                }
            ]
        elif role in ["Storage Blob Data Contributor", "Virtual Machine Contributor"]:
            # Limited access for specialized roles
            key_vaults = [
                {
                    "key_vault_name": "mytestcompany-app-config-kv",
                    "location": "eastus",
                    "resource_group": "mytestcompany-prod-web-rg",
                    "subscription_name": SUBSCRIPTION_NAME,
                    "subscription_id": SUBSCRIPTION_ID,
                    "key_vault_id": f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/mytestcompany-prod-web-rg/providers/Microsoft.KeyVault/vaults/mytestcompany-app-config-kv",
                    "access_policies": [
                        {
                            "object_id": user_type,
                            "tenant_id": TENANT_ID,
                            "permissions": {
                                "secrets": ["Get", "List"]
                            }
                        }
                    ]
                }
            ]
        else:  # Reader and others
            # Read-only access
            key_vaults = [
                {
                    "key_vault_name": "mytestcompany-app-config-kv",
                    "location": "eastus",
                    "resource_group": "mytestcompany-prod-web-rg",
                    "subscription_name": SUBSCRIPTION_NAME,
                    "subscription_id": SUBSCRIPTION_ID,
                    "key_vault_id": f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/mytestcompany-prod-web-rg/providers/Microsoft.KeyVault/vaults/mytestcompany-app-config-kv",
                    "access_policies": [
                        {
                            "object_id": user_type,
                            "tenant_id": TENANT_ID,
                            "permissions": {
                                "secrets": ["Get", "List"],
                                "keys": ["Get", "List"]
                            }
                        }
                    ]
                }
            ]

        return key_vaults

    # Helper function to generate Storage Account permissions based on role
    def get_storage_permissions(role, user_type):
        """Generate realistic Storage Account permissions based on user role"""
        storage_accounts = []

        if role == "Owner":
            # Owners get access to all storage accounts with full permissions
            storage_accounts = [
                {
                    "storage_account_name": "mytestcompanyproddata001",
                    "location": "eastus",
                    "resource_group": "mytestcompany-prod-data-rg",
                    "subscription_name": SUBSCRIPTION_NAME,
                    "subscription_id": SUBSCRIPTION_ID,
                    "sku": "Standard_LRS",
                    "kind": "StorageV2",
                    "security_level": "High",
                    "effective_permissions": [
                        "Microsoft.Storage/storageAccounts/*",
                        "Microsoft.Storage/storageAccounts/listKeys/action",
                        "Microsoft.Storage/storageAccounts/regenerateKey/action",
                        "Microsoft.Storage/storageAccounts/blobServices/*",
                        "Microsoft.Storage/storageAccounts/fileServices/*",
                        "Microsoft.Storage/storageAccounts/queueServices/*",
                        "Microsoft.Storage/storageAccounts/tableServices/*"
                    ],
                    "can_list_keys": True,
                    "can_regenerate_keys": True
                },
                {
                    "storage_account_name": "mytestcompanylogstorage",
                    "location": "eastus",
                    "resource_group": "mytestcompany-monitoring-rg",
                    "subscription_name": SUBSCRIPTION_NAME,
                    "subscription_id": SUBSCRIPTION_ID,
                    "sku": "Standard_GRS",
                    "kind": "StorageV2",
                    "security_level": "Medium",
                    "effective_permissions": [
                        "Microsoft.Storage/storageAccounts/*",
                        "Microsoft.Storage/storageAccounts/listKeys/action",
                        "Microsoft.Storage/storageAccounts/blobServices/containers/*"
                    ],
                    "can_list_keys": True,
                    "can_regenerate_keys": True
                },
                {
                    "storage_account_name": "mytestcompanybackup001",
                    "location": "westus",
                    "resource_group": "mytestcompany-backup-rg",
                    "subscription_name": SUBSCRIPTION_NAME,
                    "subscription_id": SUBSCRIPTION_ID,
                    "sku": "Standard_GRS",
                    "kind": "StorageV2",
                    "security_level": "High",
                    "effective_permissions": [
                        "Microsoft.Storage/storageAccounts/*",
                        "Microsoft.Storage/storageAccounts/listKeys/action",
                        "Microsoft.Storage/storageAccounts/blobServices/*"
                    ],
                    "can_list_keys": True,
                    "can_regenerate_keys": True
                }
            ]
        elif role == "Security Admin":
            # Security admins get monitoring and audit access
            storage_accounts = [
                {
                    "storage_account_name": "mytestcompanylogstorage",
                    "location": "eastus",
                    "resource_group": "mytestcompany-monitoring-rg",
                    "subscription_name": SUBSCRIPTION_NAME,
                    "subscription_id": SUBSCRIPTION_ID,
                    "sku": "Standard_GRS",
                    "kind": "StorageV2",
                    "security_level": "Medium",
                    "effective_permissions": [
                        "Microsoft.Storage/storageAccounts/read",
                        "Microsoft.Storage/storageAccounts/listKeys/action",
                        "Microsoft.Storage/storageAccounts/blobServices/containers/read",
                        "Microsoft.Storage/storageAccounts/blobServices/containers/write"
                    ],
                    "can_list_keys": True,
                    "can_regenerate_keys": False
                }
            ]
        elif role == "Contributor":
            # Contributors get access to prod and dev storage
            storage_accounts = [
                {
                    "storage_account_name": "mytestcompanyproddata001",
                    "location": "eastus",
                    "resource_group": "mytestcompany-prod-data-rg",
                    "subscription_name": SUBSCRIPTION_NAME,
                    "subscription_id": SUBSCRIPTION_ID,
                    "sku": "Standard_LRS",
                    "kind": "StorageV2",
                    "security_level": "High",
                    "effective_permissions": [
                        "Microsoft.Storage/storageAccounts/read",
                        "Microsoft.Storage/storageAccounts/write",
                        "Microsoft.Storage/storageAccounts/blobServices/containers/read",
                        "Microsoft.Storage/storageAccounts/blobServices/containers/write",
                        "Microsoft.Storage/storageAccounts/fileServices/shares/read",
                        "Microsoft.Storage/storageAccounts/fileServices/shares/write"
                    ],
                    "can_list_keys": False,
                    "can_regenerate_keys": False
                },
                {
                    "storage_account_name": "mytestcompanydevstg001",
                    "location": "eastus",
                    "resource_group": "mytestcompany-dev-applications-rg",
                    "subscription_name": SUBSCRIPTION_NAME,
                    "subscription_id": SUBSCRIPTION_ID,
                    "sku": "Standard_LRS",
                    "kind": "StorageV2",
                    "security_level": "Low",
                    "effective_permissions": [
                        "Microsoft.Storage/storageAccounts/*",
                        "Microsoft.Storage/storageAccounts/listKeys/action",
                        "Microsoft.Storage/storageAccounts/blobServices/*"
                    ],
                    "can_list_keys": True,
                    "can_regenerate_keys": False
                }
            ]
        elif role == "Storage Blob Data Contributor":
            # Data engineers get full access to data storage accounts
            storage_accounts = [
                {
                    "storage_account_name": "mytestcompanyproddata001",
                    "location": "eastus",
                    "resource_group": "mytestcompany-prod-data-rg",
                    "subscription_name": SUBSCRIPTION_NAME,
                    "subscription_id": SUBSCRIPTION_ID,
                    "sku": "Standard_LRS",
                    "kind": "StorageV2",
                    "security_level": "High",
                    "effective_permissions": [
                        "Microsoft.Storage/storageAccounts/read",
                        "Microsoft.Storage/storageAccounts/blobServices/containers/read",
                        "Microsoft.Storage/storageAccounts/blobServices/containers/write",
                        "Microsoft.Storage/storageAccounts/blobServices/containers/delete",
                        "Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action"
                    ],
                    "can_list_keys": False,
                    "can_regenerate_keys": False
                },
                {
                    "storage_account_name": "mytestcompanydatalake001",
                    "location": "eastus",
                    "resource_group": "mytestcompany-prod-data-rg",
                    "subscription_name": SUBSCRIPTION_NAME,
                    "subscription_id": SUBSCRIPTION_ID,
                    "sku": "Premium_LRS",
                    "kind": "BlockBlobStorage",
                    "security_level": "High",
                    "effective_permissions": [
                        "Microsoft.Storage/storageAccounts/read",
                        "Microsoft.Storage/storageAccounts/blobServices/containers/*",
                        "Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action"
                    ],
                    "can_list_keys": False,
                    "can_regenerate_keys": False
                }
            ]
        elif role == "Virtual Machine Contributor":
            # DevOps engineers get access to VM-related storage
            storage_accounts = [
                {
                    "storage_account_name": "mytestcompanyvmdiagstg001",
                    "location": "eastus",
                    "resource_group": "mytestcompany-infrastructure-rg",
                    "subscription_name": SUBSCRIPTION_NAME,
                    "subscription_id": SUBSCRIPTION_ID,
                    "sku": "Standard_LRS",
                    "kind": "Storage",
                    "security_level": "Medium",
                    "effective_permissions": [
                        "Microsoft.Storage/storageAccounts/read",
                        "Microsoft.Storage/storageAccounts/blobServices/containers/read",
                        "Microsoft.Storage/storageAccounts/blobServices/containers/write"
                    ],
                    "can_list_keys": False,
                    "can_regenerate_keys": False
                }
            ]
        else:  # Reader and others
            # Read-only access
            storage_accounts = [
                {
                    "storage_account_name": "mytestcompanyproddata001",
                    "location": "eastus",
                    "resource_group": "mytestcompany-prod-data-rg",
                    "subscription_name": SUBSCRIPTION_NAME,
                    "subscription_id": SUBSCRIPTION_ID,
                    "sku": "Standard_LRS",
                    "kind": "StorageV2",
                    "security_level": "High",
                    "effective_permissions": [
                        "Microsoft.Storage/storageAccounts/read",
                        "Microsoft.Storage/storageAccounts/blobServices/containers/read"
                    ],
                    "can_list_keys": False,
                    "can_regenerate_keys": False
                }
            ]

        return storage_accounts

    # Helper function to generate permissions based on role
    def get_permissions_for_role(role):
        """Generate comprehensive permissions based on role"""
        if role == "Owner":
            return {
                f"/subscriptions/{SUBSCRIPTION_ID}": [
                    "Microsoft.Authorization/*",
                    "Microsoft.Resources/*",
                    "Microsoft.Compute/*",
                    "Microsoft.Storage/*",
                    "Microsoft.Network/*",
                    "Microsoft.KeyVault/*",
                    "Microsoft.Security/*",
                    "Microsoft.Insights/*",
                    "Microsoft.Sql/*",
                    "Microsoft.Web/*"
                ]
            }
        elif role == "Security Admin":
            return {
                f"/subscriptions/{SUBSCRIPTION_ID}": [
                    "Microsoft.Security/*",
                    "Microsoft.Authorization/*/read",
                    "Microsoft.KeyVault/vaults/read",
                    "Microsoft.KeyVault/vaults/secrets/read",
                    "Microsoft.Resources/subscriptions/resourceGroups/read",
                    "Microsoft.Insights/alertRules/*",
                    "Microsoft.OperationalInsights/*"
                ]
            }
        elif role == "Contributor":
            return {
                f"/subscriptions/{SUBSCRIPTION_ID}": [
                    "Microsoft.Resources/*",
                    "Microsoft.Compute/*",
                    "Microsoft.Network/*",
                    "Microsoft.Storage/storageAccounts/read",
                    "Microsoft.Storage/storageAccounts/write",
                    "Microsoft.Web/*",
                    "Microsoft.Insights/*"
                ]
            }
        elif role == "Storage Blob Data Contributor":
            return {
                f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/mytestcompany-prod-data-rg": [
                    "Microsoft.Storage/storageAccounts/blobServices/containers/read",
                    "Microsoft.Storage/storageAccounts/blobServices/containers/write",
                    "Microsoft.Storage/storageAccounts/blobServices/containers/delete",
                    "Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action"
                ]
            }
        elif role == "Virtual Machine Contributor":
            return {
                f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/mytestcompany-infrastructure-rg": [
                    "Microsoft.Compute/virtualMachines/*",
                    "Microsoft.Compute/disks/*",
                    "Microsoft.Network/networkInterfaces/*",
                    "Microsoft.Network/publicIPAddresses/*",
                    "Microsoft.Resources/deployments/*"
                ]
            }
        else:  # Reader
            return {
                f"/subscriptions/{SUBSCRIPTION_ID}": [
                    "Microsoft.Resources/subscriptions/read",
                    "Microsoft.Resources/subscriptions/resourceGroups/read",
                    "Microsoft.Authorization/*/read",
                    "Microsoft.Compute/*/read",
                    "Microsoft.Storage/*/read",
                    "Microsoft.Network/*/read"
                ]
            }

    # Demo user profiles with enhanced role definitions
    demo_users = [
        {"user_id": "ceo-001", "email": "ceo@mytestcompany.com", "name": "Alex Thompson (Chief Executive Officer)", "role": "Owner"},
        {"user_id": "cto-001", "email": "cto@mytestcompany.com", "name": "Sarah Kim (Chief Technology Officer)", "role": "Owner"},
        {"user_id": "secadmin-001", "email": "security.admin@mytestcompany.com", "name": "Mike Chen (Security Administrator)", "role": "Security Admin"},
        {"user_id": "devlead-001", "email": "dev.lead@mytestcompany.com", "name": "David Park (Senior Development Lead)", "role": "Contributor"},
        {"user_id": "developer-001", "email": "developer1@mytestcompany.com", "name": "Emma Wilson (Software Developer)", "role": "Contributor"},
        {"user_id": "sysadmin-001", "email": "sysadmin@mytestcompany.com", "name": "Robert Garcia (System Administrator)", "role": "Contributor"},
        {"user_id": "pm-001", "email": "project.manager@mytestcompany.com", "name": "Lisa Chang (Project Manager)", "role": "Reader"},
        {"user_id": "dataeng-001", "email": "data.engineer@mytestcompany.com", "name": "James Rodriguez (Data Engineer)", "role": "Storage Blob Data Contributor"},
        {"user_id": "devops-001", "email": "devops.engineer@mytestcompany.com", "name": "Maria Santos (DevOps Engineer)", "role": "Virtual Machine Contributor"},
        {"user_id": "consultant-001", "email": "external.consultant@mytestcompany.com", "name": "John Smith (External Consultant)", "role": "Reader"},
    ]

    demo_data = {}

    for i, profile in enumerate(demo_users, 1):
        analysis_id = f"mytestcompany_demo_analysis_{i:03d}"

        # Create comprehensive analysis structure with realistic permissions
        analysis_data = {
            "user_id": profile["user_id"],
            "user_principal_name": profile["email"],
            "display_name": profile["name"],
            "tenant_id": TENANT_ID,
            "tenant_name": TENANT_NAME,
            "subscription_id": SUBSCRIPTION_ID,
            "subscription_name": SUBSCRIPTION_NAME,
            "organization_name": ORGANIZATION_NAME,
            "direct_assignments": [
                {
                    "role_name": profile["role"],
                    "scope": f"/subscriptions/{SUBSCRIPTION_ID}",
                    "scope_type": "Subscription",
                    "principal_type": "User",
                    "created_on": (now - timedelta(days=random.randint(1, 30))).isoformat(),
                    "condition": None
                }
            ],
            "group_assignments": [
                {
                    "role_name": "Reader" if profile["role"] == "Reader" else "Contributor",
                    "scope": f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/mytestcompany-prod-rg",
                    "scope_type": "Resource Group",
                    "principal_type": "Group",
                    "group_name": "MyTestCompany IT Administrators" if profile["role"] != "Reader" else "MyTestCompany Business Users",
                    "group_id": "group-it-admin-001" if profile["role"] != "Reader" else "group-business-001",
                    "created_on": (now - timedelta(days=random.randint(1, 60))).isoformat(),
                    "condition": None
                }
            ],
            "all_permissions": get_permissions_for_role(profile["role"]),
            "key_vault_permissions": get_keyvault_permissions(profile["role"], profile["user_id"]),
            "storage_account_permissions": get_storage_permissions(profile["role"], profile["user_id"]),
            "analyzed_at": (now - timedelta(minutes=random.randint(5, 120))).isoformat()
        }

        demo_data[analysis_id] = analysis_data

    return demo_data


def generate_dynamic_demo_data():
    """
    Generate comprehensive and dynamic demo data for MyTestCompany Corporation
    Creates diverse user profiles with realistic Azure permission scenarios

    NOTE: This is a legacy function that requires Azure dependencies (UserPermissionAnalysis)
    Use create_demo_data_json() for Azure-dependency-free demo data generation
    """
    from permissions import UserPermissionAnalysis

    # MyTestCompany company constants
    TENANT_ID = "7c52a0b8-1234-5678-90ab-123456789abc"
    TENANT_NAME = "mytestcompany.onmicrosoft.com"
    SUBSCRIPTION_ID = "12345678-90ab-cdef-1234-567890abcdef"
    SUBSCRIPTION_NAME = "MyTestCompany Production Subscription"
    ORGANIZATION_NAME = "MyTestCompany Corporation"

    # Base time for creating realistic timestamps
    now = datetime.now()

    # Azure role definitions for realistic assignments
    azure_roles = [
        "Owner", "Contributor", "Reader", "Security Admin", "Security Reader",
        "Network Contributor", "Storage Account Contributor", "Storage Blob Data Contributor",
        "Key Vault Administrator", "Key Vault Secrets User", "Virtual Machine Contributor",
        "SQL DB Contributor", "Backup Contributor", "Monitoring Contributor",
        "Application Insights Component Contributor", "Cosmos DB Account Reader Role",
        "Cognitive Services User", "Machine Learning Developer"
    ]

    # Resource groups for different environments and purposes
    resource_groups = [
        "mytestcompany-prod-web-rg", "mytestcompany-prod-data-rg", "mytestcompany-prod-security-rg",
        "mytestcompany-dev-applications-rg", "mytestcompany-test-environment-rg", "mytestcompany-staging-rg",
        "mytestcompany-infrastructure-rg", "mytestcompany-monitoring-rg", "mytestcompany-backup-rg",
        "mytestcompany-ai-ml-rg"
    ]

    # Groups for realistic organizational structure
    groups = [
        {"name": "MyTestCompany IT Administrators", "id": "group-it-admin-001"},
        {"name": "MyTestCompany Security Team", "id": "group-security-001"},
        {"name": "MyTestCompany Development Team", "id": "group-dev-001"},
        {"name": "MyTestCompany Infrastructure Team", "id": "group-infra-001"},
        {"name": "MyTestCompany Data Platform Team", "id": "group-data-001"},
        {"name": "MyTestCompany DevOps Engineers", "id": "group-devops-001"},
        {"name": "MyTestCompany Business Users", "id": "group-business-001"},
        {"name": "MyTestCompany External Consultants", "id": "group-external-001"}
    ]

    def create_storage_permissions(user_role, access_level):
        """Generate realistic storage account permissions"""
        storage_accounts = [
            {"name": "mytestcompanyproddata001", "rg": "mytestcompany-prod-data-rg"},
            {"name": "mytestcompanydevstg001", "rg": "mytestcompany-dev-applications-rg"},
            {"name": "mytestcompanybackup001", "rg": "mytestcompany-backup-rg"},
            {"name": "mytestcompanylogstorage", "rg": "mytestcompany-monitoring-rg"},
            {"name": "mytestcompanyimages001", "rg": "mytestcompany-prod-web-rg"}
        ]

        permissions_map = {
            "full": [
                "Microsoft.Storage/storageAccounts/*",
                "Microsoft.Storage/storageAccounts/blobServices/*",
                "Microsoft.Storage/storageAccounts/fileServices/*",
                "Microsoft.Storage/storageAccounts/queueServices/*",
                "Microsoft.Storage/storageAccounts/tableServices/*"
            ],
            "contributor": [
                "Microsoft.Storage/storageAccounts/read",
                "Microsoft.Storage/storageAccounts/write",
                "Microsoft.Storage/storageAccounts/blobServices/containers/*",
                "Microsoft.Storage/storageAccounts/fileServices/shares/*"
            ],
            "read": [
                "Microsoft.Storage/storageAccounts/read",
                "Microsoft.Storage/storageAccounts/blobServices/containers/read",
                "Microsoft.Storage/storageAccounts/listKeys/action"
            ]
        }

        result = []
        storage_count = random.randint(1, 3) if access_level != "read" else random.randint(1, 2)

        for storage in random.sample(storage_accounts, storage_count):
            result.append({
                "storage_account_name": storage["name"],
                "resource_group": storage["rg"],
                "permissions": permissions_map[access_level],
                "access_level": f"{access_level.title()} Access",
                "assigned_via": f"{'Direct Assignment' if random.choice([True, False]) else 'Group Assignment'} ({user_role})",
                "last_accessed": (now - timedelta(hours=random.randint(1, 168))).isoformat()
            })

        return result

    def create_keyvault_permissions(user_role, access_level):
        """Generate realistic Key Vault permissions"""
        key_vaults = [
            {"name": "mytestcompany-prod-secrets-kv", "rg": "mytestcompany-prod-security-rg"},
            {"name": "mytestcompany-app-config-kv", "rg": "mytestcompany-prod-web-rg"},
            {"name": "mytestcompany-dev-secrets-kv", "rg": "mytestcompany-dev-applications-rg"},
            {"name": "mytestcompany-certificates-kv", "rg": "mytestcompany-infrastructure-rg"},
            {"name": "mytestcompany-backup-keys-kv", "rg": "mytestcompany-backup-rg"}
        ]

        permissions_map = {
            "full": [
                "Microsoft.KeyVault/vaults/*",
                "Microsoft.KeyVault/vaults/secrets/*",
                "Microsoft.KeyVault/vaults/keys/*",
                "Microsoft.KeyVault/vaults/certificates/*"
            ],
            "admin": [
                "Microsoft.KeyVault/vaults/read",
                "Microsoft.KeyVault/vaults/secrets/*",
                "Microsoft.KeyVault/vaults/keys/read",
                "Microsoft.KeyVault/vaults/certificates/read"
            ],
            "user": [
                "Microsoft.KeyVault/vaults/read",
                "Microsoft.KeyVault/vaults/secrets/read",
                "Microsoft.KeyVault/vaults/keys/read"
            ],
            "read": [
                "Microsoft.KeyVault/vaults/read",
                "Microsoft.KeyVault/vaults/secrets/read"
            ]
        }

        access_map = {
            "full": {"secrets": True, "keys": True, "certificates": True},
            "admin": {"secrets": True, "keys": True, "certificates": True},
            "user": {"secrets": True, "keys": True, "certificates": False},
            "read": {"secrets": True, "keys": False, "certificates": False}
        }

        result = []
        vault_count = random.randint(1, 2) if access_level in ["full", "admin"] else 1

        for vault in random.sample(key_vaults, vault_count):
            result.append({
                "key_vault_name": vault["name"],
                "resource_group": vault["rg"],
                "permissions": permissions_map[access_level],
                "access_level": f"{access_level.title()} Access",
                "assigned_via": f"{'Direct Assignment' if random.choice([True, False]) else 'Group Assignment'} ({user_role})",
                "secrets_access": access_map[access_level]["secrets"],
                "keys_access": access_map[access_level]["keys"],
                "certificates_access": access_map[access_level]["certificates"],
                "last_accessed": (now - timedelta(hours=random.randint(1, 72))).isoformat()
            })

        return result

    # Define user profiles with realistic scenarios
    user_profiles = [
        {
            "user_id": "ceo-001",
            "email": "ceo@mytestcompany.com",
            "display_name": "Alex Thompson (Chief Executive Officer)",
            "direct_roles": [("Owner", "/subscriptions/" + SUBSCRIPTION_ID, "Subscription")],
            "groups": [groups[0]],  # IT Administrators
            "storage_access": "full",
            "keyvault_access": "full",
            "created_days_ago": 365
        },
        {
            "user_id": "cto-001",
            "email": "cto@mytestcompany.com",
            "display_name": "Sarah Chen (Chief Technology Officer)",
            "direct_roles": [("Owner", "/subscriptions/" + SUBSCRIPTION_ID, "Subscription")],
            "groups": [groups[0], groups[1]],  # IT Admin + Security
            "storage_access": "full",
            "keyvault_access": "full",
            "created_days_ago": 300
        },
        {
            "user_id": "sysadmin-001",
            "email": "sysadmin@mytestcompany.com",
            "display_name": "Michael Rodriguez (System Administrator)",
            "direct_roles": [("Contributor", "/subscriptions/" + SUBSCRIPTION_ID, "Subscription")],
            "groups": [groups[0], groups[3]],  # IT Admin + Infrastructure
            "storage_access": "contributor",
            "keyvault_access": "admin",
            "created_days_ago": 180
        },
        {
            "user_id": "secadmin-001",
            "email": "security.admin@mytestcompany.com",
            "display_name": "Emily Johnson (Security Administrator)",
            "direct_roles": [("Security Admin", "/subscriptions/" + SUBSCRIPTION_ID, "Subscription")],
            "groups": [groups[1]],  # Security Team
            "storage_access": "read",
            "keyvault_access": "admin",
            "created_days_ago": 150
        },
        {
            "user_id": "devlead-001",
            "email": "dev.lead@mytestcompany.com",
            "display_name": "David Park (Senior Development Lead)",
            "direct_roles": [("Contributor", "/subscriptions/" + SUBSCRIPTION_ID + "/resourceGroups/mytestcompany-prod-web-rg", "Resource Group")],
            "groups": [groups[2], groups[5]],  # Dev Team + DevOps
            "storage_access": "contributor",
            "keyvault_access": "user",
            "created_days_ago": 120
        },
        {
            "user_id": "developer-001",
            "email": "developer1@mytestcompany.com",
            "display_name": "Lisa Wang (Cloud Developer)",
            "direct_roles": [("Reader", "/subscriptions/" + SUBSCRIPTION_ID, "Subscription")],
            "groups": [groups[2]],  # Development Team
            "storage_access": "read",
            "keyvault_access": "read",
            "created_days_ago": 90
        },
        {
            "user_id": "devops-001",
            "email": "devops.engineer@mytestcompany.com",
            "display_name": "James Miller (DevOps Engineer)",
            "direct_roles": [("Virtual Machine Contributor", "/subscriptions/" + SUBSCRIPTION_ID + "/resourceGroups/mytestcompany-infrastructure-rg", "Resource Group")],
            "groups": [groups[5], groups[3]],  # DevOps + Infrastructure
            "storage_access": "contributor",
            "keyvault_access": "user",
            "created_days_ago": 75
        },
        {
            "user_id": "dataeng-001",
            "email": "data.engineer@mytestcompany.com",
            "display_name": "Maria Garcia (Data Platform Engineer)",
            "direct_roles": [("Storage Account Contributor", "/subscriptions/" + SUBSCRIPTION_ID + "/resourceGroups/mytestcompany-prod-data-rg", "Resource Group")],
            "groups": [groups[4]],  # Data Platform Team
            "storage_access": "full",
            "keyvault_access": "user",
            "created_days_ago": 60
        },
        {
            "user_id": "pm-001",
            "email": "project.manager@mytestcompany.com",
            "display_name": "Robert Kim (Technical Project Manager)",
            "direct_roles": [("Reader", "/subscriptions/" + SUBSCRIPTION_ID, "Subscription")],
            "groups": [groups[6]],  # Business Users
            "storage_access": "read",
            "keyvault_access": "read",
            "created_days_ago": 45
        },
        {
            "user_id": "consultant-001",
            "email": "external.consultant@mytestcompany.com",
            "display_name": "Jennifer Taylor (External Security Consultant)",
            "direct_roles": [("Security Reader", "/subscriptions/" + SUBSCRIPTION_ID + "/resourceGroups/mytestcompany-prod-security-rg", "Resource Group")],
            "groups": [groups[7]],  # External Consultants
            "storage_access": "read",
            "keyvault_access": "read",
            "created_days_ago": 30
        }
    ]

    demo_analyses = {}

    for i, profile in enumerate(user_profiles, 1):
        # Generate direct assignments
        direct_assignments = []
        for role, scope, scope_type in profile["direct_roles"]:
            direct_assignments.append({
                "role_name": role,
                "scope": scope,
                "scope_type": scope_type,
                "principal_type": "User",
                "created_on": (now - timedelta(days=profile["created_days_ago"])).isoformat(),
                "condition": None
            })

        # Generate group assignments
        group_assignments = []
        for group in profile["groups"]:
            # Assign additional roles through groups
            group_role = random.choice(azure_roles)
            group_rg = random.choice(resource_groups)
            group_assignments.append({
                "role_name": group_role,
                "scope": f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{group_rg}",
                "scope_type": "Resource Group",
                "principal_type": "Group",
                "group_name": group["name"],
                "group_id": group["id"],
                "created_on": (now - timedelta(days=random.randint(30, profile["created_days_ago"]))).isoformat(),
                "condition": None
            })

        # Generate comprehensive permissions map
        all_permissions = {}

        # Subscription-level permissions
        if any("Subscription" in assignment["scope_type"] for assignment in direct_assignments):
            sub_scope = f"/subscriptions/{SUBSCRIPTION_ID}"
            if any("Owner" in assignment["role_name"] for assignment in direct_assignments):
                all_permissions[sub_scope] = [
                    "Microsoft.Authorization/*", "Microsoft.Resources/*", "Microsoft.Security/*",
                    "Microsoft.Compute/*", "Microsoft.Network/*", "Microsoft.Storage/*"
                ]
            elif any("Contributor" in assignment["role_name"] for assignment in direct_assignments):
                all_permissions[sub_scope] = [
                    "Microsoft.Resources/*", "Microsoft.Compute/*", "Microsoft.Network/*"
                ]
            elif any("Reader" in assignment["role_name"] for assignment in direct_assignments):
                all_permissions[sub_scope] = [
                    "Microsoft.Resources/subscriptions/read",
                    "Microsoft.Authorization/*/read"
                ]

        # Resource group permissions
        for assignment in direct_assignments + group_assignments:
            if "resourceGroups" in assignment["scope"]:
                scope = assignment["scope"]
                role = assignment["role_name"]
                if role == "Contributor":
                    all_permissions[scope] = [
                        "Microsoft.Compute/*", "Microsoft.Storage/*", "Microsoft.Network/*"
                    ]
                elif "Security" in role:
                    all_permissions[scope] = [
                        "Microsoft.Security/*", "Microsoft.Authorization/*/read"
                    ]
                elif "Storage" in role:
                    all_permissions[scope] = [
                        "Microsoft.Storage/*"
                    ]
                elif "Virtual Machine" in role:
                    all_permissions[scope] = [
                        "Microsoft.Compute/virtualMachines/*", "Microsoft.Compute/disks/*"
                    ]

        # Create UserPermissionAnalysis object
        analysis = UserPermissionAnalysis(
            user_id=profile["user_id"],
            user_principal_name=profile["email"],
            display_name=profile["display_name"],
            tenant_id=TENANT_ID,
            tenant_name=TENANT_NAME,
            subscription_id=SUBSCRIPTION_ID,
            subscription_name=SUBSCRIPTION_NAME,
            organization_name=ORGANIZATION_NAME,
            direct_assignments=direct_assignments,
            group_assignments=group_assignments,
            all_permissions=all_permissions,
            storage_account_permissions=create_storage_permissions(profile["direct_roles"][0][0], profile["storage_access"]),
            key_vault_permissions=create_keyvault_permissions(profile["direct_roles"][0][0], profile["keyvault_access"]),
            analyzed_at=now - timedelta(minutes=random.randint(1, 60))
        )

        demo_analyses[f"mytestcompany_demo_analysis_{i:03d}"] = analysis

    return demo_analyses
