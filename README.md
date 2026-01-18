# Azure Permission Analyzer

A web-based Azure permission analysis tool for System Administrators and Cloud Engineers to analyze Azure AD permissions across subscriptions.

## Overview

This application provides a FastAPI-based web interface for analyzing user permissions in Azure environments. It helps you:
- Analyze user permissions across all Azure subscriptions
- Identify role assignments and RBAC configurations
- Generate comprehensive permission reports
- Manage Azure credentials securely with AES-256-GCM encryption

## Features

- **Azure Permission Analysis**: Comprehensive analysis of Azure AD permissions across subscriptions
- **Web Interface**: User-friendly FastAPI web application with Jinja2 templates
- **Security**: AES-256-GCM encrypted credential storage with automatic expiration
- **Visual Permission Diagrams**: Interactive Mermaid.js flowcharts showing hierarchical permission structures with color-coded nodes, zoom controls, and PNG export
- **Demo Mode**: Test the application without Azure credentials
- **Docker Support**: Containerized deployment for easy setup
- **Health Checks**: Built-in health monitoring endpoints
- **Async/Await**: High-performance async operations throughout

## Visual Diagrams

<div align="center">
  <video src="https://github.com/RazvanDuda/Azure-Visual-Permission-Analyzer/blob/main/video.webm" width="800" controls>
    Your browser does not support the video tag.
  </video>
</div>

The application generates interactive visual permission diagrams using Mermaid.js:

- **Hierarchical Flowchart View**: See the complete permission structure from subscription down to individual resources (users, assignments, groups, Key Vaults, Storage accounts)
- **Color-Coded Permissions**: Quick visual identification of permission levels:
  - Owner: Red
  - Contributor: Orange
  - Reader: Green
  - Security Admin: Purple
- **Resource Visibility**: View Key Vault access policies and Storage account permissions at a glance
- **Interactive Controls**: Zoom in/out and export diagrams as high-quality PNG images
- **Security Indicators**: High-risk permissions (e.g., storage key access) highlighted in red

## Architecture

```
├── main.py              # FastAPI application entry point
├── config.py            # Pydantic configuration models
├── database.py          # DuckDB database management
├── security.py          # AES-256-GCM credential encryption
├── permissions.py       # Core Azure permission analysis logic
├── repositories.py      # Repository pattern data access layer
├── migrations.py        # Database migration management
├── demo_data.py         # Demo data generator
├── templates/           # Jinja2 HTML templates
└── static/              # CSS and JavaScript assets
```

## Requirements

- Python 3.11+
- [uv](https://github.com/astral-sh/uv) (recommended) or pip
- Docker (optional, for containerized deployment)

## Installation

### Using uv (Recommended)

```bash
# Clone the repository
git clone <repository-url>
cd Python_simple_version_v1.1

# Install dependencies
uv sync --no-dev
```

### Using pip

```bash
# Install dependencies
pip install fastapi uvicorn jinja2 azure-identity azure-identity azure-mgmt-authorization azure-mgmt-resource duckdb pandas cryptography openpyxl pillow tqdm python-multipart
```

## Usage

### Running Locally

```bash
# Start the application
uv run uvicorn main:app --host 127.0.0.1 --port 8000
```

### Using Docker

```bash
# Build the image
docker build -t azure-permission-analyzer .

# Run the container
docker run -p 8000:8000 azure-permission-analyzer
```

### Access the Application

- **Web Interface**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs (Swagger UI)
- **Health Check**: http://localhost:8000/health

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web interface home |
| `/health` | GET | Health check |
| `/api/analyze` | POST | Start permission analysis |
| `/api/results` | GET | Get analysis results |
| `/api/config` | GET/POST | Manage configuration |
| `/api/credentials` | POST | Store Azure credentials |
| `/api/download/{id}` | GET | Download report |

## Security Features

- **AES-256-GCM Encryption**: Secure credential storage
- **Automatic Credential Expiration**: Configurable expiration times
- **Session Management**: Secure session handling
- **Non-root Docker Container**: Secure container deployment

## Configuration

Edit `config.py` to customize:
- Database settings (path, timeouts, backup)
- Security settings (credential expiry, session timeout)
- Application settings (host, port, workers)

## Development

```bash
# Install development dependencies
uv sync

# Run tests
pytest

# Format code
black .

# Lint
flake8 .
```

## License

This project is licensed under the MIT License.

## Author

Created by Razvan Duda

## Version

1.1.0
