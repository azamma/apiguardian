#!/usr/bin/env python3
"""
API Guardian - AWS API Gateway Security Auditor

Scans API Gateway resources and identifies those without authorizer configured.
Includes concurrent analysis, metadata collection, and filtering capabilities.

Features:
- Automatic filtering of APIs with -DEV and -CI suffixes
- OPTIONS method exclusion from analysis
- Configurable concurrent analysis with ThreadPoolExecutor
- Real-time CSV report generation
- Authorizer cache for improved performance
- Endpoint whitelist support
"""

# === IMPORTS ===
# Standard library imports (grouped first per PEP8)
import csv
import datetime
import json
import os
import re
import subprocess
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# === SECCIÓN 0: CONSTANTES DE CONFIGURACIÓN ===

# API Filtering
EXCLUDED_API_SUFFIXES: Tuple[str, ...] = ('-DEV', '-CI')
"""Sufijos de API a excluir del análisis automático."""

# HTTP Methods
EXCLUDED_HTTP_METHODS: Tuple[str, ...] = ('OPTIONS',)
"""Métodos HTTP a excluir del análisis."""

# Authorization Types that count as "proper auth"
PROPER_AUTH_TYPES: Tuple[str, ...] = ('CUSTOM', 'AWS_IAM', 'COGNITO_USER_POOLS')
"""Tipos de autorización que se consideran protección válida."""

# Pool Sizes
DEFAULT_RESOURCE_POOL_SIZE: int = 30
"""Tamaño de pool por defecto para procesamiento paralelo de recursos."""

MAX_RESOURCE_POOL_SIZE: int = 30
"""Tamaño máximo de pool permitido."""

# Authorizer Cache
AUTHORIZER_CACHE_RESOURCE_POOL_SIZE: int = 30
"""Pool size para recolección paralela de IDs de autorizadores."""


# === SECCIÓN 1: SISTEMA DE LOGGING CON COLORES ===

class Colors:
    """ANSI color codes for terminal output."""

    RESET = '\033[0m'
    INFO = '\033[0;36m'      # Cyan
    SUCCESS = '\033[0;32m'   # Green
    WARNING = '\033[0;33m'   # Yellow
    ERROR = '\033[0;31m'     # Red
    DEBUG = '\033[0;90m'     # Gray


def log_info(msg: str) -> None:
    """Log info message in cyan."""
    print(f"{Colors.INFO}[INFO]{Colors.RESET} {msg}")


def log_success(msg: str) -> None:
    """Log success message in green."""
    print(f"{Colors.SUCCESS}[SUCCESS]{Colors.RESET} {msg}")


def log_warning(msg: str) -> None:
    """Log warning message in yellow."""
    print(f"{Colors.WARNING}[WARNING]{Colors.RESET} {msg}")


def log_error(msg: str) -> None:
    """Log error message in red."""
    print(f"{Colors.ERROR}[ERROR]{Colors.RESET} {msg}")


def clear_screen() -> None:
    """Clear terminal screen in a cross-platform way."""
    os.system('cls' if os.name == 'nt' else 'clear')


def show_splash_screen() -> None:
    """Display API Guardian splash screen with ASCII eagle."""
    # Clear screen first
    clear_screen()

    eagle_ascii = """

⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣲⣶⠒⠷⠶⠤⠴⠦⠤⠤⢤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣴⣶⠚⠛⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠑⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡠⠴⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠤⢌⣛⠶⢤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⢚⠟⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠱⡄⠙⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡤⠖⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⣀⠀⣀⣤⣧⠔⠛⠓⠲⠤⢄⣀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢐⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣤⣄⣠⣤⣴⣾⣿⣿⣾⡗⠀⢀⣀⢤⠐⠠⠤⣉⠓⠦⣄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⠊⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠒⠒⠶⠶⢾⣿⡿⠛⢻⣻⠛⢻⣿⣿⠟⣋⣺⣿⠏⠀⠴⠿⠹⠋⠀⠀⠀⠀⠈⠀⠨⠳⣄⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢐⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣤⣤⠤⠄⠐⢾⣿⣝⠤⣀⢀⡠⣱⣿⣿⣿⣿⠿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⡆⠀
⠀⠀⠀⠀⠀⠀⢠⡂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢉⣛⣺⣿⣾⣛⣽⣿⡟⠁⠀⠀⢀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡀
⠀⠀⠀⠀⠀⠐⡟⠀⠀⠀⠀⡠⠖⠀⠀⠀⢀⡴⠃⠀⠀⠀⠀⠀⠀⡈⠉⢉⡽⠿⢛⡿⢛⠯⠭⣒⣚⣩⣭⣭⣤⡤⠭⠭⢭⣥⣀⣉⣑⣒⢵⡀⠀⠀⢸⡇
⠀⠀⠀⠀⠀⣰⠃⠀⢀⡔⠋⠀⠀⠀⣠⡴⠋⠀⠀⠀⠀⣠⣤⡴⠋⠀⠀⠀⠀⠀⠾⢶⣾⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠳⡀⠀⣸⠃
⠀⠀⠀⠀⢰⠟⢀⣴⠏⠀⡀⢀⣴⡿⠋⠀⠀⠀⢀⡴⠟⠋⠁⠀⠀⠀⠀⢀⣠⣴⣾⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣇⠔⠁⠀
⠀⠀⠀⠀⣞⣴⣿⠃⢠⣾⣴⣿⠋⠀⠀⠀⠀⠐⠋⠀⠀⠀⠀⠀⢐⣚⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠋⠁⠀⠀⠀
⠀⠀⠀⣸⣿⣿⣧⣶⣿⣿⣿⠗⠁⠀⡠⠂⠀⢀⠀⠀⠀⠀⠂⢉⣭⣿⣿⣿⣿⣿⣿⣿⣿⣿⠛⡟⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢀⠼⢻⣿⣿⣿⣿⣿⣿⠁⢀⣴⠏⢀⣠⠞⠁⢀⠀⠀⠀⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠱⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣠⣿⣿⣿⣿⣿⣿⣧⣾⡿⣡⣾⣿⠃⣠⡾⠁⠀⣀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠂⠀⢻⣍⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠈⣽⣿⣿⣿⣿⣿⣿⡟⠉⣰⣿⡿⣡⣾⣿⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⢻⣶⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣠⣿⣿⣿⣿⣿⣿⣿⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠋⣱⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⢸⣾⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠐⠛⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢫⣿⠏⠀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣼⡄⠀⣿⣿⡏⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣾⡿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢟⣴⡿⢋⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣤⣿⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠁⠀⡿⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⠿⢿⣿⣿⣿⣿⣿⣿⣿⢿⡿⠁⣿⠏⠘⢿⣿⣿⣿⠋⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠿⠋⣿⡿⠋⣸⠟⠁⠀⣾⣿⣿⣿⣿⣿⠟⠁⠈⠀⠀⠹⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠉⠀⠀⠰⠿⣿⣿⠿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⡏⠀⠻⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

         🦅 API GUARDIAN 🦅
     AWS API Gateway Security Auditor
              v1.0.0

    """

    print(f"{Colors.INFO}{eagle_ascii}{Colors.RESET}")
    time.sleep(3)
    clear_screen()


def log_section(title: str) -> None:
    """Log section separator with title."""
    print()
    print(f"{Colors.INFO}{'═' * 70}{Colors.RESET}")
    print(f"{Colors.INFO}  {title}{Colors.RESET}")
    print(f"{Colors.INFO}{'═' * 70}{Colors.RESET}")


def print_box_message(message: str, style: str = "info") -> None:
    """Print a message in a box."""
    color = {
        "info": Colors.INFO,
        "success": Colors.SUCCESS,
        "warning": Colors.WARNING,
        "error": Colors.ERROR
    }.get(style, Colors.INFO)

    lines = message.split('\n')
    max_len = max(len(line) for line in lines) if lines else 0

    print(f"\n{color}╔{'═' * (max_len + 2)}╗{Colors.RESET}")
    for line in lines:
        print(f"{color}║ {line:<{max_len}} ║{Colors.RESET}")
    print(f"{color}╚{'═' * (max_len + 2)}╝{Colors.RESET}")


def save_error_dump(
    error_msg: str,
    exception: Optional[Exception] = None
) -> None:
    """
    Save errors to a timestamped dump file in reports/ folder.

    Args:
        error_msg: Error message.
        exception: Exception (optional) to include full traceback.
    """
    try:
        reports_dir = ensure_reports_directory()
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        error_file = (
            reports_dir /
            f"error_dump_securitycheck_{timestamp}.log"
        )

        with open(error_file, 'w', encoding='utf-8') as f:
            f.write(
                f"=== ERROR DUMP - "
                f"{datetime.datetime.now().isoformat()} ===\n\n"
            )
            f.write(f"Error Message: {error_msg}\n\n")
            if exception:
                f.write("Full Traceback:\n")
                f.write(traceback.format_exc())
        log_error(f"Error dump saved to: {error_file}")
    except Exception as e:
        log_error(f"Failed to save error dump: {str(e)}")


# ===================================================================
# SECCIÓN 1: FUNCIONES DE INTERACCIÓN CON AWS
# ===================================================================

def run_command(command: str) -> Tuple[bool, str, str]:
    """
    Execute an AWS CLI command and return (success, stdout, stderr).

    Args:
        command: Command to execute.

    Returns:
        Tuple (success, stdout, stderr).
    """
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            check=False
        )
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)


def check_aws_credentials() -> bool:
    """
    Verify that AWS credentials are configured.

    Returns:
        True if credentials are valid, False otherwise.
    """
    success, stdout, stderr = run_command(
        "aws sts get-caller-identity --output json"
    )
    if not success:
        log_error("AWS credentials not configured or invalid")
        return False
    return True


def get_current_region() -> Optional[str]:
    """
    Get current AWS region.

    Returns:
        Region name or None.
    """
    success, stdout, stderr = run_command("aws configure get region")
    if success:
        return stdout.strip()
    return None


def get_rest_apis() -> Optional[List[Dict]]:
    """
    Get list of all REST APIs.

    Returns:
        List of APIs or None if failed.
    """
    log_info("Fetching REST APIs...")

    # Verify credentials first
    if not check_aws_credentials():
        log_error("Please configure AWS credentials: aws configure")
        return None

    region = get_current_region()
    if region:
        log_info(f"Using AWS region: {region}")

    success, stdout, stderr = run_command(
        "aws apigateway get-rest-apis --output json"
    )

    if not success:
        log_error(f"Failed to get REST APIs: {stderr}")
        return None

    try:
        data = json.loads(stdout)
        apis = data.get('items', [])
        log_success(f"Found {len(apis)} API(s)")
        return apis
    except json.JSONDecodeError as e:
        log_error(f"Failed to parse REST APIs response: {str(e)}")
        return None


def get_resources(api_id: str) -> Optional[List[Dict]]:
    """
    Get all resources for an API.

    Args:
        api_id: API ID.

    Returns:
        List of resources or None if failed.
    """
    success, stdout, stderr = run_command(
        f"aws apigateway get-resources --rest-api-id {api_id} --output json"
    )

    if not success:
        error_msg = stderr.strip() if stderr else "Unknown error"

        if stderr.startswith('{'):
            try:
                error_json = json.loads(stderr)
                error_msg = error_json.get('message', error_msg)
            except Exception:
                pass

        log_error(f"Failed to get resources for API {api_id}")
        return None

    try:
        data = json.loads(stdout)
        resources = data.get('items', [])
        return resources
    except json.JSONDecodeError as e:
        log_error(f"Failed to parse resources response: {str(e)}")
        return None


def get_resource_full_details(api_id: str, resource_id: str) -> Optional[Dict]:
    """
    Get full details of a resource (methods + metadata).

    Args:
        api_id: API ID.
        resource_id: Resource ID.

    Returns:
        Dictionary with resource methods and metadata or None.
    """
    success, stdout, stderr = run_command(
        f"aws apigateway get-resource --rest-api-id {api_id} "
        f"--resource-id {resource_id} --output json"
    )

    if not success:
        return None

    try:
        data = json.loads(stdout)
        return data
    except json.JSONDecodeError:
        return None


def get_resource_methods(api_id: str, resource_id: str) -> Optional[Dict]:
    """
    Get HTTP methods for a resource.

    Args:
        api_id: API ID.
        resource_id: Resource ID.

    Returns:
        Dictionary of methods or None.
    """
    resource_data = get_resource_full_details(api_id, resource_id)
    if resource_data:
        return resource_data.get('resourceMethods', {})
    return None


def get_method_authorization(
    api_id: str,
    resource_id: str,
    method: str,
    authorizer_cache: Optional[Dict[str, Dict]] = None
) -> Optional[Dict]:
    """
    Get authorization configuration for a method.

    Includes authorizer information (claims, scope, etc.) if available.

    Args:
        api_id: API ID.
        resource_id: Resource ID.
        method: HTTP method.
        authorizer_cache: Cache of authorizer details to avoid repeated API calls.

    Returns:
        Dictionary with authorization information or None.
    """
    success, stdout, stderr = run_command(
        f"aws apigateway get-method --rest-api-id {api_id} "
        f"--resource-id {resource_id} --http-method {method} --output json"
    )

    if not success:
        return None

    try:
        data = json.loads(stdout)
        auth_type = data.get('authorizationType')
        authorizer_id = data.get('authorizerId')

        # Retrieve authorizer details if exists
        authorizer_details = None
        if authorizer_id and auth_type in ['CUSTOM', 'COGNITO_USER_POOLS']:
            # Use cache if available (to avoid race conditions in ThreadPool)
            if authorizer_cache and authorizer_id in authorizer_cache:
                authorizer_details = authorizer_cache[authorizer_id]
            else:
                authorizer_details = get_authorizer_details(api_id, authorizer_id)

        # Get claims from request if configured
        method_request = data.get('methodRequest', {})
        request_models = method_request.get('requestModels', {})
        authorizer_claims = None

        # Try to extract claims from authorizer
        if authorizer_details:
            authorizer_claims = authorizer_details.get('identitySource', '')

        result = {
            'authorizationType': auth_type,
            'authorizerId': authorizer_id,
            'apiKeyRequired': data.get('apiKeyRequired', False),
            'authorizerDetails': authorizer_details,
            'identitySource': authorizer_claims
        }
        return result
    except json.JSONDecodeError:
        return None


def get_authorizer_details(api_id: str, authorizer_id: str) -> Optional[Dict]:
    """
    Get authorizer details (claims, name, etc.).

    Args:
        api_id: API ID.
        authorizer_id: Authorizer ID.

    Returns:
        Dictionary with authorizer details or None.
    """
    success, stdout, stderr = run_command(
        f"aws apigateway get-authorizer --rest-api-id {api_id} "
        f"--authorizer-id {authorizer_id} --output json"
    )

    if not success:
        return None

    try:
        data = json.loads(stdout)
        result = {
            'name': data.get('name'),
            'type': data.get('type'),
            'identitySource': data.get('identitySource'),
            'identityValidationExpression': data.get('identityValidationExpression'),
            'authorizerUri': data.get('authorizerUri'),
            'authorizerCredentials': data.get('authorizerCredentials'),
            'authorizerResultTtlInSeconds': data.get('authorizerResultTtlInSeconds')
        }
        return result
    except json.JSONDecodeError as e:
        log_error(f"Failed to parse authorizer response: {str(e)}")
        return None


def get_integration_details(
    api_id: str,
    resource_id: str,
    method: str
) -> Optional[Dict]:
    """
    Get integration details for a method (endpoint URL, headers, etc.).

    Args:
        api_id: API ID.
        resource_id: Resource ID.
        method: HTTP method.

    Returns:
        Dictionary with integration details or None if integration not found.
    """
    success, stdout, stderr = run_command(
        f"aws apigateway get-integration --rest-api-id {api_id} "
        f"--resource-id {resource_id} --http-method {method} --output json"
    )

    if not success:
        return None

    try:
        data = json.loads(stdout)

        # Extract endpoint URL
        endpoint_url = data.get('uri', '')

        # Extract headers from requestParameters
        headers = {}
        request_params = data.get('requestParameters', {})
        if request_params:
            # Filter only headers (keys starting with 'method.request.header.')
            for param_key, param_value in request_params.items():
                if param_key.startswith('method.request.header.'):
                    header_name = param_key.replace('method.request.header.', '')
                    headers[header_name] = param_value

        result = {
            'uri': endpoint_url,
            'type': data.get('type'),
            'httpMethod': data.get('httpMethod'),
            'headers': headers,
            'requestParameters': request_params
        }
        return result
    except json.JSONDecodeError:
        return None


def clean_endpoint_url(url: str) -> str:
    """
    Clean endpoint URL by removing stage variables.

    Removes the scheme and domain part that contains stage variables,
    keeping only the path-like portion.

    Examples:
    - "https://${stageVariables.urlDiscountsPrivate}/discounts/bo/campaigns" -> "/discounts/bo/campaigns"
    - "https://api.example.com/users/123" -> "/users/123"
    - "/users/123" -> "/users/123"
    - "" -> ""

    Args:
        url: Full URL or path that may contain stage variables.

    Returns:
        Cleaned path without scheme, domain, or stage variables.
    """
    if not url:
        return ""

    # If it's already just a path (starts with /), return as is
    if url.startswith('/'):
        return url

    # Parse URL to extract path
    try:
        # Remove scheme and domain
        if '://' in url:
            # Split by :// to get the part after scheme
            after_scheme = url.split('://', 1)[1]
            # Split by / to get path (everything after domain/stage variables)
            if '/' in after_scheme:
                path = '/' + after_scheme.split('/', 1)[1]
                return path
        return ""
    except Exception:
        return ""


# ===================================================================
# SECCIÓN 2: FILTRADO DE APIs Y MÉTODOS
# ===================================================================

def load_whitelist() -> Tuple[Dict[str, List[Dict]], Dict[str, List[Dict]], Dict[str, List[Dict]]]:
    """
    Load whitelists from the 3 security category files.

    Returns:
        Tuple of (no_requiere_seguridad, seguridad_en_microservicio, seguridad_por_ip) dictionaries.
        Each dict maps API names to lists of endpoint objects with 'method' and 'path' keys.
        Empty dicts if files don't exist or have errors.
    """
    no_requiere_seguridad = {}
    seguridad_en_microservicio = {}
    seguridad_por_ip = {}

    try:
        # Load NO_REQUIERE_SEGURIDAD whitelist
        file1 = Path(__file__).parent / "whitelist_NO_REQUIERE_SEGURIDAD.json"
        if file1.exists():
            with open(file1, 'r', encoding='utf-8') as f:
                data = json.load(f)
                no_requiere_seguridad = data.get('whitelist', {})
    except Exception as e:
        log_warning(f"Failed to load NO_REQUIERE_SEGURIDAD whitelist: {str(e)}")

    try:
        # Load SEGURIDAD_EN_MICROSERVICIO whitelist
        file2 = Path(__file__).parent / "whitelist_SEGURIDAD_EN_MICROSERVICIO.json"
        if file2.exists():
            with open(file2, 'r', encoding='utf-8') as f:
                data = json.load(f)
                seguridad_en_microservicio = data.get('whitelist', {})
    except Exception as e:
        log_warning(f"Failed to load SEGURIDAD_EN_MICROSERVICIO whitelist: {str(e)}")

    try:
        # Load SEGURIDAD_POR_IP whitelist
        file3 = Path(__file__).parent / "whitelist_SEGURIDAD_POR_IP.json"
        if file3.exists():
            with open(file3, 'r', encoding='utf-8') as f:
                data = json.load(f)
                seguridad_por_ip = data.get('whitelist', {})
    except Exception as e:
        log_warning(f"Failed to load SEGURIDAD_POR_IP whitelist: {str(e)}")

    return no_requiere_seguridad, seguridad_en_microservicio, seguridad_por_ip


def is_endpoint_whitelisted(
    api_name: str,
    method: str,
    path: str,
    whitelist: Dict[str, List[Dict]]
) -> bool:
    """
    Check if an endpoint (method + path) is in the whitelist.

    Supports wildcard patterns:
    - /users/*/profile: Matches /users/123/profile, but NOT /users/123/profile/extra
    - /webhook/jumio/*: Matches /webhook/jumio/validation, /webhook/jumio/confirm, etc.

    Args:
        api_name: Name of the API.
        method: HTTP method (GET, POST, PUT, DELETE, etc.).
        path: Resource path (e.g., /users/123/profile).
        whitelist: Whitelist dictionary mapping API names to lists of endpoint dicts.

    Returns:
        True if endpoint is whitelisted, False otherwise.
    """
    if api_name not in whitelist:
        return False

    whitelisted_endpoints = whitelist[api_name]

    for endpoint_entry in whitelisted_endpoints:
        # Handle both old format (string) and new format (dict with method and path)
        if isinstance(endpoint_entry, str):
            # Legacy format - only path, no method check
            endpoint_pattern = endpoint_entry
        elif isinstance(endpoint_entry, dict):
            # New format - check method first
            endpoint_method = endpoint_entry.get('method', '').upper()
            endpoint_pattern = endpoint_entry.get('path', '')

            # Method must match (case-insensitive)
            if endpoint_method != method.upper():
                continue
        else:
            # Unknown format, skip
            continue

        # Exact match
        if path == endpoint_pattern:
            return True

        # Wildcard pattern matching
        if '*' in endpoint_pattern:
            # Case 1: Pattern ends with /* (prefix match for subpaths)
            # Example: /webhook/jumio/* matches /webhook/jumio/validation, /webhook/jumio/validation/confirm, etc.
            if endpoint_pattern.endswith('/*'):
                prefix = endpoint_pattern[:-2]  # Remove the /*
                # Only match if path starts with prefix/ (at least one segment after the prefix)
                # Also exclude the case where path is just the prefix with trailing slash
                if path.startswith(prefix + '/') and path != prefix + '/':
                    return True
            else:
                # Case 2: Pattern with * in the middle (positional wildcard)
                # Example: /users/*/profile matches /users/123/profile but NOT /users/123/profile/extra
                regex_pattern = endpoint_pattern.replace('*', '[^/]+')  # Match anything except /
                regex_pattern = f"^{regex_pattern}$"
                if re.match(regex_pattern, path):
                    return True

    return False


def get_whitelist_source(
    api_name: str,
    method: str,
    path: str,
    no_requiere_seguridad: Dict[str, List[Dict]],
    seguridad_en_microservicio: Dict[str, List[Dict]],
    seguridad_por_ip: Dict[str, List[Dict]]
) -> str:
    """
    Determine whitelist source(s) for an endpoint.

    Returns the security category where the endpoint appears, or combinations if in multiple.
    Possible values: "NO_REQUIERE_SEGURIDAD", "SEGURIDAD_EN_MICROSERVICIO",
    "SEGURIDAD_POR_IP", or combinations like "NO_REQUIERE_SEGURIDAD+SEGURIDAD_POR_IP", or "NO".

    Args:
        api_name: Name of the API.
        method: HTTP method (GET, POST, PUT, DELETE, etc.).
        path: Resource path.
        no_requiere_seguridad: NO_REQUIERE_SEGURIDAD whitelist dictionary.
        seguridad_en_microservicio: SEGURIDAD_EN_MICROSERVICIO whitelist dictionary.
        seguridad_por_ip: SEGURIDAD_POR_IP whitelist dictionary.

    Returns:
        Whitelist source: category name, combination with "+", or "NO".
    """
    in_no_requiere = is_endpoint_whitelisted(api_name, method, path, no_requiere_seguridad)
    in_microservicio = is_endpoint_whitelisted(api_name, method, path, seguridad_en_microservicio)
    in_por_ip = is_endpoint_whitelisted(api_name, method, path, seguridad_por_ip)

    # Build result based on which whitelists contain this endpoint
    sources = []
    if in_no_requiere:
        sources.append("NO_REQUIERE_SEGURIDAD")
    if in_microservicio:
        sources.append("SEGURIDAD_EN_MICROSERVICIO")
    if in_por_ip:
        sources.append("SEGURIDAD_POR_IP")

    if sources:
        return "+".join(sources)
    else:
        return "NO"


def _has_proper_authorization(auth_type: Optional[str]) -> bool:
    """
    Check if an authorization type is considered proper authentication.

    Args:
        auth_type: The authorization type to check.

    Returns:
        True if auth_type is a proper authorization, False otherwise.
    """
    return auth_type in PROPER_AUTH_TYPES


def filter_apis_by_suffix(apis: List[Dict]) -> List[Dict]:
    """
    Filter out APIs with -DEV or -CI suffixes.

    Args:
        apis: List of API dictionaries.

    Returns:
        Filtered list of APIs.
    """
    return [
        api for api in apis
        if not any(
            api['name'].endswith(suffix)
            for suffix in EXCLUDED_API_SUFFIXES
        )
    ]


def filter_options_methods(methods: Dict) -> Dict:
    """
    Filter out OPTIONS methods from method dictionary.

    Args:
        methods: Dictionary of methods.

    Returns:
        Filtered dictionary without OPTIONS method.
    """
    return {
        method: config
        for method, config in methods.items()
        if method not in EXCLUDED_HTTP_METHODS
    }


# ===================================================================
# SECCIÓN 3: ANÁLISIS DE SEGURIDAD
# ===================================================================

def analyze_resource_methods(
    api_id: str,
    resource_id: str,
    path: str,
    report_file: Optional[Path] = None,
    api_name: Optional[str] = None,
    authorizer_cache: Optional[Dict[str, Dict]] = None,
    no_requiere_seguridad: Optional[Dict[str, List[Dict]]] = None,
    seguridad_en_microservicio: Optional[Dict[str, List[Dict]]] = None,
    seguridad_por_ip: Optional[Dict[str, List[Dict]]] = None
) -> Dict:
    """
    Analyze methods for a resource sequentially.

    Helper function for analyzing individual resources.
    Reports whitelist category for each endpoint based on method + path.

    Args:
        api_id: API ID.
        resource_id: Resource ID.
        path: Resource path.
        report_file: Path to report file (optional).
        api_name: API name for reporting (optional).
        authorizer_cache: Cache of authorizer details.
        no_requiere_seguridad: NO_REQUIERE_SEGURIDAD whitelist dictionary (optional).
        seguridad_en_microservicio: SEGURIDAD_EN_MICROSERVICIO whitelist dictionary (optional).
        seguridad_por_ip: SEGURIDAD_POR_IP whitelist dictionary (optional).

    Returns:
        Dictionary with resource analysis result.
    """
    methods = get_resource_methods(api_id, resource_id)
    if not methods:
        return {
            'methods': [],
            'methods_filtered': 0,
            'error': None
        }

    # Filter OPTIONS methods
    original_method_count = len(methods)
    methods = filter_options_methods(methods)
    methods_filtered = original_method_count - len(methods)

    result_methods = []

    for method in methods.keys():
        auth_info = get_method_authorization(api_id, resource_id, method, authorizer_cache)

        if not auth_info:
            continue

        # Extract specific authorization type from authorizer
        auth_type = auth_info.get('authorizationType')
        authorizer_details = auth_info.get('authorizerDetails', {})
        authorizer_name = authorizer_details.get('name', '') if authorizer_details else ''

        # Determine specific type (admin, customer, etc.)
        specific_auth_type = auth_type
        if authorizer_name:
            # If authorizer name contains "admin" or "customer"
            lower_name = authorizer_name.lower()
            if 'admin' in lower_name:
                specific_auth_type = "ADMIN"
            elif 'customer' in lower_name:
                specific_auth_type = "CUSTOMER"

        # Get integration details (endpoint URL)
        try:
            integration_info = get_integration_details(api_id, resource_id, method)
            endpoint_url_raw = integration_info.get('uri', '') if integration_info else ''
            # Clean endpoint URL to remove stage variables and domain
            endpoint_url_clean = clean_endpoint_url(endpoint_url_raw)
        except Exception:
            # If integration details fail, just use empty string
            endpoint_url_clean = ''

        method_auth = {
            'path': path,
            'resource_id': resource_id,
            'method': method,
            'authorizationType': auth_type,
            'specificAuthType': specific_auth_type,
            'authorizerId': auth_info.get('authorizerId'),
            'authorizerName': authorizer_name,
            'identitySource': auth_info.get('identitySource'),
            'apiKeyRequired': auth_info.get('apiKeyRequired'),
            'endpointUrl': endpoint_url_clean
        }

        result_methods.append(method_auth)

        # Update report in real-time (include whitelist source)
        if report_file and api_name:
            whitelist_source = "NO"
            if no_requiere_seguridad or seguridad_en_microservicio or seguridad_por_ip:
                whitelist_source = get_whitelist_source(
                    api_name,
                    method,  # Now passing the HTTP method
                    path,
                    no_requiere_seguridad or {},
                    seguridad_en_microservicio or {},
                    seguridad_por_ip or {}
                )
            # Pass whitelist source to report
            method_auth['whitelist_source'] = whitelist_source
            update_report_file(report_file, api_name, method_auth)

    return {
        'methods': result_methods,
        'methods_filtered': methods_filtered,
        'error': None
    }


def _collect_authorizer_ids_from_resource(
    api_id: str,
    resource: Dict
) -> set:
    """
    Collect authorizer IDs from a single resource's methods.

    Helper function for parallel authorizer ID collection.

    Args:
        api_id: API ID.
        resource: Resource dictionary.

    Returns:
        Set of authorizer IDs found in this resource.
    """
    authorizer_ids = set()
    resource_methods = resource.get('resourceMethods', {})

    for method in resource_methods.keys():
        if method == 'OPTIONS':
            continue
        success, stdout, stderr = run_command(
            f"aws apigateway get-method --rest-api-id {api_id} "
            f"--resource-id {resource.get('id')} --http-method {method} --output json"
        )
        if success:
            try:
                data = json.loads(stdout)
                authorizer_id = data.get('authorizerId')
                auth_type = data.get('authorizationType')
                if authorizer_id and auth_type in ['CUSTOM', 'COGNITO_USER_POOLS']:
                    authorizer_ids.add(authorizer_id)
            except Exception:
                pass

    return authorizer_ids


def build_authorizer_cache(
    api_id: str,
    resources: List[Dict],
    resource_pool_size: int = 10,
    authorizer_pool_size: int = 5
) -> Dict[str, Dict]:
    """
    Build cache of all authorizers used in an API.

    Optimized with parallel resource scanning and parallel authorizer caching.
    This prevents race conditions when using ThreadPoolExecutor.

    Args:
        api_id: API ID.
        resources: List of resources.
        resource_pool_size: Pool size for parallel resource scanning (default: 10).
        authorizer_pool_size: Pool size for parallel authorizer caching (default: 5).

    Returns:
        Dictionary mapping authorizer_id to authorizer details.
    """
    authorizer_cache = {}

    print(f"  {Colors.DEBUG}└─ Building authorizer cache...{Colors.RESET}", end='', flush=True)

    # STEP 1: Parallel collection of authorizer IDs from resources
    total_resources = len(resources)
    unique_authorizer_ids = set()

    # Use ThreadPoolExecutor to collect authorizer IDs in parallel
    with ThreadPoolExecutor(max_workers=resource_pool_size) as executor:
        # Submit tasks for all resources
        future_to_resource = {
            executor.submit(_collect_authorizer_ids_from_resource, api_id, resource): idx
            for idx, resource in enumerate(resources)
        }

        # Process results as they complete
        processed = 0
        for future in as_completed(future_to_resource):
            try:
                result_ids = future.result()
                unique_authorizer_ids.update(result_ids)
            except Exception:
                pass

            processed += 1
            if processed % 10 == 0 or processed == total_resources:
                print(
                    f"\r  {Colors.DEBUG}└─ Scanning resources... "
                    f"{processed}/{total_resources}{Colors.RESET}",
                    end='',
                    flush=True
                )

    print()  # New line after progress

    # STEP 2: Parallel caching of authorizer details
    if unique_authorizer_ids:
        unique_ids_list = list(unique_authorizer_ids)
        num_authorizers = len(unique_ids_list)
        print(
            f"  {Colors.DEBUG}└─ Caching {num_authorizers} authorizer(s)...{Colors.RESET}",
            end='',
            flush=True
        )

        # Use ThreadPoolExecutor to cache authorizers in parallel
        with ThreadPoolExecutor(max_workers=authorizer_pool_size) as executor:
            # Submit tasks for all authorizers
            future_to_auth_id = {
                executor.submit(get_authorizer_details, api_id, auth_id): auth_id
                for auth_id in unique_ids_list
            }

            # Process results as they complete
            cached = 0
            for future in as_completed(future_to_auth_id):
                auth_id = future_to_auth_id[future]
                try:
                    auth_details = future.result()
                    if auth_details:
                        authorizer_cache[auth_id] = auth_details
                except Exception:
                    pass

                cached += 1
                if cached % 5 == 0 or cached == num_authorizers:
                    print(
                        f"\r  {Colors.DEBUG}└─ Caching {num_authorizers} "
                        f"authorizer(s)... {cached}/{num_authorizers}{Colors.RESET}",
                        end='',
                        flush=True
                    )

        print()  # New line after caching

    if authorizer_cache:
        log_info(f"Cached {len(authorizer_cache)} authorizer(s)")

    return authorizer_cache


def _print_api_analysis_header(
    api_name: str,
    api_id: str,
    current_index: int,
    total_apis: int
) -> None:
    """
    Print header for API analysis.

    Args:
        api_name: API name.
        api_id: API ID.
        current_index: Current index (1-based).
        total_apis: Total APIs to analyze.
    """
    print(
        f"\n{Colors.INFO}[{current_index}/{total_apis}]{Colors.RESET} "
        f"Scanning: {Colors.INFO}{api_name}{Colors.RESET} "
        f"{Colors.DEBUG}({api_id}){Colors.RESET}"
    )
    sys.stdout.flush()


def _print_resource_status(path: str, method_statuses: List[str]) -> None:
    """
    Print resource analysis results.

    Args:
        path: Resource path.
        method_statuses: List of method status strings.
    """
    print(f"  {Colors.DEBUG}  ├─ {path}{Colors.RESET}")
    method_display = " | ".join(method_statuses)
    print(
        f"  {Colors.DEBUG}  │  └─ Methods: "
        f"{method_display}{Colors.RESET}"
    )
    sys.stdout.flush()


def _print_api_summary(
    protected_count: int,
    unprotected_count: int,
    resources_scanned: int,
    total_methods: int,
    methods_filtered_total: int
) -> None:
    """
    Print API analysis summary.

    Args:
        protected_count: Number of protected endpoints.
        unprotected_count: Number of unprotected endpoints.
        resources_scanned: Number of resources scanned.
        total_methods: Total methods analyzed.
        methods_filtered_total: Total OPTIONS methods filtered.
    """
    print(
        f"  {Colors.DEBUG}└─ Scanned {resources_scanned} resources "
        f"with {total_methods} methods{Colors.RESET}"
    )
    if methods_filtered_total > 0:
        print(
            f"  {Colors.DEBUG}   └─ Filtered out {methods_filtered_total} "
            f"OPTIONS method(s){Colors.RESET}"
        )

    if unprotected_count > 0:
        print(
            f"  {Colors.SUCCESS}✓{Colors.RESET} {protected_count} protected "
            f"| {Colors.ERROR}⚠ {unprotected_count} unprotected{Colors.RESET}"
        )
    else:
        print(
            f"  {Colors.SUCCESS}✓{Colors.RESET} {protected_count} protected "
            f"| All secure!"
        )

    sys.stdout.flush()


def check_api_security(
    api_id: str,
    api_name: str,
    current_index: int,
    total_apis: int,
    report_file: Optional[Path] = None,
    use_resource_pool: bool = True,
    resource_pool_size: int = 5,
    no_requiere_seguridad: Optional[Dict[str, List[Dict]]] = None,
    seguridad_en_microservicio: Optional[Dict[str, List[Dict]]] = None,
    seguridad_por_ip: Optional[Dict[str, List[Dict]]] = None
) -> Dict:
    """
    Review API resources and identify those without authorizer.

    With OPTIONS method filtering and real-time report updates.
    Uses concurrent analysis for resources within each API.
    Reports whitelist category for each endpoint based on method + path.

    Args:
        api_id: API ID.
        api_name: API name.
        current_index: Current index in analysis (1-based).
        total_apis: Total APIs to analyze.
        report_file: Path to report file for real-time updates (optional).
        use_resource_pool: Use ThreadPool for parallel resource analysis (default: True).
        resource_pool_size: Pool size for resources within this API (default: 5, configurable).
        no_requiere_seguridad: NO_REQUIERE_SEGURIDAD whitelist dictionary (optional).
        seguridad_en_microservicio: SEGURIDAD_EN_MICROSERVICIO whitelist dictionary (optional).
        seguridad_por_ip: SEGURIDAD_POR_IP whitelist dictionary (optional).

    Returns:
        Dictionary with analysis result.
    """
    _print_api_analysis_header(api_name, api_id, current_index, total_apis)

    resources = get_resources(api_id)
    if resources is None:
        print(
            f"  {Colors.ERROR}✗ Could not retrieve resources{Colors.RESET}"
        )
        print(
            f"  {Colors.ERROR}└─ Check AWS credentials or permissions "
            f"for this API{Colors.RESET}"
        )
        return {
            'api_id': api_id,
            'api_name': api_name,
            'total_resources': 0,
            'resources_without_auth': [],
            'resources_with_auth': [],
            'error': 'Failed to retrieve resources - Check AWS credentials/permissions'
        }

    if len(resources) == 0:
        print(
            f"  {Colors.DEBUG}└─ No resources found "
            f"(API may be empty){Colors.RESET}"
        )
        return {
            'api_id': api_id,
            'api_name': api_name,
            'total_resources': 0,
            'resources_without_auth': [],
            'resources_with_auth': [],
            'error': None
        }

    print(f"  {Colors.DEBUG}└─ Found {len(resources)} resources{Colors.RESET}")
    sys.stdout.flush()

    resources_without_auth = []
    resources_with_auth = []
    total_methods = 0
    resources_scanned = 0
    methods_filtered_total = 0

    # Build authorizer cache before processing resources
    # This prevents race conditions when multiple threads call get_authorizer_details()
    # Use same pool_size for cache resource scanning, scale down for authorizer caching
    authorizer_cache = build_authorizer_cache(
        api_id,
        resources,
        resource_pool_size=resource_pool_size,
        authorizer_pool_size=max(1, resource_pool_size // 2)  # Half the resource pool size
    )

    # Use ThreadPoolExecutor for parallel resource analysis
    # (APIs are analyzed sequentially, but resources within each API are parallelized)
    with ThreadPoolExecutor(max_workers=resource_pool_size) as executor:
        # Create analysis tasks for each resource
        future_to_resource = {}
        for resource in resources:
            resource_id = resource.get('id')
            path = resource.get('path', 'N/A')
            future = executor.submit(
                analyze_resource_methods,
                api_id,
                resource_id,
                path,
                report_file,
                api_name,
                authorizer_cache,
                no_requiere_seguridad,
                seguridad_en_microservicio,
                seguridad_por_ip
            )
            future_to_resource[future] = (resource_id, path)

        # Process results as they complete
        for future in as_completed(future_to_resource):
            resource_id, path = future_to_resource[future]
            try:
                result = future.result()
                methods_list = result.get('methods', [])
                methods_filtered_total += result.get('methods_filtered', 0)

                if not methods_list:
                    continue

                resources_scanned += 1
                total_methods += len(methods_list)
                method_statuses = []

                for method_auth in methods_list:
                    # Only count proper authorization (not API key alone)
                    has_proper_auth = _has_proper_authorization(
                        method_auth.get('authorizationType')
                    )

                    if has_proper_auth:
                        resources_with_auth.append(method_auth)
                        method = method_auth.get('method', 'N/A')
                        method_statuses.append(
                            f"{Colors.SUCCESS}✓{Colors.RESET}{method}"
                        )
                    else:
                        resources_without_auth.append(method_auth)
                        method = method_auth.get('method', 'N/A')
                        method_statuses.append(
                            f"{Colors.ERROR}✗{Colors.RESET}{method}"
                        )

                # Show resource
                _print_resource_status(path, method_statuses)

            except Exception as e:
                log_error(f"Error analyzing resource {resource_id}: {str(e)}")

    # Show scan summary
    protected_count = len(resources_with_auth)
    unprotected_count = len(resources_without_auth)

    _print_api_summary(
        protected_count,
        unprotected_count,
        resources_scanned,
        total_methods,
        methods_filtered_total
    )

    return {
        'api_id': api_id,
        'api_name': api_name,
        'total_resources': len(resources),
        'resources_without_auth': resources_without_auth,
        'resources_with_auth': resources_with_auth,
        'methods_filtered': methods_filtered_total,
        'error': None
    }


# ===================================================================
# SECCIÓN 4: GENERACIÓN DE REPORTES
# ===================================================================

def print_security_report(results: List[Dict]) -> None:
    """
    Print detailed security report.

    Args:
        results: List of analysis results.
    """
    log_section("API GUARDIAN - SECURITY REPORT")

    total_apis = len(results)
    total_unprotected = sum(
        len(r['resources_without_auth']) for r in results
        if not r.get('error')
    )
    total_protected = sum(
        len(r['resources_with_auth']) for r in results
        if not r.get('error')
    )
    total_errors = sum(1 for r in results if r.get('error'))
    total_methods_filtered = sum(
        r.get('methods_filtered', 0) for r in results
    )

    print_box_message(
        f"Scanned: {total_apis} API(s)\n"
        f"Protected endpoints: {total_protected}\n"
        f"Unprotected endpoints: {total_unprotected}\n"
        f"Methods filtered (OPTIONS): {total_methods_filtered}\n"
        f"Errors: {total_errors}",
        "info"
    )

    for result in results:
        if result.get('error'):
            log_warning(f"\nAPI: {result['api_name']} ({result['api_id']})")
            log_error(f"Error: {result['error']}")
            continue

        unprotected = result['resources_without_auth']
        protected = result['resources_with_auth']

        print(f"\n{Colors.INFO}API: {result['api_name']}{Colors.RESET}")
        print(f"  ID: {result['api_id']}")
        print(f"  Total resources: {result['total_resources']}")
        print(f"  Protected endpoints: {len(protected)}")
        print(f"  Unprotected endpoints: {len(unprotected)}")

        if unprotected:
            print(f"\n  {Colors.ERROR}⚠ UNPROTECTED ENDPOINTS:{Colors.RESET}")
            for endpoint in unprotected:
                auth_type = endpoint['authorizationType'] or 'NONE'
                print(
                    f"    {Colors.ERROR}✗{Colors.RESET} "
                    f"[{endpoint['method']}] {endpoint['path']}"
                )
                print(
                    f"      └─ Auth Type: "
                    f"{Colors.DEBUG}{auth_type}{Colors.RESET}"
                )

        if protected:
            print(f"\n  {Colors.SUCCESS}✓ PROTECTED ENDPOINTS:{Colors.RESET}")
            for endpoint in protected[:5]:  # Show first 5
                auth_type = endpoint['authorizationType'] or 'API_KEY'
                print(
                    f"    {Colors.SUCCESS}✓{Colors.RESET} "
                    f"[{endpoint['method']}] {endpoint['path']}"
                )
                print(
                    f"      └─ Auth Type: "
                    f"{Colors.DEBUG}{auth_type}{Colors.RESET}"
                )

            if len(protected) > 5:
                print(
                    f"    ... and {len(protected) - 5} more "
                    f"protected endpoints"
                )


def ensure_reports_directory() -> Path:
    """
    Ensure reports/ folder exists.

    Returns:
        Path to reports folder.

    Raises:
        Exception if cannot create folder.
    """
    reports_dir = Path(__file__).parent / "reports"
    try:
        reports_dir.mkdir(exist_ok=True)
        return reports_dir
    except Exception as e:
        log_error(f"Failed to create reports directory: {str(e)}")
        raise


def create_consolidated_report_file(api_name: Optional[str] = None) -> Optional[Path]:
    """
    Create consolidated CSV report file.

    Single file with all endpoints from all APIs (or specific API).
    Pattern: security_audit_report_YYYYMMDD_HHMMSS.csv (multiple APIs)
    Pattern: <API_NAME>_report_YYYYMMDD_HHMMSS.csv (specific API)

    Args:
        api_name: API name (if analyzing single API). If None, creates generic report.

    Returns:
        Path to created file or None.
    """
    try:
        reports_dir = ensure_reports_directory()
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        # Generate filename based on whether it's a specific API or multiple
        if api_name:
            # Clean API name for use in filename
            safe_api_name = api_name.replace(' ', '_').replace('/', '_')
            report_file = (
                reports_dir /
                f"{safe_api_name}_report_{timestamp}.csv"
            )
        else:
            report_file = (
                reports_dir /
                f"security_audit_report_{timestamp}.csv"
            )

        # Create CSV with headers
        with open(report_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    'api',
                    'method',
                    'path',
                    'is_authorized',
                    'authorization_type',
                    'authorizer_name',
                    'api_key',
                    'whitelist',
                    'endpoint_url'
                ]
            )
            writer.writeheader()
        return report_file

    except Exception as e:
        log_error(f"Failed to create report file: {str(e)}")
        return None


def update_report_file(
    report_file: Path,
    api_name: str,
    resource_data: Dict
) -> bool:
    """
    Update CSV report file in real-time.

    Adds one row per analyzed endpoint.

    Args:
        report_file: Path to CSV report file.
        api_name: API name.
        resource_data: Dictionary with analyzed resource data.

    Returns:
        True if updated successfully, False otherwise.
    """
    try:
        # Determine if it has proper authorization (not just API key)
        has_proper_auth = _has_proper_authorization(
            resource_data.get("authorizationType")
        )

        # is_authorized should be YES only if there's proper authorization (not API key alone)
        is_authorized = 'YES' if has_proper_auth else 'NO'

        # Get whitelist source
        whitelist_source = resource_data.get('whitelist_source', 'NO')

        # Check for API Key requirement
        has_api_key = resource_data.get("apiKeyRequired", False)

        # Get integration details (endpoint URL)
        endpoint_url = resource_data.get('endpointUrl', '')

        # Prepare row for CSV
        row = {
            'api': api_name,
            'method': resource_data.get('method', 'N/A'),
            'path': resource_data.get('path', 'N/A'),
            'is_authorized': is_authorized,
            'authorization_type': (
                resource_data.get('authorizationType') or 'NONE'
            ),
            'authorizer_name': resource_data.get('authorizerName') or 'NONE',
            'api_key': 'YES' if has_api_key else 'NO',
            'whitelist': whitelist_source,
            'endpoint_url': endpoint_url
        }

        # Add row to CSV
        with open(report_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    'api',
                    'method',
                    'path',
                    'is_authorized',
                    'authorization_type',
                    'authorizer_name',
                    'api_key',
                    'whitelist',
                    'endpoint_url'
                ]
            )
            writer.writerow(row)

        return True

    except Exception as e:
        log_error(f"Failed to update report file: {str(e)}")
        return False


def save_security_report(results: List[Dict]) -> Optional[str]:
    """
    Save security report to JSON file in reports/ folder.

    Args:
        results: List of analysis results.

    Returns:
        Path to created file or None.
    """
    try:
        # Ensure reports/ folder exists
        reports_dir = ensure_reports_directory()

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = (
            reports_dir / f"security_report_{timestamp}.json"
        )

        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        log_success(f"Security report saved to: {report_file}")
        return str(report_file)
    except Exception as e:
        log_error(f"Failed to save security report: {str(e)}")
        return None


def save_api_summary_report(results: List[Dict]) -> Optional[str]:
    """
    Save API summary report to CSV file.

    Generates a summary CSV with one row per API showing:
    - API Name
    - Total Endpoints (resources with methods)
    - Protected Endpoints
    - Unprotected Endpoints

    Args:
        results: List of analysis results.

    Returns:
        Path to created file or None.
    """
    try:
        reports_dir = ensure_reports_directory()
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        summary_file = (
            reports_dir / f"api_summary_{timestamp}.csv"
        )

        with open(summary_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    'api_name',
                    'total_endpoints',
                    'protected_endpoints',
                    'unprotected_endpoints',
                    'security_status'
                ]
            )
            writer.writeheader()

            for result in results:
                if result.get('error'):
                    # Skip APIs with errors
                    continue

                api_name = result.get('api_name', 'N/A')
                protected = len(result.get('resources_with_auth', []))
                unprotected = len(result.get('resources_without_auth', []))
                total = protected + unprotected

                # Determine security status
                if total == 0:
                    security_status = "No endpoints"
                elif unprotected == 0:
                    security_status = "✓ Secure"
                else:
                    security_status = "⚠ At Risk"

                writer.writerow({
                    'api_name': api_name,
                    'total_endpoints': total,
                    'protected_endpoints': protected,
                    'unprotected_endpoints': unprotected,
                    'security_status': security_status
                })

        log_success(f"API summary report saved to: {summary_file}")
        return str(summary_file)
    except Exception as e:
        log_error(f"Failed to save API summary report: {str(e)}")
        return None


# ===================================================================
# SECCIÓN 5: ANÁLISIS CONCURRENTE
# ===================================================================



def analyze_apis_sequentially(
    apis: List[Dict],
    resource_pool_size: int,
    report_file: Optional[Path] = None
) -> List[Dict]:
    """
    Analyze multiple APIs SEQUENTIALLY (one after another).

    Each API is analyzed completely (including all its resources in parallel)
    before moving to the next API. This prevents output confusion and ensures
    clean reporting per API.

    Reports whitelist category for each endpoint based on method + path combination.

    Args:
        apis: List of APIs to analyze.
        resource_pool_size: Number of concurrent workers for resources within each API.
        report_file: Path to consolidated report file.

    Returns:
        List of analysis results.
    """
    results = []
    total_apis = len(apis)

    # Load whitelists once at the beginning
    no_requiere_seguridad, seguridad_en_microservicio, seguridad_por_ip = load_whitelist()

    if no_requiere_seguridad:
        num_endpoints = sum(len(v) for v in no_requiere_seguridad.values())
        log_info(
            f"Loaded NO_REQUIERE_SEGURIDAD whitelist with {len(no_requiere_seguridad)} "
            f"API(s) and {num_endpoints} endpoint(s)"
        )

    if seguridad_en_microservicio:
        num_endpoints = sum(len(v) for v in seguridad_en_microservicio.values())
        log_info(
            f"Loaded SEGURIDAD_EN_MICROSERVICIO whitelist with {len(seguridad_en_microservicio)} "
            f"API(s) and {num_endpoints} endpoint(s)"
        )

    if seguridad_por_ip:
        num_endpoints = sum(len(v) for v in seguridad_por_ip.values())
        log_info(
            f"Loaded SEGURIDAD_POR_IP whitelist with {len(seguridad_por_ip)} "
            f"API(s) and {num_endpoints} endpoint(s)"
        )

    # Process each API sequentially
    for idx, api in enumerate(apis, 1):
        api_id = api['id']
        api_name = api['name']

        try:
            # Analyze this API completely (with resource parallelization)
            result = check_api_security(
                api_id,
                api_name,
                idx,
                total_apis,
                report_file=report_file,
                use_resource_pool=True,
                resource_pool_size=resource_pool_size,
                no_requiere_seguridad=no_requiere_seguridad,
                seguridad_en_microservicio=seguridad_en_microservicio,
                seguridad_por_ip=seguridad_por_ip
            )
            results.append(result)
        except Exception as e:
            log_error(f"Error analyzing API {api_name}: {str(e)}")
            results.append({
                'api_id': api_id,
                'api_name': api_name,
                'total_resources': 0,
                'resources_without_auth': [],
                'resources_with_auth': [],
                'error': str(e)
            })

    return results


# ===================================================================
# SECCIÓN 6: INTERFAZ DE USUARIO
# ===================================================================

def interactive_menu() -> Optional[str]:
    """
    Interactive menu for API selection.

    Automatically filters APIs with -DEV or -CI suffixes.

    Returns:
        Selected API ID or "ALL" for all APIs.
    """
    apis = get_rest_apis()
    if not apis:
        return None

    # Filter APIs by suffix
    original_count = len(apis)
    apis = filter_apis_by_suffix(apis)
    excluded_count = original_count - len(apis)

    if excluded_count > 0:
        log_info(
            f"Filtered out {excluded_count} API(s) "
            f"with -DEV or -CI suffixes"
        )

    if not apis:
        log_warning("No APIs available after filtering (all have -DEV or -CI suffix).")
        return None

    # Sort APIs alphabetically by name
    apis = sorted(apis, key=lambda x: x['name'].lower())

    print()
    print(f"{Colors.INFO}Select an API to scan:{Colors.RESET}")
    for i, api in enumerate(apis, 1):
        print(f"  {Colors.SUCCESS}{i}{Colors.RESET} - {api['name']} ({api['id']})")
    print(f"  {Colors.SUCCESS}{len(apis) + 1}{Colors.RESET} - Scan ALL APIs")

    while True:
        try:
            choice = input(
                f"\n{Colors.INFO}Enter your choice "
                f"(1-{len(apis) + 1}): {Colors.RESET}"
            ).strip()
            choice = int(choice)

            if 1 <= choice <= len(apis):
                return apis[choice - 1]['id']
            elif choice == len(apis) + 1:
                return "ALL"
            else:
                log_warning("Invalid choice. Please try again.")
        except ValueError:
            log_warning("Please enter a valid number.")


# ===================================================================
# SECCIÓN 7: FUNCIÓN PRINCIPAL
# ===================================================================

def main() -> int:
    """
    Main function.

    Returns:
        Exit code (0 = success, 1 = error).
    """
    try:
        # Show splash screen
        show_splash_screen()

        log_section("API GUARDIAN")

        log_info("Choose operation:")
        print(f"  {Colors.SUCCESS}1{Colors.RESET} - Scan specific API")
        print(f"  {Colors.SUCCESS}2{Colors.RESET} - Scan all APIs")

        while True:
            try:
                mode = input(
                    f"\n{Colors.INFO}Enter your choice (1-2): {Colors.RESET}"
                ).strip()
                mode = int(mode)
                if mode in [1, 2]:
                    break
                log_warning("Invalid choice. Please try again.")
            except ValueError:
                log_warning("Please enter a valid number.")

        # Scan mode - get APIs
        api_id = None
        selected_api_name = None  # Save selected API name
        if mode == 1:
            api_id = interactive_menu()
            if not api_id:
                log_error("No API selected or no APIs available.")
                return 1
        else:
            api_id = "ALL"

        # Get APIs to scan
        apis = get_rest_apis()
        if not apis:
            log_error("Failed to retrieve any APIs.")
            return 1

        if api_id != "ALL":
            apis = [api for api in apis if api['id'] == api_id]
            # Save selected API name for report filename
            if apis:
                selected_api_name = apis[0]['name']

        # Filter APIs by suffix
        original_count = len(apis)
        apis = filter_apis_by_suffix(apis)
        excluded_count = original_count - len(apis)

        if excluded_count > 0:
            log_info(
                f"Filtered out {excluded_count} API(s) "
                f"with -DEV or -CI suffixes"
            )

        if not apis:
            log_warning("No APIs to scan after filtering.")
            return 0

        # Set pool size to default (10 concurrent workers)
        pool_size = 10
        log_info(f"Using pool size: {pool_size} concurrent workers")

        print()  # Blank line for better formatting

        # Create consolidated report file
        # If a specific API was selected, include its name in the report
        consolidated_report = create_consolidated_report_file(api_name=selected_api_name)
        if not consolidated_report:
            log_error("Failed to create consolidated report file.")
            return 1

        # Execute sequential analysis (APIs sequentially, resources in parallel)
        print()
        log_info("Starting sequential API analysis with parallel resource processing...")
        results = analyze_apis_sequentially(
            apis,
            resource_pool_size=pool_size,
            report_file=consolidated_report
        )

        # Calculate execution summary
        total_apis = len(results)
        successful = sum(1 for r in results if not r.get('error'))
        failed = sum(1 for r in results if r.get('error'))

        log_section("API GUARDIAN - EXECUTION SUMMARY")

        print_box_message(
            f"APIs Analyzed: {total_apis}\n"
            f"Successful: {successful}\n"
            f"Failed: {failed}\n"
            f"Success Rate: {(successful/total_apis*100):.1f}%\n\n"
            f"Report File: {consolidated_report.name}",
            "info"
        )

        # Show instruction to view report
        log_info(f"\n✓ Consolidated report saved to: {consolidated_report.absolute()}")
        log_info("You can open the CSV file with Excel, Google Sheets, or any text editor")

        # Generate API summary report
        summary_report = save_api_summary_report(results)
        if summary_report:
            log_info(f"✓ API summary report saved to: {summary_report}")

        # Final summary
        total_unprotected = sum(
            len(r['resources_without_auth']) for r in results
        )

        if total_unprotected > 0:
            print_box_message(
                f"Found {total_unprotected} unprotected endpoint(s)\n"
                f"Review them immediately!",
                "warning"
            )
        else:
            print_box_message(
                "All endpoints are protected!\n"
                "Great security posture!",
                "success"
            )

        return 0

    except KeyboardInterrupt:
        log_warning("\nOperation cancelled by user.")
        return 1
    except Exception as e:
        log_error(f"Unexpected error: {str(e)}")
        save_error_dump(f"Unexpected error in security check: {str(e)}", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
