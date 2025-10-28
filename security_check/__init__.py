"""
API Gateway Security Check - Package

Módulos para análisis de seguridad de APIs en AWS API Gateway.
Incluye filtrado, análisis concurrente, y generación de reportes.
"""

from .api_filter import (
    APIFilter,
    filter_apis,
    filter_methods,
    get_excluded_api_count,
    get_excluded_method_count,
    EXCLUDED_API_SUFFIXES,
    EXCLUDED_HTTP_METHODS,
)
from .concurrent_analyzer import ConcurrentAnalyzer, AnalysisResult
from .metadata_collector import MetadataCollector, ResourceMetadata

__version__ = "2.1"
__all__ = [
    # API Filter
    "APIFilter",
    "filter_apis",
    "filter_methods",
    "get_excluded_api_count",
    "get_excluded_method_count",
    "EXCLUDED_API_SUFFIXES",
    "EXCLUDED_HTTP_METHODS",
    # Concurrent Analyzer
    "ConcurrentAnalyzer",
    "AnalysisResult",
    # Metadata Collector
    "MetadataCollector",
    "ResourceMetadata",
]
