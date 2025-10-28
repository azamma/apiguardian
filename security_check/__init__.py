"""
API Gateway Security Check - Package

Módulos para análisis de seguridad de APIs en AWS API Gateway.
Incluye filtrado, análisis concurrente, y generación de reportes.
"""

from .api_filter import APIFilter
from .concurrent_analyzer import ConcurrentAnalyzer, AnalysisResult
from .metadata_collector import MetadataCollector, ResourceMetadata

__version__ = "2.1"
__all__ = [
    "APIFilter",
    "ConcurrentAnalyzer",
    "AnalysisResult",
    "MetadataCollector",
    "ResourceMetadata",
]
