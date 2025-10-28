"""
API filtering module for excluding specific environments and methods.

Proporciona utilidades para filtrar APIs según criterios
de entorno y métodos HTTP específicos.
"""

from typing import List, Dict, Any, Set, Optional


# === CONSTANTES DE FILTRADO ===

EXCLUDED_API_SUFFIXES: Set[str] = {"-DEV", "-CI"}
"""Sufijos de API a excluir del análisis."""

EXCLUDED_HTTP_METHODS: Set[str] = {"OPTIONS"}
"""Métodos HTTP a excluir del análisis."""


# === FUNCIONES DE FILTRADO ===

def filter_apis(
    apis: List[Dict[str, Any]],
    excluded_suffixes: Optional[Set[str]] = None
) -> List[Dict[str, Any]]:
    """
    Filtra APIs excluyendo aquellas con sufijos especificados.

    Args:
        apis: Lista de APIs devueltas por AWS API Gateway.
        excluded_suffixes: Conjunto de sufijos a excluir.
                          Default: {"-DEV", "-CI"}.

    Returns:
        Lista filtrada de APIs.

    Example:
        >>> apis = [
        ...     {"id": "api1", "name": "payment-api-DEV"},
        ...     {"id": "api2", "name": "payment-api-PROD"},
        ... ]
        >>> filtered = filter_apis(apis)
        >>> len(filtered)
        1
    """
    suffixes = excluded_suffixes or EXCLUDED_API_SUFFIXES
    return [
        api for api in apis
        if not any(
            api.get("name", "").endswith(suffix)
            for suffix in suffixes
        )
    ]


def filter_methods(
    methods: Dict[str, Any],
    excluded_methods: Optional[Set[str]] = None
) -> Dict[str, Any]:
    """
    Filtra métodos HTTP excluyendo los especificados.

    Args:
        methods: Diccionario de métodos HTTP de un recurso.
        excluded_methods: Conjunto de métodos a excluir.
                        Default: {"OPTIONS"}.

    Returns:
        Diccionario filtrado de métodos.

    Example:
        >>> methods = {"GET": {}, "POST": {}, "OPTIONS": {}}
        >>> filtered = filter_methods(methods)
        >>> list(filtered.keys())
        ['GET', 'POST']
    """
    excludes = excluded_methods or EXCLUDED_HTTP_METHODS
    return {
        method: config for method, config in methods.items()
        if method not in excludes
    }


def get_excluded_api_count(
    apis: List[Dict[str, Any]],
    excluded_suffixes: Optional[Set[str]] = None
) -> int:
    """
    Retorna cantidad de APIs excluidas.

    Args:
        apis: Lista original de APIs.
        excluded_suffixes: Conjunto de sufijos a excluir.

    Returns:
        Cantidad de APIs filtradas.
    """
    total = len(apis)
    filtered = len(filter_apis(apis, excluded_suffixes))
    return total - filtered


def get_excluded_method_count(
    methods: Dict[str, Any],
    excluded_methods: Optional[Set[str]] = None
) -> int:
    """
    Retorna cantidad de métodos excluidos.

    Args:
        methods: Diccionario de métodos HTTP.
        excluded_methods: Conjunto de métodos a excluir.

    Returns:
        Cantidad de métodos filtrados.
    """
    total = len(methods)
    filtered = len(filter_methods(methods, excluded_methods))
    return total - filtered


# === CLASE PARA COMPATIBILIDAD (DEPRECATED) ===

class APIFilter:
    """
    Clase de compatibilidad para código existente.

    DEPRECATED: Usar funciones de módulo en su lugar.
    Las funciones filter_apis() y filter_methods() son preferibles.
    """

    EXCLUDED_SUFFIXES: Set[str] = EXCLUDED_API_SUFFIXES
    """Sufijos de API a excluir del análisis."""

    EXCLUDED_METHODS: Set[str] = EXCLUDED_HTTP_METHODS
    """Métodos HTTP a excluir del análisis."""

    @classmethod
    def filter_apis(
        cls,
        apis: List[Dict[str, Any]],
        excluded_suffixes: Optional[Set[str]] = None
    ) -> List[Dict[str, Any]]:
        """Wrapper para compatibilidad."""
        return filter_apis(apis, excluded_suffixes)

    @classmethod
    def filter_methods(
        cls,
        methods: Dict[str, Any],
        excluded_methods: Optional[Set[str]] = None
    ) -> Dict[str, Any]:
        """Wrapper para compatibilidad."""
        return filter_methods(methods, excluded_methods)

    @classmethod
    def get_excluded_api_count(
        cls,
        apis: List[Dict[str, Any]],
        excluded_suffixes: Optional[Set[str]] = None
    ) -> int:
        """Wrapper para compatibilidad."""
        return get_excluded_api_count(apis, excluded_suffixes)

    @classmethod
    def get_excluded_method_count(
        cls,
        methods: Dict[str, Any],
        excluded_methods: Optional[Set[str]] = None
    ) -> int:
        """Wrapper para compatibilidad."""
        return get_excluded_method_count(methods, excluded_methods)
