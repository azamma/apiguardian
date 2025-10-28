"""
Concurrent analysis module with ThreadPoolExecutor.

Implementa análisis paralelo de múltiples APIs
con control configurable del pool size.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Callable, Optional
from dataclasses import dataclass
import time


@dataclass
class AnalysisResult:
    """
    Resultado del análisis de una API.

    Atributos:
        api_id: Identificador único de la API.
        api_name: Nombre legible de la API.
        success: Indica si el análisis fue exitoso.
        result: Diccionario con datos del análisis (si success=True).
        error: Mensaje de error (si success=False).
        execution_time: Tiempo de ejecución en segundos.
    """

    api_id: str
    api_name: str
    success: bool
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    execution_time: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convierte resultado a diccionario."""
        return {
            "api_id": self.api_id,
            "api_name": self.api_name,
            "success": self.success,
            "result": self.result,
            "error": self.error,
            "execution_time": self.execution_time,
        }


class ConcurrentAnalyzer:
    """
    Analizador de APIs con soporte para ThreadPoolExecutor.

    Permite procesar múltiples APIs en paralelo con
    límite configurable de workers simultáneos.
    """

    def __init__(self, pool_size: int = 5, timeout: int = 300):
        """
        Inicializa el analizador.

        Args:
            pool_size: Número de threads simultáneos (default: 5).
                      Debe estar entre 1 y 10.
            timeout: Timeout en segundos por API (default: 300).
                    Debe ser >= 10.

        Raises:
            ValueError: Si pool_size o timeout están fuera de rango.

        Example:
            >>> analyzer = ConcurrentAnalyzer(pool_size=5, timeout=300)
        """
        if not isinstance(pool_size, int) or pool_size < 1:
            raise ValueError("pool_size debe ser un entero >= 1")
        if not isinstance(timeout, int) or timeout < 10:
            raise ValueError("timeout debe ser un entero >= 10 segundos")

        self.pool_size = pool_size
        self.timeout = timeout

    def analyze_apis(
        self,
        apis: List[Dict[str, Any]],
        analysis_fn: Callable[[str, str, int, int], Dict[str, Any]],
        progress_callback: Optional[Callable[[AnalysisResult], None]] = None,
    ) -> List[AnalysisResult]:
        """
        Analiza múltiples APIs en paralelo.

        Args:
            apis: Lista de APIs a analizar.
            analysis_fn: Función que ejecuta análisis para una API.
                        Firma: (api_id: str, api_name: str, index: int, total: int) -> Dict
            progress_callback: Callback opcional para reportar progreso.
                              Recibe AnalysisResult.

        Returns:
            Lista de AnalysisResult con resultados de cada API.
            El orden de retorno es según finalización, no original.

        Raises:
            ValueError: Si apis está vacía o analysis_fn es None.

        Example:
            >>> analyzer = ConcurrentAnalyzer(pool_size=5)
            >>> results = analyzer.analyze_apis(
            ...     apis=api_list,
            ...     analysis_fn=check_api_security,
            ...     progress_callback=lambda r: print(f"✓ {r.api_name}")
            ... )
        """
        if not apis:
            raise ValueError("La lista de APIs no puede estar vacía")
        if analysis_fn is None:
            raise ValueError("analysis_fn no puede ser None")

        results = []
        total = len(apis)

        with ThreadPoolExecutor(max_workers=self.pool_size) as executor:
            # Crear futures para cada API
            future_to_api = {
                executor.submit(
                    self._run_analysis_task,
                    api,
                    analysis_fn,
                    index + 1,
                    total
                ): api
                for index, api in enumerate(apis)
            }

            # Procesar resultados conforme se completen
            for future in as_completed(future_to_api, timeout=self.timeout):
                api = future_to_api[future]

                try:
                    result = future.result()
                    results.append(result)

                    # Callback de progreso
                    if progress_callback:
                        progress_callback(result)

                except TimeoutError:
                    result = AnalysisResult(
                        api_id=api.get("id", "UNKNOWN"),
                        api_name=api.get("name", "UNKNOWN"),
                        success=False,
                        error=f"Timeout después de {self.timeout}s",
                        execution_time=self.timeout
                    )
                    results.append(result)

                    if progress_callback:
                        progress_callback(result)

                except Exception as e:
                    result = AnalysisResult(
                        api_id=api.get("id", "UNKNOWN"),
                        api_name=api.get("name", "UNKNOWN"),
                        success=False,
                        error=f"Error: {str(e)}",
                        execution_time=0.0
                    )
                    results.append(result)

                    if progress_callback:
                        progress_callback(result)

        return results

    @staticmethod
    def _run_analysis_task(
        api: Dict[str, Any],
        analysis_fn: Callable,
        index: int,
        total: int
    ) -> AnalysisResult:
        """
        Ejecuta tarea de análisis para una API individual.

        Este método se ejecuta dentro del ThreadPoolExecutor.

        Args:
            api: Datos de la API.
            analysis_fn: Función de análisis.
            index: Posición actual (1-based).
            total: Total de APIs a procesar.

        Returns:
            AnalysisResult con resultado de análisis.
        """
        api_id = api.get("id", "UNKNOWN")
        api_name = api.get("name", "UNKNOWN")

        start_time = time.time()

        try:
            result = analysis_fn(api_id, api_name, index, total)
            execution_time = time.time() - start_time

            return AnalysisResult(
                api_id=api_id,
                api_name=api_name,
                success=True,
                result=result,
                execution_time=execution_time
            )
        except Exception as e:
            execution_time = time.time() - start_time

            return AnalysisResult(
                api_id=api_id,
                api_name=api_name,
                success=False,
                error=str(e),
                execution_time=execution_time
            )

    @staticmethod
    def get_summary(results: List[AnalysisResult]) -> Dict[str, Any]:
        """
        Genera resumen estadístico de ejecución.

        Args:
            results: Lista de AnalysisResult.

        Returns:
            Diccionario con estadísticas de ejecución.

        Example:
            >>> summary = analyzer.get_summary(results)
            >>> print(f"Success rate: {summary['success_rate']}")
        """
        if not results:
            return {
                "total": 0,
                "successful": 0,
                "failed": 0,
                "total_execution_time": 0.0,
                "average_time_per_api": 0.0,
                "success_rate": "0%"
            }

        successful = sum(1 for r in results if r.success)
        failed = sum(1 for r in results if not r.success)
        total_time = sum(r.execution_time for r in results)
        avg_time = total_time / len(results) if results else 0

        return {
            "total": len(results),
            "successful": successful,
            "failed": failed,
            "total_execution_time": total_time,
            "average_time_per_api": avg_time,
            "success_rate": f"{(successful / len(results) * 100):.1f}%" if results else "0%"
        }
