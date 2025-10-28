"""
Metadata collection for audit and compliance.

Recolecta información de creación, usuario y cambios
de recursos en API Gateway mediante AWS Tags.
"""

from dataclasses import dataclass
from typing import Optional, Dict, Any
from datetime import datetime


@dataclass(frozen=True)
class ResourceMetadata:
    """
    Metadata de auditoría para recursos de API Gateway.

    Atributos:
        resource_id: ID del recurso en API Gateway.
        api_id: ID de la API que contiene el recurso.
        path: Path del recurso.
        created_date: Fecha de creación (ISO 8601).
        created_by: Usuario o rol que creó el recurso.
        last_modified_date: Última modificación (ISO 8601).
        last_modified_by: Usuario que modificó.
    """

    resource_id: str
    api_id: str
    path: str
    created_date: Optional[datetime] = None
    created_by: Optional[str] = None
    last_modified_date: Optional[datetime] = None
    last_modified_by: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """
        Convierte metadata a diccionario para serialización.

        Returns:
            Diccionario con campos ISO 8601.
        """
        return {
            "resource_id": self.resource_id,
            "api_id": self.api_id,
            "path": self.path,
            "created_date": (
                self.created_date.isoformat()
                if self.created_date else None
            ),
            "created_by": self.created_by,
            "last_modified_date": (
                self.last_modified_date.isoformat()
                if self.last_modified_date else None
            ),
            "last_modified_by": self.last_modified_by,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ResourceMetadata":
        """
        Crea ResourceMetadata desde diccionario.

        Args:
            data: Diccionario con campos de metadata.

        Returns:
            ResourceMetadata instanciado.
        """
        created_date = None
        if data.get("created_date"):
            created_date = datetime.fromisoformat(data["created_date"])

        last_modified_date = None
        if data.get("last_modified_date"):
            last_modified_date = datetime.fromisoformat(
                data["last_modified_date"]
            )

        return cls(
            resource_id=data["resource_id"],
            api_id=data["api_id"],
            path=data["path"],
            created_date=created_date,
            created_by=data.get("created_by"),
            last_modified_date=last_modified_date,
            last_modified_by=data.get("last_modified_by"),
        )


class MetadataCollector:
    """
    Recolecta metadata de recursos usando AWS Tags.

    Nota: Para obtener created_by/created_date de forma confiable:
    1. Usar AWS Tags (recomendado - simple y rápido)
    2. Usar AWS CloudTrail (completo pero requiere permisos adicionales)
    3. Usar IAM para obtener info de creación (limitado)

    Esta implementación se enfoca en AWS Tags por simplicidad.
    """

    CREATED_DATE_TAG = "CreatedDate"
    """Nombre del tag para fecha de creación."""

    CREATED_BY_TAG = "CreatedBy"
    """Nombre del tag para usuario creador."""

    MODIFIED_DATE_TAG = "LastModifiedDate"
    """Nombre del tag para última modificación."""

    MODIFIED_BY_TAG = "LastModifiedBy"
    """Nombre del tag para usuario que modificó."""

    @classmethod
    def extract_from_tags(
        cls,
        resource: Dict[str, Any],
        api_id: str
    ) -> ResourceMetadata:
        """
        Extrae metadata de AWS Tags del recurso.

        Asume estructura de tags:
        {
            "CreatedDate": "2024-01-15T10:30:00",
            "CreatedBy": "arn:aws:iam::123456:user/john.doe",
            "LastModifiedDate": "2024-01-20T15:45:00",
            "LastModifiedBy": "arn:aws:iam::123456:user/jane.doe"
        }

        Args:
            resource: Recurso de API Gateway con tags.
            api_id: ID de la API padre.

        Returns:
            ResourceMetadata con información disponible en tags.
            Si no hay tags, los campos opcionales serán None.

        Example:
            >>> metadata = MetadataCollector.extract_from_tags(resource, api_id)
            >>> print(metadata.created_by)
        """
        tags = resource.get("tags", {})
        resource_id = resource.get("id", "UNKNOWN")
        path = resource.get("path", "N/A")

        # Extraer created_date
        created_date = None
        created_date_str = tags.get(cls.CREATED_DATE_TAG)
        if created_date_str:
            try:
                created_date = datetime.fromisoformat(created_date_str)
            except ValueError:
                # Si el formato es inválido, ignorar
                pass

        # Extraer last_modified_date
        last_modified_date = None
        modified_date_str = tags.get(cls.MODIFIED_DATE_TAG)
        if modified_date_str:
            try:
                last_modified_date = datetime.fromisoformat(modified_date_str)
            except ValueError:
                pass

        return ResourceMetadata(
            resource_id=resource_id,
            api_id=api_id,
            path=path,
            created_date=created_date,
            created_by=tags.get(cls.CREATED_BY_TAG),
            last_modified_date=last_modified_date,
            last_modified_by=tags.get(cls.MODIFIED_BY_TAG),
        )

    @staticmethod
    def extract_user_from_arn(arn: str) -> str:
        """
        Extrae nombre de usuario legible desde ARN.

        Args:
            arn: AWS ARN completo.

        Returns:
            Nombre de usuario o el ARN completo si no puede parsear.

        Example:
            >>> arn = "arn:aws:iam::123456:user/john.doe"
            >>> user = MetadataCollector.extract_user_from_arn(arn)
            >>> user
            'john.doe'
        """
        if not arn:
            return "UNKNOWN"

        try:
            # Formato: arn:aws:iam::123456:user/john.doe
            parts = arn.split("/")
            if len(parts) >= 2:
                return parts[-1]  # Retorna 'john.doe'
        except Exception:
            pass

        return arn

    @classmethod
    def format_metadata_for_report(
        cls,
        metadata: ResourceMetadata
    ) -> Dict[str, str]:
        """
        Formatea metadata para presentación en reporte.

        Args:
            metadata: ResourceMetadata a formatear.

        Returns:
            Diccionario con strings formateados para reporte.

        Example:
            >>> formatted = MetadataCollector.format_metadata_for_report(meta)
            >>> print(formatted["created_by"])
            'john.doe (2024-01-15 10:30)'
        """
        created_info = "N/A"
        if metadata.created_date or metadata.created_by:
            user = cls.extract_user_from_arn(metadata.created_by or "")
            date_str = (
                metadata.created_date.strftime("%Y-%m-%d %H:%M")
                if metadata.created_date else "UNKNOWN"
            )
            created_info = f"{user} ({date_str})" if user != "UNKNOWN" else date_str

        modified_info = "N/A"
        if metadata.last_modified_date or metadata.last_modified_by:
            user = cls.extract_user_from_arn(
                metadata.last_modified_by or ""
            )
            date_str = (
                metadata.last_modified_date.strftime("%Y-%m-%d %H:%M")
                if metadata.last_modified_date else "UNKNOWN"
            )
            modified_info = f"{user} ({date_str})" if user != "UNKNOWN" else date_str

        return {
            "resource_id": metadata.resource_id,
            "path": metadata.path,
            "created": created_info,
            "last_modified": modified_info,
        }
