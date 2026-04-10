"""SDK configuration from environment variables."""

import os
from dataclasses import dataclass

_DEFAULT_EXCLUDE_PATHS = ["/healthz", "/readyz", "/metrics"]


def _parse_exclude_paths() -> list[str]:
    raw = os.environ.get("CORESDK_EXCLUDE_PATHS", "")
    if raw:
        return [p.strip() for p in raw.split(",") if p.strip()]
    return list(_DEFAULT_EXCLUDE_PATHS)


@dataclass
class SDKConfig:
    sidecar_addr: str = "localhost:50051"
    tenant_id: str = "default"
    service_name: str = "unknown-service"
    fail_mode: str = "closed"
    policy_fail_mode: str = ""
    dev_mode: bool = False
    log_level: str = "INFO"
    control_plane_url: str = ""
    tls_cert: str = ""
    tls_key: str = ""
    tls_ca: str = ""
    inject_headers: bool = True
    exclude_paths: list[str] = None  # type: ignore[assignment]
    service_token: str = ""
    api_key_prefix: str = ""
    database_url: str = ""

    def __post_init__(self) -> None:
        if self.exclude_paths is None:
            self.exclude_paths = list(_DEFAULT_EXCLUDE_PATHS)

    def validate(self) -> None:
        """Validate configuration. Raises ValueError on invalid settings."""
        if self.fail_mode not in {"open", "closed"}:
            raise ValueError(f"fail_mode must be 'open' or 'closed', got {self.fail_mode!r}")
        if self.policy_fail_mode and self.policy_fail_mode not in {"open", "closed"}:
            raise ValueError(
                f"policy_fail_mode must be 'open', 'closed', or empty, "
                f"got {self.policy_fail_mode!r}"
            )
        if not self.sidecar_addr:
            raise ValueError("sidecar_addr must not be empty")
        _valid_log_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if self.log_level.upper() not in _valid_log_levels:
            raise ValueError(
                f"log_level must be one of {sorted(_valid_log_levels)}, got {self.log_level!r}"
            )
        if not self.service_name:
            raise ValueError("service_name must not be empty")
        tls_fields = [self.tls_cert, self.tls_key, self.tls_ca]
        if any(tls_fields) and not all(tls_fields):
            raise ValueError(
                "tls_cert, tls_key, and tls_ca must all be set together or all be empty"
            )

    @classmethod
    def from_env(cls) -> "SDKConfig":
        env = os.environ.get("CORESDK_ENV", "production")
        default_fail_mode = "open" if env == "development" else "closed"
        config = cls(
            sidecar_addr=os.environ.get("CORESDK_SIDECAR_ADDR", "localhost:50051"),
            tenant_id=os.environ.get("CORESDK_TENANT_ID", "default"),
            service_name=os.environ.get("CORESDK_SERVICE_NAME", "unknown-service"),
            fail_mode=os.environ.get("CORESDK_FAIL_MODE", default_fail_mode),
            policy_fail_mode=os.environ.get("CORESDK_POLICY_FAIL_MODE", ""),
            control_plane_url=os.environ.get("CORESDK_CONTROL_PLANE_URL", ""),
            dev_mode=os.environ.get("CORESDK_ENV", "production") == "development",
            log_level=os.environ.get("CORESDK_LOG_LEVEL", "INFO"),
            tls_cert=os.environ.get("CORESDK_TLS_CERT", ""),
            tls_key=os.environ.get("CORESDK_TLS_KEY", ""),
            tls_ca=os.environ.get("CORESDK_TLS_CA", ""),
            inject_headers=os.environ.get("CORESDK_INJECT_TENANT_HEADERS", "true").lower()
            in ("true", "1", "yes"),
            service_token=os.environ.get("CORESDK_SERVICE_TOKEN", ""),
            exclude_paths=_parse_exclude_paths(),
            api_key_prefix=os.environ.get("CORESDK_API_KEY_PREFIX", ""),
            database_url=os.environ.get("DATABASE_URL", ""),
        )
        config.validate()
        return config
