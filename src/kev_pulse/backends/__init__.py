from .base import BackendAdapter
from .tsc_adapter import TSCAdapter
from .tvm_adapter import TVMAdapter


def build_adapter(config) -> BackendAdapter:
    """Factory: build the right adapter from a loaded Config.backend section."""
    if config.type == "sc":
        return TSCAdapter(
            url=config.url,
            username=config.username,
            password=config.password,
            verify_tls=config.verify_tls,
        )
    if config.type == "tvm":
        return TVMAdapter(
            url=config.url,
            access_key=config.access_key,
            secret_key=config.secret_key,
            verify_tls=config.verify_tls,
        )
    raise ValueError(f"Unknown backend type: {config.type!r}")


__all__ = ["BackendAdapter", "TSCAdapter", "TVMAdapter", "build_adapter"]
