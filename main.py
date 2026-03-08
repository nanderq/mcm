import json
import tarfile
import asyncio
import re
import os
import shutil
import tempfile
import threading
import time
from collections.abc import Iterable, Mapping
from datetime import datetime
from io import BytesIO
import posixpath
import secrets
import sqlite3
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Literal, Protocol, TypedDict, cast
from urllib.parse import urlencode
import zipfile

import docker
import fastapi
import requests
import uvicorn
from docker.errors import APIError, DockerException, ImageNotFound, NotFound
from docker.models.containers import Container
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    StreamingResponse,
)
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.background import BackgroundTask

from auth import (
    COOKIE_NAME,
    CsrfError,
    clear_login_failures,
    csrf_http_exception,
    enforce_login_rate_limit,
    get_csrf_token,
    is_authenticated,
    load_auth_settings,
    login_user,
    logout_user,
    record_login_failure,
    require_csrf,
    validate_auth_configuration,
    verify_credentials,
)
from database import Database

APP_ROOT = Path(__file__).resolve().parent


def resolve_runtime_path(env_var: str, default: Path) -> Path:
    raw_value = os.environ.get(env_var)
    path = Path(raw_value).expanduser() if raw_value else default
    if not path.is_absolute():
        path = Path.cwd() / path
    return path.resolve()


DATA_ROOT = resolve_runtime_path("MCM_DATA_ROOT", APP_ROOT)
DATABASE_PATH = resolve_runtime_path("MCM_DATABASE_PATH", DATA_ROOT / "database.db")
SCHEMA_PATH = APP_ROOT / "schema.sql"
SERVERS_ROOT = resolve_runtime_path("MCM_SERVERS_ROOT", DATA_ROOT / "servers")
TEMPLATES_ROOT = APP_ROOT / "templates"
FAVICON_PATH = APP_ROOT / "favicon.svg"
DEFAULT_WEBUI_PORT = 8000

app = fastapi.FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
db = Database(str(DATABASE_PATH))
MINECRAFT_IMAGE = "itzg/minecraft-server"
MINECRAFT_PORT = 25565
DEFAULT_STOP_DURATION = 60
DOCKER_MEMORY_LIMIT_BYTES = 1024 * 1024 * 1024
MINECRAFT_JVM_MEMORY = "768M"
MAX_FILE_PREVIEW_BYTES = 131072
MAX_LOG_TAIL_BYTES = 131072
RCON_CLI_TIMEOUT_SECONDS = 3.0
RCON_CLI_PROMPT = b"> "
COMMON_SERVER_TYPES = (
    "VANILLA",
    "PAPER",
    "PURPUR",
    "SPIGOT",
    "FABRIC",
    "FORGE",
)
SERVER_VIEW_PATH_PATTERN = re.compile(r"^/servers/\d+/view$")

client = docker.from_env()
templates = Jinja2Templates(directory=str(TEMPLATES_ROOT))

ScalarValue = str | int | float | bool | None


class SupportsSocketIO(Protocol):
    def recv(self, size: int) -> bytes: ...

    def sendall(self, data: bytes) -> None: ...

    def close(self) -> None: ...

    def settimeout(self, value: float | None) -> None: ...


class SupportsItems(Protocol):
    def items(self) -> Iterable[tuple[str, object]]: ...


class EnvironmentState(TypedDict):
    version: str
    server_type: str
    stop_duration: int
    rcon_host: str | None
    rcon_port: int | None
    rcon_password: str | None


PUBLIC_ROUTES = {
    ("GET", "/login"),
    ("POST", "/login"),
    ("GET", "/favicon.svg"),
}
AUTH_PASSTHROUGH_PATHS = {"/docs", "/redoc", "/openapi.json"}


def build_template_context(
    request: fastapi.Request, context: dict[str, object]
) -> dict[str, object]:
    merged = dict(context)
    merged["csrf_token"] = get_csrf_token(request) if is_authenticated(request) else ""
    return merged


def is_html_navigation_path(path: str) -> bool:
    return path == "/" or SERVER_VIEW_PATH_PATTERN.fullmatch(path) is not None


def build_current_request_path(request: fastapi.Request) -> str:
    return (
        f"{request.url.path}?{request.url.query}"
        if request.url.query
        else request.url.path
    )


def build_login_redirect(request: fastapi.Request) -> RedirectResponse:
    return RedirectResponse(
        url=f"/login?{urlencode([('next', build_current_request_path(request))])}",
        status_code=303,
    )


def build_unauthenticated_response(request: fastapi.Request) -> fastapi.Response:
    path = request.url.path
    if is_html_navigation_path(path):
        return build_login_redirect(request)
    if path.endswith("/logs/stream") or path.endswith("/download"):
        return PlainTextResponse("Authentication required", status_code=401)
    return JSONResponse({"detail": "Authentication required"}, status_code=401)


def csrf_plain_text_response() -> PlainTextResponse:
    return PlainTextResponse("Invalid CSRF token", status_code=403)


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: fastapi.Request, call_next) -> fastapi.Response:
        route_key = (request.method.upper(), request.url.path)
        if request.url.path in AUTH_PASSTHROUGH_PATHS:
            return await call_next(request)
        if route_key in PUBLIC_ROUTES:
            return await call_next(request)
        if is_authenticated(request):
            return await call_next(request)
        return build_unauthenticated_response(request)


class ServerCreateRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: str
    port: int = Field(default=MINECRAFT_PORT, ge=1, le=65535)
    status: Literal["running", "stopped"] = "running"
    version: str = "LATEST"
    server_type: str = Field(default="VANILLA", alias="type")
    eula: bool = True
    data_dir: str | None = None
    stop_duration: int = Field(default=DEFAULT_STOP_DURATION, ge=15, le=600)
    environment: dict[str, ScalarValue] = Field(default_factory=dict)


class ServerResponse(BaseModel):
    id: int
    name: str
    port: int
    status: Literal["running", "stopped"]
    container_id: str
    container_name: str
    image: str
    version: str
    server_type: str
    data_dir: str
    stop_duration: int
    rcon_host: str | None
    rcon_port: int | None
    rcon_password: str | None
    port_bindings: dict[str, object]
    volume_bindings: dict[str, object]
    environment: dict[str, str]
    created_at: str


class ServerPropertiesUpdateRequest(BaseModel):
    contents: str


class ServerEnvironmentUpdateRequest(BaseModel):
    environment: dict[str, ScalarValue]


class ServerCommandRequest(BaseModel):
    command: str


class RconProtocolError(RuntimeError):
    pass


class RconAuthenticationError(RconProtocolError):
    pass


class PersistentRconConnection:
    def __init__(self, container_id: str, host: str, port: int, password: str) -> None:
        self.container_id = container_id
        self.host = host
        self.port = port
        self.password = password
        self._socket: SupportsSocketIO | None = None
        self._lock = threading.Lock()

    def matches(self, container_id: str, host: str, port: int, password: str) -> bool:
        return (
            self.container_id == container_id
            and self.host == host
            and self.port == port
            and self.password == password
        )

    def close(self) -> None:
        with self._lock:
            self._disconnect_locked()

    def execute(self, command: str) -> str:
        with self._lock:
            self._ensure_connected_locked()
            try:
                return self._execute_locked(command)
            except RconAuthenticationError:
                self._disconnect_locked()
                raise
            except (EOFError, OSError, RconProtocolError, TimeoutError):
                self._disconnect_locked()
                self._ensure_connected_locked()
                return self._execute_locked(command)

    def _ensure_connected_locked(self) -> None:
        if self._socket is not None:
            return

        exec_instance = client.api.exec_create(
            self.container_id,
            [
                "rcon-cli",
                "--host",
                self.host,
                "--port",
                str(self.port),
                "--password",
                self.password,
            ],
            stdin=True,
            stdout=True,
            stderr=True,
            tty=True,
        )
        connection = client.api.exec_start(
            exec_instance["Id"],
            tty=True,
            socket=True,
        )
        self._socket = cast(SupportsSocketIO, connection)
        self._socket.settimeout(RCON_CLI_TIMEOUT_SECONDS)
        try:
            self._read_until_prompt_locked()
        except Exception:
            self._disconnect_locked()
            raise

    def _disconnect_locked(self) -> None:
        if self._socket is None:
            return

        try:
            self._socket.close()
        finally:
            self._socket = None

    def _execute_locked(self, command: str) -> str:
        if self._socket is None:
            raise EOFError("RCON CLI session is not connected.")

        self._socket.sendall(f"{command}\n".encode("utf-8"))
        response = self._read_until_prompt_locked().decode("utf-8", errors="replace")
        normalized = response.replace("\r\n", "\n").replace("\r", "\n")
        if normalized.endswith("> "):
            normalized = normalized[:-2]

        lines = normalized.split("\n")
        if lines and lines[0].strip() == command:
            lines = lines[1:]
        return "\n".join(lines).strip()

    def _read_until_prompt_locked(self) -> bytes:
        if self._socket is None:
            raise EOFError("RCON CLI session is not connected.")

        buffer = bytearray()
        deadline = time.monotonic() + RCON_CLI_TIMEOUT_SECONDS
        while True:
            if buffer.endswith(RCON_CLI_PROMPT):
                return bytes(buffer)
            if time.monotonic() >= deadline:
                raise TimeoutError("Timed out waiting for the RCON CLI prompt.")
            chunk = self._socket.recv(4096)
            if not chunk:
                message = buffer.decode("utf-8", errors="replace").strip()
                if "auth" in message.lower():
                    raise RconAuthenticationError(
                        message or "RCON authentication failed."
                    )
                raise EOFError("RCON CLI session closed unexpectedly.")
            buffer.extend(chunk)


class PersistentRconConnectionManager:
    def __init__(self) -> None:
        self._connections: dict[int, PersistentRconConnection] = {}
        self._lock = threading.Lock()

    def execute(
        self,
        server_id: int,
        container_id: str,
        host: str,
        port: int,
        password: str,
        command: str,
    ) -> str:
        with self._lock:
            connection = self._connections.get(server_id)
            if connection is None or not connection.matches(
                container_id, host, port, password
            ):
                if connection is not None:
                    connection.close()
                connection = PersistentRconConnection(
                    container_id, host, port, password
                )
                self._connections[server_id] = connection

        return connection.execute(command)

    def close_server(self, server_id: int) -> None:
        with self._lock:
            connection = self._connections.pop(server_id, None)

        if connection is not None:
            connection.close()

    def close_all(self) -> None:
        with self._lock:
            connections = list(self._connections.values())
            self._connections.clear()

        for connection in connections:
            connection.close()


rcon_connection_manager = PersistentRconConnectionManager()
auth_settings = load_auth_settings(validate_required=False)
app.add_middleware(AuthMiddleware)
app.add_middleware(
    SessionMiddleware,
    secret_key=auth_settings.session_secret,
    session_cookie=COOKIE_NAME,
    same_site="lax",
    https_only=auth_settings.cookie_secure,
    max_age=auth_settings.session_ttl_seconds,
)


@app.on_event("startup")
def initialize_database() -> None:
    validate_auth_configuration()
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    db.initialize_schema(SCHEMA_PATH)
    migrate_server_schema()
    SERVERS_ROOT.mkdir(parents=True, exist_ok=True)


@app.on_event("shutdown")
def shutdown_rcon_connections() -> None:
    rcon_connection_manager.close_all()


def migrate_server_schema() -> None:
    existing_columns = db.table_columns("servers")
    migrations = {
        "container_name": "ALTER TABLE servers ADD COLUMN container_name TEXT NOT NULL DEFAULT ''",
        "image": f"ALTER TABLE servers ADD COLUMN image TEXT NOT NULL DEFAULT '{MINECRAFT_IMAGE}'",
        "version": "ALTER TABLE servers ADD COLUMN version TEXT NOT NULL DEFAULT 'LATEST'",
        "server_type": "ALTER TABLE servers ADD COLUMN server_type TEXT NOT NULL DEFAULT 'VANILLA'",
        "data_dir": "ALTER TABLE servers ADD COLUMN data_dir TEXT NOT NULL DEFAULT ''",
        "stop_duration": f"ALTER TABLE servers ADD COLUMN stop_duration INTEGER NOT NULL DEFAULT {DEFAULT_STOP_DURATION}",
        "rcon_host": "ALTER TABLE servers ADD COLUMN rcon_host TEXT",
        "rcon_port": "ALTER TABLE servers ADD COLUMN rcon_port INTEGER",
        "rcon_password": "ALTER TABLE servers ADD COLUMN rcon_password TEXT",
        "port_bindings": "ALTER TABLE servers ADD COLUMN port_bindings TEXT NOT NULL DEFAULT '{}'",
        "volume_bindings": "ALTER TABLE servers ADD COLUMN volume_bindings TEXT NOT NULL DEFAULT '{}'",
        "environment": "ALTER TABLE servers ADD COLUMN environment TEXT NOT NULL DEFAULT '{}'",
    }

    for column, statement in migrations.items():
        if column not in existing_columns:
            db.execute(statement)


def slugify_name(name: str) -> str:
    slug = "".join(
        character.lower() if character.isalnum() else "-" for character in name
    )
    compact = "-".join(part for part in slug.split("-") if part)
    return compact or "minecraft"


def normalize_scalar(value: ScalarValue) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    return str(value)


def deserialize_json_object(raw_value: str | None) -> dict[str, object]:
    if not raw_value:
        return {}
    try:
        value = json.loads(raw_value)
    except json.JSONDecodeError:
        return {}
    if isinstance(value, dict):
        return value
    return {}


def normalize_environment_updates(
    environment: Mapping[str, ScalarValue],
) -> dict[str, str]:
    normalized: dict[str, str] = {}

    for raw_key, raw_value in environment.items():
        key = str(raw_key).strip()
        if not key:
            raise fastapi.HTTPException(
                status_code=400, detail="Environment variable names cannot be empty."
            )
        normalized[key] = normalize_scalar(raw_value)

    return normalized


def parse_stop_duration(value: str | int) -> int:
    try:
        stop_duration = int(str(value))
    except (TypeError, ValueError) as exc:
        raise fastapi.HTTPException(
            status_code=400,
            detail="STOP_DURATION must be an integer between 15 and 600.",
        ) from exc

    if stop_duration < 15 or stop_duration > 600:
        raise fastapi.HTTPException(
            status_code=400,
            detail="STOP_DURATION must be an integer between 15 and 600.",
        )

    return stop_duration


def parse_network_port(value: str | None, *, key: str, default: int) -> int:
    if value is None or not str(value).strip():
        return default

    try:
        port = int(str(value))
    except (TypeError, ValueError) as exc:
        raise fastapi.HTTPException(
            status_code=400,
            detail=f"{key} must be an integer between 1 and 65535.",
        ) from exc

    if port < 1 or port > 65535:
        raise fastapi.HTTPException(
            status_code=400,
            detail=f"{key} must be an integer between 1 and 65535.",
        )

    return port


def build_environment_state(
    row: sqlite3.Row, environment: dict[str, str]
) -> EnvironmentState:
    version = (environment.get("VERSION") or row["version"]).strip()
    if not version:
        raise fastapi.HTTPException(status_code=400, detail="VERSION cannot be empty.")

    server_type = (environment.get("TYPE") or row["server_type"]).strip()
    if not server_type:
        raise fastapi.HTTPException(status_code=400, detail="TYPE cannot be empty.")

    stop_duration = parse_stop_duration(
        environment.get("STOP_DURATION") or row["stop_duration"]
    )
    rcon_enabled = environment.get("ENABLE_RCON", "TRUE").upper() == "TRUE"

    if not rcon_enabled:
        environment.setdefault("CREATE_CONSOLE_IN_PIPE", "TRUE")

    rcon_host: str | None = None
    rcon_port: int | None = None
    rcon_password: str | None = None

    if rcon_enabled:
        rcon_password = (environment.get("RCON_PASSWORD") or "").strip()
        if not rcon_password:
            raise fastapi.HTTPException(
                status_code=400,
                detail="RCON_PASSWORD cannot be empty while RCON is enabled.",
            )
        rcon_host = (environment.get("RCON_HOST") or "127.0.0.1").strip() or "127.0.0.1"
        rcon_port = parse_network_port(
            environment.get("RCON_PORT"), key="RCON_PORT", default=25575
        )

    return {
        "version": version,
        "server_type": server_type,
        "stop_duration": stop_duration,
        "rcon_host": rcon_host,
        "rcon_port": rcon_port,
        "rcon_password": rcon_password,
    }


def extract_environment_updates_from_form(form_data: SupportsItems) -> dict[str, str]:
    updates: dict[str, str] = {}

    for key, value in form_data.items():
        if not key.startswith("environment__"):
            continue
        updates[key.removeprefix("environment__")] = str(value)

    return updates


def get_data_directory(request: ServerCreateRequest) -> Path:
    if request.data_dir:
        data_dir = Path(request.data_dir)
        if not data_dir.is_absolute():
            data_dir = Path.cwd() / data_dir
        return data_dir.resolve()

    return (SERVERS_ROOT / f"{slugify_name(request.name)}-{request.port}").resolve()


def get_server_properties_path(row: sqlite3.Row) -> Path:
    return Path(row["data_dir"]).resolve() / "server.properties"


def get_server_log_path(row: sqlite3.Row) -> Path:
    return Path(row["data_dir"]).resolve() / "logs" / "latest.log"


def get_server_data_root(row: sqlite3.Row) -> Path:
    return Path(row["data_dir"]).resolve()


def parse_server_properties(contents: str) -> dict[str, str]:
    properties: dict[str, str] = {}

    for raw_line in contents.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue

        if "=" in line:
            key, value = line.split("=", 1)
        elif ":" in line:
            key, value = line.split(":", 1)
        else:
            parts = line.split(None, 1)
            if len(parts) == 1:
                key, value = parts[0], ""
            else:
                key, value = parts

        properties[key.strip()] = value.strip()

    return properties


def normalize_browser_path(raw_path: str | None) -> str:
    if raw_path is None:
        return ""

    text = str(raw_path).strip()
    if not text:
        return ""

    normalized = posixpath.normpath(text.replace("\\", "/").lstrip("/"))
    return "" if normalized == "." else normalized


def format_file_timestamp(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def format_file_size(size: int | None) -> str:
    if size is None:
        return "Directory"

    units = ("B", "KB", "MB", "GB", "TB")
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024

    return f"{size} B"


def resolve_data_path(root: Path, raw_path: str | None) -> Path:
    root = root.resolve()
    raw_value = "" if raw_path is None else str(raw_path).strip()

    if not root.exists():
        raise ValueError("Data directory not found.")

    if not root.is_dir():
        raise ValueError("Data directory is not a directory.")

    if raw_value:
        posix_candidate = raw_value.replace("\\", "/")
        if (
            raw_value.startswith(("/", "\\"))
            or PureWindowsPath(raw_value).is_absolute()
            or PurePosixPath(posix_candidate).is_absolute()
        ):
            raise ValueError("Absolute paths are not allowed.")

    normalized = normalize_browser_path(raw_path)
    if not normalized:
        return root

    candidate = root.joinpath(*PurePosixPath(normalized).parts).resolve(strict=False)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("Path escapes the data directory.") from exc
    return candidate


def list_directory_entries(root: Path, directory: Path) -> list[dict[str, object]]:
    if not directory.exists():
        raise FileNotFoundError("Directory not found.")

    if not directory.is_dir():
        raise ValueError("Browse target is not a directory.")

    entries: list[dict[str, object]] = []
    for entry in directory.iterdir():
        stats = entry.stat()
        is_directory = entry.is_dir()
        relative_path = entry.relative_to(root).as_posix()
        entries.append(
            {
                "name": entry.name,
                "relative_path": relative_path,
                "type": "directory" if is_directory else "file",
                "size": None if is_directory else stats.st_size,
                "display_size": format_file_size(
                    None if is_directory else stats.st_size
                ),
                "modified_at": format_file_timestamp(stats.st_mtime),
            }
        )

    entries.sort(
        key=lambda item: (item["type"] != "directory", str(item["name"]).lower())
    )
    return entries


def build_breadcrumbs(relative_dir: str) -> list[dict[str, str]]:
    breadcrumbs = [{"label": "/data", "path": ""}]
    if not relative_dir:
        return breadcrumbs

    current_parts: list[str] = []
    for part in PurePosixPath(relative_dir).parts:
        current_parts.append(part)
        breadcrumbs.append(
            {
                "label": part,
                "path": "/".join(current_parts),
            }
        )
    return breadcrumbs


def read_preview_file(path: Path) -> dict[str, object]:
    stats = path.stat()
    with path.open("rb") as handle:
        preview_bytes = handle.read(MAX_FILE_PREVIEW_BYTES + 1)

    truncated = len(preview_bytes) > MAX_FILE_PREVIEW_BYTES
    sample = preview_bytes[:MAX_FILE_PREVIEW_BYTES]
    is_text = b"\0" not in sample
    contents = ""
    if is_text:
        try:
            contents = sample.decode("utf-8")
        except UnicodeDecodeError:
            is_text = False

    return {
        "name": path.name,
        "is_text": is_text,
        "contents": contents if is_text else "",
        "truncated": truncated,
        "size": stats.st_size,
        "display_size": format_file_size(stats.st_size),
        "modified_at": format_file_timestamp(stats.st_mtime),
    }


def read_text_file_tail(
    path: Path, max_bytes: int = MAX_LOG_TAIL_BYTES
) -> tuple[str, bool]:
    if max_bytes <= 0:
        return "", False

    file_size = path.stat().st_size
    start_offset = max(file_size - max_bytes, 0)

    with path.open("rb") as handle:
        handle.seek(start_offset)
        data = handle.read(max_bytes)

    truncated = start_offset > 0
    if truncated:
        newline_index = data.find(b"\n")
        if 0 <= newline_index < len(data) - 1:
            data = data[newline_index + 1 :]

    return data.decode("utf-8", errors="replace"), truncated


def read_server_log_snapshot(
    row: sqlite3.Row, max_bytes: int = MAX_LOG_TAIL_BYTES
) -> dict[str, object]:
    log_path = get_server_log_path(row)
    snapshot: dict[str, object] = {
        "path": str(log_path),
        "exists": False,
        "contents": "",
        "truncated": False,
        "modified_at": None,
    }

    if not log_path.exists() or not log_path.is_file():
        return snapshot

    try:
        contents, truncated = read_text_file_tail(log_path, max_bytes=max_bytes)
        snapshot.update(
            {
                "exists": True,
                "contents": contents,
                "truncated": truncated,
                "modified_at": format_file_timestamp(log_path.stat().st_mtime),
            }
        )
    except OSError:
        return snapshot

    return snapshot


def build_server_log_payload(
    server_id: int, row: sqlite3.Row, status: str
) -> dict[str, object]:
    log_snapshot = read_server_log_snapshot(row)
    return {
        "server_id": server_id,
        "status": status,
        "path": log_snapshot["path"],
        "exists": log_snapshot["exists"],
        "contents": log_snapshot["contents"],
        "truncated": log_snapshot["truncated"],
        "modified_at": log_snapshot["modified_at"],
    }


def format_sse_message(data: dict[str, object], event: str | None = None) -> str:
    lines: list[str] = []
    if event:
        lines.append(f"event: {event}")
    payload = json.dumps(data, separators=(",", ":"))
    for line in payload.splitlines() or ("",):
        lines.append(f"data: {line}")
    return "\n".join(lines) + "\n\n"


async def stream_server_logs(request: fastapi.Request, server_id: int):
    row = get_server_row(server_id)
    previous_payload: str | None = None

    while True:
        if await request.is_disconnected():
            break

        current_row = get_server_row(server_id)
        server = sync_server_row(current_row)
        payload = build_server_log_payload(server_id, current_row, server.status)
        serialized_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))

        if serialized_payload != previous_payload:
            yield format_sse_message(payload)
            previous_payload = serialized_payload
        else:
            yield ": keep-alive\n\n"

        await asyncio.sleep(1)


def build_server_view_href(
    server_id: int,
    browse: str = "",
    file: str | None = None,
    fragment: str | None = "data-files",
) -> str:
    query_items: list[tuple[str, str]] = []
    if browse:
        query_items.append(("browse", browse))
    if file:
        query_items.append(("file", file))

    base_path = f"/servers/{server_id}/view"
    query = f"?{urlencode(query_items)}" if query_items else ""
    hash_fragment = f"#{fragment}" if fragment else ""
    return f"{base_path}{query}{hash_fragment}"


def get_server_world_directory(row: sqlite3.Row, *, must_exist: bool = True) -> Path:
    data_root = get_server_data_root(row)
    properties_contents = read_server_properties_from_host(row) or ""
    world_name = (
        parse_server_properties(properties_contents).get("level-name") or "world"
    )

    try:
        world_dir = resolve_data_path(data_root, world_name)
    except ValueError as exc:
        raise ValueError("World directory is invalid.") from exc

    if must_exist and (not world_dir.exists() or not world_dir.is_dir()):
        raise FileNotFoundError("World directory not found.")

    return world_dir


def build_world_archive(world_dir: Path, archive_path: Path) -> None:
    world_root = world_dir.resolve()
    archive_root = world_dir.name

    with zipfile.ZipFile(
        archive_path, mode="w", compression=zipfile.ZIP_DEFLATED
    ) as archive:
        for current_root, dir_names, file_names in os.walk(
            world_root, topdown=True, followlinks=False
        ):
            current_path = Path(current_root).resolve()
            try:
                relative_root = current_path.relative_to(world_root)
            except ValueError:
                dir_names[:] = []
                continue

            safe_dir_names: list[str] = []
            for dir_name in dir_names:
                candidate = current_path / dir_name
                try:
                    candidate.resolve().relative_to(world_root)
                except ValueError:
                    continue
                safe_dir_names.append(dir_name)
            dir_names[:] = safe_dir_names

            if relative_root == Path("."):
                archive_dir = archive_root
            else:
                archive_dir = f"{archive_root}/{relative_root.as_posix()}"

            if not dir_names and not file_names:
                archive.writestr(f"{archive_dir}/", b"")

            for file_name in file_names:
                file_path = current_path / file_name
                try:
                    file_path.resolve().relative_to(world_root)
                except ValueError:
                    continue
                if not file_path.is_file():
                    continue

                relative_path = file_path.relative_to(world_root).as_posix()
                archive.write(file_path, arcname=f"{archive_root}/{relative_path}")


def remove_file_if_exists(path: str) -> None:
    Path(path).unlink(missing_ok=True)


def extract_world_archive(archive_bytes: bytes, destination: Path) -> None:
    try:
        archive = zipfile.ZipFile(BytesIO(archive_bytes))
    except zipfile.BadZipFile as exc:
        raise ValueError("Upload a valid zip archive.") from exc

    with archive:
        safe_members: list[tuple[zipfile.ZipInfo, tuple[str, ...]]] = []
        for info in archive.infolist():
            raw_name = info.filename.replace("\\", "/")
            if not raw_name or raw_name.startswith("/"):
                raise ValueError("Archive contains invalid paths.")

            normalized = posixpath.normpath(raw_name).lstrip("/")
            if normalized in ("", "."):
                continue

            parts = tuple(
                part
                for part in PurePosixPath(normalized).parts
                if part not in ("", ".")
            )
            if any(part == ".." for part in parts):
                raise ValueError("Archive contains invalid paths.")
            if parts and parts[0] == "__MACOSX":
                continue
            safe_members.append((info, parts))

        file_members = [
            (info, parts) for info, parts in safe_members if not info.is_dir()
        ]
        if not file_members:
            raise ValueError("Archive does not contain any world files.")

        top_levels = {parts[0] for _, parts in file_members if parts}
        strip_root = (
            next(iter(top_levels))
            if len(top_levels) == 1 and all(len(parts) > 1 for _, parts in file_members)
            else None
        )

        for info, parts in safe_members:
            relative_parts = (
                parts[1:] if strip_root and parts and parts[0] == strip_root else parts
            )
            if not relative_parts:
                continue

            target_path = destination.joinpath(*relative_parts)
            resolved_target = target_path.resolve(strict=False)
            try:
                resolved_target.relative_to(destination.resolve())
            except ValueError as exc:
                raise ValueError("Archive contains invalid paths.") from exc

            if info.is_dir():
                target_path.mkdir(parents=True, exist_ok=True)
                continue

            target_path.parent.mkdir(parents=True, exist_ok=True)
            with (
                archive.open(info, mode="r") as source,
                target_path.open("wb") as output,
            ):
                shutil.copyfileobj(source, output)

    if not any(destination.iterdir()):
        raise ValueError("Archive does not contain any world files.")


def import_world_archive(row: sqlite3.Row, archive_bytes: bytes) -> Path:
    data_root = get_server_data_root(row)
    world_dir = get_server_world_directory(row, must_exist=False)
    world_dir.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(
        prefix=f"server-{row['id']}-world-import-",
        dir=str(data_root),
    ) as temp_dir:
        staging_dir = Path(temp_dir) / world_dir.name
        staging_dir.mkdir(parents=True, exist_ok=True)
        extract_world_archive(archive_bytes, staging_dir)

        backup_dir: Path | None = None
        try:
            if world_dir.exists():
                if not world_dir.is_dir():
                    raise ValueError("World path is not a directory.")
                backup_dir = (
                    world_dir.parent / f"{world_dir.name}.backup-{secrets.token_hex(4)}"
                )
                world_dir.replace(backup_dir)

            staging_dir.replace(world_dir)
        except Exception:
            if (
                backup_dir is not None
                and backup_dir.exists()
                and not world_dir.exists()
            ):
                backup_dir.replace(world_dir)
            raise
        else:
            if backup_dir is not None and backup_dir.exists():
                shutil.rmtree(backup_dir)

    return world_dir


def build_file_browser_context(
    server_id: int,
    row: sqlite3.Row,
    browse: str | None,
    file: str | None,
) -> dict[str, object]:
    root = get_server_data_root(row)
    browser_error: str | None = None
    browser_entries: list[dict[str, object]] = []
    browser_preview: dict[str, object] | None = None
    browser_download_href: str | None = None
    browser_selected_file: str | None = None
    current_path = ""

    requested_browse = browse
    if not requested_browse and file:
        file_parent = PurePosixPath(normalize_browser_path(file)).parent
        requested_browse = "" if str(file_parent) == "." else str(file_parent)

    try:
        current_directory = resolve_data_path(root, requested_browse)
        if not current_directory.exists():
            raise FileNotFoundError("Browse target does not exist.")
        if not current_directory.is_dir():
            raise ValueError("Browse target is not a directory.")
        current_path = (
            current_directory.relative_to(root).as_posix()
            if current_directory != root
            else ""
        )
    except (FileNotFoundError, OSError, ValueError):
        browser_error = "Unable to open that folder. Showing /data instead."
        current_directory = root
        current_path = ""
        file = None

    try:
        browser_entries = list_directory_entries(root, current_directory)
    except (FileNotFoundError, OSError, ValueError):
        browser_error = browser_error or "Data directory is unavailable."
        browser_entries = []

    if file:
        try:
            preview_path = resolve_data_path(root, file)
            if not preview_path.exists():
                raise FileNotFoundError("Selected file does not exist.")
            if not preview_path.is_file():
                raise ValueError("Selected path is not a file.")
            browser_selected_file = preview_path.relative_to(root).as_posix()
            browser_preview = read_preview_file(preview_path)
            browser_preview["relative_path"] = browser_selected_file
            browser_download_href = f"/servers/{server_id}/files/download?{urlencode([('path', browser_selected_file)])}"
        except (FileNotFoundError, OSError, ValueError):
            browser_error = browser_error or "Unable to preview that file."

    parent_href: str | None = None
    if current_path:
        parent = PurePosixPath(current_path).parent
        parent_path = "" if str(parent) == "." else str(parent)
        parent_href = build_server_view_href(server_id, browse=parent_path)

    breadcrumbs = build_breadcrumbs(current_path)
    for crumb in breadcrumbs:
        crumb["href"] = build_server_view_href(server_id, browse=crumb["path"])

    for entry in browser_entries:
        relative_path = str(entry["relative_path"])
        if entry["type"] == "directory":
            entry["href"] = build_server_view_href(server_id, browse=relative_path)
        else:
            entry["href"] = build_server_view_href(
                server_id, browse=current_path, file=relative_path
            )
        entry["is_selected"] = relative_path == browser_selected_file

    server_view_next = build_server_view_href(
        server_id,
        browse=current_path,
        file=browser_selected_file,
    )
    server_properties_action = (
        f"/servers/{server_id}/server-properties/view?"
        f"{urlencode([('next', server_view_next)])}"
    )
    server_world_import_next = build_server_view_href(
        server_id,
        browse=current_path,
        file=browser_selected_file,
        fragment="world-transfer",
    )

    return {
        "browser_root_label": "/data",
        "browser_current_path": current_path,
        "browser_breadcrumbs": breadcrumbs,
        "browser_entries": browser_entries,
        "browser_selected_file": browser_selected_file,
        "browser_preview": browser_preview,
        "browser_error": browser_error,
        "browser_download_href": browser_download_href,
        "browser_parent_href": parent_href,
        "server_properties_action": server_properties_action,
        "server_view_next": server_view_next,
        "server_world_import_next": server_world_import_next,
    }


def get_container_or_none(row: sqlite3.Row) -> Container | None:
    try:
        return client.containers.get(row["container_id"])
    except NotFound:
        return None


def get_container_env_map(container: Container) -> dict[str, str]:
    env_values = container.attrs.get("Config", {}).get("Env", [])
    return dict(item.split("=", 1) for item in env_values if "=" in item)


def read_text_from_archive(stream: list[bytes]) -> str:
    chunks: list[bytes] = []
    for chunk in stream:
        chunks.append(chunk)

    with tarfile.open(fileobj=BytesIO(b"".join(chunks)), mode="r:*") as archive:
        members = [member for member in archive.getmembers() if member.isfile()]
        if not members:
            return ""
        extracted = archive.extractfile(members[0])
        if extracted is None:
            return ""
        return extracted.read().decode("utf-8")


def read_server_properties_from_container(row: sqlite3.Row) -> str | None:
    container = get_container_or_none(row)
    if container is None:
        return None

    try:
        stream, _ = container.get_archive("/data/server.properties")
    except APIError:
        return None

    try:
        return read_text_from_archive(stream)
    except (tarfile.TarError, UnicodeDecodeError):
        return None


def read_server_properties_from_host(row: sqlite3.Row) -> str | None:
    properties_path = get_server_properties_path(row)
    if not properties_path.exists():
        return None
    return properties_path.read_text(encoding="utf-8")


def read_server_properties(row: sqlite3.Row) -> str:
    container_contents = read_server_properties_from_container(row)
    if container_contents is not None:
        return container_contents

    host_contents = read_server_properties_from_host(row)
    if host_contents is not None:
        return host_contents

    return ""


def server_properties_exists(row: sqlite3.Row) -> bool:
    if read_server_properties_from_container(row) is not None:
        return True
    return read_server_properties_from_host(row) is not None


def write_server_properties_to_container(row: sqlite3.Row, contents: str) -> bool:
    container = get_container_or_none(row)
    if container is None:
        return False

    buffer = BytesIO()
    encoded = contents.encode("utf-8")
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo(name="server.properties")
        info.size = len(encoded)
        archive.addfile(info, BytesIO(encoded))

    buffer.seek(0)

    try:
        return container.put_archive("/data", buffer.read())
    except APIError:
        return False


def write_server_properties(row: sqlite3.Row, contents: str) -> Path:
    data_dir = Path(row["data_dir"]).resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    properties_path = data_dir / "server.properties"
    properties_path.write_text(contents, encoding="utf-8")
    write_server_properties_to_container(row, contents)
    return properties_path


def get_next_available_port(
    used_ports: Iterable[int], start_port: int = MINECRAFT_PORT
) -> int:
    port = start_port
    unavailable = set(used_ports)

    while port in unavailable and port <= 65535:
        port += 1

    if port > 65535:
        raise fastapi.HTTPException(
            status_code=409, detail="No Minecraft server ports are available"
        )

    return port


def build_container_environment(request: ServerCreateRequest) -> dict[str, str]:
    environment: dict[str, str] = {
        "EULA": normalize_scalar(request.eula),
        "TYPE": request.server_type,
        "VERSION": request.version,
        "ENABLE_RCON": "TRUE",
        "RCON_PASSWORD": secrets.token_urlsafe(18),
        "STOP_DURATION": str(request.stop_duration),
    }

    for key, value in request.environment.items():
        environment[key] = normalize_scalar(value)

    # Keep the JVM heap below the container cap to leave room for non-heap memory.
    environment["MEMORY"] = MINECRAFT_JVM_MEMORY

    if environment.get("ENABLE_RCON", "TRUE").upper() != "TRUE":
        environment.setdefault("CREATE_CONSOLE_IN_PIPE", "TRUE")

    return environment


def container_exists(name: str) -> bool:
    try:
        client.containers.get(name)
    except NotFound:
        return False
    return True


def row_to_response(row: sqlite3.Row) -> ServerResponse:
    return ServerResponse(
        id=row["id"],
        name=row["name"],
        port=row["port"],
        status=row["status"],
        container_id=row["container_id"],
        container_name=row["container_name"],
        image=row["image"],
        version=row["version"],
        server_type=row["server_type"],
        data_dir=row["data_dir"],
        stop_duration=row["stop_duration"],
        rcon_host=row["rcon_host"],
        rcon_port=row["rcon_port"],
        rcon_password=row["rcon_password"],
        port_bindings=deserialize_json_object(row["port_bindings"]),
        volume_bindings=deserialize_json_object(row["volume_bindings"]),
        environment={
            str(key): str(value)
            for key, value in deserialize_json_object(row["environment"]).items()
        },
        created_at=row["created_at"],
    )


def current_server_status(container_id: str) -> Literal["running", "stopped"]:
    try:
        container = client.containers.get(container_id)
    except NotFound:
        return "stopped"

    container.reload()
    return "running" if container.status == "running" else "stopped"


def update_server_status(server_id: int, status: Literal["running", "stopped"]) -> None:
    db.execute("UPDATE servers SET status = ? WHERE id = ?", (status, server_id))


def sync_server_row(row: sqlite3.Row) -> ServerResponse:
    actual_status = current_server_status(row["container_id"])
    if actual_status != row["status"]:
        update_server_status(row["id"], actual_status)
        row = get_server_row(row["id"])
    return row_to_response(row)


def get_server_row(server_id: int) -> sqlite3.Row:
    row = db.fetch_one("SELECT * FROM servers WHERE id = ?", (server_id,))
    if row is None:
        raise fastapi.HTTPException(status_code=404, detail="Server not found")
    return row


def get_all_servers() -> list[ServerResponse]:
    rows = db.fetch_all("SELECT * FROM servers ORDER BY id DESC")
    return [sync_server_row(row) for row in rows]


def resolve_redirect_target(next_path: str | None, fallback: str) -> str:
    if next_path and next_path.startswith("/") and not next_path.startswith("//"):
        return next_path
    return fallback


def recreate_server_container(
    row: sqlite3.Row,
    environment: dict[str, str],
    stop_duration: int,
    desired_status: Literal["running", "stopped"],
) -> tuple[str, Literal["running", "stopped"]]:
    old_container = get_container_or_none(row)
    backup_name: str | None = None
    new_container: Container | None = None
    volume_bindings = deserialize_json_object(row["volume_bindings"]) or {
        str(Path(row["data_dir"]).resolve()): {
            "bind": "/data",
            "mode": "rw",
        }
    }

    if old_container is not None:
        old_container.reload()
        if old_container.status == "running":
            stop_server(row["id"])
            old_container.reload()

        backup_name = f"{row['container_name']}-backup-{secrets.token_hex(4)}"
        try:
            old_container.rename(backup_name)
        except APIError as exc:
            raise fastapi.HTTPException(status_code=502, detail=str(exc)) from exc
        except DockerException as exc:
            raise fastapi.HTTPException(status_code=503, detail=str(exc)) from exc

    try:
        host_config = client.api.create_host_config(
            binds=volume_bindings,
            port_bindings={MINECRAFT_PORT: row["port"]},
        )
        container_config = client.api.create_container(
            image=row["image"],
            name=row["container_name"],
            detach=True,
            environment=environment,
            ports=[MINECRAFT_PORT],
            volumes=["/data"],
            host_config=host_config,
            labels={
                "managed-by": "manage-api",
                "minecraft-server-name": row["name"],
            },
            stop_timeout=stop_duration,
        )
        new_container = client.containers.get(container_config["Id"])
        if desired_status == "running":
            new_container.start()
    except APIError as exc:
        if new_container is not None:
            try:
                new_container.remove(force=True)
            except (APIError, DockerException):
                pass
        if old_container is not None and backup_name is not None:
            try:
                old_container.rename(row["container_name"])
            except (APIError, DockerException):
                pass
        raise fastapi.HTTPException(status_code=502, detail=str(exc)) from exc
    except DockerException as exc:
        if new_container is not None:
            try:
                new_container.remove(force=True)
            except (APIError, DockerException):
                pass
        if old_container is not None and backup_name is not None:
            try:
                old_container.rename(row["container_name"])
            except (APIError, DockerException):
                pass
        raise fastapi.HTTPException(status_code=503, detail=str(exc)) from exc

    if old_container is not None:
        try:
            old_container.remove(force=True)
        except (APIError, DockerException):
            pass

    actual_status: Literal["running", "stopped"] = "stopped"
    if desired_status == "running" and new_container is not None:
        new_container.reload()
        actual_status = "running" if new_container.status == "running" else "stopped"

    return container_config["Id"], actual_status


def update_server_environment(
    server_id: int, updates: Mapping[str, ScalarValue]
) -> tuple[ServerResponse, bool]:
    server = sync_server_row(get_server_row(server_id))
    row = get_server_row(server_id)
    environment = {
        str(key): str(value)
        for key, value in deserialize_json_object(row["environment"]).items()
    }
    environment.update(normalize_environment_updates(updates))

    environment_state = build_environment_state(row, environment)
    container_id, status = recreate_server_container(
        row,
        environment,
        stop_duration=environment_state["stop_duration"],
        desired_status=server.status,
    )

    db.execute(
        """
        UPDATE servers
        SET
            container_id = ?,
            status = ?,
            version = ?,
            server_type = ?,
            stop_duration = ?,
            rcon_host = ?,
            rcon_port = ?,
            rcon_password = ?,
            environment = ?
        WHERE id = ?
        """,
        (
            container_id,
            status,
            environment_state["version"],
            environment_state["server_type"],
            environment_state["stop_duration"],
            environment_state["rcon_host"],
            environment_state["rcon_port"],
            environment_state["rcon_password"],
            json.dumps(environment),
            server_id,
        ),
    )

    return sync_server_row(
        get_server_row(server_id)
    ), server.status == "running" and status == "running"


def get_exec_user(container: Container) -> str:
    env_map = get_container_env_map(container)
    uid = env_map.get("UID", "1000")
    gid = env_map.get("GID", "1000")
    return f"{uid}:{gid}"


def send_stop_command(container: Container) -> None:
    env_map = get_container_env_map(container)
    rcon_enabled = env_map.get("ENABLE_RCON", "TRUE").upper() == "TRUE"

    if rcon_enabled:
        result = container.exec_run(cmd=["rcon-cli", "stop"])
    else:
        result = container.exec_run(
            cmd=["mc-send-to-console", "stop"],
            user=get_exec_user(container),
        )

    if result.exit_code != 0:
        raise RuntimeError("Failed to send stop command to the Minecraft server")


def get_rcon_connection_settings(container: Container) -> tuple[str, str, str]:
    env_map = get_container_env_map(container)
    if env_map.get("ENABLE_RCON", "TRUE").upper() != "TRUE":
        raise ValueError("RCON is disabled for this server.")

    host = env_map.get("RCON_HOST") or "127.0.0.1"
    port = env_map.get("RCON_PORT") or "25575"
    password = env_map.get("RCON_PASSWORD")
    if not password:
        raise ValueError("RCON password is unavailable for this server.")

    return host, port, password


def execute_server_command(row: sqlite3.Row, command: str) -> str:
    stripped_command = command.strip()
    if not stripped_command:
        raise ValueError("Command cannot be empty.")

    container = get_container_or_none(row)
    if container is None:
        raise RuntimeError("Container not found.")

    container.reload()
    if container.status != "running":
        raise RuntimeError("Server must be running before sending commands.")

    host, port, password = get_rcon_connection_settings(container)
    try:
        return rcon_connection_manager.execute(
            row["id"],
            row["container_id"],
            host,
            int(port),
            password,
            stripped_command,
        )
    except RconAuthenticationError as exc:
        raise RuntimeError("RCON authentication failed.") from exc
    except (EOFError, OSError, RconProtocolError, TimeoutError) as exc:
        raise RuntimeError("Failed to execute the RCON command.") from exc


def wait_for_container_stop(container: Container, timeout: int) -> bool:
    try:
        container.wait(timeout=timeout, condition="not-running")
    except APIError:
        return False
    except requests.exceptions.ReadTimeout:
        return False
    container.reload()
    return container.status != "running"


def ensure_image_available(image: str) -> None:
    try:
        client.images.get(image)
    except ImageNotFound:
        client.images.pull(image)


def add_server(
    name: str,
    port: int,
    status: Literal["running", "stopped"],
    request: ServerCreateRequest,
) -> ServerResponse:
    ensure_image_available(MINECRAFT_IMAGE)

    container_name = f"mc-{slugify_name(name)}-{port}"
    if container_exists(container_name):
        raise fastapi.HTTPException(
            status_code=409, detail="Container name already exists"
        )

    data_dir = get_data_directory(request)
    data_dir.mkdir(parents=True, exist_ok=True)
    environment = build_container_environment(request)
    port_bindings = {
        f"{MINECRAFT_PORT}/tcp": {
            "host_ip": "",
            "host_port": port,
            "container_port": MINECRAFT_PORT,
            "protocol": "tcp",
        }
    }
    volume_bindings = {
        str(data_dir): {
            "bind": "/data",
            "mode": "rw",
        }
    }
    rcon_enabled = environment.get("ENABLE_RCON", "TRUE").upper() == "TRUE"
    rcon_host = "127.0.0.1" if rcon_enabled else None
    rcon_port = 25575 if rcon_enabled else None
    rcon_password = environment.get("RCON_PASSWORD") if rcon_enabled else None

    try:
        host_config = client.api.create_host_config(
            binds=volume_bindings,
            port_bindings={MINECRAFT_PORT: port},
            mem_limit=DOCKER_MEMORY_LIMIT_BYTES,
        )
        container_config = client.api.create_container(
            image=MINECRAFT_IMAGE,
            name=container_name,
            detach=True,
            environment=environment,
            ports=[MINECRAFT_PORT],
            volumes=["/data"],
            host_config=host_config,
            labels={
                "managed-by": "manage-api",
                "minecraft-server-name": name,
            },
            stop_timeout=request.stop_duration,
        )
        container = client.containers.get(container_config["Id"])
        if status == "running":
            container.start()
    except APIError as exc:
        raise fastapi.HTTPException(status_code=502, detail=str(exc)) from exc
    except DockerException as exc:
        raise fastapi.HTTPException(status_code=503, detail=str(exc)) from exc

    try:
        db.execute(
            """
            INSERT INTO servers (
                name,
                port,
                status,
                container_id,
                container_name,
                image,
                version,
                server_type,
                data_dir,
                stop_duration,
                rcon_host,
                rcon_port,
                rcon_password,
                port_bindings,
                volume_bindings,
                environment
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                name,
                port,
                status,
                container.id,
                container_name,
                MINECRAFT_IMAGE,
                request.version,
                request.server_type,
                str(data_dir),
                request.stop_duration,
                rcon_host,
                rcon_port,
                rcon_password,
                json.dumps(port_bindings),
                json.dumps(volume_bindings),
                json.dumps(environment),
            ),
        )
    except sqlite3.IntegrityError as exc:
        container.remove(force=True)
        raise fastapi.HTTPException(
            status_code=409, detail="Server port already exists"
        ) from exc

    row = db.fetch_one("SELECT * FROM servers WHERE container_id = ?", (container.id,))
    if row is None:
        raise fastapi.HTTPException(
            status_code=500, detail="Created server could not be loaded"
        )
    return row_to_response(row)


def start_server(server_id: int) -> ServerResponse:
    row = get_server_row(server_id)

    try:
        container = client.containers.get(row["container_id"])
    except NotFound as exc:
        raise fastapi.HTTPException(
            status_code=404, detail="Container not found"
        ) from exc

    container.reload()
    if container.status != "running":
        try:
            container.start()
        except APIError as exc:
            raise fastapi.HTTPException(status_code=502, detail=str(exc)) from exc
        except DockerException as exc:
            raise fastapi.HTTPException(status_code=503, detail=str(exc)) from exc

    update_server_status(server_id, "running")
    return sync_server_row(get_server_row(server_id))


def stop_server(server_id: int) -> ServerResponse:
    row = get_server_row(server_id)

    try:
        container = client.containers.get(row["container_id"])
    except NotFound as exc:
        raise fastapi.HTTPException(
            status_code=404, detail="Container not found"
        ) from exc

    container.reload()
    if container.status != "running":
        rcon_connection_manager.close_server(server_id)
        update_server_status(server_id, "stopped")
        return sync_server_row(get_server_row(server_id))

    env_values = container.attrs.get("Config", {}).get("Env", [])
    env_map = dict(item.split("=", 1) for item in env_values if "=" in item)
    stop_timeout = int(env_map.get("STOP_DURATION", DEFAULT_STOP_DURATION))

    try:
        send_stop_command(container)
    except RuntimeError:
        pass
    except APIError:
        pass

    if not wait_for_container_stop(container, timeout=stop_timeout + 15):
        try:
            container.stop(timeout=stop_timeout)
        except APIError as exc:
            raise fastapi.HTTPException(status_code=502, detail=str(exc)) from exc
        except DockerException as exc:
            raise fastapi.HTTPException(status_code=503, detail=str(exc)) from exc

    update_server_status(server_id, "stopped")
    rcon_connection_manager.close_server(server_id)
    return sync_server_row(get_server_row(server_id))


def remove_server_data_path(path: Path) -> None:
    if not path.exists():
        return
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
        return
    shutil.rmtree(path)


def delete_server(server_id: int) -> None:
    row = get_server_row(server_id)
    container = get_container_or_none(row)
    data_dir = Path(row["data_dir"])

    rcon_connection_manager.close_server(server_id)

    if container is not None:
        try:
            container.remove(force=True)
        except APIError as exc:
            raise fastapi.HTTPException(status_code=502, detail=str(exc)) from exc
        except DockerException as exc:
            raise fastapi.HTTPException(status_code=503, detail=str(exc)) from exc

    try:
        remove_server_data_path(data_dir)
    except OSError as exc:
        raise fastapi.HTTPException(
            status_code=500, detail="Failed to remove server data directory"
        ) from exc

    db.execute("DELETE FROM servers WHERE id = ?", (server_id,))


def render_login_page(
    request: fastapi.Request,
    *,
    error: str = "",
    next_path: str | None = None,
) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "csrf_token": "",
            "error": error,
            "next": resolve_redirect_target(next_path, "/"),
        },
    )


@app.get("/favicon.svg", include_in_schema=False)
def favicon() -> FileResponse:
    if not FAVICON_PATH.is_file():
        raise fastapi.HTTPException(status_code=404, detail="Favicon not found")

    return FileResponse(path=FAVICON_PATH, media_type="image/svg+xml")


@app.get("/login", response_class=HTMLResponse)
def login_page(request: fastapi.Request, next: str | None = None) -> fastapi.Response:
    redirect_target = resolve_redirect_target(next, "/")
    if is_authenticated(request):
        return RedirectResponse(url=redirect_target, status_code=303)
    return render_login_page(request, next_path=redirect_target)


@app.post("/login", response_class=HTMLResponse)
def login_action(
    request: fastapi.Request,
    username: str = fastapi.Form(""),
    password: str = fastapi.Form(""),
    next: str | None = fastapi.Form(None),
) -> fastapi.Response:
    redirect_target = resolve_redirect_target(next, "/")

    try:
        enforce_login_rate_limit(request)
    except Exception as exc:
        retry_after = getattr(exc, "retry_after", None)
        if retry_after is None:
            raise

        response = render_login_page(
            request,
            error="Too many login attempts. Try again later.",
            next_path=redirect_target,
        )
        response.status_code = 429
        response.headers["Retry-After"] = str(retry_after)
        return response

    if verify_credentials(username, password):
        clear_login_failures(request)
        login_user(request)
        return RedirectResponse(url=redirect_target, status_code=303)

    record_login_failure(request)
    return render_login_page(
        request, error="Invalid credentials", next_path=redirect_target
    )


@app.post("/logout")
async def logout_action(request: fastapi.Request) -> fastapi.Response:
    try:
        await require_csrf(request)
    except CsrfError:
        return csrf_plain_text_response()

    logout_user(request)
    return RedirectResponse(url="/login", status_code=303)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: fastapi.Request) -> HTMLResponse:
    servers = get_all_servers()
    suggested_port = get_next_available_port(server.port for server in servers)
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context=build_template_context(
            request,
            {
                "servers": servers,
                "server_count": len(servers),
                "running_count": sum(
                    1 for server in servers if server.status == "running"
                ),
                "stopped_count": sum(
                    1 for server in servers if server.status == "stopped"
                ),
                "default_port": suggested_port,
                "default_stop_duration": DEFAULT_STOP_DURATION,
                "server_type_options": COMMON_SERVER_TYPES,
            },
        ),
    )


@app.get("/servers/{server_id}/view", response_class=HTMLResponse)
def server_detail_page(
    request: fastapi.Request,
    server_id: int,
    browse: str | None = None,
    file: str | None = None,
) -> HTMLResponse:
    row = get_server_row(server_id)
    server = sync_server_row(row)
    properties_contents = read_server_properties(row)
    browser_context = build_file_browser_context(server_id, row, browse, file)
    log_snapshot = read_server_log_snapshot(row)
    return templates.TemplateResponse(
        request=request,
        name="server.html",
        context=build_template_context(
            request,
            {
                "server": server,
                "environment_items": sorted(server.environment.items()),
                "server_environment_url": f"/servers/{server_id}/environment",
                "server_environment_action": f"/servers/{server_id}/environment/view",
                "server_environment_next": f"/servers/{server_id}/view#environment",
                "server_environment_saved": request.query_params.get("env-saved")
                == "1",
                "server_environment_error": request.query_params.get("env-error"),
                "server_logs_url": f"/servers/{server_id}/logs",
                "server_logs_stream_url": f"/servers/{server_id}/logs/stream",
                "server_command_url": f"/servers/{server_id}/commands",
                "server_logs_path": log_snapshot["path"],
                "server_logs_exists": log_snapshot["exists"],
                "server_logs_contents": log_snapshot["contents"],
                "server_logs_truncated": log_snapshot["truncated"],
                "server_logs_modified_at": log_snapshot["modified_at"],
                "server_properties_contents": properties_contents,
                "server_properties_exists": server_properties_exists(row),
                "server_properties_saved": request.query_params.get("saved") == "1",
                "server_world_imported": request.query_params.get("world-imported")
                == "1",
                "server_world_import_error": request.query_params.get(
                    "world-import-error"
                ),
                "server_world_download_url": f"/servers/{server_id}/world/download",
                "server_world_import_action": f"/servers/{server_id}/world/import/view",
                **browser_context,
            },
        ),
    )


@app.post("/servers/{server_id}/start/view")
async def start_server_view_action(
    request: fastapi.Request,
    server_id: int,
    next: str | None = None,
) -> fastapi.Response:
    try:
        await require_csrf(request)
    except CsrfError:
        return csrf_plain_text_response()

    start_server(server_id)
    return RedirectResponse(
        url=resolve_redirect_target(next, f"/servers/{server_id}/view"),
        status_code=303,
    )


@app.post("/servers/{server_id}/stop/view")
async def stop_server_view_action(
    request: fastapi.Request,
    server_id: int,
    next: str | None = None,
) -> fastapi.Response:
    try:
        await require_csrf(request)
    except CsrfError:
        return csrf_plain_text_response()

    stop_server(server_id)
    return RedirectResponse(
        url=resolve_redirect_target(next, f"/servers/{server_id}/view"),
        status_code=303,
    )


@app.post("/servers/{server_id}/delete/view")
async def delete_server_view_action(
    request: fastapi.Request,
    server_id: int,
    next: str | None = None,
) -> fastapi.Response:
    try:
        await require_csrf(request)
    except CsrfError:
        return csrf_plain_text_response()

    delete_server(server_id)
    return RedirectResponse(
        url=resolve_redirect_target(next, "/"),
        status_code=303,
    )


@app.get("/servers/{server_id}/logs")
def get_server_logs_endpoint(server_id: int) -> dict[str, object]:
    row = get_server_row(server_id)
    server = sync_server_row(row)
    return build_server_log_payload(server_id, row, server.status)


@app.get("/servers/{server_id}/logs/stream")
async def stream_server_logs_endpoint(
    request: fastapi.Request, server_id: int
) -> StreamingResponse:
    stream = stream_server_logs(request, server_id)
    return StreamingResponse(
        stream,
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/servers/{server_id}/commands")
async def execute_server_command_endpoint(
    http_request: fastapi.Request,
    server_id: int,
    request: ServerCommandRequest,
) -> dict[str, object]:
    try:
        await require_csrf(http_request)
    except CsrfError as exc:
        raise csrf_http_exception() from exc

    row = get_server_row(server_id)

    try:
        output = execute_server_command(row, request.command)
    except ValueError as exc:
        raise fastapi.HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise fastapi.HTTPException(status_code=409, detail=str(exc)) from exc
    except APIError as exc:
        raise fastapi.HTTPException(
            status_code=502, detail="Docker rejected the command."
        ) from exc
    except DockerException as exc:
        raise fastapi.HTTPException(
            status_code=503, detail="Docker is unavailable."
        ) from exc

    return {
        "server_id": server_id,
        "command": request.command.strip(),
        "output": output,
    }


@app.get("/servers", response_model=list[ServerResponse])
def list_servers() -> list[ServerResponse]:
    return get_all_servers()


@app.post("/servers", response_model=ServerResponse, status_code=201)
async def create_server(
    http_request: fastapi.Request,
    request: ServerCreateRequest,
) -> ServerResponse:
    try:
        await require_csrf(http_request)
    except CsrfError as exc:
        raise csrf_http_exception() from exc

    return add_server(request.name, request.port, request.status, request)


@app.post("/servers/{server_id}/start", response_model=ServerResponse)
async def start_server_endpoint(
    request: fastapi.Request,
    server_id: int,
) -> ServerResponse:
    try:
        await require_csrf(request)
    except CsrfError as exc:
        raise csrf_http_exception() from exc

    return start_server(server_id)


@app.post("/servers/{server_id}/stop", response_model=ServerResponse)
async def stop_server_endpoint(
    request: fastapi.Request,
    server_id: int,
) -> ServerResponse:
    try:
        await require_csrf(request)
    except CsrfError as exc:
        raise csrf_http_exception() from exc

    return stop_server(server_id)


@app.delete("/servers/{server_id}", status_code=204)
async def delete_server_endpoint(
    request: fastapi.Request,
    server_id: int,
) -> fastapi.Response:
    try:
        await require_csrf(request)
    except CsrfError as exc:
        raise csrf_http_exception() from exc

    delete_server(server_id)
    return fastapi.Response(status_code=204)


@app.put("/servers/{server_id}/environment")
async def update_server_environment_endpoint(
    http_request: fastapi.Request,
    server_id: int,
    request: ServerEnvironmentUpdateRequest,
) -> dict[str, object]:
    try:
        await require_csrf(http_request)
    except CsrfError as exc:
        raise csrf_http_exception() from exc

    server, restarted = update_server_environment(server_id, request.environment)
    return {
        "server_id": server_id,
        "saved": True,
        "restarted": restarted,
        "server": server.model_dump(),
    }


@app.post("/servers/{server_id}/environment/view")
async def update_server_environment_view_action(
    server_id: int,
    request: fastapi.Request,
) -> fastapi.Response:
    try:
        await require_csrf(request)
    except CsrfError:
        return csrf_plain_text_response()

    form_data = await request.form()
    next_path = str(form_data.get("next") or "") or None
    environment_updates = extract_environment_updates_from_form(form_data)

    try:
        update_server_environment(server_id, environment_updates)
    except fastapi.HTTPException as exc:
        fallback = f"/servers/{server_id}/view#environment"
        redirect_target = resolve_redirect_target(next_path, fallback)
        redirect_base, has_fragment, redirect_fragment = redirect_target.partition("#")
        separator = "&" if "?" in redirect_base else "?"
        if "env-error=" not in redirect_base:
            redirect_base = f"{redirect_base}{separator}{urlencode([('env-error', str(exc.detail))])}"
        redirect_target = (
            f"{redirect_base}#{redirect_fragment}" if has_fragment else redirect_base
        )
        return RedirectResponse(url=redirect_target, status_code=303)

    fallback = f"/servers/{server_id}/view?env-saved=1#environment"
    redirect_target = resolve_redirect_target(next_path, fallback)
    redirect_base, has_fragment, redirect_fragment = redirect_target.partition("#")
    separator = "&" if "?" in redirect_base else "?"
    if "env-saved=" not in redirect_base:
        redirect_base = f"{redirect_base}{separator}env-saved=1"
    redirect_target = (
        f"{redirect_base}#{redirect_fragment}" if has_fragment else redirect_base
    )
    return RedirectResponse(url=redirect_target, status_code=303)


@app.get("/servers/{server_id}/server-properties")
def get_server_properties_endpoint(server_id: int) -> dict[str, object]:
    row = get_server_row(server_id)
    contents = read_server_properties(row)
    return {
        "server_id": server_id,
        "path": str(get_server_properties_path(row)),
        "exists": server_properties_exists(row),
        "contents": contents,
    }


@app.put("/servers/{server_id}/server-properties")
async def update_server_properties_endpoint(
    http_request: fastapi.Request,
    server_id: int,
    request: ServerPropertiesUpdateRequest,
) -> dict[str, object]:
    try:
        await require_csrf(http_request)
    except CsrfError as exc:
        raise csrf_http_exception() from exc

    row = get_server_row(server_id)
    properties_path = write_server_properties(row, request.contents)
    return {
        "server_id": server_id,
        "path": str(properties_path),
        "saved": True,
    }


@app.post("/servers/{server_id}/server-properties/view")
async def update_server_properties_view_action(
    request: fastapi.Request,
    server_id: int,
    contents: str = fastapi.Form(...),
    next: str | None = None,
) -> fastapi.Response:
    try:
        await require_csrf(request)
    except CsrfError:
        return csrf_plain_text_response()

    row = get_server_row(server_id)
    write_server_properties(row, contents)

    fallback = f"/servers/{server_id}/view?saved=1"
    redirect_target = resolve_redirect_target(next, fallback)
    redirect_base, has_fragment, redirect_fragment = redirect_target.partition("#")
    separator = "&" if "?" in redirect_base else "?"
    if "saved=" not in redirect_base:
        redirect_base = f"{redirect_base}{separator}saved=1"
    redirect_target = (
        f"{redirect_base}#{redirect_fragment}" if has_fragment else redirect_base
    )

    return RedirectResponse(
        url=redirect_target,
        status_code=303,
    )


@app.get("/servers/{server_id}/files/download")
def download_server_file(server_id: int, path: str) -> FileResponse:
    row = get_server_row(server_id)
    root = get_server_data_root(row)

    try:
        target = resolve_data_path(root, path)
    except ValueError as exc:
        raise fastapi.HTTPException(status_code=404, detail="File not found") from exc

    if not target.exists() or not target.is_file():
        raise fastapi.HTTPException(status_code=404, detail="File not found")

    return FileResponse(path=target, filename=target.name)


@app.get("/servers/{server_id}/world/download")
def download_server_world(server_id: int) -> FileResponse:
    row = get_server_row(server_id)

    try:
        world_dir = get_server_world_directory(row)
    except (FileNotFoundError, ValueError) as exc:
        raise fastapi.HTTPException(
            status_code=404, detail="World folder not found"
        ) from exc

    archive_handle = tempfile.NamedTemporaryFile(
        prefix=f"server-{server_id}-world-",
        suffix=".zip",
        delete=False,
    )
    archive_path = Path(archive_handle.name)
    archive_handle.close()

    try:
        build_world_archive(world_dir, archive_path)
    except Exception:
        remove_file_if_exists(str(archive_path))
        raise

    archive_name = f"{slugify_name(str(row['name']))}-{world_dir.name}.zip"
    return FileResponse(
        path=archive_path,
        filename=archive_name,
        media_type="application/zip",
        background=BackgroundTask(remove_file_if_exists, str(archive_path)),
    )


@app.post("/servers/{server_id}/world/import")
async def import_server_world(
    request: fastapi.Request,
    server_id: int,
    archive: fastapi.UploadFile = fastapi.File(...),
) -> dict[str, object]:
    try:
        await require_csrf(request)
    except CsrfError as exc:
        raise csrf_http_exception() from exc

    row = get_server_row(server_id)
    server = sync_server_row(row)
    if server.status == "running":
        raise fastapi.HTTPException(
            status_code=409, detail="Stop the server before importing a world."
        )

    archive_bytes = archive.file.read()
    archive.file.close()

    try:
        world_dir = import_world_archive(row, archive_bytes)
    except ValueError as exc:
        raise fastapi.HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "server_id": server_id,
        "path": str(world_dir),
        "imported": True,
    }


@app.post("/servers/{server_id}/world/import/view")
async def import_server_world_view_action(
    request: fastapi.Request,
    server_id: int,
    archive: fastapi.UploadFile = fastapi.File(...),
    next: str | None = fastapi.Form(None),
) -> fastapi.Response:
    try:
        await require_csrf(request)
    except CsrfError:
        return csrf_plain_text_response()

    try:
        await import_server_world(request, server_id, archive)
    except fastapi.HTTPException as exc:
        fallback = f"/servers/{server_id}/view?world-import-error={urlencode([('message', str(exc.detail))]).split('=', 1)[1]}#world-transfer"
        redirect_target = resolve_redirect_target(next, fallback)
        redirect_base, has_fragment, redirect_fragment = redirect_target.partition("#")
        separator = "&" if "?" in redirect_base else "?"
        if "world-import-error=" not in redirect_base:
            redirect_base = f"{redirect_base}{separator}{urlencode([('world-import-error', str(exc.detail))])}"
        redirect_target = (
            f"{redirect_base}#{redirect_fragment}" if has_fragment else redirect_base
        )
        return RedirectResponse(url=redirect_target, status_code=303)

    fallback = f"/servers/{server_id}/view?world-imported=1#world-transfer"
    redirect_target = resolve_redirect_target(next, fallback)
    redirect_base, has_fragment, redirect_fragment = redirect_target.partition("#")
    separator = "&" if "?" in redirect_base else "?"
    if "world-imported=" not in redirect_base:
        redirect_base = f"{redirect_base}{separator}world-imported=1"
    redirect_target = (
        f"{redirect_base}#{redirect_fragment}" if has_fragment else redirect_base
    )
    return RedirectResponse(url=redirect_target, status_code=303)


def main() -> None:
    try:
        port = parse_network_port(
            os.environ.get("MCM_WEBUI_PORT"),
            key="MCM_WEBUI_PORT",
            default=DEFAULT_WEBUI_PORT,
        )
    except fastapi.HTTPException as exc:
        raise ValueError(str(exc.detail)) from exc
    uvicorn.run("main:app", host="0.0.0.0", port=port)


def dev() -> None:
    try:
        port = parse_network_port(
            os.environ.get("MCM_WEBUI_PORT"),
            key="MCM_WEBUI_PORT",
            default=DEFAULT_WEBUI_PORT,
        )
    except fastapi.HTTPException as exc:
        raise ValueError(str(exc.detail)) from exc
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)


if __name__ == "__main__":
    main()
