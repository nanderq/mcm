import asyncio
import json
import os
import re
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
import zipfile

import pytest
from fastapi.testclient import TestClient

from auth import reset_login_attempts
import main
from database import Database


def create_server_files(data_dir: Path) -> None:
    (data_dir / "logs").mkdir(parents=True)
    (data_dir / "world" / "region").mkdir(parents=True)
    (data_dir / "empty-dir").mkdir(parents=True)

    (data_dir / "server.properties").write_text("motd=Test Server\npvp=true\n", encoding="utf-8")
    (data_dir / ".rcon-cli.env").write_text("RCON_PASSWORD=test\n", encoding="utf-8")
    (data_dir / "logs" / "latest.log").write_text("[Server] started\n", encoding="utf-8")
    (data_dir / "world" / "region" / "r.0.0.mca").write_bytes(b"\x00\x01binary-region")
    (data_dir / "minecraft_server.1.21.11.jar").write_bytes(b"\x00jar-bytes")


def insert_server_record(database: Database, data_dir: Path, *, server_id: int = 1, port: int = 25565) -> None:
    database.execute(
        """
        INSERT INTO servers (
            id,
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
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            server_id,
            "Survival",
            port,
            "stopped",
            f"test-container-id-{server_id}",
            f"mc-survival-{port}",
            main.MINECRAFT_IMAGE,
            "LATEST",
            "VANILLA",
            str(data_dir),
            60,
            "127.0.0.1",
            25575,
            "secret",
            json.dumps({}),
            json.dumps({}),
            json.dumps(
                {
                    "EULA": "TRUE",
                    "TYPE": "VANILLA",
                    "VERSION": "LATEST",
                    "ENABLE_RCON": "TRUE",
                    "RCON_PASSWORD": "secret",
                    "STOP_DURATION": "60",
                }
            ),
        ),
    )


def build_zip_archive(files: dict[str, bytes]) -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, contents in files.items():
            archive.writestr(path, contents)
    return buffer.getvalue()


def extract_csrf_token(html: str) -> str:
    match = re.search(r'<meta name="csrf-token" content="([^"]+)"', html)
    assert match is not None
    return match.group(1)


def authenticate_client(client: TestClient) -> str:
    response = client.post(
        "/login",
        data={
            "username": os.environ["MCM_AUTH_USERNAME"],
            "password": os.environ["MCM_AUTH_TEST_PASSWORD"],
            "next": "/",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303

    dashboard_response = client.get("/")
    assert dashboard_response.status_code == 200
    return extract_csrf_token(dashboard_response.text)


class FakeContainer:
    def __init__(
        self,
        *,
        container_id: str = "test-container-id-1",
        status: str = "running",
        env: dict[str, str] | None = None,
        exit_code: int = 0,
        output: bytes = b"",
    ) -> None:
        self.id = container_id
        self.status = status
        self.exit_code = exit_code
        self.output = output
        self.last_cmd: list[str] | None = None
        self.attrs = {
            "Config": {
                "Env": [f"{key}={value}" for key, value in (env or {}).items()]
            }
        }

    def reload(self) -> None:
        return None

    def exec_run(self, cmd: list[str]) -> SimpleNamespace:
        self.last_cmd = cmd
        return SimpleNamespace(exit_code=self.exit_code, output=self.output)


class FakeManagedContainer:
    def __init__(self, container_id: str, *, status: str = "exited") -> None:
        self.id = container_id
        self.status = status
        self.attrs = {"Config": {"Env": []}}
        self.started = False
        self.removed = False
        self.renamed_to: str | None = None

    def reload(self) -> None:
        return None

    def rename(self, name: str) -> None:
        self.renamed_to = name

    def remove(self, force: bool = False) -> None:
        self.removed = True

    def start(self) -> None:
        self.started = True
        self.status = "running"


class FakeContainerCollection:
    def __init__(self, containers: dict[str, FakeManagedContainer]) -> None:
        self._containers = containers

    def get(self, container_id: str) -> FakeManagedContainer:
        return self._containers[container_id]


class FakeDockerApi:
    def __init__(self, new_container_id: str) -> None:
        self.new_container_id = new_container_id
        self.last_host_config: dict[str, object] | None = None
        self.last_create_container: dict[str, object] | None = None

    def create_host_config(self, *, binds: dict[str, object], port_bindings: dict[int, int]) -> dict[str, object]:
        self.last_host_config = {
            "binds": binds,
            "port_bindings": port_bindings,
        }
        return {"binds": binds, "port_bindings": port_bindings}

    def create_container(self, **kwargs: object) -> dict[str, str]:
        self.last_create_container = kwargs
        return {"Id": self.new_container_id}


class FakeDockerClient:
    def __init__(self, containers: dict[str, FakeManagedContainer], new_container_id: str) -> None:
        self.containers = FakeContainerCollection(containers)
        self.api = FakeDockerApi(new_container_id)

class FakeRconSocket:
    def __init__(self, command_outputs: dict[str, str] | None = None) -> None:
        self.command_outputs = command_outputs or {}
        self.recv_buffer = bytearray(b"> ")
        self.sent_commands: list[str] = []
        self.closed = False
        self.timeout: float | None = None

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def sendall(self, data: bytes) -> None:
        command = data.decode("utf-8").strip()
        self.sent_commands.append(command)
        response_body = self.command_outputs.get(command, "")
        self.recv_buffer.extend(f"{command}\r\n{response_body}\r\n> ".encode("utf-8"))

    def recv(self, size: int) -> bytes:
        if not self.recv_buffer:
            return b""

        chunk = bytes(self.recv_buffer[:size])
        del self.recv_buffer[:size]
        return chunk

    def close(self) -> None:
        self.closed = True


class FakeRconManager:
    def __init__(self, output: str) -> None:
        self.output = output
        self.calls: list[tuple[int, str, str, int, str, str]] = []

    def execute(
        self,
        server_id: int,
        container_id: str,
        host: str,
        port: int,
        password: str,
        command: str,
    ) -> str:
        self.calls.append((server_id, container_id, host, port, password, command))
        return self.output

    def close_server(self, server_id: int) -> None:
        return None

    def close_all(self) -> None:
        return None


@pytest.fixture()
def server_data_dir(tmp_path: Path) -> Path:
    data_dir = tmp_path / "server-data"
    data_dir.mkdir()
    create_server_files(data_dir)
    return data_dir


@pytest.fixture()
def test_client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, server_data_dir: Path) -> TestClient:
    reset_login_attempts()
    database = Database(str(tmp_path / "test.db"))
    database.initialize_schema(main.SCHEMA_PATH)
    monkeypatch.setattr(main, "db", database)
    insert_server_record(database, server_data_dir)

    monkeypatch.setattr(main, "sync_server_row", lambda row: main.row_to_response(row))
    monkeypatch.setattr(main, "read_server_properties", lambda row: main.read_server_properties_from_host(row) or "")
    monkeypatch.setattr(
        main,
        "server_properties_exists",
        lambda row: main.read_server_properties_from_host(row) is not None,
    )

    with TestClient(main.app) as client:
        client.csrf_token = authenticate_client(client)
        yield client


def test_normalize_browser_path_handles_root_and_backslashes() -> None:
    assert main.normalize_browser_path(None) == ""
    assert main.normalize_browser_path(r"logs\latest.log") == "logs/latest.log"
    assert main.normalize_browser_path("./logs/../server.properties") == "server.properties"


def test_resolve_data_path_rejects_traversal(server_data_dir: Path) -> None:
    with pytest.raises(ValueError):
        main.resolve_data_path(server_data_dir, "../server.properties")


def test_resolve_data_path_rejects_absolute_paths(server_data_dir: Path) -> None:
    with pytest.raises(ValueError):
        main.resolve_data_path(server_data_dir, "/server.properties")


def test_resolve_data_path_rejects_symlink_escape(server_data_dir: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")
    symlink = server_data_dir / "escape-link"

    try:
        symlink.symlink_to(outside)
    except (NotImplementedError, OSError):
        pytest.skip("Symlinks are not available in this environment.")

    with pytest.raises(ValueError):
        main.resolve_data_path(server_data_dir, "escape-link")


def test_list_directory_entries_includes_dotfiles_and_sorts_directories_first(server_data_dir: Path) -> None:
    entries = main.list_directory_entries(server_data_dir, server_data_dir)
    names = [entry["name"] for entry in entries]

    assert ".rcon-cli.env" in names
    assert names[:3] == ["empty-dir", "logs", "world"]


def test_read_preview_file_returns_text_and_truncation(tmp_path: Path) -> None:
    preview_file = tmp_path / "large.txt"
    preview_file.write_text("a" * (main.MAX_FILE_PREVIEW_BYTES + 32), encoding="utf-8")

    preview = main.read_preview_file(preview_file)

    assert preview["is_text"] is True
    assert preview["truncated"] is True
    assert len(str(preview["contents"])) == main.MAX_FILE_PREVIEW_BYTES


def test_read_preview_file_marks_binary_files(tmp_path: Path) -> None:
    preview_file = tmp_path / "binary.dat"
    preview_file.write_bytes(b"\x00\x01binary")

    preview = main.read_preview_file(preview_file)

    assert preview["is_text"] is False
    assert preview["contents"] == ""


def test_get_next_available_port_returns_first_gap() -> None:
    assert main.get_next_available_port([25565, 25566, 25568]) == 25567


def test_get_next_available_port_returns_default_when_unused() -> None:
    assert main.get_next_available_port([25564, 25570]) == main.MINECRAFT_PORT


def test_build_container_environment_uses_selected_ram_allocation() -> None:
    request = main.ServerCreateRequest(
        name="Survival",
        ram_allocation=4,
        data_dir="server-data",
        environment={
            "MEMORY": "2G",
            "DIFFICULTY": "hard",
        },
    )

    environment = main.build_container_environment(request)

    assert environment["MEMORY"] == main.get_minecraft_jvm_memory(4)
    assert environment["DIFFICULTY"] == "hard"


def test_add_server_sets_selected_container_memory_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = Database(str(tmp_path / "provision-test.db"))
    database.initialize_schema(main.SCHEMA_PATH)
    monkeypatch.setattr(main, "db", database)
    monkeypatch.setattr(main, "ensure_image_available", lambda image: None)
    monkeypatch.setattr(main, "container_exists", lambda name: False)
    monkeypatch.setattr(main, "sync_server_row", lambda row: main.row_to_response(row))

    host_config_calls: list[dict[str, object]] = []
    container_calls: list[dict[str, object]] = []

    class FakeProvisionedContainer:
        def __init__(self, container_id: str) -> None:
            self.id = container_id
            self.started = False

        def start(self) -> None:
            self.started = True

    fake_container = FakeProvisionedContainer("test-container-id")

    class FakeApi:
        def create_host_config(self, **kwargs: object) -> dict[str, object]:
            host_config_calls.append(kwargs)
            return {"mock": "host-config"}

        def create_container(self, **kwargs: object) -> dict[str, str]:
            container_calls.append(kwargs)
            return {"Id": fake_container.id}

    class FakeContainers:
        def get(self, identifier: str) -> FakeProvisionedContainer:
            if identifier == fake_container.id:
                return fake_container
            raise AssertionError(f"Unexpected container lookup: {identifier}")

    class FakeClient:
        def __init__(self) -> None:
            self.api = FakeApi()
            self.containers = FakeContainers()

    monkeypatch.setattr(main, "client", FakeClient())

    request = main.ServerCreateRequest(
        name="Survival",
        port=25565,
        ram_allocation=4,
        data_dir=str(tmp_path / "server-data"),
    )

    response = main.add_server("Survival", 25565, "running", request)

    assert host_config_calls == [
        {
            "binds": {str((tmp_path / "server-data").resolve()): {"bind": "/data", "mode": "rw"}},
            "port_bindings": {main.MINECRAFT_PORT: 25565},
            "mem_limit": main.get_container_memory_limit_bytes(4),
        }
    ]
    assert container_calls[0]["environment"]["MEMORY"] == main.get_minecraft_jvm_memory(4)
    assert fake_container.started is True
    assert response.environment["MEMORY"] == main.get_minecraft_jvm_memory(4)


def test_dashboard_uses_next_available_port_in_page_data(
    test_client: TestClient,
    server_data_dir: Path,
) -> None:
    insert_server_record(main.db, server_data_dir, server_id=2, port=25566)

    response = test_client.get("/")

    assert response.status_code == 200
    assert '"default_port": 25567' in response.text
    assert f'"default_ram_allocation": {main.DEFAULT_RAM_ALLOCATION}' in response.text
    assert f'"ram_allocation_options": {json.dumps(list(main.RAM_ALLOCATION_OPTIONS))}' in response.text


def test_pages_render_route_specific_titles(test_client: TestClient) -> None:
    dashboard_response = test_client.get("/")
    detail_response = test_client.get("/servers/1/view")

    assert dashboard_response.status_code == 200
    assert "<title>MCM - home</title>" in dashboard_response.text
    assert detail_response.status_code == 200
    assert "<title>MCM - Survival</title>" in detail_response.text


def test_favicon_route_serves_svg(test_client: TestClient) -> None:
    response = test_client.get("/favicon.svg")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/svg+xml")
    assert "<svg" in response.text
    assert 'viewBox="0 0 16 16"' in response.text


def test_pages_link_to_favicon(test_client: TestClient) -> None:
    expected_link = '<link rel="icon" href="/favicon.svg" type="image/svg+xml">'

    dashboard_response = test_client.get("/")
    detail_response = test_client.get("/servers/1/view")

    assert dashboard_response.status_code == 200
    assert expected_link in dashboard_response.text
    assert detail_response.status_code == 200
    assert expected_link in detail_response.text


def test_pages_render_delete_actions(test_client: TestClient) -> None:
    dashboard_response = test_client.get("/")
    detail_response = test_client.get("/servers/1/view")

    assert dashboard_response.status_code == 200
    assert '/servers/1/delete/view?next=/' in dashboard_response.text
    assert "data-confirm-form" in dashboard_response.text
    assert "Critical action" in dashboard_response.text
    assert "This removes the container, database record, and all files in" in dashboard_response.text
    assert detail_response.status_code == 200
    assert '/servers/1/delete/view?next=/' in detail_response.text
    assert "data-confirm-form" in detail_response.text
    assert "Critical action" in detail_response.text
    assert "This removes the container, database record, and all files in" in detail_response.text


def test_server_detail_page_renders_root_browser_state(test_client: TestClient) -> None:
    response = test_client.get("/servers/1/view")

    assert response.status_code == 200
    assert "Browsing `/data` from the container bind mount." in response.text
    assert "Breadcrumb" in response.text
    assert "Data files" in response.text
    assert ".rcon-cli.env" in response.text
    assert "Select a file to preview it here." in response.text


def test_server_detail_page_renders_environment_quick_edit(test_client: TestClient) -> None:
    response = test_client.get("/servers/1/view")

    assert response.status_code == 200
    assert "Quick edit" in response.text
    assert 'data-environment-url="/servers/1/environment"' in response.text
    assert "Save changes" in response.text


def test_server_detail_page_renders_selected_file_preview(test_client: TestClient) -> None:
    response = test_client.get(
        "/servers/1/view",
        params={"browse": "logs", "file": "logs/latest.log"},
    )

    assert response.status_code == 200
    assert "[Server] started" in response.text
    assert "latest.log" in response.text
    assert "Download" in response.text
    assert "#data-files" in response.text


def test_server_detail_page_handles_invalid_browse_without_500(test_client: TestClient) -> None:
    response = test_client.get("/servers/1/view", params={"browse": "../escape"})

    assert response.status_code == 200
    assert "Unable to open that folder. Showing /data instead." in response.text


def test_download_server_file_returns_file_contents(test_client: TestClient) -> None:
    response = test_client.get("/servers/1/files/download", params={"path": "server.properties"})

    assert response.status_code == 200
    assert "attachment; filename=\"server.properties\"" in response.headers["content-disposition"]
    assert b"motd=Test Server" in response.content


def test_download_server_file_rejects_invalid_paths(test_client: TestClient) -> None:
    response = test_client.get("/servers/1/files/download", params={"path": "../server.properties"})

    assert response.status_code == 404


def test_download_server_world_returns_zip_contents(test_client: TestClient) -> None:
    response = test_client.get("/servers/1/world/download")

    assert response.status_code == 200
    assert "attachment; filename=\"survival-world.zip\"" in response.headers["content-disposition"]

    archive = zipfile.ZipFile(BytesIO(response.content))
    assert "world/region/r.0.0.mca" in archive.namelist()
    assert archive.read("world/region/r.0.0.mca") == b"\x00\x01binary-region"


def test_download_server_world_uses_custom_level_name(
    test_client: TestClient,
    server_data_dir: Path,
) -> None:
    custom_world = server_data_dir / "adventure" / "region"
    custom_world.mkdir(parents=True)
    (custom_world / "r.1.1.mca").write_bytes(b"custom-world")
    (server_data_dir / "server.properties").write_text("level-name=adventure\n", encoding="utf-8")

    response = test_client.get("/servers/1/world/download")

    assert response.status_code == 200
    archive = zipfile.ZipFile(BytesIO(response.content))
    assert "adventure/region/r.1.1.mca" in archive.namelist()
    assert archive.read("adventure/region/r.1.1.mca") == b"custom-world"


def test_import_server_world_replaces_existing_world(
    test_client: TestClient,
    server_data_dir: Path,
) -> None:
    (server_data_dir / "world" / "obsolete.txt").write_text("remove-me\n", encoding="utf-8")
    archive_bytes = build_zip_archive(
        {
            "uploaded-world/level.dat": b"new-level",
            "uploaded-world/region/r.0.0.mca": b"new-region",
        }
    )

    response = test_client.post(
        "/servers/1/world/import",
        data={"csrf_token": test_client.csrf_token},
        files={"archive": ("world.zip", archive_bytes, "application/zip")},
    )

    assert response.status_code == 200
    assert response.json()["imported"] is True
    assert (server_data_dir / "world" / "level.dat").read_bytes() == b"new-level"
    assert (server_data_dir / "world" / "region" / "r.0.0.mca").read_bytes() == b"new-region"
    assert not (server_data_dir / "world" / "obsolete.txt").exists()


def test_import_server_world_view_redirects_with_success_state(test_client: TestClient) -> None:
    archive_bytes = build_zip_archive({"world/level.dat": b"ok"})

    response = test_client.post(
        "/servers/1/world/import/view",
        data={"csrf_token": test_client.csrf_token, "next": "/servers/1/view#world-transfer"},
        files={"archive": ("world.zip", archive_bytes, "application/zip")},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/servers/1/view?world-imported=1#world-transfer"


def test_import_server_world_requires_stopped_server(test_client: TestClient) -> None:
    main.db.execute("UPDATE servers SET status = ? WHERE id = ?", ("running", 1))
    archive_bytes = build_zip_archive({"world/level.dat": b"blocked"})

    response = test_client.post(
        "/servers/1/world/import",
        data={"csrf_token": test_client.csrf_token},
        files={"archive": ("world.zip", archive_bytes, "application/zip")},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "Stop the server before importing a world."


def test_import_server_world_rejects_invalid_archives(test_client: TestClient) -> None:
    response = test_client.post(
        "/servers/1/world/import",
        data={"csrf_token": test_client.csrf_token},
        files={"archive": ("broken.zip", b"not-a-zip", "application/zip")},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Upload a valid zip archive."


def test_delete_server_endpoint_removes_container_data_and_record(
    test_client: TestClient,
    server_data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    container = FakeManagedContainer("test-container-id-1", status="running")
    fake_client = FakeDockerClient({"test-container-id-1": container}, new_container_id="unused")
    closed_servers: list[int] = []

    class TrackingRconManager:
        def close_server(self, server_id: int) -> None:
            closed_servers.append(server_id)

        def close_all(self) -> None:
            return None

    monkeypatch.setattr(main, "client", fake_client)
    monkeypatch.setattr(main, "rcon_connection_manager", TrackingRconManager())

    response = test_client.delete(
        "/servers/1",
        headers={"X-CSRF-Token": test_client.csrf_token},
    )

    assert response.status_code == 204
    assert response.content == b""
    assert container.removed is True
    assert closed_servers == [1]
    assert not server_data_dir.exists()
    assert main.db.fetch_one("SELECT * FROM servers WHERE id = ?", (1,)) is None


def test_delete_server_view_redirects_to_dashboard(
    test_client: TestClient,
    server_data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    container = FakeManagedContainer("test-container-id-1", status="exited")
    fake_client = FakeDockerClient({"test-container-id-1": container}, new_container_id="unused")
    monkeypatch.setattr(main, "client", fake_client)
    monkeypatch.setattr(
        main,
        "rcon_connection_manager",
        SimpleNamespace(close_server=lambda server_id: None, close_all=lambda: None),
    )

    response = test_client.post(
        "/servers/1/delete/view",
        params={"next": "/"},
        data={"csrf_token": test_client.csrf_token},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert container.removed is True
    assert not server_data_dir.exists()
    assert main.db.fetch_one("SELECT * FROM servers WHERE id = ?", (1,)) is None


def test_server_properties_save_redirect_preserves_browser_state(test_client: TestClient) -> None:
    next_url = "/servers/1/view?browse=logs&file=logs/latest.log#data-files"
    response = test_client.post(
        "/servers/1/server-properties/view",
        params={"next": next_url},
        data={"csrf_token": test_client.csrf_token, "contents": "motd=Updated\n"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/servers/1/view?browse=logs&file=logs/latest.log&saved=1#data-files"


def test_update_server_environment_endpoint_recreates_container_and_updates_server(
    test_client: TestClient,
    server_data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_container = FakeManagedContainer("test-container-id-1", status="exited")
    new_container = FakeManagedContainer("new-container-id", status="exited")
    fake_client = FakeDockerClient(
        {
            "test-container-id-1": old_container,
            "new-container-id": new_container,
        },
        new_container_id="new-container-id",
    )
    monkeypatch.setattr(main, "client", fake_client)

    response = test_client.put(
        "/servers/1/environment",
        headers={"X-CSRF-Token": test_client.csrf_token},
        json={
            "environment": {
                "VERSION": "1.21.4",
                "STOP_DURATION": "120",
                "RCON_PASSWORD": "rotated-secret",
            }
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["saved"] is True
    assert payload["restarted"] is False
    assert payload["server"]["container_id"] == "new-container-id"
    assert payload["server"]["version"] == "1.21.4"
    assert payload["server"]["stop_duration"] == 120
    assert payload["server"]["rcon_password"] == "rotated-secret"

    row = main.db.fetch_one("SELECT * FROM servers WHERE id = ?", (1,))
    assert row is not None
    assert row["container_id"] == "new-container-id"
    assert row["version"] == "1.21.4"
    assert row["stop_duration"] == 120
    assert row["rcon_password"] == "rotated-secret"
    assert json.loads(str(row["environment"]))["STOP_DURATION"] == "120"

    assert old_container.renamed_to is not None
    assert old_container.removed is True
    assert fake_client.api.last_create_container is not None
    assert fake_client.api.last_create_container["environment"]["VERSION"] == "1.21.4"
    assert fake_client.api.last_create_container["stop_timeout"] == 120
    assert fake_client.api.last_host_config is not None
    assert str(server_data_dir) in fake_client.api.last_host_config["binds"]


def test_update_server_environment_view_redirects_with_saved_state(
    test_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        main,
        "update_server_environment",
        lambda server_id, updates: (main.row_to_response(main.get_server_row(server_id)), False),
    )

    response = test_client.post(
        "/servers/1/environment/view",
        data={
            "csrf_token": test_client.csrf_token,
            "next": "/servers/1/view?browse=logs#environment",
            "environment__EULA": "TRUE",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/servers/1/view?browse=logs&env-saved=1#environment"


def test_get_server_logs_endpoint_returns_latest_log_contents(test_client: TestClient) -> None:
    response = test_client.get("/servers/1/logs")

    assert response.status_code == 200
    assert response.json()["exists"] is True
    assert response.json()["contents"].replace("\r\n", "\n") == "[Server] started\n"


def test_server_logs_stream_emits_initial_snapshot(
    server_data_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = Database(str(tmp_path / "stream-test.db"))
    database.initialize_schema(main.SCHEMA_PATH)
    insert_server_record(database, server_data_dir)
    monkeypatch.setattr(main, "db", database)
    monkeypatch.setattr(main, "sync_server_row", lambda row: main.row_to_response(row))

    class FakeRequest:
        def __init__(self) -> None:
            self.calls = 0

        async def is_disconnected(self) -> bool:
            self.calls += 1
            return self.calls > 1

    async def read_first_message() -> str:
        generator = main.stream_server_logs(FakeRequest(), 1)
        return await anext(generator)

    first_chunk = asyncio.run(read_first_message())

    assert "data:" in first_chunk
    assert "\"exists\":true" in first_chunk
    assert "[Server] started" in first_chunk


def test_execute_server_command_uses_container_rcon_env(server_data_dir: Path, tmp_path: Path) -> None:
    database = Database(str(tmp_path / "command-test.db"))
    database.initialize_schema(main.SCHEMA_PATH)
    insert_server_record(database, server_data_dir)
    row = database.fetch_one("SELECT * FROM servers WHERE id = 1")
    assert row is not None

    container = FakeContainer(
        env={
            "ENABLE_RCON": "TRUE",
            "RCON_HOST": "mc-rcon",
            "RCON_PORT": "25576",
            "RCON_PASSWORD": "from-container",
        },
        output=b"Executed",
    )
    fake_socket = FakeRconSocket({"say hello world": "Executed"})
    exec_create_calls: list[tuple[str, list[str]]] = []
    exec_start_calls: list[tuple[str, bool, bool]] = []

    original_get_container = main.get_container_or_none
    original_manager = main.rcon_connection_manager
    try:
        main.get_container_or_none = lambda _: container
        main.rcon_connection_manager = main.PersistentRconConnectionManager()
        original_exec_create = main.client.api.exec_create
        original_exec_start = main.client.api.exec_start
        try:
            def fake_exec_create(
                container_id: str,
                cmd: list[str],
                stdout: bool = True,
                stderr: bool = True,
                stdin: bool = False,
                tty: bool = False,
                **_kwargs: object,
            ) -> dict[str, str]:
                exec_create_calls.append((container_id, cmd))
                assert stdout is True
                assert stderr is True
                assert stdin is True
                assert tty is True
                return {"Id": "exec-1"}

            def fake_exec_start(exec_id: str, tty: bool = False, socket: bool = False, **_kwargs: object) -> FakeRconSocket:
                exec_start_calls.append((exec_id, tty, socket))
                return fake_socket

            main.client.api.exec_create = fake_exec_create
            main.client.api.exec_start = fake_exec_start
            first_output = main.execute_server_command(row, "say hello world")
            second_output = main.execute_server_command(row, "say hello world")
        finally:
            main.client.api.exec_create = original_exec_create
            main.client.api.exec_start = original_exec_start
    finally:
        main.get_container_or_none = original_get_container
        main.rcon_connection_manager = original_manager

    assert first_output == "Executed"
    assert second_output == "Executed"
    assert exec_create_calls == [
        (
            "test-container-id-1",
            [
                "rcon-cli",
                "--host",
                "mc-rcon",
                "--port",
                "25576",
                "--password",
                "from-container",
            ],
        )
    ]
    assert exec_start_calls == [("exec-1", True, True)]
    assert fake_socket.sent_commands == [
        "say hello world",
        "say hello world",
    ]


def test_execute_server_command_endpoint_returns_output(
    test_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    container = FakeContainer(
        env={
            "ENABLE_RCON": "TRUE",
            "RCON_PASSWORD": "secret",
        },
    )
    monkeypatch.setattr(main, "get_container_or_none", lambda row: container)
    manager = FakeRconManager("There are 0 of a max of 20 players online")
    monkeypatch.setattr(main, "rcon_connection_manager", manager)

    response = test_client.post(
        "/servers/1/commands",
        headers={"X-CSRF-Token": test_client.csrf_token},
        json={"command": "list"},
    )

    assert response.status_code == 200
    assert response.json()["command"] == "list"
    assert response.json()["output"] == "There are 0 of a max of 20 players online"
    assert manager.calls == [
        (1, "test-container-id-1", "127.0.0.1", 25575, "secret", "list")
    ]
