import json
import os
import re
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

from auth import COOKIE_NAME, reset_login_attempts
import main
from database import Database


def create_server_files(data_dir: Path) -> None:
    (data_dir / "logs").mkdir(parents=True)
    (data_dir / "world").mkdir(parents=True)
    (data_dir / "server.properties").write_text("motd=Test Server\n", encoding="utf-8")
    (data_dir / "logs" / "latest.log").write_text("[Server] started\n", encoding="utf-8")


def insert_server_record(database: Database, data_dir: Path, *, server_id: int = 1) -> None:
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
            25565,
            "stopped",
            f"test-container-id-{server_id}",
            "mc-survival-25565",
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
            json.dumps({"RCON_PASSWORD": "secret"}),
        ),
    )


def extract_csrf_token(html: str) -> str:
    match = re.search(r'<meta name="csrf-token" content="([^"]+)"', html)
    assert match is not None
    return match.group(1)


def login(client: TestClient, *, password: str | None = None, next_path: str = "/") -> TestClient:
    response = client.post(
        "/login",
        data={
            "username": os.environ["MCM_AUTH_USERNAME"],
            "password": password or os.environ["MCM_AUTH_TEST_PASSWORD"],
            "next": next_path,
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    return client


@pytest.fixture()
def server_data_dir(tmp_path: Path) -> Path:
    data_dir = tmp_path / "server-data"
    data_dir.mkdir()
    create_server_files(data_dir)
    return data_dir


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, server_data_dir: Path) -> TestClient:
    reset_login_attempts()
    database = Database(str(tmp_path / "auth-test.db"))
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

    with TestClient(main.app) as test_client:
        yield test_client


def test_unauthenticated_dashboard_redirects_to_login(client: TestClient) -> None:
    response = client.get("/", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login?next=%2F"


def test_unauthenticated_server_view_redirects_to_login(client: TestClient) -> None:
    response = client.get("/servers/1/view?browse=logs", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login?next=%2Fservers%2F1%2Fview%3Fbrowse%3Dlogs"


def test_unauthenticated_json_route_returns_401(client: TestClient) -> None:
    response = client.post("/servers", json={"name": "Survival", "port": 25566})

    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required"


def test_unauthenticated_sse_route_returns_401(client: TestClient) -> None:
    response = client.get("/servers/1/logs/stream")

    assert response.status_code == 401
    assert response.text == "Authentication required"


def test_fastapi_docs_are_disabled(client: TestClient) -> None:
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_valid_login_sets_session_cookie_and_redirects(client: TestClient) -> None:
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
    assert response.headers["location"] == "/"
    assert COOKIE_NAME in response.headers.get("set-cookie", "")


def test_invalid_login_shows_generic_error_and_does_not_authenticate(client: TestClient) -> None:
    response = client.post(
        "/login",
        data={
            "username": os.environ["MCM_AUTH_USERNAME"],
            "password": "wrong-password",
            "next": "/",
        },
    )

    assert response.status_code == 200
    assert "Invalid credentials" in response.text

    follow_up = client.get("/", follow_redirects=False)
    assert follow_up.status_code == 303
    assert follow_up.headers["location"] == "/login?next=%2F"


def test_logout_clears_session(client: TestClient) -> None:
    login(client)
    csrf_token = extract_csrf_token(client.get("/").text)

    response = client.post(
        "/logout",
        data={"csrf_token": csrf_token},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/login"

    follow_up = client.get("/", follow_redirects=False)
    assert follow_up.status_code == 303


def test_authenticated_session_can_access_pages_and_json(client: TestClient) -> None:
    login(client)

    page_response = client.get("/")
    json_response = client.get("/servers")

    assert page_response.status_code == 200
    assert json_response.status_code == 200
    assert json_response.json()[0]["name"] == "Survival"


def test_session_is_invalidated_when_password_hash_changes(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    login(client)
    monkeypatch.setenv("MCM_AUTH_PASSWORD_HASH", PasswordHasher().hash("rotated-password"))

    response = client.get("/", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login?next=%2F"


def test_mutating_form_route_requires_csrf(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    login(client)
    monkeypatch.setattr(main, "start_server", lambda server_id: main.row_to_response(main.get_server_row(server_id)))

    response = client.post(
        "/servers/1/start/view",
        data={"next": "/servers/1/view"},
        follow_redirects=False,
    )

    assert response.status_code == 403
    assert response.text == "Invalid CSRF token"


def test_mutating_json_route_requires_csrf(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    login(client)
    monkeypatch.setattr(main, "start_server", lambda server_id: main.row_to_response(main.get_server_row(server_id)))

    response = client.post("/servers/1/start")

    assert response.status_code == 403
    assert response.json()["detail"] == "Invalid CSRF token"


def test_mutating_json_route_accepts_valid_csrf(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    login(client)
    csrf_token = extract_csrf_token(client.get("/").text)
    monkeypatch.setattr(main, "start_server", lambda server_id: main.row_to_response(main.get_server_row(server_id)))

    response = client.post(
        "/servers/1/start",
        headers={"X-CSRF-Token": csrf_token},
    )

    assert response.status_code == 200
    assert response.json()["id"] == 1


def test_failed_login_rate_limit_triggers_on_sixth_attempt(client: TestClient) -> None:
    for _ in range(5):
        response = client.post(
            "/login",
            data={
                "username": os.environ["MCM_AUTH_USERNAME"],
                "password": "wrong-password",
                "next": "/",
            },
        )
        assert response.status_code == 200

    rate_limited = client.post(
        "/login",
        data={
            "username": os.environ["MCM_AUTH_USERNAME"],
            "password": "wrong-password",
            "next": "/",
        },
    )

    assert rate_limited.status_code == 429
    assert "Retry-After" in rate_limited.headers
    assert "Too many login attempts" in rate_limited.text
