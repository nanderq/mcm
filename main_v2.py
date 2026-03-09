import sqlite3

from fastapi import FastAPI, WebSocket
from fastapi.responses import HTMLResponse
from database import Database
from pathlib import Path
import os
import json
import docker

from main import DATA_ROOT

def resolve_runtime_path(env_var: str, default: Path) -> Path:
    raw_value = os.environ.get(env_var)
    path = Path(raw_value).expanduser() if raw_value else default
    if not path.is_absolute():
        path = Path.cwd() / path
    return path.resolve()

DATABASE_PATH = resolve_runtime_path("MCM_DATABASE_PATH", DATA_ROOT / "database.db")

app = FastAPI()
db = Database(str(DATABASE_PATH))

def get_server_row(server_id: str) -> sqlite3.Row:
    db.execute("SELECT * FROM servers WHERE id = ?", (server_id,))
    return db.fetchone()

def start_log_stream(container_id: str):
    client = docker.from_env()
    try:
        container = client.containers.get(container_id)
        for log in container.logs(stream=True, follow=True):
            yield log.decode("utf-8")
    except docker.errors.NotFound:
        yield f"Container with ID '{container_id}' not found."

@app.get("/")
async def index():
    return HTMLResponse()



@app.websocket("/ws/{server_id}")
async def get_ws(websocket: WebSocket, server_id: str):
    await websocket.accept()

    server_data = get_server_row(server_id)
    if not server_data:
        await websocket.send_text(json.dumps({
            "type": "error",
            "message": f"Server with ID '{server_id}' not found."
        }))
        await websocket.close()
        return

    await websocket.send_text(json.dumps({
        "type": "server.initial_data",
        "data": dict(server_data)
    }))

    log_stream = start_log_stream(server_data["container_id"])
    async for log in log_stream:
        await websocket.send_text(json.dumps({
            "type": "server.log",
            "data": log
        }))

    while True:
        try:
            raw_data = await websocket.receive_text()
        except Exception:
            break

        try:
            message = json.loads(raw_data)
        except json.JSONDecodeError:
            await websocket.send_text(json.dumps({
                "type": "error",
                "message": "Invalid JSON payload."
            }))
            continue

        message_type = message.get("type")

        if message_type == "server.start":
            if not row:
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "message": f"Server with ID '{server_id}' not found."
                }))
                continue
            container_id = row["container_id"]
            try:
                container = docker.from_env().containers.get(container_id)
                container.start()
                await websocket.send_text(json.dumps({
                    "type": "server.started",
                    "data": dict(row)
                }))
            except docker.errors.NotFound:
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "message": f"Container with ID '{container_id}' not found."
                }))
        elif message_type == "server.stop":
            row = get_server_row(server_id)
            if not row:
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "message": f"Server with ID '{server_id}' not found."
                }))
                continue
            container_id = row["container_id"]
            try:
                container = docker.from_env().containers.get(container_id)
                container.stop()
                await websocket.send_text(json.dumps({
                    "type": "server.stopped",
                    "data": dict(row)
                }))
            except docker.errors.NotFound:
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "message": f"Container with ID '{container_id}' not found."
                }))
        elif message_type == "server.command":
            
        else:
            await websocket.send_text(json.dumps({
                "type": "error",
                "message": f"Unsupported message type: {message_type}"
            }))

    await websocket.close()