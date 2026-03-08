import sqlite3
from collections.abc import Sequence
from pathlib import Path
from typing import Any


class Database:
    def __init__(self, path: str) -> None:
        self.path = path

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def execute(self, query: str, params: Sequence[Any] = ()) -> int:
        with self._connect() as conn:
            cursor = conn.execute(query, params)
            return cursor.rowcount

    def execute_script(self, script: str) -> None:
        with self._connect() as conn:
            conn.executescript(script)

    def initialize_schema(self, schema_path: str | Path) -> None:
        schema = Path(schema_path).read_text(encoding="utf-8")
        self.execute_script(schema)

    def table_columns(self, table_name: str) -> set[str]:
        with self._connect() as conn:
            cursor = conn.execute(f"PRAGMA table_info({table_name})")
            return {row["name"] for row in cursor.fetchall()}

    def fetch_one(
        self, query: str, params: Sequence[Any] = ()
    ) -> sqlite3.Row | None:
        with self._connect() as conn:
            cursor = conn.execute(query, params)
            return cursor.fetchone()

    def fetch_all(self, query: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        with self._connect() as conn:
            cursor = conn.execute(query, params)
            return cursor.fetchall()
