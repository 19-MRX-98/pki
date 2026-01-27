import sqlite3
from datetime import datetime

from werkzeug.security import check_password_hash, generate_password_hash

from pki_paths import DATA_DIR

DB_PATH = DATA_DIR / "pki.db"


def _get_connection() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_db() -> None:
    with _get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        row = conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()
        if row and row["count"] == 0:
            _create_user(conn, "admin", "admin")


def _create_user(conn: sqlite3.Connection, username: str, password: str) -> None:
    conn.execute(
        "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
        (username, generate_password_hash(password), datetime.utcnow().isoformat()),
    )


def create_user(username: str, password: str) -> bool:
    if not username or not password:
        return False
    with _get_connection() as conn:
        try:
            _create_user(conn, username, password)
        except sqlite3.IntegrityError:
            return False
    return True


def list_users() -> list[dict[str, str]]:
    with _get_connection() as conn:
        rows = conn.execute("SELECT id, username, created_at FROM users ORDER BY username").fetchall()
    return [dict(row) for row in rows]


def get_user_by_id(user_id: int) -> dict[str, str] | None:
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT id, username, created_at FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    return dict(row) if row else None


def get_user_by_username(username: str) -> dict[str, str] | None:
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT id, username, password_hash, created_at FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    return dict(row) if row else None


def verify_user(username: str, password: str) -> dict[str, str] | None:
    user = get_user_by_username(username)
    if not user:
        return None
    if check_password_hash(user["password_hash"], password):
        return {"id": user["id"], "username": user["username"]}
    return None


def update_password(user_id: int, new_password: str) -> bool:
    if not new_password:
        return False
    with _get_connection() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), user_id),
        )
    return True


def delete_user(user_id: int) -> None:
    with _get_connection() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
