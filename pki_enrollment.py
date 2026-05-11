import secrets
import sqlite3
from datetime import UTC, datetime

from werkzeug.security import check_password_hash, generate_password_hash

from pki_auth import _get_connection


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def ensure_enrollment_tables(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS enrollment_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            ca_slug TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_used_at TEXT,
            active INTEGER NOT NULL DEFAULT 1
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS enrollment_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_id INTEGER,
            ca_slug TEXT NOT NULL,
            certificate_slug TEXT NOT NULL,
            subject TEXT NOT NULL,
            sans TEXT,
            validity_days INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(token_id) REFERENCES enrollment_tokens(id)
        )
        """
    )


def create_enrollment_token(name: str, ca_slug: str) -> dict[str, object]:
    plain_token = f"pki_{secrets.token_urlsafe(32)}"
    created_at = _utc_now()
    token_hash = generate_password_hash(plain_token)

    with _get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO enrollment_tokens
                (name, ca_slug, token_hash, created_at, last_used_at, active)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (name, ca_slug, token_hash, created_at, None, 1),
        )
        token_id = cursor.lastrowid

    return {
        "id": token_id,
        "name": name,
        "ca_slug": ca_slug,
        "plain_token": plain_token,
        "active": 1,
        "last_used_at": None,
    }


def list_enrollment_tokens() -> list[dict[str, object]]:
    with _get_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, name, ca_slug, created_at, last_used_at, active
            FROM enrollment_tokens
            ORDER BY id
            """
        ).fetchall()
    return [dict(row) for row in rows]


def verify_enrollment_token(plain_token: str) -> dict[str, object] | None:
    with _get_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, name, ca_slug, token_hash, created_at, last_used_at, active
            FROM enrollment_tokens
            WHERE active = 1
            ORDER BY id
            """
        ).fetchall()

        for row in rows:
            if not check_password_hash(row["token_hash"], plain_token):
                continue

            last_used_at = _utc_now()
            conn.execute(
                "UPDATE enrollment_tokens SET last_used_at = ? WHERE id = ?",
                (last_used_at, row["id"]),
            )
            return {
                "id": row["id"],
                "name": row["name"],
                "ca_slug": row["ca_slug"],
                "created_at": row["created_at"],
                "last_used_at": last_used_at,
                "active": row["active"],
            }

    return None


def set_enrollment_token_active(token_id: int, active: bool) -> None:
    with _get_connection() as conn:
        conn.execute(
            "UPDATE enrollment_tokens SET active = ? WHERE id = ?",
            (1 if active else 0, token_id),
        )


def delete_enrollment_token(token_id: int) -> None:
    with _get_connection() as conn:
        conn.execute("DELETE FROM enrollment_tokens WHERE id = ?", (token_id,))


def record_enrollment_audit(
    token_id: int,
    ca_slug: str,
    certificate_slug: str,
    subject: str,
    sans: str | None,
    validity_days: int,
) -> None:
    with _get_connection() as conn:
        conn.execute(
            """
            INSERT INTO enrollment_audit
                (token_id, ca_slug, certificate_slug, subject, sans, validity_days, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                token_id,
                ca_slug,
                certificate_slug,
                subject,
                sans,
                validity_days,
                _utc_now(),
            ),
        )


def list_enrollment_audit() -> list[dict[str, object]]:
    with _get_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, token_id, ca_slug, certificate_slug, subject, sans, validity_days, created_at
            FROM enrollment_audit
            ORDER BY id DESC
            """
        ).fetchall()
    return [dict(row) for row in rows]
