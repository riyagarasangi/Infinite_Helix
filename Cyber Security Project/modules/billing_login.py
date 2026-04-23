"""
Module 2: SQL Injection Attack on Billing Login System.

Exposes two login functions:

    vulnerable_login(username, password)
        Builds a SQL string by concatenation. Vulnerable to:
            username:  admin' OR '1'='1
            password:  anything

    secure_login(username, password)
        Uses parameterized queries (prepared statements). Same payload
        above is safely treated as a literal string.

Both functions return a dict:
    {
        "success": bool,
        "user": {...} or None,
        "query": "the SQL string that was executed",
        "rows": list of matching users,
        "message": human-readable result,
    }
"""

import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "database", "store.db")


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def vulnerable_login(username: str, password: str) -> dict:
    """INSECURE: concatenates user input directly into SQL."""
    conn = _connect()
    cur = conn.cursor()

    # DANGER: this is exactly what students should NEVER do.
    query = (
        f"SELECT id, username, role FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )

    try:
        # executescript would run multiple statements; we keep execute() so
        # the classic `' OR '1'='1` payload is the clearest demonstration.
        cur.execute(query)
        rows = [dict(r) for r in cur.fetchall()]
    except sqlite3.Error as e:
        conn.close()
        return {
            "success": False,
            "user": None,
            "query": query,
            "rows": [],
            "message": f"SQL error: {e}",
        }

    conn.close()
    if rows:
        return {
            "success": True,
            "user": rows[0],
            "query": query,
            "rows": rows,
            "message": (
                f"Login succeeded. {len(rows)} row(s) matched. "
                "If more than 1 row matched, SQL injection likely bypassed auth."
            ),
        }
    return {
        "success": False,
        "user": None,
        "query": query,
        "rows": [],
        "message": "Invalid credentials.",
    }


def secure_login(username: str, password: str) -> dict:
    """SECURE: uses parameterized query."""
    conn = _connect()
    cur = conn.cursor()

    query = "SELECT id, username, role FROM users WHERE username = ? AND password = ?"
    cur.execute(query, (username, password))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    # For display, show the final query WITH the parameters in a safe way
    display_query = (
        f"{query}\n-- params: username={username!r}, password={password!r}"
    )
    if rows:
        return {
            "success": True,
            "user": rows[0],
            "query": display_query,
            "rows": rows,
            "message": "Login succeeded with parameterized query.",
        }
    return {
        "success": False,
        "user": None,
        "query": display_query,
        "rows": [],
        "message": "Invalid credentials. Injection payload was treated as plain text.",
    }
