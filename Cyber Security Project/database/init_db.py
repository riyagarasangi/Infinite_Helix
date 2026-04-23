"""
Database initializer for the Smart Retail Store Security Audit project.

Creates a SQLite database `store.db` with a `users` table used by the
Billing Login System (Module 2 - SQL Injection demo).

Run:
    python database/init_db.py
"""

import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), "store.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute(
        """
        CREATE TABLE users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role     TEXT NOT NULL
        )
        """
    )

    # Seed accounts used by the billing login demo.
    # NOTE: Passwords are stored in plain text INTENTIONALLY so that the
    # SQL injection demo is easy to follow for students. A real system
    # must always store salted password hashes.
    seed = [
        ("admin",  "admin123",  "admin"),
        ("cashier", "cash@123", "cashier"),
        ("manager", "mgr2024",  "manager"),
    ]
    cur.executemany(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        seed,
    )

    conn.commit()
    conn.close()
    print(f"[OK] Database created at {DB_PATH}")
    print(f"     Seeded {len(seed)} users: admin / cashier / manager")


if __name__ == "__main__":
    init_db()
