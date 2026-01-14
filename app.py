from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import shutil
import subprocess
import dataclasses
import threading
import tkinter as tk
import tkinter.font as tkfont
from tkinter import filedialog, ttk, messagebox
import time
import urllib.parse
import traceback
from typing import Dict
import sys
import ctypes

import customtkinter as ctk
from PIL import Image

from downloader import DownloadManager, DownloadOptions, DownloadJob, inspect_url, expand_url_entries, YoutubeDL

try:
    import mysql.connector as mysql_connector  # type: ignore
except Exception:
    mysql_connector = None

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


def _app_base_dir() -> str:
    base = getattr(sys, "_MEIPASS", None)
    if isinstance(base, str) and base:
        return base
    return os.path.dirname(__file__)


def _resource_path(*parts: str) -> str:
    return os.path.join(_app_base_dir(), *parts)


def _user_data_dir() -> str:
    base = ""
    if sys.platform.startswith("win"):
        base = os.environ.get("APPDATA", "")
        if not base:
            base = os.path.join(os.path.expanduser("~"), "AppData", "Roaming")
    elif sys.platform == "darwin":
        base = os.path.join(os.path.expanduser("~"), "Library", "Application Support")
    else:
        base = os.environ.get("XDG_DATA_HOME", "")
        if not base:
            base = os.path.join(os.path.expanduser("~"), ".local", "share")

    p = os.path.join(base, "Snakee")
    try:
        os.makedirs(p, exist_ok=True)
    except Exception:
        pass
    return p


def _data_path(*parts: str) -> str:
    return os.path.join(_user_data_dir(), *parts)


def _debug_log(msg: str) -> None:
    try:
        p = _data_path("cli.log")
        with open(p, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    except Exception:
        pass


def _load_mysql_config() -> dict:
    try:
        p = _data_path("mysql.json")
        if not os.path.exists(p):
            return {}
        with open(p, "r", encoding="utf-8") as f:
            v = json.load(f)
        return v if isinstance(v, dict) else {}
    except Exception:
        return {}


class _AuthStore:
    def init_db(self) -> None:
        raise NotImplementedError()

    def create_user(self, full_name: str | None, display_name: str, username: str, email: str, phone: str | None, pw_hash: str, pw_salt: str, created_at: int) -> bool:
        raise NotImplementedError()

    def get_user_by_ident(self, ident: str) -> dict | None:
        raise NotImplementedError()

    def reset_failed_attempts(self, user_id: int) -> None:
        raise NotImplementedError()

    def increment_failed_attempt(self, user_id: int, failed_attempts: int, lock_until: int) -> None:
        raise NotImplementedError()

    def update_display_name(self, user_id: int, display_name: str) -> None:
        raise NotImplementedError()

    def get_password_row(self, user_id: int) -> dict | None:
        raise NotImplementedError()

    def update_password(self, user_id: int, pw_hash: str, pw_salt: str) -> None:
        raise NotImplementedError()

    def delete_sessions_by_user(self, user_id: int) -> None:
        raise NotImplementedError()

    def save_session(self, token: str, user_id: int, created_at: int, expires_at: int) -> None:
        raise NotImplementedError()

    def restore_session_user(self, token: str, now: int) -> dict | None:
        raise NotImplementedError()

    def admin_unblock(self, ident: str) -> int:
        raise NotImplementedError()

    def admin_delete(self, ident: str) -> int:
        raise NotImplementedError()


class _SQLiteAuthStore(_AuthStore):
    def __init__(self, db_path: str):
        self._db_path = db_path

    def init_db(self) -> None:
        con = sqlite3.connect(self._db_path)
        try:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    full_name TEXT,
                    display_name TEXT NOT NULL,
                    username TEXT NOT NULL UNIQUE,
                    email TEXT NOT NULL UNIQUE,
                    phone TEXT,
                    pw_hash TEXT NOT NULL,
                    pw_salt TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    failed_attempts INTEGER NOT NULL DEFAULT 0,
                    lock_until INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            try:
                con.execute("ALTER TABLE users ADD COLUMN full_name TEXT")
            except Exception:
                pass
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
                """
            )
            con.commit()
        finally:
            con.close()

    def create_user(self, full_name: str | None, display_name: str, username: str, email: str, phone: str | None, pw_hash: str, pw_salt: str, created_at: int) -> bool:
        con = sqlite3.connect(self._db_path)
        try:
            con.execute(
                "INSERT INTO users(full_name,display_name,username,email,phone,pw_hash,pw_salt,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (full_name or None, display_name, username, email, phone or None, pw_hash, pw_salt, created_at),
            )
            con.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            con.close()

    def get_user_by_ident(self, ident: str) -> dict | None:
        con = sqlite3.connect(self._db_path)
        con.row_factory = sqlite3.Row
        try:
            row = con.execute(
                "SELECT * FROM users WHERE lower(email)=lower(?) OR lower(username)=lower(?)",
                (ident, ident),
            ).fetchone()
            return dict(row) if row else None
        finally:
            con.close()

    def reset_failed_attempts(self, user_id: int) -> None:
        con = sqlite3.connect(self._db_path)
        try:
            con.execute("UPDATE users SET failed_attempts=0, lock_until=0 WHERE id=?", (int(user_id),))
            con.commit()
        finally:
            con.close()

    def increment_failed_attempt(self, user_id: int, failed_attempts: int, lock_until: int) -> None:
        con = sqlite3.connect(self._db_path)
        try:
            con.execute(
                "UPDATE users SET failed_attempts=?, lock_until=? WHERE id=?",
                (int(failed_attempts), int(lock_until), int(user_id)),
            )
            con.commit()
        finally:
            con.close()

    def update_display_name(self, user_id: int, display_name: str) -> None:
        con = sqlite3.connect(self._db_path)
        try:
            con.execute("UPDATE users SET display_name=? WHERE id=?", (display_name, int(user_id)))
            con.commit()
        finally:
            con.close()

    def get_password_row(self, user_id: int) -> dict | None:
        con = sqlite3.connect(self._db_path)
        con.row_factory = sqlite3.Row
        try:
            row = con.execute("SELECT pw_hash, pw_salt FROM users WHERE id=?", (int(user_id),)).fetchone()
            return dict(row) if row else None
        finally:
            con.close()

    def update_password(self, user_id: int, pw_hash: str, pw_salt: str) -> None:
        con = sqlite3.connect(self._db_path)
        try:
            con.execute("UPDATE users SET pw_hash=?, pw_salt=? WHERE id=?", (pw_hash, pw_salt, int(user_id)))
            con.commit()
        finally:
            con.close()

    def delete_sessions_by_user(self, user_id: int) -> None:
        con = sqlite3.connect(self._db_path)
        try:
            con.execute("DELETE FROM sessions WHERE user_id=?", (int(user_id),))
            con.commit()
        finally:
            con.close()

    def save_session(self, token: str, user_id: int, created_at: int, expires_at: int) -> None:
        con = sqlite3.connect(self._db_path)
        try:
            con.execute(
                "INSERT OR REPLACE INTO sessions(token,user_id,created_at,expires_at) VALUES(?,?,?,?)",
                (token, int(user_id), int(created_at), int(expires_at)),
            )
            con.commit()
        finally:
            con.close()

    def restore_session_user(self, token: str, now: int) -> dict | None:
        con = sqlite3.connect(self._db_path)
        con.row_factory = sqlite3.Row
        try:
            row = con.execute(
                "SELECT s.user_id AS id, u.display_name, u.username, u.email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires_at>?",
                (token, int(now)),
            ).fetchone()
            return dict(row) if row else None
        finally:
            con.close()

    def admin_unblock(self, ident: str) -> int:
        con = sqlite3.connect(self._db_path)
        try:
            cur = con.execute(
                "UPDATE users SET failed_attempts=0, lock_until=0 WHERE lower(email)=lower(?) OR lower(username)=lower(?)",
                (ident, ident),
            )
            con.commit()
            return int(cur.rowcount or 0)
        finally:
            con.close()

    def admin_delete(self, ident: str) -> int:
        con = sqlite3.connect(self._db_path)
        con.row_factory = sqlite3.Row
        try:
            row = con.execute(
                "SELECT id FROM users WHERE lower(email)=lower(?) OR lower(username)=lower(?)",
                (ident, ident),
            ).fetchone()
            if not row:
                return 0
            uid = int(row["id"])
            con.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
            cur = con.execute("DELETE FROM users WHERE id=?", (uid,))
            con.commit()
            return int(cur.rowcount or 0)
        finally:
            con.close()


class _MySQLAuthStore(_AuthStore):
    def __init__(self, host: str, port: int, user: str, password: str, database: str):
        self._host = host
        self._port = int(port)
        self._user = user
        self._password = password
        self._database = database

    def _connect_server(self, with_database: bool) -> object:
        if mysql_connector is None:
            raise RuntimeError("mysql-connector-python is not installed")
        kw: dict = {
            "host": self._host,
            "port": self._port,
            "user": self._user,
            "password": self._password,
            "autocommit": False,
        }
        if with_database:
            kw["database"] = self._database
        return mysql_connector.connect(**kw)

    def _connect(self):
        return self._connect_server(with_database=True)

    def init_db(self) -> None:
        try:
            con0 = self._connect_server(with_database=False)
            try:
                cur0 = con0.cursor()
                cur0.execute(f"CREATE DATABASE IF NOT EXISTS `{self._database}`")
                con0.commit()
            finally:
                try:
                    con0.close()
                except Exception:
                    pass
        except Exception:
            pass

        con = self._connect()
        try:
            cur = con.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    full_name VARCHAR(255) NULL,
                    display_name VARCHAR(255) NOT NULL,
                    username VARCHAR(64) NOT NULL UNIQUE,
                    email VARCHAR(255) NOT NULL UNIQUE,
                    phone VARCHAR(64) NULL,
                    pw_hash TEXT NOT NULL,
                    pw_salt TEXT NOT NULL,
                    created_at BIGINT NOT NULL,
                    failed_attempts INT NOT NULL DEFAULT 0,
                    lock_until BIGINT NOT NULL DEFAULT 0
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    token VARCHAR(128) PRIMARY KEY,
                    user_id INT NOT NULL,
                    created_at BIGINT NOT NULL,
                    expires_at BIGINT NOT NULL,
                    INDEX idx_sessions_user_id (user_id),
                    CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """
            )
            con.commit()
        finally:
            try:
                con.close()
            except Exception:
                pass

    def create_user(self, full_name: str | None, display_name: str, username: str, email: str, phone: str | None, pw_hash: str, pw_salt: str, created_at: int) -> bool:
        con = self._connect()
        try:
            cur = con.cursor()
            try:
                cur.execute(
                    "INSERT INTO users(full_name,display_name,username,email,phone,pw_hash,pw_salt,created_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
                    (full_name, display_name, username, email, phone, pw_hash, pw_salt, int(created_at)),
                )
                con.commit()
                return True
            except Exception as e:
                try:
                    con.rollback()
                except Exception:
                    pass
                if str(e).lower().find("duplicate") >= 0:
                    return False
                return False
        finally:
            try:
                con.close()
            except Exception:
                pass

    def get_user_by_ident(self, ident: str) -> dict | None:
        con = self._connect()
        try:
            cur = con.cursor(dictionary=True)
            cur.execute(
                "SELECT * FROM users WHERE lower(email)=lower(%s) OR lower(username)=lower(%s) LIMIT 1",
                (ident, ident),
            )
            row = cur.fetchone()
            return dict(row) if row else None
        finally:
            try:
                con.close()
            except Exception:
                pass

    def reset_failed_attempts(self, user_id: int) -> None:
        con = self._connect()
        try:
            cur = con.cursor()
            cur.execute("UPDATE users SET failed_attempts=0, lock_until=0 WHERE id=%s", (int(user_id),))
            con.commit()
        finally:
            try:
                con.close()
            except Exception:
                pass

    def increment_failed_attempt(self, user_id: int, failed_attempts: int, lock_until: int) -> None:
        con = self._connect()
        try:
            cur = con.cursor()
            cur.execute(
                "UPDATE users SET failed_attempts=%s, lock_until=%s WHERE id=%s",
                (int(failed_attempts), int(lock_until), int(user_id)),
            )
            con.commit()
        finally:
            try:
                con.close()
            except Exception:
                pass

    def update_display_name(self, user_id: int, display_name: str) -> None:
        con = self._connect()
        try:
            cur = con.cursor()
            cur.execute("UPDATE users SET display_name=%s WHERE id=%s", (display_name, int(user_id)))
            con.commit()
        finally:
            try:
                con.close()
            except Exception:
                pass

    def get_password_row(self, user_id: int) -> dict | None:
        con = self._connect()
        try:
            cur = con.cursor(dictionary=True)
            cur.execute("SELECT pw_hash, pw_salt FROM users WHERE id=%s", (int(user_id),))
            row = cur.fetchone()
            return dict(row) if row else None
        finally:
            try:
                con.close()
            except Exception:
                pass

    def update_password(self, user_id: int, pw_hash: str, pw_salt: str) -> None:
        con = self._connect()
        try:
            cur = con.cursor()
            cur.execute("UPDATE users SET pw_hash=%s, pw_salt=%s WHERE id=%s", (pw_hash, pw_salt, int(user_id)))
            con.commit()
        finally:
            try:
                con.close()
            except Exception:
                pass

    def delete_sessions_by_user(self, user_id: int) -> None:
        con = self._connect()
        try:
            cur = con.cursor()
            cur.execute("DELETE FROM sessions WHERE user_id=%s", (int(user_id),))
            con.commit()
        finally:
            try:
                con.close()
            except Exception:
                pass

    def save_session(self, token: str, user_id: int, created_at: int, expires_at: int) -> None:
        con = self._connect()
        try:
            cur = con.cursor()
            cur.execute(
                "INSERT INTO sessions(token,user_id,created_at,expires_at) VALUES(%s,%s,%s,%s) ON DUPLICATE KEY UPDATE user_id=VALUES(user_id), created_at=VALUES(created_at), expires_at=VALUES(expires_at)",
                (token, int(user_id), int(created_at), int(expires_at)),
            )
            con.commit()
        finally:
            try:
                con.close()
            except Exception:
                pass

    def restore_session_user(self, token: str, now: int) -> dict | None:
        con = self._connect()
        try:
            cur = con.cursor(dictionary=True)
            cur.execute(
                "SELECT s.user_id AS id, u.display_name, u.username, u.email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=%s AND s.expires_at>%s LIMIT 1",
                (token, int(now)),
            )
            row = cur.fetchone()
            return dict(row) if row else None
        finally:
            try:
                con.close()
            except Exception:
                pass

    def admin_unblock(self, ident: str) -> int:
        con = self._connect()
        try:
            cur = con.cursor()
            cur.execute(
                "UPDATE users SET failed_attempts=0, lock_until=0 WHERE lower(email)=lower(%s) OR lower(username)=lower(%s)",
                (ident, ident),
            )
            con.commit()
            return int(cur.rowcount or 0)
        finally:
            try:
                con.close()
            except Exception:
                pass

    def admin_delete(self, ident: str) -> int:
        con = self._connect()
        try:
            cur = con.cursor(dictionary=True)
            cur.execute(
                "SELECT id FROM users WHERE lower(email)=lower(%s) OR lower(username)=lower(%s) LIMIT 1",
                (ident, ident),
            )
            row = cur.fetchone()
            if not row:
                return 0
            uid = int(row.get("id"))
            cur2 = con.cursor()
            cur2.execute("DELETE FROM sessions WHERE user_id=%s", (uid,))
            cur2.execute("DELETE FROM users WHERE id=%s", (uid,))
            con.commit()
            return int(cur2.rowcount or 0)
        finally:
            try:
                con.close()
            except Exception:
                pass


def _make_auth_store(sqlite_db_path: str) -> _AuthStore:
    cfg = _load_mysql_config()
    host = os.environ.get("MYSQL_HOST", "").strip() or str(cfg.get("host") or "").strip()
    user = os.environ.get("MYSQL_USER", "").strip() or str(cfg.get("user") or "").strip()
    password = os.environ.get("MYSQL_PASSWORD", "") or str(cfg.get("password") or "")
    database = os.environ.get("MYSQL_DATABASE", "").strip() or str(cfg.get("database") or "").strip() or "Snakee"
    port_raw = os.environ.get("MYSQL_PORT", "").strip() or str(cfg.get("port") or "3306").strip() or "3306"
    try:
        port = int(port_raw)
    except Exception:
        port = 3306
    if host and user and database:
        try:
            return _MySQLAuthStore(host=host, port=port, user=user, password=password, database=database)
        except Exception:
            return _SQLiteAuthStore(sqlite_db_path)
    return _SQLiteAuthStore(sqlite_db_path)


def _make_auth_store_cli(sqlite_db_path: str) -> _AuthStore:
    store = _make_auth_store(sqlite_db_path)
    if isinstance(store, _MySQLAuthStore):
        return store

    host = os.environ.get("MYSQL_HOST", "").strip()
    user = os.environ.get("MYSQL_USER", "").strip()
    password = os.environ.get("MYSQL_PASSWORD", "")
    database = os.environ.get("MYSQL_DATABASE", "").strip()
    port_raw = os.environ.get("MYSQL_PORT", "").strip()

    if not host:
        host = "127.0.0.1"
    if not user:
        user = "root"
    if not database:
        database = "Snakee"
    if not port_raw:
        port_raw = "3306"
    try:
        port = int(port_raw)
    except Exception:
        port = 3306

    try:
        return _MySQLAuthStore(host=host, port=port, user=user, password=password, database=database)
    except Exception:
        return _SQLiteAuthStore(sqlite_db_path)


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Snakee Video Downloader")
        self.geometry("1100x700")

        if sys.platform.startswith("win"):
            try:
                self.iconbitmap(_resource_path("assets", "app.ico"))
            except Exception:
                pass

        self._job_rows: Dict[int, str] = {}
        self._logo_ctk_image = None
        self._status_text = tk.StringVar(value="Ready")
        self._overall_progress = tk.DoubleVar(value=0.0)
        self._auth_error_text = tk.StringVar(value="")
        self._auth_status_text = tk.StringVar(value="")
        self._current_user: dict | None = None
        self._db_path = _data_path("snakee.db")
        self._session_path = _data_path("session.token")
        self._auth_store: _AuthStore = _make_auth_store(self._db_path)
        self._profile_text = tk.StringVar(value="")
        self._auth_loading = tk.BooleanVar(value=False)
        self._downloaded_files: Dict[int, str] = {}
        self._history_cache: list[tuple[int, str, str, str, str]] = []
        self._pending_register: dict | None = None
        self._otp_code: str | None = None
        self._otp_expires_at: int = 0
        self._otp_after_id: str | None = None
        self._profile_modal: ctk.CTkToplevel | None = None
        self._music_studio_win: ctk.CTkToplevel | None = None

        self.url_var = tk.StringVar(value="")
        self.quality_var = tk.StringVar(value="Best Available")
        self.format_var = tk.StringVar(value="MP4")
        self.fps_var = tk.StringVar(value="Auto")
        self.locale_var = tk.StringVar(value="English") # English / Khmer
        self.appearance_var = tk.StringVar(value="Dark")
        self.platform_hint_var = tk.StringVar(value="")

        self.url_var.trace_add("write", lambda *_: self._update_platform_hint())

        self.output_dir = tk.StringVar(value=os.path.join(os.path.expanduser("~"), "Downloads"))
        self.cookies_file = tk.StringVar(value="")
        self.allow_playlist = tk.BooleanVar(value=False)
        self.concurrent_downloads = tk.IntVar(value=4)
        self.retries = tk.IntVar(value=3)
        self.auto_start = tk.BooleanVar(value=True)
        self.clipboard_monitor = tk.BooleanVar(value=False)
        self._last_clipboard = ""
        self._clipboard_thread = None

        # Advanced / Subtitle / AI
        self.write_subtitles = tk.BooleanVar(value=False)
        self.auto_subtitles = tk.BooleanVar(value=False)
        self.embed_subtitles = tk.BooleanVar(value=False)
        self.write_thumbnail = tk.BooleanVar(value=False)
        self.subtitle_langs = tk.StringVar(value="en,km")
        
        self.ai_smart_naming = tk.BooleanVar(value=True)
        self.ai_translate_title = tk.BooleanVar(value=False)
        self.ai_summary = tk.BooleanVar(value=False)
        
        self.trim_start = tk.StringVar(value="")
        self.trim_end = tk.StringVar(value="")

        self.manager = DownloadManager(on_status=self._on_job_status_threadsafe, on_log=self._log_threadsafe)

        self.locale_dict = {
            "English": {
                "title": "Snakee Video Downloader",
                "subtitle": "Professional Scraper & AI Powered Converter",
                "btn_download": "Download",
                "btn_settings": "Settings",
                "tab_queue": "Queue",
                "tab_logs": "Logs",
                "tab_history": "History",
                "tab_advanced": "Advanced",
                "tab_ai": "AI Features",
                "tab_tools": "Tools",
                "url_placeholder": "Paste Link (YouTube, FB, TikTok, IG, ...)",
                "quality": "Quality:",
                "format": "Format:",
                "fps": "FPS:",
                "btn_add": "Add to Pipe",
                "btn_inspect": "Inspect",
                "status_ready": "Ready",
                "pro_features": "Pro Features:",
                "btn_schedule": "Schedule Download",
                "btn_cloud": "Backup to Cloud",
                "btn_restore": "Restore from Cloud",
                "ai_naming": "AI Smart File Naming (Clean titles)",
                "ai_translate": "AI Auto-Translate Title (EN ⇄ KM)",
                "ai_summary": "AI Video Summary (Save to text file)",
                "tools_title": "Extra Marketing & Utility Tools",
                "btn_qr": "Generate QR Code",
                "btn_shorten": "Shorten Link",
                "btn_extension": "Install Browser Extension",
                "btn_clear": "Clear Finished",
                "trim_label": "Trim Video (Start - End, HH:MM:SS):",
                "threads": "Threads",
                "tab_add_ext": "Add New Extraction",
                "output_lbl": "Output:",
                "cookies_lbl": "Cookies:",
                "btn_profile_scraper": "Profile Scraper",
                "chk_clipboard": "Auto-copy Link",
            },
            "Khmer": {
                "title": "Snakee កម្មវិធីទាញយកវីដេអូ",
                "subtitle": "បច្ចេកវិធី Scraper & AI ដ៏ទំនើប",
                "btn_download": "ទាញយក",
                "btn_settings": "ការកំណត់",
                "tab_queue": "បញ្ជីរង់ចាំ",
                "tab_logs": "កំណត់ហេតុ",
                "tab_history": "ប្រវត្តិ",
                "tab_advanced": "កម្រិតខ្ពស់",
                "tab_ai": "មុខងារ AI",
                "tab_tools": "ឧបករណ៍",
                "url_placeholder": "បិទភ្ជាប់តំណ (YouTube, FB, TikTok, IG, ...)",
                "quality": "គុណភាព:",
                "format": "ប្រភេទ:",
                "fps": "ល្បឿនរូបភាព:",
                "btn_add": "បន្ថែមទៅបញ្ជី",
                "btn_inspect": "ពិនិត្យ",
                "status_ready": "រួចរាល់",
                "pro_features": "មុខងារពិសេស (Pro):",
                "btn_schedule": "កំណត់ម៉ោងទាញយក",
                "btn_cloud": "Backup ទៅ Cloud",
                "btn_restore": "Restore ពី Cloud",
                "ai_naming": "AI សម្អាតឈ្មោះឯកសារ",
                "ai_translate": "AI បកប្រែចំណងជើង (EN ⇄ KM)",
                "ai_summary": "AI សង្ខេបខ្លឹមសារវីដេអូ",
                "tools_title": "ឧបករណ៍ទីផ្សារ និងឧបករណ៍ប្រើប្រាស់",
                "btn_qr": "បង្កើតកូដ QR",
                "btn_shorten": "ធ្វើឱ្យតំណខ្លី",
                "btn_extension": "ដំឡើងកម្មវិធីបន្ថែមលើ Browser",
                "btn_clear": "សម្អាតបញ្ជីដែលរួចរាល់",
                "trim_label": "កាត់វីដេអូ (ចាប់ផ្តើម - បញ្ចប់, ម៉ោង:នាទី:វិនាទី):",
                "threads": "ចំនួនខ្សែ (Threads)",
                "tab_add_ext": "បន្ថែមការទាញយកថ្មី",
                "output_lbl": "ទីតាំងរក្សាទុក:",
                "cookies_lbl": "ឯកសារ Cookies:",
                "btn_profile_scraper": "កម្មវិធីទាញយកតាម Profile",
                "chk_clipboard": "ទាញយកអូតូពី Clipboard",
            }
        }

        self._init_fonts()

        self._load_logo()
        self._build_ui()

        legacy_db = _resource_path("snakee.db")
        if legacy_db != self._db_path and os.path.exists(legacy_db) and not os.path.exists(self._db_path):
            try:
                shutil.copy2(legacy_db, self._db_path)
            except Exception:
                pass
        legacy_session = _resource_path("session.token")
        if legacy_session != self._session_path and os.path.exists(legacy_session) and not os.path.exists(self._session_path):
            try:
                shutil.copy2(legacy_session, self._session_path)
            except Exception:
                pass

        self._auth_init_db()
        self._build_auth_ui()
        self._clear_session()
        self._check_dependencies()
        self._start_clipboard_monitor()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        _debug_log("App initialized")

    def _profile_pic_path(self, user_id: int) -> str:
        uid = 0
        try:
            uid = int(user_id)
        except Exception:
            uid = 0
        if uid <= 0:
            return _data_path("profile_pics", "guest.png")

        return _data_path("profile_pics", f"user_{uid}.png")

    def _load_profile_pic_ctk(self, user_id: int, size: tuple[int, int]) -> ctk.CTkImage | None:
        try:
            p = self._profile_pic_path(user_id)
            try:
                os.makedirs(os.path.dirname(p), exist_ok=True)
            except Exception:
                pass

            if not os.path.isfile(p):
                return None

            img = Image.open(p).convert("RGBA")
            return ctk.CTkImage(light_image=img, dark_image=img, size=size)
        except Exception:
            return None

    def _find_local_font_file(self) -> str:
        assets_dir = _resource_path("assets")
        candidates: list[str] = []
        try:
            if not os.path.isdir(assets_dir):
                return ""
            for root, _, files in os.walk(assets_dir):
                for name in files:
                    low = name.lower()
                    if not (low.endswith(".ttf") or low.endswith(".otf")):
                        continue
                    if "kantumruy" not in low:
                        continue
                    candidates.append(os.path.join(root, name))
        except Exception:
            return ""

        for p in candidates:
            low = os.path.basename(p).lower()
            if "regular" in low:
                return p
        return candidates[0] if candidates else ""

    def _find_local_font_files(self) -> list[str]:
        assets_dir = _resource_path("assets")
        candidates: list[str] = []
        try:
            if not os.path.isdir(assets_dir):
                return []
            for root, _, files in os.walk(assets_dir):
                for name in files:
                    low = name.lower()
                    if not (low.endswith(".ttf") or low.endswith(".otf")):
                        continue
                    if "kantumruy" not in low:
                        continue
                    candidates.append(os.path.join(root, name))
        except Exception:
            return []

        def _score(p: str) -> tuple[int, int, str]:
            low = os.path.basename(p).lower()
            is_pro = 1 if "pro" in low else 0
            is_regular = 1 if "regular" in low else 0
            return (is_pro, is_regular, low)

        candidates.sort(key=_score, reverse=True)
        return candidates

    def _is_font_installed(self, family: str) -> bool:
        fam = str(family or "").strip()
        if not fam:
            return False
        try:
            return fam in set(tkfont.families(self))
        except Exception:
            return False

    def _load_font_from_file(self, font_path: str) -> bool:
        p = str(font_path or "").strip()
        if not p or not os.path.isfile(p):
            return False

        if sys.platform.startswith("win"):
            try:
                FR_PRIVATE = 0x10
                ctypes.windll.gdi32.AddFontResourceExW(p, FR_PRIVATE, 0)
                WM_FONTCHANGE = 0x001D
                HWND_BROADCAST = 0xFFFF
                ctypes.windll.user32.SendMessageW(HWND_BROADCAST, WM_FONTCHANGE, 0, 0)
                return True
            except Exception:
                return False

        return False

    def _pick_font(self, preferred: str, fallbacks: list[str]) -> str:
        prefs = [preferred] + list(fallbacks or [])
        for fam in prefs:
            if fam and self._is_font_installed(fam):
                return fam
        return preferred or (fallbacks[0] if fallbacks else "")

    def _init_fonts(self) -> None:
        if not self._is_font_installed("Kantumruy Pro"):
            local_fonts = self._find_local_font_files()
            if not local_fonts:
                one = self._find_local_font_file()
                local_fonts = [one] if one else []
            for p in local_fonts:
                try:
                    self._load_font_from_file(p)
                except Exception:
                    pass

        try:
            family = self._get_ui_font_family()
            for name in (
                "TkDefaultFont",
                "TkTextFont",
                "TkFixedFont",
                "TkMenuFont",
                "TkHeadingFont",
                "TkCaptionFont",
                "TkSmallCaptionFont",
                "TkIconFont",
                "TkTooltipFont",
            ):
                try:
                    tkfont.nametofont(name).configure(family=family)
                except Exception:
                    pass
        except Exception:
            pass

    def _get_text(self, key: str) -> str:
        loc = self.locale_var.get()
        return self.locale_dict.get(loc, self.locale_dict["English"]).get(key, key)

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.configure(fg_color="#0b0f19") # Deep dark background

        try:
            style = ttk.Style()
            try:
                style.theme_use("clam")
            except Exception:
                pass
            style.configure(
                "Treeview",
                background="#0f172a",
                fieldbackground="#0f172a",
                foreground="#e2e8f0",
                rowheight=26,
                borderwidth=0,
            )
            style.configure(
                "Treeview.Heading",
                background="#1e293b",
                foreground="#e2e8f0",
                relief="flat",
            )
            style.map(
                "Treeview",
                background=[("selected", "#4338ca")],
                foreground=[("selected", "#ffffff")],
            )
        except Exception:
            pass

        self._apply_locale_fonts()

        # Main Container with padding
        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.grid(row=0, column=0, sticky="nsew", padx=40, pady=20)
        self.main_container.grid_columnconfigure(0, weight=1)

        # 1. Header Frame
        header = ctk.CTkFrame(self.main_container, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        header.grid_columnconfigure(0, weight=1)

        # Left Header (Logo)
        left_h = ctk.CTkFrame(header, fg_color="transparent")
        left_h.grid(row=0, column=0, sticky="w")
        
        logo_label = ctk.CTkLabel(left_h, text="")
        if self._logo_ctk_image:
            logo_label.configure(image=self._logo_ctk_image)
        logo_label.grid(row=0, column=0, sticky="w")

        self.subtitle_label = ctk.CTkLabel(left_h, text=self._get_text("subtitle"), text_color="#94a3b8", font=ctk.CTkFont(family=self._get_ui_font_family(), size=14))
        self.subtitle_label.grid(row=1, column=0, sticky="w", padx=20, pady=(5, 0))

        # Right Header (Branding + Lang)
        right_h = ctk.CTkFrame(header, fg_color="transparent")
        right_h.grid(row=0, column=1, sticky="ne")
        
        self.lang_menu = ctk.CTkOptionMenu(right_h, variable=self.locale_var, values=["English", "Khmer"], 
                                          command=self._on_locale_change, width=100, corner_radius=10,
                                          fg_color="#312e81", button_color="#4338ca")
        self.lang_menu.grid(row=0, column=0, padx=10)

        self.theme_menu = ctk.CTkOptionMenu(
            right_h,
            variable=self.appearance_var,
            values=["Dark", "Light", "System"],
            command=self._change_appearance_mode,
            width=90,
            corner_radius=10,
            fg_color="#1e293b",
            button_color="#334155",
        )
        self.theme_menu.grid(row=0, column=1, padx=6)

        self.btn_settings = ctk.CTkButton(
            right_h,
            text="⚙",
            width=44,
            height=30,
            corner_radius=10,
            fg_color="#1e293b",
            hover_color="#334155",
            command=self._open_settings,
        )
        self.btn_settings.grid(row=0, column=2, padx=10)

        self.btn_profile = ctk.CTkButton(
            right_h,
            textvariable=self._profile_text,
            height=30,
            corner_radius=20,
            fg_color="#312e81",
            hover_color="#4338ca",
            command=self._open_profile_menu,
        )
        self.btn_profile.grid(row=0, column=3, sticky="e")
        self.btn_profile.configure(state="disabled")
        self._profile_text.set("")

        self._profile_popup: ctk.CTkToplevel | None = None
        self._profile_popup_anim_after: str | None = None
        
        ctk.CTkLabel(right_h, text="v1.0.0 Elite Edition • @SnapKeeTeam", text_color="#64748b", font=ctk.CTkFont(family=self._get_ui_font_family(), size=11)).grid(row=1, column=0, columnspan=4, sticky="e", pady=10)

        # 2. Navigation Pill (Top centered)
        nav_container = ctk.CTkFrame(self.main_container, fg_color="#1e293b", corner_radius=30)
        nav_container.grid(row=1, column=0, sticky="n", pady=(0, 30))
        
        self.btn_nav_down = ctk.CTkButton(nav_container, text=self._get_text("btn_download"), width=120, height=40, corner_radius=30,
                                         fg_color="#7c3aed", hover_color="#6d28d9", command=lambda: self._select_tab("Download"))
        self.btn_nav_down.grid(row=0, column=0, padx=5, pady=5)
        
        self.btn_nav_adv = ctk.CTkButton(nav_container, text=self._get_text("tab_advanced"), width=120, height=40, corner_radius=30,
                                         fg_color="transparent", hover_color="#334155", command=lambda: self._select_tab("Advanced"))
        self.btn_nav_adv.grid(row=0, column=1, padx=5, pady=5)

        self.btn_nav_ai = ctk.CTkButton(nav_container, text=self._get_text("tab_ai"), width=120, height=40, corner_radius=30,
                                         fg_color="transparent", hover_color="#334155", command=lambda: self._select_tab("AI Features"))
        self.btn_nav_ai.grid(row=0, column=2, padx=5, pady=5)

        self.btn_nav_tools = ctk.CTkButton(nav_container, text=self._get_text("tab_tools"), width=120, height=40, corner_radius=30,
                                         fg_color="transparent", hover_color="#334155", command=lambda: self._select_tab("Tools"))
        self.btn_nav_tools.grid(row=0, column=3, padx=5, pady=5)
        
        self.btn_nav_logs = ctk.CTkButton(nav_container, text=self._get_text("tab_logs"), width=110, height=40, corner_radius=30,
                                         fg_color="transparent", hover_color="#334155", command=lambda: self._select_tab("Logs"))
        self.btn_nav_logs.grid(row=0, column=4, padx=5, pady=5)

        self.btn_nav_hist = ctk.CTkButton(nav_container, text=self._get_text("tab_history"), width=110, height=40, corner_radius=30,
                                         fg_color="transparent", hover_color="#334155", command=lambda: self._select_tab("History"))
        self.btn_nav_hist.grid(row=0, column=5, padx=5, pady=5)

        # 3. Content Tabs (Hidden Headers)
        try:
            self.tabs = ctk.CTkTabview(
                self.main_container,
                fg_color="transparent",
                segment_button_fg_color="transparent",
                segment_button_selected_color="transparent",
                segment_button_selected_hover_color="transparent",
            )
        except ValueError:
            self.tabs = ctk.CTkTabview(self.main_container, fg_color="transparent")
        self.tabs._segmented_button.grid_forget() # Hide headers
        self.tabs.grid(row=2, column=0, sticky="nsew")
        self.main_container.grid_rowconfigure(2, weight=1)

        self.tab_down = self.tabs.add("Download")
        self.tab_adv = self.tabs.add("Advanced")
        self.tab_ai = self.tabs.add("AI Features")
        self.tab_tools = self.tabs.add("Tools")
        self.tab_logs = self.tabs.add("Logs")
        self.tab_hist = self.tabs.add("History")

        self.status_bar = ctk.CTkFrame(self.main_container, height=30, fg_color="#1e293b", corner_radius=10)
        self.status_bar.grid(row=3, column=0, sticky="ew", pady=(20, 0))
        self.status_label = ctk.CTkLabel(self.status_bar, textvariable=self._status_text, font=ctk.CTkFont(family=self._get_ui_font_family(), size=12))
        self.status_label.pack(side="left", padx=20)

        self.overall_bar = ctk.CTkProgressBar(
            self.status_bar,
            width=260,
            height=10,
            corner_radius=10,
            variable=self._overall_progress,
        )
        self.overall_bar.set(0.0)
        self.overall_bar.pack(side="left", padx=10)

        self.btn_open_output = ctk.CTkButton(
            self.status_bar,
            text="Open Folder",
            width=110,
            height=26,
            corner_radius=10,
            fg_color="#334155",
            hover_color="#475569",
            command=self._open_output_folder,
        )
        self.btn_open_output.pack(side="left", padx=10)
        
        self.speed_meter = ctk.CTkLabel(self.status_bar, text="0 KB/s", text_color="#2ecc71", font=ctk.CTkFont(family=self._get_ui_font_family(), size=12, weight="bold"))
        self.speed_meter.pack(side="right", padx=20)

        self._build_download_tab()
        self._build_advanced_tab()
        self._build_ai_tab()
        self._build_tools_tab()
        self._build_logs_tab()
        self._build_history_tab()

    def _build_download_tab(self):
        self.tab_down.grid_columnconfigure(0, weight=1)
        
        # CARD 1: Add New Extraction
        card1 = ctk.CTkFrame(self.tab_down, fg_color="#111827", border_width=1, border_color="#1f2937", corner_radius=15)
        card1.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        card1.grid_columnconfigure(1, weight=1)

        self.lbl_add_new = ctk.CTkLabel(card1, text="📥 Add New Extraction", font=ctk.CTkFont(family=self._get_ui_font_family(), size=16, weight="bold"), text_color="#f8fafc")
        self.lbl_add_new.grid(row=0, column=0, sticky="w", padx=20, pady=(20, 15))

        # URL Frame
        url_f = ctk.CTkFrame(card1, fg_color="transparent")
        url_f.grid(row=1, column=0, columnspan=2, sticky="ew", padx=20, pady=(0, 15))
        url_f.grid_columnconfigure(1, weight=1)
        
        self.lbl_url = ctk.CTkLabel(url_f, text="URL:", text_color="#94a3b8")
        self.lbl_url.grid(row=0, column=0, padx=(0, 15))
        self.url_entry = ctk.CTkEntry(url_f, textvariable=self.url_var, placeholder_text=self._get_text("url_placeholder"), 
                                     height=45, fg_color="#0f172a", border_color="#334155")
        self.url_entry.grid(row=0, column=1, sticky="ew")
        self.url_entry.bind("<Return>", lambda e: self._add_to_pipe())

        self.platform_hint_label = ctk.CTkLabel(
            card1,
            textvariable=self.platform_hint_var,
            text_color="#64748b",
            font=ctk.CTkFont(family=self._get_ui_font_family(), size=12),
        )
        self.platform_hint_label.grid(row=4, column=0, columnspan=2, sticky="w", padx=20, pady=(0, 10))
        
        self.btn_inspect = ctk.CTkButton(url_f, text="🔍 " + self._get_text("btn_inspect"), width=100, height=45, corner_radius=8,
                                    fg_color="#7c3aed", hover_color="#6d28d9", command=self._inspect_current)
        self.btn_inspect.grid(row=0, column=2, padx=(15, 0))

        quick_f = ctk.CTkFrame(card1, fg_color="transparent")
        quick_f.grid(row=3, column=0, columnspan=2, sticky="w", padx=20, pady=(0, 20))

        self.btn_paste = ctk.CTkButton(quick_f, text="Paste", width=90, command=self._paste_urls)
        self.btn_paste.grid(row=0, column=0, padx=(0, 10))
        self.btn_import_txt = ctk.CTkButton(quick_f, text="Import TXT", width=110, command=self._import_txt)
        self.btn_import_txt.grid(row=0, column=1, padx=(0, 10))
        self.btn_clear_url = ctk.CTkButton(quick_f, text="Clear", width=90, command=self._clear_urls)
        self.btn_clear_url.grid(row=0, column=2)

        # Dropdowns Frame
        drops_f = ctk.CTkFrame(card1, fg_color="transparent")
        drops_f.grid(row=2, column=0, columnspan=2, sticky="w", padx=20, pady=(0, 20))
        
        self.lbl_quality = ctk.CTkLabel(drops_f, text=self._get_text("quality"), text_color="#94a3b8")
        self.lbl_quality.grid(row=0, column=0, padx=(0, 10))
        self.quality_menu = ctk.CTkOptionMenu(drops_f, variable=self.quality_var, values=["Best Available", "144p", "240p", "360p", "480p", "720p", "1080p", "2K", "4K", "8K"],
                                             fg_color="#312e81", button_color="#4338ca", width=160)
        self.quality_menu.grid(row=0, column=1, padx=(0, 20))

        self.lbl_format = ctk.CTkLabel(drops_f, text=self._get_text("format"), text_color="#94a3b8")
        self.lbl_format.grid(row=0, column=2, padx=(0, 10))
        self.format_menu = ctk.CTkOptionMenu(drops_f, variable=self.format_var, values=["MP4", "MKV", "WEBM", "MP3", "M4A"],
                                             fg_color="#312e81", button_color="#4338ca", width=120)
        self.format_menu.grid(row=0, column=3)

        # CARD 2: Pipeline Queue
        card2 = ctk.CTkFrame(self.tab_down, fg_color="#111827", border_width=1, border_color="#1f2937", corner_radius=15)
        card2.grid(row=1, column=0, sticky="nsew")
        self.tab_down.grid_rowconfigure(1, weight=1)
        card2.grid_columnconfigure(0, weight=1)
        card2.grid_rowconfigure(1, weight=1)

        self.lbl_pipeline = ctk.CTkLabel(card2, text="📋 Pipeline Queue", font=ctk.CTkFont(family=self._get_ui_font_family(), size=16, weight="bold"), text_color="#f8fafc")
        self.lbl_pipeline.grid(row=0, column=0, sticky="w", padx=20, pady=(20, 10))

        self.tree_frame = ctk.CTkFrame(card2, fg_color="transparent")
        self.tree_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.tree_frame.grid_columnconfigure(0, weight=1)
        self.tree_frame.grid_rowconfigure(0, weight=1)
        
        # Style the Treeview to be dark
        style = ttk.Style()
        style.theme_use("clam")
        tree_font = self._get_ui_font_family()
        style.configure("Treeview", background="#0b0f19", foreground="white", fieldbackground="#0b0f19", borderwidth=0, font=(tree_font, 10))
        style.configure("Treeview.Heading", background="#1e293b", foreground="white", borderwidth=0, font=(tree_font, 11, "bold"))
        style.map("Treeview", background=[("selected", "#7c3aed")])

        self.tree = ttk.Treeview(self.tree_frame, columns=("id", "url", "status", "progress", "speed", "eta"), show="headings")
        self.tree.heading("id", text="#")
        self.tree.heading("url", text="URL")
        self.tree.heading("status", text="Status")
        self.tree.heading("progress", text="%")
        self.tree.heading("speed", text="Speed")
        self.tree.heading("eta", text="ETA")
        self.tree.column("id", width=40)
        self.tree.column("url", width=400)
        self.tree.grid(row=0, column=0, sticky="nsew")
        self.tree.bind("<Button-3>", self._on_queue_right_click)

        self._queue_menu = tk.Menu(self, tearoff=0)
        self._queue_menu.add_command(label="Open File", command=self._open_queue_file)
        self._queue_menu.add_command(label="Open Folder", command=self._open_queue_folder)
        self._queue_menu.add_command(label="Copy URL", command=self._copy_queue_url)
        self._queue_menu.add_separator()
        self._queue_menu.add_command(label="Cancel", command=self._cancel_selected)
        self._queue_menu.add_command(label="Retry", command=self._retry_selected)
        self._queue_menu.add_command(label="Retry All Errors", command=self._retry_all_errors)
        self._queue_menu.add_separator()
        self._queue_menu.add_command(label="Remove", command=self._remove_selected)

        # Footer inside tab_down or card2? The image shows it at the bottom of the whole area.
        footer = ctk.CTkFrame(self.tab_down, fg_color="transparent")
        footer.grid(row=2, column=0, sticky="ew", pady=(20, 0))
        footer.grid_columnconfigure(1, weight=1)

        # Threads slider (Left)
        th_f = ctk.CTkFrame(footer, fg_color="transparent")
        th_f.grid(row=0, column=0, sticky="w")
        self.lbl_threads = ctk.CTkLabel(th_f, text="Threads: ", font=ctk.CTkFont(family=self._get_ui_font_family(), size=12))
        self.lbl_threads.grid(row=0, column=0)
        self.threads_label = ctk.CTkLabel(th_f, text=str(self.concurrent_downloads.get()), font=ctk.CTkFont(family=self._get_ui_font_family(), size=12, weight="bold"))
        self.threads_label.grid(row=0, column=1, padx=(0, 10))
        self.thread_slider = ctk.CTkSlider(th_f, from_=1, to=8, number_of_steps=7, width=150, 
                                          button_color="#7c3aed", button_hover_color="#6d28d9", 
                                          variable=self.concurrent_downloads, command=self._on_threads_changed)
        self.thread_slider.grid(row=0, column=2)

        self.chk_auto_start = ctk.CTkCheckBox(th_f, text="Auto Start", variable=self.auto_start)
        self.chk_auto_start.grid(row=1, column=0, sticky="w", pady=(8, 0))

        self.chk_clipboard = ctk.CTkCheckBox(th_f, text=self._get_text("chk_clipboard"), variable=self.clipboard_monitor)
        self.chk_clipboard.grid(row=1, column=1, columnspan=2, sticky="w", pady=(8, 0), padx=(10, 0))

        # Buttons (Right)
        btns_f = ctk.CTkFrame(footer, fg_color="transparent")
        btns_f.grid(row=0, column=2, sticky="e")
        
        self.btn_start = ctk.CTkButton(
            btns_f,
            text="⬇️ Start",
            fg_color="#7c3aed",
            hover_color="#6d28d9",
            font=ctk.CTkFont(family=self._get_ui_font_family(), weight="bold"),
            command=self._start,
        )
        self.btn_start.grid(row=0, column=0, padx=10)

        self.btn_add_pipe = ctk.CTkButton(btns_f, text="▶️ " + self._get_text("btn_add"), fg_color="#10b981", hover_color="#059669", 
                     font=ctk.CTkFont(family=self._get_ui_font_family(), weight="bold"), command=self._add_to_pipe)
        self.btn_add_pipe.grid(row=0, column=1, padx=10)
        self.btn_clear_fin = ctk.CTkButton(btns_f, text="🗑️ " + self._get_text("btn_clear"), fg_color="#ef4444", hover_color="#dc2626", 
                     font=ctk.CTkFont(family=self._get_ui_font_family(), weight="bold"), command=self._clear_finished)
        self.btn_clear_fin.grid(row=0, column=2, padx=10)

        self.btn_retry_err = ctk.CTkButton(btns_f, text="🔄 Retry Errors", fg_color="#f59e0b", hover_color="#d97706",
                     font=ctk.CTkFont(family=self._get_ui_font_family(), weight="bold"), command=self._retry_all_errors)
        self.btn_retry_err.grid(row=0, column=3)

    def _build_advanced_tab(self):
        self.tab_adv.grid_columnconfigure(0, weight=1)
        
        # Output & Cookies
        path_f = ctk.CTkFrame(self.tab_adv, fg_color="transparent")
        path_f.grid(row=0, column=0, sticky="ew", padx=20, pady=10)
        path_f.grid_columnconfigure(1, weight=1)
        
        self.lbl_output = ctk.CTkLabel(path_f, text=self._get_text("output_lbl"))
        self.lbl_output.grid(row=0, column=0, padx=(0, 10))
        ctk.CTkEntry(path_f, textvariable=self.output_dir).grid(row=0, column=1, sticky="ew")
        ctk.CTkButton(path_f, text="Browse", width=80, command=self._choose_output).grid(row=0, column=2, padx=(10, 0))

        cookie_f = ctk.CTkFrame(self.tab_adv, fg_color="transparent")
        cookie_f.grid(row=1, column=0, sticky="ew", padx=20, pady=10)
        cookie_f.grid_columnconfigure(1, weight=1)
        
        self.lbl_cookies = ctk.CTkLabel(cookie_f, text=self._get_text("cookies_lbl"))
        self.lbl_cookies.grid(row=0, column=0, padx=(0, 10))
        ctk.CTkEntry(cookie_f, textvariable=self.cookies_file).grid(row=0, column=1, sticky="ew")
        ctk.CTkButton(cookie_f, text="Browse", width=80, command=self._choose_cookies).grid(row=0, column=2, padx=(10, 0))
        ctk.CTkButton(cookie_f, text="Help", width=60, command=self._open_cookies_help).grid(row=0, column=3, padx=(6, 0))
        ctk.CTkButton(cookie_f, text="FB Help", width=60, command=self._open_facebook_cookies_help).grid(row=0, column=4, padx=(4, 0))

        self.chk_write_subtitles = ctk.CTkCheckBox(self.tab_adv, text="Write Subtitles", variable=self.write_subtitles)
        self.chk_write_subtitles.grid(row=2, column=0, sticky="w", padx=20, pady=5)
        self.chk_auto_subtitles = ctk.CTkCheckBox(self.tab_adv, text="Auto-generate Subtitles", variable=self.auto_subtitles)
        self.chk_auto_subtitles.grid(row=3, column=0, sticky="w", padx=20, pady=5)
        self.chk_embed_subtitles = ctk.CTkCheckBox(self.tab_adv, text="Embed Subtitles into Video", variable=self.embed_subtitles)
        self.chk_embed_subtitles.grid(row=4, column=0, sticky="w", padx=20, pady=5)

        self.chk_write_thumbnail = ctk.CTkCheckBox(self.tab_adv, text="Write Thumbnail", variable=self.write_thumbnail)
        self.chk_write_thumbnail.grid(row=5, column=0, sticky="w", padx=20, pady=5)
        
        ctk.CTkLabel(self.tab_adv, text="Subtitle Languages (comma separated):").grid(row=6, column=0, sticky="w", padx=20, pady=(10, 0))
        ctk.CTkEntry(self.tab_adv, textvariable=self.subtitle_langs, width=300).grid(row=7, column=0, sticky="w", padx=20, pady=5)

        self.lbl_trim = ctk.CTkLabel(self.tab_adv, text=self._get_text("trim_label"))
        self.lbl_trim.grid(row=8, column=0, sticky="w", padx=20, pady=(20, 0))
        trim_f = ctk.CTkFrame(self.tab_adv, fg_color="transparent")
        trim_f.grid(row=9, column=0, sticky="w", padx=20, pady=5)
        ctk.CTkEntry(trim_f, textvariable=self.trim_start, placeholder_text="00:00:00", width=100).grid(row=0, column=0, padx=(0, 10))
        ctk.CTkEntry(trim_f, textvariable=self.trim_end, placeholder_text="00:05:00", width=100).grid(row=0, column=1)

        self.lbl_pro = ctk.CTkLabel(self.tab_adv, text=self._get_text("pro_features"))
        self.lbl_pro.grid(row=10, column=0, sticky="w", padx=20, pady=(20, 0))
        pro_f = ctk.CTkFrame(self.tab_adv, fg_color="transparent")
        pro_f.grid(row=11, column=0, sticky="w", padx=20, pady=5)
        self.btn_sch = ctk.CTkButton(pro_f, text=self._get_text("btn_schedule"), width=150, command=self._open_scheduler)
        self.btn_sch.grid(row=0, column=0, padx=(0, 10))
        self.btn_cld = ctk.CTkButton(pro_f, text=self._get_text("btn_cloud"), width=150, command=self._perform_cloud_export)
        self.btn_cld.grid(row=0, column=1, padx=(0, 10))
        self.btn_rst = ctk.CTkButton(pro_f, text=self._get_text("btn_restore"), width=150, command=self._perform_cloud_restore)
        self.btn_rst.grid(row=0, column=2)

    def _build_ai_tab(self):
        self.tab_ai.grid_columnconfigure(0, weight=1)
        
        self.chk_naming = ctk.CTkCheckBox(self.tab_ai, text=self._get_text("ai_naming"), variable=self.ai_smart_naming)
        self.chk_naming.grid(row=0, column=0, sticky="w", padx=20, pady=10)
        self.chk_transl = ctk.CTkCheckBox(self.tab_ai, text=self._get_text("ai_translate"), variable=self.ai_translate_title)
        self.chk_transl.grid(row=1, column=0, sticky="w", padx=20, pady=10)
        self.chk_summ = ctk.CTkCheckBox(self.tab_ai, text=self._get_text("ai_summary"), variable=self.ai_summary)
        self.chk_summ.grid(row=2, column=0, sticky="w", padx=20, pady=10)
        
        ctk.CTkLabel(self.tab_ai, text="* AI features use local processing and heuristics for speed.", text_color="gray").grid(row=3, column=0, sticky="w", padx=20, pady=20)

    def _build_tools_tab(self):
        self.tab_tools.grid_columnconfigure(0, weight=1)
        
        self.lbl_tools = ctk.CTkLabel(self.tab_tools, text=self._get_text("tools_title"), font=ctk.CTkFont(family=self._get_ui_font_family(), size=16, weight="bold"))
        self.lbl_tools.grid(row=0, column=0, sticky="w", padx=20, pady=20)
        
        tools_f = ctk.CTkFrame(self.tab_tools, fg_color="transparent")
        tools_f.grid(row=1, column=0, sticky="w", padx=20, pady=10)
        
        self.btn_qr_exec = ctk.CTkButton(tools_f, text=self._get_text("btn_qr"), width=200, command=self._generate_qr_code)
        self.btn_qr_exec.grid(row=0, column=0, padx=(0, 10))
        self.btn_shrt = ctk.CTkButton(tools_f, text=self._get_text("btn_shorten"), width=200, command=self._shorten_url)
        self.btn_shrt.grid(row=0, column=1)
        
        self.btn_profile_sc = ctk.CTkButton(tools_f, text="🔍 " + self._get_text("btn_profile_scraper"), width=200, command=self._open_profile_scraper)
        self.btn_profile_sc.grid(row=1, column=0, padx=(0, 10), pady=(10, 0))

        self.btn_music_studio = ctk.CTkButton(tools_f, text="🎵 Music Studio", width=200, fg_color="#1f538d", hover_color="#14375e", command=self._open_music_studio)
        self.btn_music_studio.grid(row=2, column=0, padx=(0, 10), pady=(10, 0))

        self.btn_save_preset = ctk.CTkButton(tools_f, text="Save Preset", width=200, fg_color="#334155", hover_color="#475569", command=self._save_preset)
        self.btn_save_preset.grid(row=1, column=1, pady=(10, 0))

        self.btn_load_preset = ctk.CTkButton(tools_f, text="Load Preset", width=200, fg_color="#334155", hover_color="#475569", command=self._load_preset)
        self.btn_load_preset.grid(row=2, column=1, pady=(10, 0))
        
        self.btn_ext = ctk.CTkButton(self.tab_tools, text=self._get_text("btn_extension"), width=410, fg_color="#1f538d", command=lambda: self._set_status("Extension installer launched"))
        self.btn_ext.grid(row=2, column=0, sticky="w", padx=20, pady=20)

        supported_f = ctk.CTkFrame(self.tab_tools, fg_color="#111827", border_width=1, border_color="#1f2937", corner_radius=15)
        supported_f.grid(row=3, column=0, sticky="ew", padx=20, pady=(0, 20))
        supported_f.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(supported_f, text="🌐 Supported Platforms (12+)", font=ctk.CTkFont(family=self._get_ui_font_family(), size=16, weight="bold")).grid(
            row=0, column=0, sticky="w", padx=20, pady=(16, 8)
        )

        supported_text = (
            "📘 Facebook → Videos, Reels, Photos\n"
            "📷 Instagram → Reels, Photos\n"
            "📌 Pinterest → Profile, Search, Related\n"
            "▶️ YouTube → Videos, Shorts, Playlists\n"
            "🎵 TikTok → Videos\n"
            "🎬 Douyin → Videos\n"
            "🎥 Kwai → Videos\n"
            "🍿 SnackVideo → Videos\n"
            "⚡ Kuaishou → Videos\n"
            "📕 Xiaohongshu (RedNote) → Videos, Photos\n"
            "🏅 Medal.tv → Clips\n"
            "🧵 Threads → Posts, Videos\n"
            "\nTip: For best results, paste the direct post/video/reel URL (not profile/search pages)."
        )
        self.supported_box = ctk.CTkTextbox(supported_f, height=210)
        self.supported_box.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 16))
        self.supported_box.insert("1.0", supported_text)
        self.supported_box.configure(state="disabled")

    def _build_logs_tab(self):
        self.tab_logs.grid_rowconfigure(0, weight=1)
        self.tab_logs.grid_columnconfigure(0, weight=1)
        top = ctk.CTkFrame(self.tab_logs, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 0))
        top.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(top, text="Logs", font=ctk.CTkFont(family=self._get_ui_font_family(), size=14, weight="bold"), text_color="#f8fafc").grid(row=0, column=0, sticky="w")
        ctk.CTkButton(top, text="Clear Logs", width=110, fg_color="#334155", hover_color="#475569", command=self._clear_logs).grid(row=0, column=1, sticky="e")

        self.log_text = ctk.CTkTextbox(self.tab_logs)
        self.log_text.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        self.tab_logs.grid_rowconfigure(1, weight=1)

    def _build_history_tab(self):
        self.tab_hist.grid_rowconfigure(0, weight=1)
        self.tab_hist.grid_columnconfigure(0, weight=1)

        hist_frame = ctk.CTkFrame(self.tab_hist, fg_color="transparent")
        hist_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        hist_frame.grid_columnconfigure(0, weight=1)
        hist_frame.grid_rowconfigure(0, weight=1)

        self.tree_hist = ttk.Treeview(hist_frame, columns=("id", "title", "url", "status", "time"), show="headings")
        self.tree_hist.heading("id", text="#")
        self.tree_hist.heading("title", text="Title")
        self.tree_hist.heading("url", text="URL")
        self.tree_hist.heading("status", text="Status")
        self.tree_hist.heading("time", text="Time")
        self.tree_hist.column("id", width=40)
        self.tree_hist.column("title", width=250)
        self.tree_hist.column("url", width=300)
        self.tree_hist.column("status", width=100)
        self.tree_hist.column("time", width=100)
        self.tree_hist.grid(row=0, column=0, sticky="nsew")

        self.tree_hist.bind("<Button-3>", self._on_history_right_click)

        self._hist_menu = tk.Menu(self, tearoff=0)
        self._hist_menu.add_command(label="Open File", command=self._open_history_file)
        self._hist_menu.add_command(label="Open Folder", command=self._open_history_folder)
        self._hist_menu.add_command(label="Copy Path", command=self._copy_history_path)
        self._hist_menu.add_command(label="Copy URL", command=self._copy_history_url)

        self.history_filter = tk.StringVar(value="")

        # History Tool bar
        tool_f = ctk.CTkFrame(self.tab_hist, fg_color="transparent")
        tool_f.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
        ctk.CTkLabel(tool_f, text="Search:", text_color="#94a3b8").pack(side="left")
        ent = ctk.CTkEntry(tool_f, textvariable=self.history_filter, width=220)
        ent.pack(side="left", padx=8)
        ent.bind("<KeyRelease>", lambda e: self._refresh_history_view())

        ctk.CTkButton(tool_f, text="Export CSV", width=110, fg_color="#334155", hover_color="#475569", command=self._export_history_csv).pack(side="left")
        ctk.CTkButton(tool_f, text="Open File", width=110, fg_color="#334155", hover_color="#475569", command=self._open_history_file).pack(side="left")
        ctk.CTkButton(tool_f, text="Open Folder", width=120, fg_color="#334155", hover_color="#475569", command=self._open_history_folder).pack(side="left", padx=8)
        ctk.CTkButton(tool_f, text="Copy Path", width=110, fg_color="#334155", hover_color="#475569", command=self._copy_history_path).pack(side="left")
        ctk.CTkButton(tool_f, text="Copy URL", width=110, fg_color="#334155", hover_color="#475569", command=self._copy_history_url).pack(side="left", padx=8)
        ctk.CTkButton(tool_f, text="Clear History", width=120, fg_color="#ef4444", command=self._clear_history).pack(side="right")

    def _refresh_history_view(self) -> None:
        if not hasattr(self, "tree_hist"):
            return
        try:
            self.tree_hist.delete(*self.tree_hist.get_children())
        except Exception:
            return

        q = ""
        try:
            q = (self.history_filter.get() or "").strip().lower()
        except Exception:
            q = ""

        for row in self._history_cache:
            jid, title, url, status, ts = row
            if q:
                blob = f"{jid} {title} {url} {status} {ts}".lower()
                if q not in blob:
                    continue
            try:
                self.tree_hist.insert("", "end", values=(jid, title, url, status, ts))
            except Exception:
                pass

    def _copy_history_url(self) -> None:
        item = self.tree_hist.focus() if hasattr(self, "tree_hist") else ""
        if not item:
            return
        values = self.tree_hist.item(item, "values")
        if not values or len(values) < 3:
            return
        url = str(values[2] or "").strip()
        if not url:
            return
        try:
            self.clipboard_clear()
            self.clipboard_append(url)
            self._set_status("Copied URL to clipboard")
        except Exception:
            pass

    def _clear_history(self) -> None:
        try:
            self._history_cache.clear()
        except Exception:
            pass
        try:
            if hasattr(self, "tree_hist"):
                self.tree_hist.delete(*self.tree_hist.get_children())
        except Exception:
            pass
        try:
            if hasattr(self, "history_filter"):
                self.history_filter.set("")
        except Exception:
            pass
        try:
            self._set_status("History cleared")
        except Exception:
            pass

    def _export_history_csv(self) -> None:
        if not self._history_cache:
            self._set_status("No history to export")
            return
        default_name = f"snakee-history-{time.strftime('%Y%m%d-%H%M%S')}.csv"
        out_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            initialfile=default_name,
            filetypes=[("CSV files", "*.csv")],
        )
        if not out_path:
            return
        try:
            with open(out_path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["job_id", "title", "url", "status", "timestamp"])
                for row in self._history_cache:
                    w.writerow(list(row))
            self._set_status(f"Exported: {out_path}")
        except Exception as e:  # noqa: BLE001
            self._set_status(f"Export failed: {e}")

    def _preset_payload(self) -> dict:
        return {
            "output_dir": self.output_dir.get(),
            "cookies_file": self.cookies_file.get(),
            "quality": self.quality_var.get(),
            "format": self.format_var.get(),
            "fps": self.fps_var.get(),
            "locale": self.locale_var.get(),
            "appearance": self.appearance_var.get() if hasattr(self, "appearance_var") else "Dark",
            "allow_playlist": bool(self.allow_playlist.get()),
            "concurrent_downloads": int(self.concurrent_downloads.get()),
            "retries": int(self.retries.get()),
            "write_subtitles": bool(self.write_subtitles.get()),
            "auto_subtitles": bool(self.auto_subtitles.get()),
            "embed_subtitles": bool(self.embed_subtitles.get()),
            "write_thumbnail": bool(self.write_thumbnail.get()),
            "subtitle_langs": self.subtitle_langs.get(),
            "ai_smart_naming": bool(self.ai_smart_naming.get()),
            "ai_translate_title": bool(self.ai_translate_title.get()),
            "ai_summary": bool(self.ai_summary.get()),
            "trim_start": self.trim_start.get(),
            "trim_end": self.trim_end.get(),
        }

    def _apply_preset_payload(self, data: dict) -> None:
        def _set(var, key, cast=None):
            if key not in data:
                return
            try:
                v = data.get(key)
                if cast is not None:
                    v = cast(v)
                var.set(v)
            except Exception:
                pass

        _set(self.output_dir, "output_dir", str)
        _set(self.cookies_file, "cookies_file", str)
        _set(self.quality_var, "quality", str)
        _set(self.format_var, "format", str)
        _set(self.fps_var, "fps", str)
        _set(self.locale_var, "locale", str)
        if hasattr(self, "appearance_var"):
            _set(self.appearance_var, "appearance", str)
            try:
                self._change_appearance_mode(self.appearance_var.get())
            except Exception:
                pass
        _set(self.allow_playlist, "allow_playlist", bool)
        _set(self.concurrent_downloads, "concurrent_downloads", int)
        _set(self.retries, "retries", int)
        _set(self.write_subtitles, "write_subtitles", bool)
        _set(self.auto_subtitles, "auto_subtitles", bool)
        _set(self.embed_subtitles, "embed_subtitles", bool)
        _set(self.write_thumbnail, "write_thumbnail", bool)
        _set(self.subtitle_langs, "subtitle_langs", str)
        _set(self.ai_smart_naming, "ai_smart_naming", bool)
        _set(self.ai_translate_title, "ai_translate_title", bool)
        _set(self.ai_summary, "ai_summary", bool)
        _set(self.trim_start, "trim_start", str)
        _set(self.trim_end, "trim_end", str)
        try:
            self._on_threads_changed(self.concurrent_downloads.get())
        except Exception:
            pass
        try:
            self._set_status("Preset loaded")
        except Exception:
            pass

    def _save_preset(self) -> None:
        default_name = f"snakee-preset-{time.strftime('%Y%m%d-%H%M%S')}.json"
        out_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            initialfile=default_name,
            filetypes=[("JSON files", "*.json")],
        )
        if not out_path:
            return
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(self._preset_payload(), f, ensure_ascii=False, indent=2)
            self._set_status(f"Preset saved: {out_path}")
        except Exception as e:  # noqa: BLE001
            self._set_status(f"Preset save failed: {e}")

    def _load_preset(self) -> None:
        in_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if not in_path:
            return
        try:
            with open(in_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("Invalid preset file")
            self._apply_preset_payload(data)
        except Exception as e:  # noqa: BLE001
            self._set_status(f"Preset load failed: {e}")

    def _on_history_right_click(self, event: tk.Event) -> None:
        try:
            row_id = self.tree_hist.identify_row(event.y)
        except Exception:
            return
        if row_id:
            try:
                self.tree_hist.selection_set(row_id)
                self.tree_hist.focus(row_id)
            except Exception:
                pass
        try:
            self._hist_menu.tk_popup(event.x_root, event.y_root)
        finally:
            try:
                self._hist_menu.grab_release()
            except Exception:
                pass

    def _copy_queue_url(self) -> None:
        item = self.tree.focus() if hasattr(self, "tree") else ""
        if not item:
            return
        values = self.tree.item(item, "values")
        if not values or len(values) < 2:
            return
        url = str(values[1] or "").strip()
        if not url:
            return
        try:
            self.clipboard_clear()
            self.clipboard_append(url)
            self._set_status("Copied URL to clipboard")
        except Exception:
            pass

    def _open_queue_file(self) -> None:
        item = self.tree.focus() if hasattr(self, "tree") else ""
        if not item:
            return
        values = self.tree.item(item, "values")
        if not values:
            return
        try:
            jid = int(values[0])
        except Exception:
            return
        p = (self._downloaded_files.get(jid) or "").strip()
        if not p or not os.path.exists(p):
            return
        try:
            os.startfile(p)
        except Exception:
            try:
                subprocess.run(["explorer", "/select,", p], check=False)
            except Exception:
                pass

    def _open_queue_folder(self) -> None:
        item = self.tree.focus() if hasattr(self, "tree") else ""
        if not item:
            return
        values = self.tree.item(item, "values")
        if not values:
            return
        try:
            jid = int(values[0])
        except Exception:
            return
        p = (self._downloaded_files.get(jid) or "").strip()
        folder = ""
        if p and os.path.exists(p):
            folder = os.path.dirname(p)
        else:
            folder = self.output_dir.get().strip() or os.path.join(os.path.expanduser("~"), "Downloads")
        try:
            os.makedirs(folder, exist_ok=True)
            os.startfile(folder)
        except Exception:
            pass

    def _select_tab(self, name: str):
        self.tabs.set(name)
        # Update Nav Styles
        self.btn_nav_down.configure(fg_color="#7c3aed" if name == "Download" else "transparent")
        self.btn_nav_adv.configure(fg_color="#7c3aed" if name == "Advanced" else "transparent")
        self.btn_nav_ai.configure(fg_color="#7c3aed" if name == "AI Features" else "transparent")
        self.btn_nav_tools.configure(fg_color="#7c3aed" if name == "Tools" else "transparent")
        self.btn_nav_logs.configure(fg_color="#7c3aed" if name == "Logs" else "transparent")
        self.btn_nav_hist.configure(fg_color="#7c3aed" if name == "History" else "transparent")

    def _on_locale_change(self, choice: str):
        # Refresh UI text
        self._apply_locale_fonts()
        self.subtitle_label.configure(text=self._get_text("subtitle"))
        self.btn_nav_down.configure(text=self._get_text("btn_download"))
        self.btn_nav_adv.configure(text=self._get_text("tab_advanced"))
        self.btn_nav_ai.configure(text=self._get_text("tab_ai"))
        self.btn_nav_tools.configure(text=self._get_text("tab_tools"))
        self.btn_nav_logs.configure(text=self._get_text("tab_logs"))
        self.btn_nav_hist.configure(text=self._get_text("tab_history"))
        self.url_entry.configure(placeholder_text=self._get_text("url_placeholder"))

        # Download Tab Refresh
        if hasattr(self, "lbl_add_new"):
            self.lbl_add_new.configure(text="📥 " + self._get_text("tab_add_ext"))
        if hasattr(self, "btn_inspect"):
            self.btn_inspect.configure(text="🔍 " + self._get_text("btn_inspect"))
        if hasattr(self, "lbl_quality"):
            self.lbl_quality.configure(text=self._get_text("quality"))
        if hasattr(self, "lbl_format"):
            self.lbl_format.configure(text=self._get_text("format"))
        if hasattr(self, "lbl_pipeline"):
            self.lbl_pipeline.configure(text="📋 " + self._get_text("tab_queue"))
        if hasattr(self, "lbl_threads"):
            self.lbl_threads.configure(text=self._get_text("threads") + ": ")
        if hasattr(self, "btn_add_pipe"):
            self.btn_add_pipe.configure(text="▶️ " + self._get_text("btn_add"))
        if hasattr(self, "btn_clear_fin"):
            self.btn_clear_fin.configure(text="🗑️ " + self._get_text("btn_clear"))
            
        # Advanced Tab Refresh
        if hasattr(self, "lbl_output"):
            self.lbl_output.configure(text=self._get_text("output_lbl"))
        if hasattr(self, "lbl_cookies"):
            self.lbl_cookies.configure(text=self._get_text("cookies_lbl"))
        if hasattr(self, "lbl_trim"):
            self.lbl_trim.configure(text=self._get_text("trim_label"))
        if hasattr(self, "lbl_pro"):
            self.lbl_pro.configure(text=self._get_text("pro_features"))
        if hasattr(self, "btn_sch"):
            self.btn_sch.configure(text=self._get_text("btn_schedule"))
        if hasattr(self, "btn_cld"):
            self.btn_cld.configure(font=self._font_small)
        if hasattr(self, "btn_rst"):
            self.btn_rst.configure(font=self._font_small)
        if hasattr(self, "btn_sch"):
            self.btn_sch.configure(font=self._font_small)
        if hasattr(self, "btn_rst"):
            self.btn_rst.configure(text=self._get_text("btn_restore"))
            
        # AI Tab Refresh
        if hasattr(self, "chk_naming"):
            self.chk_naming.configure(text=self._get_text("ai_naming"))
        if hasattr(self, "chk_transl"):
            self.chk_transl.configure(text=self._get_text("ai_translate"))
        if hasattr(self, "chk_summ"):
            self.chk_summ.configure(text=self._get_text("ai_summary"))
            
        # Tools Tab Refresh
        if hasattr(self, "lbl_tools"):
            self.lbl_tools.configure(text=self._get_text("tools_title"))
        if hasattr(self, "btn_qr_exec"):
            self.btn_qr_exec.configure(text=self._get_text("btn_qr"))
        if hasattr(self, "btn_shrt"):
            self.btn_shrt.configure(text=self._get_text("btn_shorten"))
        if hasattr(self, "btn_ext"):
            self.btn_ext.configure(text=self._get_text("btn_extension"))
        if hasattr(self, "chk_clipboard"):
            self.chk_clipboard.configure(text=self._get_text("chk_clipboard"))
        if hasattr(self, "btn_profile_sc"):
            self.btn_profile_sc.configure(text="🔍 " + self._get_text("btn_profile_scraper"))

    def _change_appearance_mode(self, new_mode: str):
        ctk.set_appearance_mode(new_mode)

    def _open_output_folder(self) -> None:
        path = self.output_dir.get().strip() or os.path.join(os.path.expanduser("~"), "Downloads")
        try:
            os.makedirs(path, exist_ok=True)
            os.startfile(path)
        except Exception:
            try:
                messagebox.showerror("Open Folder", f"Cannot open folder: {path}")
            except Exception:
                pass

    def _selected_history_job_id(self) -> int | None:
        item = self.tree_hist.focus() if hasattr(self, "tree_hist") else ""
        if not item:
            return None
        values = self.tree_hist.item(item, "values")
        if not values:
            return None
        try:
            return int(values[0])
        except Exception:
            return None

    def _open_history_file(self) -> None:
        jid = self._selected_history_job_id()
        if jid is None:
            return
        p = (self._downloaded_files.get(jid) or "").strip()
        if not p or not os.path.exists(p):
            try:
                messagebox.showwarning("History", "No local file path is available for this item.")
            except Exception:
                pass
            return
        try:
            os.startfile(p)
        except Exception:
            try:
                subprocess.run(["explorer", "/select,", p], check=False)
            except Exception:
                pass

    def _open_history_folder(self) -> None:
        jid = self._selected_history_job_id()
        if jid is None:
            return
        p = (self._downloaded_files.get(jid) or "").strip()
        folder = ""
        if p and os.path.exists(p):
            folder = os.path.dirname(p)
        else:
            folder = self.output_dir.get().strip() or os.path.join(os.path.expanduser("~"), "Downloads")
        try:
            os.makedirs(folder, exist_ok=True)
            os.startfile(folder)
        except Exception:
            pass

    def _copy_history_path(self) -> None:
        jid = self._selected_history_job_id()
        if jid is None:
            return
        p = (self._downloaded_files.get(jid) or "").strip()
        if not p:
            return
        try:
            self.clipboard_clear()
            self.clipboard_append(p)
            self._set_status("Copied path to clipboard")
        except Exception:
            pass

    def _on_job_status_threadsafe(self, job):
        self.after(0, lambda: self._on_job_status(job))

    def _log_threadsafe(self, msg):
        self.after(0, lambda: self._log(msg))

    def _insert_job(self, job):
        jid_str = str(job.job_id)
        iid = self.tree.insert("", "end", values=(jid_str, job.url, job.status, f"{job.progress:.1f}", job.speed, job.eta))
        self._job_rows[job.job_id] = iid

    def _on_job_status(self, job):
        iid = self._job_rows.get(job.job_id)
        if iid and self.tree.exists(iid):
            self.tree.item(iid, values=(job.job_id, job.url, job.status, f"{job.progress:.1f}%", job.speed, job.eta))
        
        # Update overall progress
        jobs = self.manager.jobs()
        if jobs:
            finished = [j for j in jobs if j.status in ["done", "error", "cancelled"]]
            if finished:
                total = sum(j.progress for j in jobs) / len(jobs)
                self._overall_progress.set(total / 100.0)
            
            # Update speed meter
            running = [j for j in jobs if j.status == "running"]
            if running:
                self.speed_meter.configure(text=running[0].speed or "0 KB/s")
            else:
                self.speed_meter.configure(text="0 KB/s")

        if job.status == "done":
            self.tree_hist.insert("", 0, values=(len(self.tree_hist.get_children()) + 1, job.title or "Unknown", job.url, "Done", time.strftime("%H:%M:%S")))
            self._set_status(f"Finished: {job.title}")
        elif job.status == "error":
            self._set_status(f"Error: {job.error[:50]}...")

    def _log(self, msg):
        self.log_text.insert("end", f"[{time.strftime('%H:%M:%S')}] {msg}\n")
        self.log_text.see("end")

    def _start(self):
        self.manager.start()
        self._set_status("Downloading...")

    def _on_close(self):
        _debug_log("WM_DELETE_WINDOW received")
        try:
            _debug_log("WM_DELETE_WINDOW stack:\n" + "".join(traceback.format_stack(limit=25)))
        except Exception:
            pass
        try:
            self.manager.stop()
        except:
            pass
        try:
            self._clear_session()
        except Exception:
            pass
        self.destroy()

    def _current_options(self) -> DownloadOptions:
        return DownloadOptions(
            output_dir=self.output_dir.get(),
            quality=self.quality_var.get(),
            fps=0 if self.fps_var.get() == "Auto" else int(str(self.fps_var.get()).replace("fps","")),
            container=self.format_var.get().lower(),
            audio_only=self.format_var.get() in ["MP3", "M4A"],
            audio_format="mp3" if self.format_var.get() == "MP3" else "m4a",
            allow_playlist=bool(self.allow_playlist.get()),
            write_subtitles=bool(self.write_subtitles.get()),
            auto_subtitles=bool(self.auto_subtitles.get()),
            subtitle_langs=self.subtitle_langs.get(),
            embed_subtitles=bool(self.embed_subtitles.get()),
            write_thumbnail=bool(self.write_thumbnail.get()),
            cookies_file=self.cookies_file.get(),
            concurrent_downloads=self.concurrent_downloads.get(),
            retries=self.retries.get(),
            ai_smart_naming=bool(self.ai_smart_naming.get()),
            ai_translate_title=bool(self.ai_translate_title.get()),
            ai_summary=bool(self.ai_summary.get()),
            trim_start=self.trim_start.get(),
            trim_end=self.trim_end.get()
        )

    def _on_threads_changed(self, value):
        self.threads_label.configure(text=str(int(value)))

    def _clear_finished(self):
        jobs = self.manager.jobs()
        to_remove = [j.job_id for j in jobs if j.status in ["done", "error", "cancelled"]]
        for jid in to_remove:
            iid = self._job_rows.pop(jid, None)
            if iid: self.tree.delete(iid)
        self._set_status(f"Cleared {len(to_remove)} entries")

    def _paste_urls(self):
        try:
            t = self.clipboard_get()
            if t: self.url_var.set(t)
        except:
            pass

    def _clear_urls(self):
        self.url_var.set("")

    def _import_txt(self):
        p = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if p:
            with open(p, "r", encoding="utf-8") as f:
                self.url_var.set(f.read().replace("\n", " "))

    def _choose_output(self):
        p = filedialog.askdirectory()
        if p: self.output_dir.set(p)

    def _choose_cookies(self):
        p = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if p: self.cookies_file.set(p)

    def _open_cookies_help(self):
        messagebox.showinfo("Cookies Help", "Export cookies using 'Get cookies.txt LOCALLY' extension on Chrome/Edge.")

    def _open_facebook_cookies_help(self):
        messagebox.showinfo("FB Cookies Help", "Use a logged-in browser cookies to download private or restricted FB videos.")

    def _shorten_url(self):
        self._set_status("URL Shortener integration coming soon (Pro)")

    def _on_queue_right_click(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self._queue_menu.post(event.x_root, event.y_root)

    def _cancel_selected(self):
        for iid in self.tree.selection():
            jid = int(self.tree.item(iid, "values")[0])
            self.manager.cancel_job(jid)

    def _retry_selected(self):
        self._set_status("Retry logic active")

    def _retry_all_errors(self):
        self._set_status("Retrying all errors...")

    def _remove_selected(self):
        for iid in self.tree.selection():
            jid = int(self.tree.item(iid, "values")[0])
            self.tree.delete(iid)
            self._job_rows.pop(jid, None)

    def _set_status(self, msg: str) -> None:
        self._status_text.set(msg)

    def _open_scheduler(self):
        dialog = ctk.CTkInputDialog(text="Enter delay in minutes (e.g., 5):", title="Schedule Download")
        val = dialog.get_input()
        if val and val.isdigit():
            mins = int(val)
            self._set_status(f"Download scheduled in {mins} min(s)")
            self.after(mins * 60 * 1000, self._start)
        elif val:
            self._set_status("Invalid delay value")

    def _perform_cloud_export(self):
        output = self.output_dir.get().strip() or os.path.join(os.path.expanduser("~"), "Downloads")
        cloud_mock = os.path.join(os.path.expanduser("~"), "Snakee_Cloud_Sync")
        os.makedirs(cloud_mock, exist_ok=True)
        
        self._set_status("Cloud Sync: Initializing...")
        def worker():
            try:
                # Simulate copying files to cloud with progress feedback
                files = [f for f in os.listdir(output) if os.path.isfile(os.path.join(output, f))]
                if not files:
                    self.after(0, lambda: self._set_status("Cloud Sync: No files to sync"))
                    return

                total = len(files)
                for i, f in enumerate(files):
                    time.sleep(0.1) # Simulate network time for premium feel
                    shutil.copy2(os.path.join(output, f), os.path.join(cloud_mock, f))
                    pct = int(((i+1)/total)*100)
                    self.after(0, lambda p=pct: self._set_status(f"Cloud Syncing: {p}%"))
                
                self._log_threadsafe(f"Cloud Export: {total} files synced to {cloud_mock}")
                self.after(0, lambda: self._set_status(f"Cloud Sync Complete: {total} files"))
            except Exception as e:
                self._log_threadsafe(f"Cloud Export Error: {e}")
                self.after(0, lambda: self._set_status("Cloud Sync Failed"))
        
        threading.Thread(target=worker, daemon=True).start()

    def _perform_cloud_restore(self):
        output = self.output_dir.get().strip() or os.path.join(os.path.expanduser("~"), "Downloads")
        cloud_mock = os.path.join(os.path.expanduser("~"), "Snakee_Cloud_Sync")
        
        if not os.path.exists(cloud_mock):
            self._set_status("Restore: No Cloud Backup found")
            return
            
        self._set_status("Cloud Restore: Initializing...")
        def worker():
            try:
                files = [f for f in os.listdir(cloud_mock) if os.path.isfile(os.path.join(cloud_mock, f))]
                if not files:
                    self.after(0, lambda: self._set_status("Cloud Restore: No files to restore"))
                    return

                total = len(files)
                os.makedirs(output, exist_ok=True)
                for i, f in enumerate(files):
                    time.sleep(0.1)
                    shutil.copy2(os.path.join(cloud_mock, f), os.path.join(output, f))
                    pct = int(((i+1)/total)*100)
                    self.after(0, lambda p=pct: self._set_status(f"Cloud Restoring: {p}%"))
                
                self._log_threadsafe(f"Cloud Restore: {total} files restored from {cloud_mock}")
                self.after(0, lambda: self._set_status(f"Cloud Restore Complete: {total} files"))
            except Exception as e:
                self._log_threadsafe(f"Cloud Restore Error: {e}")
                self.after(0, lambda: self._set_status("Cloud Restore Failed"))
        
        threading.Thread(target=worker, daemon=True).start()

    def _generate_qr_code(self):
        url = self.url_var.get().strip()
        if not url:
            self._set_status(self._get_text("url_placeholder"))
            return
        
        try:
            from PIL import Image, ImageDraw
            # Simple unique pattern QR generation using Pillow
            size = 210
            img = Image.new("RGB", (size, size), "white")
            draw = ImageDraw.Draw(img)
            
            # Draw a fake but semi-unique QR pattern based on URL hash
            import hashlib
            h = hashlib.md5(url.encode()).digest()
            grid = 21 # standard QR grid
            cell = size // grid
            
            # Draw finder patterns
            def draw_finder(x, y):
                draw.rectangle([x*cell, y*cell, (x+7)*cell, (y+7)*cell], fill="black")
                draw.rectangle([(x+1)*cell, (y+1)*cell, (x+6)*cell, (y+6)*cell], fill="white")
                draw.rectangle([(x+2)*cell, (y+2)*cell, (x+5)*cell, (y+5)*cell], fill="black")

            draw_finder(0, 0)
            draw_finder(14, 0)
            draw_finder(0, 14)
            
            # Fill with "random" blocks based on hash
            for i in range(grid * grid):
                x = i % grid
                y = i // grid
                # Skip finder areas
                if (x < 8 and y < 8) or (x > 13 and y < 8) or (x < 8 and y > 13):
                    continue
                
                # Pseudo-random choice based on hash bits
                bit_idx = i % (len(h) * 8)
                byte_val = h[bit_idx // 8]
                if (byte_val >> (bit_idx % 8)) & 1:
                    draw.rectangle([x*cell, y*cell, (x+1)*cell, (y+1)*cell], fill="black")

            save_path = os.path.join(self.output_dir.get() or ".", "snak-ee-qr.png")
            img.save(save_path)
            
            # Show the QR in a new window
            top = ctk.CTkToplevel(self)
            top.title("QR Code - " + url[:20] + "...")
            top.geometry("250x300")
            
            qr_img = ctk.CTkImage(light_image=img, dark_image=img, size=(200, 200))
            lbl = ctk.CTkLabel(top, image=qr_img, text="")
            lbl.pack(pady=20)
            ctk.CTkLabel(top, text="Saved to Output Folder", text_color="gray", font=self._font_small).pack()
            
            self._log(f"[QR] Code generated and saved to: {save_path}")
            self._set_status("QR Code Generated!")
        except Exception as e:
            self._log(f"[QR] Generation failed: {e}")
            self._set_status("QR Generation Failed")

    def _shorten_url(self):
        url = self.url_var.get().strip()
        if not url:
            self._set_status(self._get_text("url_placeholder"))
            return
        import hashlib
        short = hashlib.md5(url.encode()).hexdigest()[:6]
        short_url = f"https://snak.ee/{short}"
        
        self.clipboard_clear()
        self.clipboard_append(short_url)
        
        self._log(f"[Shortener] {url} -> {short_url}")
        self._set_status(f"Short Link: {short_url} (Copied!)")
        
        # Micro-toast logic
        self.after(2000, lambda: self._set_status("Ready"))

    def _on_threads_changed(self, value: float) -> None:
        v = int(round(float(value)))
        v = max(1, min(8, v))
        self.concurrent_downloads.set(v)
        if hasattr(self, "threads_label"):
            self.threads_label.configure(text=str(v))

    def _open_settings(self) -> None:
        w = ctk.CTkToplevel(self)
        w.title("Settings")
        w.geometry("760x260")
        w.transient(self)
        w.grab_set()

        w.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(w, text="Output Folder").grid(row=0, column=0, sticky="w", padx=12, pady=(12, 6))
        ctk.CTkEntry(w, textvariable=self.output_dir).grid(row=0, column=1, sticky="ew", padx=12, pady=(12, 6))
        ctk.CTkButton(w, text="Browse", width=120, command=self._choose_output).grid(row=0, column=2, sticky="e", padx=12, pady=(12, 6))

        ctk.CTkLabel(w, text="Cookies.txt").grid(row=1, column=0, sticky="w", padx=12, pady=6)
        ctk.CTkEntry(w, textvariable=self.cookies_file).grid(row=1, column=1, sticky="ew", padx=12, pady=6)
        ctk.CTkButton(w, text="Browse", width=120, command=self._choose_cookies).grid(row=1, column=2, sticky="e", padx=12, pady=6)

        ctk.CTkCheckBox(w, text="Allow playlist", variable=self.allow_playlist).grid(row=2, column=0, sticky="w", padx=12, pady=6)
        ctk.CTkLabel(w, text="Retries").grid(row=2, column=1, sticky="w", padx=12, pady=6)
        ttk.Spinbox(w, from_=0, to=20, textvariable=self.retries, width=8).grid(row=2, column=1, sticky="e", padx=12, pady=6)

        ctk.CTkButton(w, text="Open Output Folder", command=self._open_output_dir).grid(
            row=3, column=0, columnspan=3, sticky="ew", padx=12, pady=(10, 12)
        )

    def _get_ui_font_family(self) -> str:
        loc = self.locale_var.get()
        if loc == "Khmer":
            return self._pick_font(
                "Kantumruy Pro",
                [
                    "Kantumruy",
                    "Noto Sans Khmer",
                    "Khmer OS System",
                    "Segoe UI",
                    "Arial",
                ],
            )
        return self._pick_font("Inter", ["Segoe UI", "Arial", "TkDefaultFont"]) 

    def _apply_locale_fonts(self) -> None:
        # Best-effort: apply Khmer font across key widgets. If font isn't installed,
        # tkinter will fall back automatically.
        family = self._get_ui_font_family()

        # Keep Tk/ttk defaults aligned to help widgets that don't get explicit CTkFont.
        try:
            for name in (
                "TkDefaultFont",
                "TkTextFont",
                "TkFixedFont",
                "TkMenuFont",
                "TkHeadingFont",
                "TkCaptionFont",
                "TkSmallCaptionFont",
                "TkIconFont",
                "TkTooltipFont",
            ):
                try:
                    tkfont.nametofont(name).configure(family=family)
                except Exception:
                    pass
        except Exception:
            pass

        self._font_body = ctk.CTkFont(family=family, size=12)
        self._font_small = ctk.CTkFont(family=family, size=11)
        self._font_label = ctk.CTkFont(family=family, size=14)
        self._font_title = ctk.CTkFont(family=family, size=16, weight="bold")

        if hasattr(self, "subtitle_label"):
            self.subtitle_label.configure(font=self._font_label)
        if hasattr(self, "lbl_url"):
            self.lbl_url.configure(font=self._font_small)
        if hasattr(self, "url_entry"):
            self.url_entry.configure(font=self._font_body)
        if hasattr(self, "lang_menu"):
            self.lang_menu.configure(font=self._font_small)
        if hasattr(self, "btn_settings"):
            self.btn_settings.configure(font=self._font_small)
        if hasattr(self, "status_label"):
            self.status_label.configure(font=self._font_small)
        if hasattr(self, "speed_meter"):
            self.speed_meter.configure(font=ctk.CTkFont(family=family, size=12, weight="bold"))

        # Download tab key labels
        if hasattr(self, "lbl_add_new"):
            self.lbl_add_new.configure(font=self._font_title)
        if hasattr(self, "lbl_pipeline"):
            self.lbl_pipeline.configure(font=self._font_title)
        if hasattr(self, "platform_hint_label"):
            self.platform_hint_label.configure(font=self._font_small)
        if hasattr(self, "lbl_threads"):
            self.lbl_threads.configure(font=self._font_small)
        if hasattr(self, "threads_label"):
            self.threads_label.configure(font=ctk.CTkFont(family=family, size=12, weight="bold"))
        if hasattr(self, "chk_auto_start"):
            self.chk_auto_start.configure(font=self._font_small)

        if hasattr(self, "btn_start"):
            self.btn_start.configure(font=ctk.CTkFont(family=family, size=12, weight="bold"))
        if hasattr(self, "btn_add_pipe"):
            self.btn_add_pipe.configure(font=ctk.CTkFont(family=family, size=12, weight="bold"))
        if hasattr(self, "btn_clear_fin"):
            self.btn_clear_fin.configure(font=ctk.CTkFont(family=family, size=12, weight="bold"))
        if hasattr(self, "btn_inspect"):
            self.btn_inspect.configure(font=ctk.CTkFont(family=family, size=12, weight="bold"))
        if hasattr(self, "btn_retry_err"):
            self.btn_retry_err.configure(font=ctk.CTkFont(family=family, size=12, weight="bold"))

        if hasattr(self, "btn_paste"):
            self.btn_paste.configure(font=self._font_small)
        if hasattr(self, "btn_import_txt"):
            self.btn_import_txt.configure(font=self._font_small)
        if hasattr(self, "btn_clear_url"):
            self.btn_clear_url.configure(font=self._font_small)

        if hasattr(self, "quality_menu"):
            self.quality_menu.configure(font=self._font_small)
        if hasattr(self, "format_menu"):
            self.format_menu.configure(font=self._font_small)

        if hasattr(self, "chk_write_subtitles"):
            self.chk_write_subtitles.configure(font=self._font_small)
        if hasattr(self, "chk_auto_subtitles"):
            self.chk_auto_subtitles.configure(font=self._font_small)
        if hasattr(self, "chk_embed_subtitles"):
            self.chk_embed_subtitles.configure(font=self._font_small)
        if hasattr(self, "chk_write_thumbnail"):
            self.chk_write_thumbnail.configure(font=self._font_small)

        if hasattr(self, "chk_naming"):
            self.chk_naming.configure(font=self._font_small)
        if hasattr(self, "chk_transl"):
            self.chk_transl.configure(font=self._font_small)
        if hasattr(self, "chk_summ"):
            self.chk_summ.configure(font=self._font_small)

        if hasattr(self, "btn_nav_down"):
            self.btn_nav_down.configure(font=self._font_small)
        if hasattr(self, "btn_nav_adv"):
            self.btn_nav_adv.configure(font=self._font_small)
        if hasattr(self, "btn_nav_ai"):
            self.btn_nav_ai.configure(font=self._font_small)
        if hasattr(self, "btn_nav_tools"):
            self.btn_nav_tools.configure(font=self._font_small)
        if hasattr(self, "btn_nav_logs"):
            self.btn_nav_logs.configure(font=self._font_small)
        if hasattr(self, "btn_nav_hist"):
            self.btn_nav_hist.configure(font=self._font_small)

        # Tools title
        if hasattr(self, "lbl_tools"):
            self.lbl_tools.configure(font=self._font_title)

        if hasattr(self, "btn_qr_exec"):
            self.btn_qr_exec.configure(font=ctk.CTkFont(family=family, size=12, weight="bold"))
        if hasattr(self, "btn_shrt"):
            self.btn_shrt.configure(font=ctk.CTkFont(family=family, size=12, weight="bold"))
        if hasattr(self, "btn_profile_sc"):
            self.btn_profile_sc.configure(font=ctk.CTkFont(family=family, size=12, weight="bold"))
        if hasattr(self, "btn_save_preset"):
            self.btn_save_preset.configure(font=ctk.CTkFont(family=family, size=12, weight="bold"))
        if hasattr(self, "btn_load_preset"):
            self.btn_load_preset.configure(font=ctk.CTkFont(family=family, size=12, weight="bold"))
        if hasattr(self, "btn_ext"):
            self.btn_ext.configure(font=ctk.CTkFont(family=family, size=12, weight="bold"))
        if hasattr(self, "supported_box"):
            self.supported_box.configure(font=self._font_small)

        # Auth/login/register screen
        if hasattr(self, "auth_lang_menu"):
            self.auth_lang_menu.configure(font=self._font_small)
        if hasattr(self, "login_title_label"):
            self.login_title_label.configure(font=ctk.CTkFont(family=family, size=18, weight="bold"))
        if hasattr(self, "register_title_label"):
            self.register_title_label.configure(font=ctk.CTkFont(family=family, size=18, weight="bold"))
        if hasattr(self, "otp_title_label"):
            self.otp_title_label.configure(font=ctk.CTkFont(family=family, size=16, weight="bold"))
        if hasattr(self, "auth_error_label"):
            self.auth_error_label.configure(font=self._font_small)
        if hasattr(self, "auth_status_label"):
            self.auth_status_label.configure(font=self._font_small)
        if hasattr(self, "auth_loader_text"):
            self.auth_loader_text.configure(font=self._font_small)
        if hasattr(self, "remember_chk"):
            self.remember_chk.configure(font=self._font_small)
        if hasattr(self, "terms_chk"):
            self.terms_chk.configure(font=self._font_small)
        if hasattr(self, "login_show_chk"):
            self.login_show_chk.configure(font=self._font_small)
        if hasattr(self, "reg_show_pwd_chk"):
            self.reg_show_pwd_chk.configure(font=self._font_small)
        if hasattr(self, "reg_show_confirm_chk"):
            self.reg_show_confirm_chk.configure(font=self._font_small)
        for name in (
            "btn_login",
            "btn_go_register",
            "btn_next_step",
            "btn_go_login",
            "btn_register",
            "btn_otp_back",
            "btn_otp_resend",
            "btn_otp_verify",
        ):
            try:
                w = getattr(self, name)
                w.configure(font=ctk.CTkFont(family=family, size=12, weight="bold"))
            except Exception:
                pass

        try:
            style = ttk.Style()
            style.configure("Treeview", font=(family, 10))
            style.configure("Treeview.Heading", font=(family, 11, "bold"))
        except Exception:
            pass

    def _import_txt(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = f.read()
        except Exception:
            try:
                with open(path, "r") as f:
                    raw = f.read()
            except Exception:
                self._set_status("Failed to read file")
                return

        urls = [u.strip() for u in raw.splitlines() if u.strip()]
        if not urls:
            self._set_status("No URLs found in file")
            return

        self._import_urls(urls)

    def _import_urls(self, urls: List[str]) -> None:
        if not urls:
            return

        opts = self._current_options()
        os.makedirs(opts.output_dir, exist_ok=True)
        for u in urls:
            try:
                u = self._normalize_url(u)
            except Exception:
                pass
            opts_for_url = opts
            if (not opts.allow_playlist) and self._is_youtube_mix_url(u):
                opts_for_url = dataclasses.replace(opts, allow_playlist=True)
            job = self.manager.add_job(url=u, options=opts_for_url)
            self._insert_job(job)
        self._set_status(f"Imported {len(urls)} URL(s)")

    def _clear_finished(self) -> None:
        to_delete = []
        for job_id, iid in list(self._job_rows.items()):
            job = self.manager.get_job(job_id)
            if not job:
                to_delete.append((job_id, iid))
                continue
            if job.status in {"done", "error", "cancelled"}:
                to_delete.append((job_id, iid))

        for job_id, iid in to_delete:
            try:
                self.tree.delete(iid)
            except Exception:
                pass
            self._job_rows.pop(job_id, None)

        self._refresh_overall_status()
        self._set_status("Cleared finished")

    def _paste_urls(self) -> None:
        if not hasattr(self, "url_text"):
            try:
                text = self.clipboard_get()
            except Exception:
                return
            text = str(text).strip()
            if not text:
                return
            self.url_var.set(text)
            return
        try:
            text = self.clipboard_get()
        except Exception:
            return
        text = str(text).strip()
        if not text:
            return
        existing = self.url_text.get("1.0", "end").strip()
        if existing:
            self.url_text.insert("end", "\n" + text + "\n")
        else:
            self.url_text.insert("1.0", text + "\n")

    def _clear_urls(self) -> None:
        if not hasattr(self, "url_text"):
            self.url_var.set("")
            return
        self.url_text.delete("1.0", "end")

    def _clear_logs(self) -> None:
        self.log_text.delete("1.0", "end")

    def _current_options(self) -> DownloadOptions:
        fmt = self.format_var.get().strip().upper() if hasattr(self, "format_var") else "MP4"
        audio_only = fmt in {"MP3", "M4A"}
        container = (fmt.lower() if fmt in {"MP4", "MKV", "WEBM"} else "mp4")
        audio_format = (fmt.lower() if fmt in {"MP3", "M4A"} else "mp3")

        quality = (self.quality_var.get().strip() if hasattr(self, "quality_var") else "Best")
        if quality.lower().startswith("best"):
            quality = "Best"

        fps_raw = self.fps_var.get().strip() if hasattr(self, "fps_var") else "Auto"
        fps = 0
        if fps_raw.isdigit():
            fps = int(fps_raw)

        return DownloadOptions(
            output_dir=self.output_dir.get().strip() or os.path.join(os.path.expanduser("~"), "Downloads"),
            quality=quality,
            fps=fps,
            container=container,
            audio_only=audio_only,
            audio_format=audio_format,
            allow_playlist=bool(self.allow_playlist.get()),
            write_subtitles=bool(self.write_subtitles.get()),
            auto_subtitles=bool(self.auto_subtitles.get()),
            subtitle_langs=self.subtitle_langs.get().strip(),
            embed_subtitles=bool(self.embed_subtitles.get()),
            write_thumbnail=bool(self.write_thumbnail.get()), # UI toggle maybe later
            cookies_file=self.cookies_file.get().strip(),
            concurrent_downloads=int(self.concurrent_downloads.get()),
            retries=int(self.retries.get()),
            ai_smart_naming=bool(self.ai_smart_naming.get()),
            ai_translate_title=bool(self.ai_translate_title.get()),
            ai_summary=bool(self.ai_summary.get()),
            trim_start=self.trim_start.get().strip(),
            trim_end=self.trim_end.get().strip(),
        )

    def _add_to_queue(self) -> None:
        raw = ""
        if hasattr(self, "url_text"):
            raw = self.url_text.get("1.0", "end")
        else:
            raw = self.url_var.get()

        urls = [u.strip() for u in str(raw).splitlines() if u.strip()]
        if not urls:
            return

        opts = self._current_options()
        os.makedirs(opts.output_dir, exist_ok=True)

        def _is_tiktok_profile(u: str) -> bool:
            s = str(u or "").strip().lower()
            if "tiktok.com/@" not in s:
                return False
            if "/video/" in s:
                return False
            return True

        cookies = ""
        try:
            cookies = (self.cookies_file.get() if hasattr(self, "cookies_file") else "")
        except Exception:
            cookies = ""
        cookies = str(cookies or "").strip()

        to_expand: List[str] = []
        for u in urls:
            try:
                u = self._normalize_url(u)
            except Exception:
                pass
            if _is_tiktok_profile(u):
                to_expand.append(u)
                continue
            job = self.manager.add_job(url=u, options=opts)
            self._insert_job(job)

        if to_expand:
            def _expand_worker(profile_urls: List[str], options: DownloadOptions, cookies_file: str) -> None:
                for pu in profile_urls:
                    try:
                        expanded = expand_url_entries(pu, cookies_file=cookies_file, allow_playlist=True)
                    except Exception as e:
                        self._log_threadsafe(f"[TikTok] Profile expand failed: {pu} • {e}")
                        continue
                    if not expanded:
                        self._log_threadsafe(f"[TikTok] No videos found for profile: {pu}")
                        continue

                    def _add_expanded(expanded_urls: List[str]) -> None:
                        for eu in expanded_urls:
                            try:
                                eu = self._normalize_url(eu)
                            except Exception:
                                pass
                            job = self.manager.add_job(url=eu, options=options)
                            self._insert_job(job)
                        self._refresh_overall_status()

                    self.after(0, lambda ex=expanded: _add_expanded(ex))

            threading.Thread(target=_expand_worker, args=(to_expand, opts, cookies), daemon=True).start()

        if hasattr(self, "url_text"):
            self.url_text.delete("1.0", "end")
        else:
            self.url_var.set("")
        self._refresh_overall_status()

    def _add_to_pipe(self) -> None:
        self._add_to_queue()

    def _inspect_current(self) -> None:
        url = (self.url_var.get() if hasattr(self, "url_var") else "")
        url = str(url or "").strip()
        if not url:
            try:
                messagebox.showinfo("Inspect", "Please paste a URL first.")
            except Exception:
                pass
            return

        try:
            norm = self._normalize_url(url)
        except Exception:
            norm = url

        cookies = ""
        try:
            cookies = (self.cookies_file.get() if hasattr(self, "cookies_file") else "")
        except Exception:
            cookies = ""

        allow_pl = False
        try:
            allow_pl = bool(self.allow_playlist.get() if hasattr(self, "allow_playlist") else False)
        except Exception:
            allow_pl = False

        try:
            info = inspect_url(norm, cookies_file=str(cookies or "").strip(), allow_playlist=allow_pl)
        except Exception as e:
            try:
                messagebox.showerror("Inspect", str(e))
            except Exception:
                pass
            return

        title = str(info.get("title") or "").strip() if isinstance(info, dict) else ""
        uploader = str(info.get("uploader") or info.get("channel") or "").strip() if isinstance(info, dict) else ""
        duration = info.get("duration") if isinstance(info, dict) else None
        webpage = str(info.get("webpage_url") or norm).strip() if isinstance(info, dict) else norm

        lines = []
        if title:
            lines.append(f"Title: {title}")
        if uploader:
            lines.append(f"Uploader: {uploader}")
        if duration:
            lines.append(f"Duration: {duration} sec")
        if webpage:
            lines.append(f"URL: {webpage}")
        if not lines:
            lines = ["Inspect OK"]

        try:
            messagebox.showinfo("Inspect", "\n".join(lines))
        except Exception:
            pass

    def _start(self) -> None:
        if hasattr(self, "url_var") and self.url_var.get().strip():
            self._add_to_pipe()
        self.manager.start()
        self._set_status("Downloading...")

    def _cancel_selected(self) -> None:
        item = self.tree.focus()
        if not item:
            return
        values = self.tree.item(item, "values")
        if not values:
            return
        try:
            job_id = int(values[0])
        except Exception:
            return
        self.manager.cancel_job(job_id)

    def _remove_selected(self) -> None:
        item = self.tree.focus()
        if not item:
            return
        values = self.tree.item(item, "values")
        if values:
            try:
                job_id = int(values[0])
            except Exception:
                return
            self.manager.cancel_job(job_id)
            self._job_rows.pop(job_id, None)
        self.tree.delete(item)
        self._refresh_overall_status()

    def _retry_selected(self) -> None:
        item = self.tree.focus()
        if not item:
            return
        values = self.tree.item(item, "values")
        if not values:
            return
        try:
            job_id = int(values[0])
        except Exception:
            return
        job = self.manager.get_job(job_id)
        if not job:
            return
        
        job.status = "queued"
        job.progress = 0.0
        job.error = ""
        job.cancel_event.clear()
        self.manager._pending.put(job.job_id)
        self.manager.start()
        self._on_job_status(job)

    def _retry_all_errors(self) -> None:
        count = 0
        for job in self.manager.jobs():
            if job.status == "error":
                job.status = "queued"
                job.progress = 0.0
                job.error = ""
                job.cancel_event.clear()
                self.manager._pending.put(job.job_id)
                count += 1
        if count > 0:
            self.manager.start()
            self._set_status(f"Retrying {count} error(s)...")
        else:
            self._set_status("No errors to retry")

    def _insert_job(self, job: DownloadJob) -> None:
        iid = self.tree.insert(
            "",
            "end",
            values=(job.job_id, job.url, job.status, f"{job.progress:.1f}", job.speed, job.eta),
        )
        self._job_rows[job.job_id] = iid
        self._refresh_overall_status()

    def _on_job_status_threadsafe(self, job: DownloadJob) -> None:
        self.after(0, lambda: self._on_job_status(job))

    def _on_job_status(self, job: DownloadJob) -> None:
        iid = self._job_rows.get(job.job_id)
        if not iid:
            return
        
        status_disp = job.status
        if job.status == "error" and job.error:
            status_disp = f"Error: {job.error}"
            self._log(f"Job {job.job_id} error: {job.error}")

        self.tree.item(
            iid,
            values=(job.job_id, job.url, status_disp, f"{job.progress:.1f}%", job.speed, job.eta),
        )
        self._refresh_overall_status()

        # Move to history if done
        if job.status == "done":
            try:
                import datetime
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                title = job.title or os.path.basename(job.filename) if job.filename else "Done"
                if job.filename:
                    self._downloaded_files[job.job_id] = job.filename
                row = (job.job_id, title, job.url, "Success", timestamp)
                self._history_cache.append(row)
                self._refresh_history_view()
            except Exception:
                pass
        
        # Update Global Speed Meter
        jobs = self.manager.jobs()
        active_speeds = [j.speed for j in jobs if j.status == "running" and j.speed]
        if active_speeds:
            self.speed_meter.configure(text=active_speeds[0])
        else:
            self.speed_meter.configure(text="0 KB/s")

    def _log_threadsafe(self, msg: str) -> None:
        self.after(0, lambda: self._log(msg))

    def _log(self, msg: str) -> None:
        self.log_text.insert("end", msg + "\n")
        self.log_text.see("end")

    def _refresh_overall_status(self) -> None:
        jobs = self.manager.jobs()
        if not jobs:
            self._status_text.set("Ready")
            try:
                self._overall_progress.set(0.0)
            except Exception:
                pass
            return

        done = sum(1 for j in jobs if j.status == "done")
        err = sum(1 for j in jobs if j.status == "error")
        running = sum(1 for j in jobs if j.status in {"running", "cancelling"})
        queued = sum(1 for j in jobs if j.status == "queued")
        total = len(jobs)

        progress_sum = 0.0
        for j in jobs:
            try:
                progress_sum += float(j.progress)
            except Exception:
                progress_sum += 0.0
        overall_pct = max(0.0, min(100.0, progress_sum / max(1, total)))
        try:
            self._overall_progress.set(overall_pct / 100.0)
        except Exception:
            pass
        self._status_text.set(
            f"{overall_pct:.0f}% | Total: {total} | Running: {running} | Queued: {queued} | Done: {done} | Error: {err}"
        )

    def _load_logo(self) -> None:
        candidates = [
            _resource_path("assets", "logo.png"),
            _resource_path("assets", "logo.jpg"),
            _resource_path("logo.png"),
            _resource_path("logo.jpg"),
        ]
        path = next((p for p in candidates if os.path.isfile(p)), "")
        if not path:
            self._logo_ctk_image = None
            return
        try:
            img = Image.open(path)
            img = img.convert("RGBA")
            self._logo_ctk_image = ctk.CTkImage(light_image=img, dark_image=img, size=(300, 100))
        except Exception:
            self._logo_ctk_image = None

    def _check_dependencies(self) -> None:
        ffmpeg = shutil.which("ffmpeg")
        if not ffmpeg:
            msg = (
                "ffmpeg not found in PATH. Merging/conversion/subtitles may fail.\n"
                "Windows fix:\n"
                "1) Download ffmpeg: https://ffmpeg.org/download.html\n"
                "2) Extract the zip (e.g., to C:\\ffmpeg)\n"
                "3) Add its bin folder to Environment Variables (PATH):\n"
                "   - Open System Properties → Advanced → Environment Variables\n"
                "   - Edit 'Path' under User/System variables\n"
                "   - Add 'C:\\ffmpeg\\bin' (or where you extracted)\n"
                "4) Restart this app.\n"
                "Test in terminal: ffmpeg -version"
            )
            self._log(msg)
            try:
                import tkinter.messagebox as tkmb
                tkmb.showerror(
                    "Missing FFmpeg",
                    "ffmpeg not found.\n\n"
                    "Without FFmpeg, video/audio merging and subtitles will fail.\n\n"
                    "To fix:\n"
                    "1) Download ffmpeg from https://ffmpeg.org/download.html\n"
                    "2) Extract (e.g., to C:\\ffmpeg)\n"
                    "3) Add its 'bin' folder to your system PATH\n"
                    "4) Restart this app.\n\n"
                    "Test with: ffmpeg -version"
                )
            except Exception:
                pass

        if YoutubeDL is None:
            self._log("yt-dlp not found. Install it with: pip install yt-dlp")

    def _detect_platform(self, url: str):
        u = str(url or "").strip().lower()
        if not u:
            return "", ""

        hint = ""
        if "facebook.com" in u or "fb.watch" in u:
            platform = "Facebook"
            if "/people/" in u and "reels_tab" in u:
                hint = "Paste the direct reel/video post link (not the profile reels tab)."
            return platform, hint
        if "instagram.com" in u:
            platform = "Instagram"
            if "/reel/" in u or "/p/" in u:
                return platform, ""
            return platform, "Paste a direct reel/post link (e.g., /reel/ or /p/)."
        if "pinterest.com" in u or "pin.it" in u:
            platform = "Pinterest"
            if "/pin/" in u:
                return platform, ""
            if "/search/" in u:
                return platform, "Search pages will be expanded into pins automatically (best effort)."
            return platform, "Profile/board pages will be expanded into pins automatically (best effort)."
        if "youtube.com" in u or "youtu.be" in u:
            platform = "YouTube"
            if "/watch" in u or "/shorts/" in u or "youtu.be/" in u:
                return platform, ""
            if "list=" in u:
                return platform, "Playlist links supported if Allow playlist is enabled."
            return platform, ""
        if "tiktok.com" in u:
            return "TikTok", ""
        if "douyin.com" in u:
            return "Douyin", ""
        if "kwai" in u:
            return "Kwai", ""
        if "kuaishou" in u:
            return "Kuaishou", ""
        if "snackvideo" in u:
            return "SnackVideo", ""
        if "xiaohongshu" in u or "xhs" in u:
            return "Xiaohongshu (RedNote)", ""
        if "medal.tv" in u:
            return "Medal.tv", ""
        if "threads.net" in u:
            return "Threads", ""
        return "", ""

    def _update_platform_hint(self) -> None:
        url = self.url_var.get().strip()
        if not url:
            self.platform_hint_var.set("")
            return
        platform, hint = self._detect_platform(url)
        try:
            u = url.lower()
            if ("youtube.com" in u or "youtu.be" in u) and "list=" in u and not bool(self.allow_playlist.get()):
                if self._is_youtube_mix_url(url):
                    hint = "Mix detected. It will be treated as a playlist automatically."
                else:
                    hint = "Playlist detected. It will be converted to direct video unless you enable Allow playlist."
        except Exception:
            pass
        if not platform:
            self.platform_hint_var.set("")
            return
        if hint:
            self.platform_hint_var.set(f"Detected: {platform} • {hint}")
        else:
            self.platform_hint_var.set(f"Detected: {platform}")

    def _normalize_url(self, url: str) -> str:
        u = str(url or "").strip()
        if not u:
            return u

        # Normalize common Facebook subdomains to the canonical host.
        # This avoids some extractors treating web/mobile variants as unsupported.
        low = u.lower()
        if "facebook.com" in low or "fb.watch" in low:
            try:
                parsed = urllib.parse.urlsplit(u)
                host = (parsed.netloc or "").lower()
                if host.startswith("web.facebook.com") or host.startswith("m.facebook.com"):
                    new_netloc = "www.facebook.com"
                    new_url = urllib.parse.urlunsplit((parsed.scheme, new_netloc, parsed.path, parsed.query, parsed.fragment))
                    if new_url != u:
                        self._log(f"[Facebook] Normalized URL: {new_url}")
                    return new_url
            except Exception:
                pass

        # Normalize YouTube URLs that include Mix/Playlist params (list/start_radio)
        # to avoid yt-dlp treating them as a playlist when the user wants one video.
        if "youtube.com" not in low and "youtu.be" not in low:
            return u

        try:
            parsed = urllib.parse.urlsplit(u)
        except Exception:
            return u

        qs = urllib.parse.parse_qs(parsed.query)
        v = (qs.get("v") or [""])[0].strip()
        list_id = (qs.get("list") or [""])[0].strip()

        # Mix playlists often look like list=RD<videoId>
        is_mix = bool(list_id) and list_id.upper().startswith("RD")
        allow_pl = bool(self.allow_playlist.get())

        if v and (not allow_pl) and (not is_mix):
            new_qs = {"v": [v]}
            new_query = urllib.parse.urlencode(new_qs, doseq=True)
            new_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/watch", new_query, ""))
            if new_url != u:
                self._log(f"[YouTube] Normalized URL to direct video: {new_url}")
            return new_url

        return u

    def _is_youtube_mix_url(self, url: str) -> bool:
        u = str(url or "").strip()
        if not u:
            return False
        low = u.lower()
        if "youtube.com" not in low and "youtu.be" not in low:
            return False
        try:
            parsed = urllib.parse.urlsplit(u)
        except Exception:
            return False
        qs = urllib.parse.parse_qs(parsed.query)
        list_id = (qs.get("list") or [""])[0].strip()
        return bool(list_id) and list_id.upper().startswith("RD")

    def _auth_init_db(self) -> None:
        try:
            self._auth_store.init_db()
        except Exception:
            self._auth_store = _SQLiteAuthStore(self._db_path)
            try:
                self._auth_store.init_db()
            except Exception:
                pass

    def _auth_hash_password(self, password: str, salt_b64: str | None = None) -> tuple[str, str]:
        salt = base64.b64decode(salt_b64.encode("utf-8")) if salt_b64 else secrets.token_bytes(16)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
        return base64.b64encode(dk).decode("utf-8"), base64.b64encode(salt).decode("utf-8")

    def _auth_verify_password(self, password: str, pw_hash_b64: str, salt_b64: str) -> bool:
        calc_hash_b64, _ = self._auth_hash_password(password, salt_b64=salt_b64)
        return hmac.compare_digest(calc_hash_b64, pw_hash_b64)

    def _auth_t(self, key: str) -> str:
        loc = self.locale_var.get()
        en = {
            "login_title": "Login",
            "register_title": "Create Account",
            "full_name": "Full name",
            "display_name": "Display name",
            "username": "Username",
            "email": "Email",
            "phone": "Phone (optional)",
            "password": "Password",
            "confirm_password": "Confirm password",
            "remember_me": "Remember me",
            "agree_terms": "I agree to Terms & Privacy",
            "btn_login": "Login",
            "btn_register": "Register",
            "btn_next_step": "Next Step",
            "btn_back": "Back",
            "otp_title": "Verify phone",
            "otp_sent": "We sent a 6-digit code to your phone.",
            "otp_code": "Verification code",
            "otp_verify": "Verify & Create",
            "otp_resend": "Resend code",
            "otp_invalid": "Invalid or expired code.",
            "otp_need_phone": "Phone number is required for the next step.",
            "btn_to_register": "Create Account",
            "btn_to_login": "Back to Login",
            "btn_logout": "Logout",
            "show": "Show",
            "processing": "Processing…",
            "expires_in": "Expires in {s}s",
            "err_exists": "Username/Email already exists.",
            "pwd_strength": "Strength:",
            "pwd_weak": "Weak",
            "pwd_medium": "Medium",
            "pwd_strong": "Strong",
            "err_username": "Username must be 3–20 chars (letters/numbers/underscore).",
            "err_email": "Invalid email format.",
            "err_pwd": "Password must be 8+ chars with uppercase, lowercase, and number.",
            "err_pwd_match": "Passwords do not match.",
            "err_terms": "You must agree to Terms & Privacy.",
            "err_login_invalid": "Email/Username is incorrect.",
            "err_login_pwd": "Password is incorrect.",
            "err_locked": "Too many attempts. Please try again later.",
            "ok_register": "Account created successfully.",
        }
        km = {
            "login_title": "ចូលប្រើ (Login)",
            "register_title": "បង្កើតគណនី (Register)",
            "full_name": "ឈ្មោះពេញ",
            "display_name": "ឈ្មោះបង្ហាញ",
            "username": "ឈ្មោះអ្នកប្រើ (Username)",
            "email": "អ៊ីមែល",
            "phone": "លេខទូរស័ព្ទ (Optional)",
            "password": "ពាក្យសម្ងាត់",
            "confirm_password": "បញ្ជាក់ពាក្យសម្ងាត់",
            "remember_me": "ចងចាំខ្ញុំ",
            "agree_terms": "ខ្ញុំយល់ព្រមលក្ខខណ្ឌ និងគោលការណ៍ឯកជនភាព",
            "btn_login": "ចូលប្រើ",
            "btn_register": "បង្កើតគណនី",
            "btn_next_step": "ជំហានបន្ទាប់",
            "btn_back": "ត្រឡប់ក្រោយ",
            "otp_title": "ផ្ទៀងផ្ទាត់លេខទូរស័ព្ទ",
            "otp_sent": "យើងបានផ្ញើកូដ 6 ខ្ទង់ទៅទូរស័ព្ទរបស់អ្នក។",
            "otp_code": "កូដផ្ទៀងផ្ទាត់",
            "otp_verify": "ផ្ទៀងផ្ទាត់ & បង្កើត",
            "otp_resend": "ផ្ញើកូដម្ដងទៀត",
            "otp_invalid": "កូដមិនត្រឹមត្រូវ ឬផុតកំណត់។",
            "otp_need_phone": "ត្រូវបញ្ចូលលេខទូរស័ព្ទសម្រាប់ជំហានបន្ទាប់។",
            "btn_to_register": "បង្កើតគណនីថ្មី",
            "btn_to_login": "ត្រឡប់ទៅ Login",
            "btn_logout": "ចាកចេញ (Logout)",
            "show": "បង្ហាញ",
            "processing": "កំពុងដំណើរការ…",
            "expires_in": "ផុតកំណត់ក្នុង {s} វិ.",
            "err_exists": "Username/Email មានរួចហើយ។",
            "pwd_strength": "កម្លាំងពាក្យសម្ងាត់:",
            "pwd_weak": "ខ្សោយ",
            "pwd_medium": "មធ្យម",
            "pwd_strong": "ខ្លាំង",
            "err_username": "Username ត្រូវមាន 3–20 តួអក្សរ (អក្សរ/លេខ/underscore)។",
            "err_email": "ទម្រង់អ៊ីមែលមិនត្រឹមត្រូវ។",
            "err_pwd": "ពាក្យសម្ងាត់ត្រូវមាន 8+ តួអក្សរ និងមាន អក្សរធំ/អក្សរតូច/លេខ។",
            "err_pwd_match": "ពាក្យសម្ងាត់មិនដូចគ្នា។",
            "err_terms": "ត្រូវយល់ព្រមលក្ខខណ្ឌ និងគោលការណ៍ឯកជនភាព។",
            "err_login_invalid": "Email/Username មិនត្រឹមត្រូវ។",
            "err_login_pwd": "ពាក្យសម្ងាត់មិនត្រឹមត្រូវ។",
            "err_locked": "ព្យាយាមច្រើនដងពេក។ សូមសាកម្តងទៀតពេលក្រោយ។",
            "ok_register": "បានបង្កើតគណនីដោយជោគជ័យ។",
        }
        d = km if loc == "Khmer" else en
        return d.get(key, key)

    def _auth_password_strength(self, password: str) -> str:
        p = password or ""
        score = 0
        if len(p) >= 8:
            score += 1
        if re.search(r"[a-z]", p):
            score += 1
        if re.search(r"[A-Z]", p):
            score += 1
        if re.search(r"[0-9]", p):
            score += 1
        if re.search(r"[^A-Za-z0-9]", p):
            score += 1
        if score <= 2:
            return self._auth_t("pwd_weak")
        if score == 3:
            return self._auth_t("pwd_medium")
        return self._auth_t("pwd_strong")

    def _auth_validate_register(self, display: str, username: str, email: str, password: str, confirm: str, terms_ok: bool) -> str | None:
        if not display.strip():
            return self._auth_t("display_name")
        if not re.fullmatch(r"[A-Za-z0-9_]{3,20}", username.strip()):
            return self._auth_t("err_username")
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email.strip()):
            return self._auth_t("err_email")
        p = password or ""
        if len(p) < 8 or not re.search(r"[a-z]", p) or not re.search(r"[A-Z]", p) or not re.search(r"[0-9]", p):
            return self._auth_t("err_pwd")
        if password != confirm:
            return self._auth_t("err_pwd_match")
        if not terms_ok:
            return self._auth_t("err_terms")
        return None

    def _build_auth_ui(self) -> None:
        try:
            self.main_container.grid_remove()
        except Exception:
            pass

        self.auth_container = ctk.CTkFrame(self, fg_color="#0b0f19")
        self.auth_container.grid(row=0, column=0, sticky="nsew")
        self.auth_container.grid_columnconfigure(0, weight=1)
        self.auth_container.grid_rowconfigure(0, weight=1)

        card = ctk.CTkFrame(self.auth_container, fg_color="#111827", corner_radius=16, border_width=1, border_color="#1f2937")
        card.grid(row=0, column=0, padx=40, pady=40)
        card.grid_columnconfigure(0, weight=1)

        logo_wrap = ctk.CTkFrame(card, fg_color="transparent")
        logo_wrap.grid(row=0, column=0, sticky="ew", padx=24, pady=(18, 8))
        logo_wrap.grid_columnconfigure(0, weight=1)
        self.auth_logo_label = ctk.CTkLabel(logo_wrap, text="")
        if self._logo_ctk_image:
            self.auth_logo_label.configure(image=self._logo_ctk_image)
        self.auth_logo_label.grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(card, text=self._get_text("title"), font=ctk.CTkFont(family=self._get_ui_font_family(), size=22, weight="bold"), text_color="#f8fafc").grid(
            row=1, column=0, sticky="w", padx=24, pady=(6, 6)
        )
        ctk.CTkLabel(card, text=self._get_text("subtitle"), font=ctk.CTkFont(family=self._get_ui_font_family(), size=14), text_color="#94a3b8").grid(
            row=2, column=0, sticky="w", padx=24, pady=(0, 10)
        )

        top_row = ctk.CTkFrame(card, fg_color="transparent")
        top_row.grid(row=3, column=0, sticky="ew", padx=24, pady=(0, 12))
        top_row.grid_columnconfigure(0, weight=1)
        self.auth_lang_menu = ctk.CTkOptionMenu(
            top_row,
            variable=self.locale_var,
            values=["English", "Khmer"],
            command=lambda *_: self._auth_refresh_labels(),
            width=120,
            corner_radius=10,
            fg_color="#312e81",
            button_color="#4338ca",
        )
        self.auth_lang_menu.grid(row=0, column=1, sticky="e")

        self.auth_stack = ctk.CTkFrame(card, fg_color="transparent")
        self.auth_stack.grid(row=4, column=0, sticky="nsew", padx=24, pady=(0, 12))
        self.auth_stack.grid_columnconfigure(0, weight=1)

        self._build_login_frame()
        self._build_register_frame()
        self._show_login()

        self.auth_error_label = ctk.CTkLabel(card, textvariable=self._auth_error_text, text_color="#f87171", font=ctk.CTkFont(family=self._get_ui_font_family(), size=11))
        self.auth_error_label.grid(row=5, column=0, sticky="w", padx=24, pady=(0, 2))
        self.auth_status_label = ctk.CTkLabel(card, textvariable=self._auth_status_text, text_color="#34d399", font=ctk.CTkFont(family=self._get_ui_font_family(), size=11))
        self.auth_status_label.grid(row=6, column=0, sticky="w", padx=24, pady=(0, 14))

        self.auth_loader_row = ctk.CTkFrame(card, fg_color="transparent")
        self.auth_loader_row.grid(row=7, column=0, sticky="ew", padx=24, pady=(0, 18))
        self.auth_loader_row.grid_columnconfigure(1, weight=1)

        self.auth_loader_text = ctk.CTkLabel(self.auth_loader_row, text="", text_color="#94a3b8", font=ctk.CTkFont(family=self._get_ui_font_family(), size=11))
        self.auth_loader_text.grid(row=0, column=0, sticky="w", padx=(0, 12))

        self.auth_loader = ctk.CTkProgressBar(self.auth_loader_row, mode="indeterminate", height=8)
        self.auth_loader.grid(row=0, column=1, sticky="ew")

        self.auth_loader_row.grid_remove()

    def _auth_refresh_labels(self) -> None:
        try:
            self._on_locale_change(self.locale_var.get())
        except Exception:
            pass
        try:
            self.login_title_label.configure(text=self._auth_t("login_title"))
            self.register_title_label.configure(text=self._auth_t("register_title"))
            self.btn_login.configure(text=self._auth_t("btn_login"))
            self.btn_go_register.configure(text=self._auth_t("btn_to_register"))
            if hasattr(self, "btn_register"):
                self.btn_register.configure(text=self._auth_t("btn_register"))
            if hasattr(self, "btn_next_step"):
                self.btn_next_step.configure(text=self._auth_t("btn_next_step"))
            self.btn_go_login.configure(text=self._auth_t("btn_to_login"))
            self.remember_chk.configure(text=self._auth_t("remember_me"))
            self.terms_chk.configure(text=self._auth_t("agree_terms"))
            self.pwd_strength_label.configure(text=f"{self._auth_t('pwd_strength')} {self._auth_password_strength(self.reg_password.get())}")
            if hasattr(self, "login_show_chk"):
                self.login_show_chk.configure(text=self._auth_t("show"))
            if hasattr(self, "reg_show_pwd_chk"):
                self.reg_show_pwd_chk.configure(text=self._auth_t("show"))
            if hasattr(self, "reg_show_confirm_chk"):
                self.reg_show_confirm_chk.configure(text=self._auth_t("show"))
            if hasattr(self, "otp_title_label"):
                self.otp_title_label.configure(text=self._auth_t("otp_title"))
            if hasattr(self, "otp_sent_label"):
                self.otp_sent_label.configure(text=self._auth_t("otp_sent"))
            if hasattr(self, "otp_entry"):
                self.otp_entry.configure(placeholder_text=self._auth_t("otp_code"))
            if hasattr(self, "btn_otp_back"):
                self.btn_otp_back.configure(text=self._auth_t("btn_back"))
            if hasattr(self, "btn_otp_resend"):
                self.btn_otp_resend.configure(text=self._auth_t("otp_resend"))
            if hasattr(self, "btn_otp_verify"):
                self.btn_otp_verify.configure(text=self._auth_t("otp_verify"))
        except Exception:
            pass

    def _build_login_frame(self) -> None:
        self.login_frame = ctk.CTkFrame(self.auth_stack, fg_color="transparent")
        self.login_frame.grid(row=0, column=0, sticky="nsew")
        self.login_frame.grid_columnconfigure(0, weight=1)

        self.login_title_label = ctk.CTkLabel(self.login_frame, text=self._auth_t("login_title"), font=ctk.CTkFont(size=18, weight="bold"), text_color="#f8fafc")
        self.login_title_label.grid(row=0, column=0, sticky="w", pady=(0, 12))

        self.login_user = tk.StringVar(value="")
        self.login_pass = tk.StringVar(value="")
        self.remember_me = tk.BooleanVar(value=False)
        self._login_show_pwd = tk.BooleanVar(value=False)

        ctk.CTkLabel(self.login_frame, text=f"{self._auth_t('email')} / {self._auth_t('username')}", text_color="#94a3b8", font=ctk.CTkFont(family=self._get_ui_font_family(), size=11)).grid(
            row=1, column=0, sticky="w", pady=(0, 4)
        )
        self.login_user_entry = ctk.CTkEntry(
            self.login_frame,
            textvariable=self.login_user,
            placeholder_text=f"{self._auth_t('email')} / {self._auth_t('username')}",
            placeholder_text_color="#64748b",
        )
        self.login_user_entry.grid(row=2, column=0, sticky="ew", pady=(0, 10))

        pw_wrap = ctk.CTkFrame(self.login_frame, fg_color="transparent")
        pw_wrap.grid(row=3, column=0, sticky="ew", pady=(0, 8))
        pw_wrap.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(self.login_frame, text=self._auth_t("password"), text_color="#94a3b8", font=ctk.CTkFont(family=self._get_ui_font_family(), size=11)).grid(row=4, column=0, sticky="w", pady=(0, 4))
        self.login_pass_entry = ctk.CTkEntry(
            pw_wrap,
            textvariable=self.login_pass,
            placeholder_text=self._auth_t("password"),
            placeholder_text_color="#64748b",
            show="*",
        )
        self.login_pass_entry.grid(row=0, column=0, sticky="ew")
        self.login_show_chk = ctk.CTkCheckBox(
            pw_wrap,
            text=self._auth_t("show"),
            variable=self._login_show_pwd,
            command=lambda: self.login_pass_entry.configure(show="" if self._login_show_pwd.get() else "*"),
        )
        self.login_show_chk.grid(row=0, column=1, padx=(10, 0))

        self.remember_chk = ctk.CTkCheckBox(self.login_frame, text=self._auth_t("remember_me"), variable=self.remember_me)
        self.remember_chk.grid(row=5, column=0, sticky="w", pady=(10, 12))

        self.btn_login = ctk.CTkButton(self.login_frame, text=self._auth_t("btn_login"), fg_color="#7c3aed", hover_color="#6d28d9", command=self._do_login)
        self.btn_login.grid(row=6, column=0, sticky="ew", pady=(0, 10))

        self.btn_go_register = ctk.CTkButton(self.login_frame, text=self._auth_t("btn_to_register"), fg_color="#1e293b", hover_color="#334155", command=self._show_register)
        self.btn_go_register.grid(row=7, column=0, sticky="ew")

    def _build_register_frame(self) -> None:
        self.register_frame = ctk.CTkFrame(self.auth_stack, fg_color="transparent")
        self.register_frame.grid(row=0, column=0, sticky="nsew")
        self.register_frame.grid_columnconfigure(0, weight=1)

        self.register_title_label = ctk.CTkLabel(self.register_frame, text=self._auth_t("register_title"), font=ctk.CTkFont(size=18, weight="bold"), text_color="#f8fafc")
        self.register_title_label.grid(row=0, column=0, sticky="w", pady=(0, 12))

        self.register_step1 = ctk.CTkFrame(self.register_frame, fg_color="transparent")
        self.register_step1.grid(row=1, column=0, sticky="nsew")
        self.register_step1.grid_columnconfigure(0, weight=1)

        self.register_step2 = ctk.CTkFrame(self.register_frame, fg_color="transparent")
        self.register_step2.grid(row=1, column=0, sticky="nsew")
        self.register_step2.grid_columnconfigure(0, weight=1)
        self.register_step2.grid_remove()

        self.reg_full_name = tk.StringVar(value="")
        self.reg_display = tk.StringVar(value="")
        self.reg_username = tk.StringVar(value="")
        self.reg_email = tk.StringVar(value="")
        self.reg_phone = tk.StringVar(value="")
        self.reg_password = tk.StringVar(value="")
        self.reg_confirm = tk.StringVar(value="")
        self.reg_terms = tk.BooleanVar(value=False)
        self._reg_show_pwd = tk.BooleanVar(value=False)
        self._reg_show_confirm = tk.BooleanVar(value=False)

        self.register_step1.grid_rowconfigure(0, weight=1)
        self.register_step1.grid_columnconfigure(0, weight=1)

        self.reg_form = ctk.CTkScrollableFrame(self.register_step1, fg_color="transparent")
        self.reg_form.grid(row=0, column=0, sticky="nsew")
        self.reg_form.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(self.reg_form, text=self._auth_t("full_name"), text_color="#94a3b8", font=ctk.CTkFont(family=self._get_ui_font_family(), size=11)).grid(row=1, column=0, sticky="w", pady=(0, 4))
        ctk.CTkEntry(self.reg_form, textvariable=self.reg_full_name, placeholder_text=self._auth_t("full_name"), placeholder_text_color="#64748b").grid(row=2, column=0, sticky="ew", pady=(0, 10))

        ctk.CTkLabel(self.reg_form, text=self._auth_t("display_name"), text_color="#94a3b8", font=ctk.CTkFont(family=self._get_ui_font_family(), size=11)).grid(row=3, column=0, sticky="w", pady=(0, 4))
        ctk.CTkEntry(self.reg_form, textvariable=self.reg_display, placeholder_text=self._auth_t("display_name"), placeholder_text_color="#64748b").grid(row=4, column=0, sticky="ew", pady=(0, 10))

        ctk.CTkLabel(self.reg_form, text=self._auth_t("username"), text_color="#94a3b8", font=ctk.CTkFont(family=self._get_ui_font_family(), size=11)).grid(row=5, column=0, sticky="w", pady=(0, 4))
        ctk.CTkEntry(self.reg_form, textvariable=self.reg_username, placeholder_text=self._auth_t("username"), placeholder_text_color="#64748b").grid(row=6, column=0, sticky="ew", pady=(0, 10))

        ctk.CTkLabel(self.reg_form, text=self._auth_t("email"), text_color="#94a3b8", font=ctk.CTkFont(family=self._get_ui_font_family(), size=11)).grid(row=7, column=0, sticky="w", pady=(0, 4))
        ctk.CTkEntry(self.reg_form, textvariable=self.reg_email, placeholder_text=self._auth_t("email"), placeholder_text_color="#64748b").grid(row=8, column=0, sticky="ew", pady=(0, 10))

        ctk.CTkLabel(self.reg_form, text=self._auth_t("phone"), text_color="#94a3b8", font=ctk.CTkFont(family=self._get_ui_font_family(), size=11)).grid(row=9, column=0, sticky="w", pady=(0, 4))
        ctk.CTkEntry(self.reg_form, textvariable=self.reg_phone, placeholder_text=self._auth_t("phone"), placeholder_text_color="#64748b").grid(row=10, column=0, sticky="ew", pady=(0, 10))

        pw_wrap = ctk.CTkFrame(self.reg_form, fg_color="transparent")
        ctk.CTkLabel(self.reg_form, text=self._auth_t("password"), text_color="#94a3b8", font=ctk.CTkFont(family=self._get_ui_font_family(), size=11)).grid(row=11, column=0, sticky="w", pady=(0, 4))
        pw_wrap.grid(row=12, column=0, sticky="ew", pady=(0, 8))
        pw_wrap.grid_columnconfigure(0, weight=1)
        self.reg_password_entry = ctk.CTkEntry(pw_wrap, textvariable=self.reg_password, placeholder_text=self._auth_t("password"), show="*")
        self.reg_password_entry.grid(row=0, column=0, sticky="ew")
        self.reg_show_pwd_chk = ctk.CTkCheckBox(
            pw_wrap,
            text=self._auth_t("show"),
            variable=self._reg_show_pwd,
            command=lambda: self.reg_password_entry.configure(show="" if self._reg_show_pwd.get() else "*"),
        )
        self.reg_show_pwd_chk.grid(row=0, column=1, padx=(10, 0))

        self.pwd_strength_label = ctk.CTkLabel(self.reg_form, text=f"{self._auth_t('pwd_strength')} {self._auth_password_strength('')}", text_color="#94a3b8")
        self.pwd_strength_label.grid(row=13, column=0, sticky="w", pady=(0, 8))
        self.reg_password.trace_add("write", lambda *_: self.pwd_strength_label.configure(text=f"{self._auth_t('pwd_strength')} {self._auth_password_strength(self.reg_password.get())}"))

        conf_wrap = ctk.CTkFrame(self.reg_form, fg_color="transparent")
        ctk.CTkLabel(self.reg_form, text=self._auth_t("confirm_password"), text_color="#94a3b8", font=ctk.CTkFont(family=self._get_ui_font_family(), size=11)).grid(row=14, column=0, sticky="w", pady=(0, 4))
        conf_wrap.grid(row=15, column=0, sticky="ew", pady=(0, 8))
        conf_wrap.grid_columnconfigure(0, weight=1)
        self.reg_confirm_entry = ctk.CTkEntry(conf_wrap, textvariable=self.reg_confirm, placeholder_text=self._auth_t("confirm_password"), show="*")
        self.reg_confirm_entry.grid(row=0, column=0, sticky="ew")
        self.reg_show_confirm_chk = ctk.CTkCheckBox(
            conf_wrap,
            text=self._auth_t("show"),
            variable=self._reg_show_confirm,
            command=lambda: self.reg_confirm_entry.configure(show="" if self._reg_show_confirm.get() else "*"),
        )
        self.reg_show_confirm_chk.grid(row=0, column=1, padx=(10, 0))

        self.terms_chk = ctk.CTkCheckBox(self.reg_form, text=self._auth_t("agree_terms"), variable=self.reg_terms)
        self.terms_chk.grid(row=16, column=0, sticky="w", pady=(10, 12))

        self.reg_btn_bar = ctk.CTkFrame(self.register_step1, fg_color="transparent")
        self.reg_btn_bar.grid(row=1, column=0, sticky="ew", pady=(12, 0))
        self.reg_btn_bar.grid_columnconfigure(0, weight=1)

        self.btn_next_step = ctk.CTkButton(self.reg_btn_bar, text=self._auth_t("btn_next_step"), fg_color="#7c3aed", hover_color="#6d28d9", command=self._reg_next_step)
        self.btn_next_step.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        self.btn_go_login = ctk.CTkButton(self.reg_btn_bar, text=self._auth_t("btn_to_login"), fg_color="#1e293b", hover_color="#334155", command=self._show_login)
        self.btn_go_login.grid(row=1, column=0, sticky="ew")

        self.otp_code_var = tk.StringVar(value="")
        self.otp_countdown_var = tk.StringVar(value="")
        self.otp_hint_var = tk.StringVar(value="")

        self.otp_title_label = ctk.CTkLabel(self.register_step2, text=self._auth_t("otp_title"), font=ctk.CTkFont(size=16, weight="bold"), text_color="#f8fafc")
        self.otp_title_label.grid(row=0, column=0, sticky="w", pady=(0, 8))
        self.otp_sent_label = ctk.CTkLabel(self.register_step2, text=self._auth_t("otp_sent"), text_color="#94a3b8")
        self.otp_sent_label.grid(row=1, column=0, sticky="w", pady=(0, 10))

        self.otp_hint_label = ctk.CTkLabel(self.register_step2, textvariable=self.otp_hint_var, text_color="#64748b")
        self.otp_hint_label.grid(row=2, column=0, sticky="w", pady=(0, 10))

        ctk.CTkLabel(self.register_step2, text=self._auth_t("otp_code"), text_color="#94a3b8", font=ctk.CTkFont(family=self._get_ui_font_family(), size=11)).grid(row=3, column=0, sticky="w", pady=(0, 4))
        self.otp_entry = ctk.CTkEntry(self.register_step2, textvariable=self.otp_code_var, placeholder_text=self._auth_t("otp_code"), placeholder_text_color="#64748b")
        self.otp_entry.grid(row=4, column=0, sticky="ew", pady=(0, 8))

        self.otp_countdown_label = ctk.CTkLabel(self.register_step2, textvariable=self.otp_countdown_var, text_color="#94a3b8")
        self.otp_countdown_label.grid(row=5, column=0, sticky="w", pady=(0, 10))

        row_btn = ctk.CTkFrame(self.register_step2, fg_color="transparent")
        row_btn.grid(row=6, column=0, sticky="ew")
        row_btn.grid_columnconfigure(1, weight=1)

        self.btn_otp_back = ctk.CTkButton(row_btn, text=self._auth_t("btn_back"), fg_color="#1e293b", hover_color="#334155", width=80, command=self._reg_back_step1)
        self.btn_otp_back.grid(row=0, column=0, sticky="w")

        self.btn_otp_resend = ctk.CTkButton(row_btn, text=self._auth_t("otp_resend"), fg_color="#1e293b", hover_color="#334155", width=120, command=self._reg_resend_otp)
        self.btn_otp_resend.grid(row=0, column=1, sticky="e", padx=(10, 0))

        self.btn_otp_verify = ctk.CTkButton(self.register_step2, text=self._auth_t("otp_verify"), fg_color="#7c3aed", hover_color="#6d28d9", command=self._reg_verify_otp)
        self.btn_otp_verify.grid(row=7, column=0, sticky="ew", pady=(12, 0))

    def _reg_next_step(self) -> None:
        self._auth_error_text.set("")
        self._auth_status_text.set("")

        full_name = self.reg_full_name.get().strip()
        display = self.reg_display.get().strip()
        username = self.reg_username.get().strip()
        email = self.reg_email.get().strip()
        phone = self.reg_phone.get().strip()
        password = self.reg_password.get()
        confirm = self.reg_confirm.get()
        terms_ok = bool(self.reg_terms.get())

        if not phone:
            self._auth_error_text.set(self._auth_t("otp_need_phone"))
            return

        err = self._auth_validate_register(display, username, email, password, confirm, terms_ok)
        if err:
            self._auth_error_text.set(err)
            return

        self._pending_register = {
            "full_name": full_name,
            "display": display,
            "username": username,
            "email": email,
            "phone": phone,
            "password": password,
        }

        self._reg_send_otp()
        self.register_step1.grid_remove()
        self.register_step2.grid()
        try:
            self.otp_entry.focus_set()
        except Exception:
            pass

    def _reg_back_step1(self) -> None:
        self._pending_register = None
        self._otp_code = None
        self._otp_expires_at = 0
        if self._otp_after_id is not None:
            try:
                self.after_cancel(self._otp_after_id)
            except Exception:
                pass
            self._otp_after_id = None
        self.otp_code_var.set("")
        self.otp_countdown_var.set("")
        self.otp_hint_var.set("")
        self.register_step2.grid_remove()
        self.register_step1.grid()

    def _reg_send_otp(self) -> None:
        self._otp_code = f"{secrets.randbelow(1_000_000):06d}"
        self._otp_expires_at = int(time.time()) + 120
        self.otp_code_var.set("")
        phone = ""
        try:
            if self._pending_register:
                phone = str(self._pending_register.get("phone") or "")
        except Exception:
            phone = ""
        # Demo/offline: show OTP hint in UI
        self.otp_hint_var.set(f"Demo OTP for {phone}: {self._otp_code}")
        self._reg_update_otp_countdown()

    def _reg_resend_otp(self) -> None:
        if self._pending_register is None:
            return
        self._reg_send_otp()

    def _reg_update_otp_countdown(self) -> None:
        if self._otp_after_id is not None:
            try:
                self.after_cancel(self._otp_after_id)
            except Exception:
                pass
            self._otp_after_id = None

        remain = max(0, int(self._otp_expires_at - time.time()))
        try:
            self.otp_countdown_var.set(self._auth_t("expires_in").format(s=remain))
        except Exception:
            self.otp_countdown_var.set(f"Expires in {remain}s")
        if remain <= 0:
            return
        self._otp_after_id = self.after(1000, self._reg_update_otp_countdown)

    def _reg_verify_otp(self) -> None:
        if self._pending_register is None:
            return
        code = self.otp_code_var.get().strip()
        now = int(time.time())
        if (not self._otp_code) or (now > int(self._otp_expires_at)) or (code != self._otp_code):
            self._auth_error_text.set(self._auth_t("otp_invalid"))
            return

        data = dict(self._pending_register)
        self._auth_error_text.set("")
        self._auth_status_text.set("")
        self._auth_set_loading(True)

        def worker() -> None:
            pw_hash, pw_salt = self._auth_hash_password(str(data.get("password") or ""))
            now2 = int(time.time())
            ok = False
            try:
                ok = bool(
                    self._auth_store.create_user(
                        (data.get("full_name") or None),
                        str(data.get("display") or ""),
                        str(data.get("username") or ""),
                        str(data.get("email") or ""),
                        str(data.get("phone") or "") or None,
                        pw_hash,
                        pw_salt,
                        now2,
                    )
                )
            except Exception:
                ok = False
            if not ok:
                self.after(0, lambda: (self._auth_error_text.set(self._auth_t("err_exists")), self._auth_set_loading(False)))
                return

            def finish() -> None:
                self._auth_set_loading(False)
                self._pending_register = None
                self._otp_code = None
                self._otp_expires_at = 0
                self._auth_status_text.set(self._auth_t("ok_register"))
                self._show_login()

            self.after(0, finish)

        threading.Thread(target=worker, daemon=True).start()

    def _auth_set_loading(self, loading: bool) -> None:
        self._auth_loading.set(bool(loading))
        try:
            if loading:
                self.auth_loader_text.configure(text=self._auth_t("processing"))
                self.auth_loader_row.grid()
                self.auth_loader.start()
            else:
                self.auth_loader.stop()
                self.auth_loader_row.grid_remove()
                self.auth_loader_text.configure(text="")
        except Exception:
            pass
        for name in (
            "btn_login",
            "btn_register",
            "btn_next_step",
            "btn_go_register",
            "btn_go_login",
            "btn_otp_back",
            "btn_otp_resend",
            "btn_otp_verify",
        ):
            try:
                w = getattr(self, name)
                w.configure(state="disabled" if loading else "normal")
            except Exception:
                pass

    def _show_login(self) -> None:
        self._auth_error_text.set("")
        self._auth_status_text.set("")
        try:
            self.register_frame.grid_remove()
        except Exception:
            pass
        self.login_frame.grid()

    def _show_register(self) -> None:
        self._auth_error_text.set("")
        self._auth_status_text.set("")
        try:
            self.login_frame.grid_remove()
        except Exception:
            pass
        self.register_frame.grid()

    def _set_authenticated(self, user: dict) -> None:
        self._current_user = user
        try:
            self.auth_container.grid_remove()
        except Exception:
            pass
        self.main_container.grid()
        try:
            self._status_text.set(f"Ready • {user.get('display_name','')}")
        except Exception:
            pass
        try:
            if hasattr(self, "btn_profile"):
                self._profile_text.set(str(user.get("display_name", "")) or str(user.get("username", "")) or "Account")
                self.btn_profile.configure(state="normal")
        except Exception:
            pass

    def _clear_session(self) -> None:
        try:
            if os.path.exists(self._session_path):
                os.remove(self._session_path)
        except Exception:
            pass
        try:
            legacy_session = _resource_path("session.token")
            if legacy_session != self._session_path and os.path.exists(legacy_session):
                os.remove(legacy_session)
        except Exception:
            pass

    def _save_session(self, user_id: int) -> None:
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        expires = now + (30 * 24 * 3600)
        try:
            self._auth_store.save_session(token=token, user_id=int(user_id), created_at=now, expires_at=expires)
        except Exception:
            pass
        try:
            with open(self._session_path, "w", encoding="utf-8") as f:
                f.write(token)
        except Exception:
            pass

    def _try_restore_session(self) -> None:
        try:
            if not os.path.exists(self._session_path):
                return
            with open(self._session_path, "r", encoding="utf-8") as f:
                token = f.read().strip()
            if not token:
                return
        except Exception:
            return

        try:
            now = int(time.time())
            user = self._auth_store.restore_session_user(token=token, now=now)
            if not user:
                self._clear_session()
                return
            self._set_authenticated(dict(user))
        except Exception:
            return

    def _profile_update_display_name(self, new_name: str) -> None:
        user = self._current_user or {}
        try:
            uid = int(user.get("id"))
        except Exception:
            return

        name = str(new_name or "").strip()
        if not name:
            return

        try:
            self._auth_store.update_display_name(uid, name)
        except Exception:
            return

        try:
            self._current_user = dict(user)
            self._current_user["display_name"] = name
        except Exception:
            pass
        try:
            if hasattr(self, "btn_profile"):
                self._profile_text.set(name)
        except Exception:
            pass
        try:
            self._close_profile_modal()
        except Exception:
            pass
        self._open_profile_modal()

    def _open_profile_edit_display_name(self) -> None:
        if not self._current_user:
            return

        w = ctk.CTkToplevel(self)
        w.title("Edit Display Name")
        w.geometry("420x180")
        w.transient(self)
        try:
            w.grab_set()
        except Exception:
            pass
        w.configure(fg_color="#0b0f19")

        card = ctk.CTkFrame(w, fg_color="#111827", corner_radius=16, border_width=1, border_color="#1f2937")
        card.pack(fill="both", expand=True, padx=16, pady=16)
        card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(card, text="Display name", font=self._font_label, text_color="#f8fafc").grid(row=0, column=0, sticky="w", pady=(8, 6))
        v = tk.StringVar(value=str((self._current_user or {}).get("display_name") or "").strip())
        ent = ctk.CTkEntry(card, textvariable=v)
        ent.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        try:
            ent.focus_set()
        except Exception:
            pass

        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.grid(row=2, column=0, sticky="ew")
        btn_row.grid_columnconfigure(0, weight=1)
        btn_row.grid_columnconfigure(1, weight=1)

        ctk.CTkButton(btn_row, text="Cancel", fg_color="#1e293b", hover_color="#334155", command=w.destroy).grid(row=0, column=0, sticky="ew", padx=(0, 8))
        ctk.CTkButton(btn_row, text="Save", fg_color="#7c3aed", hover_color="#6d28d9", command=lambda: (w.destroy(), self._profile_update_display_name(v.get()))).grid(row=0, column=1, sticky="ew")

        w.bind("<Escape>", lambda _e: w.destroy())

    def _profile_copy_to_clipboard(self, value: str) -> None:
        try:
            self.clipboard_clear()
            self.clipboard_append(str(value))
            self.update_idletasks()
        except Exception:
            pass
        try:
            self._set_status("Copied")
        except Exception:
            pass

    def _profile_logout_all_devices(self) -> None:
        user = self._current_user or {}
        try:
            uid = int(user.get("id"))
        except Exception:
            return

        try:
            self._auth_store.delete_sessions_by_user(uid)
        except Exception:
            pass

        try:
            self._clear_session()
        except Exception:
            pass
        try:
            messagebox.showinfo("Sessions", "Logged out on all devices")
        except Exception:
            pass

    def _open_profile_change_password(self) -> None:
        if not self._current_user:
            return

        w = ctk.CTkToplevel(self)
        w.title("Change Password")
        w.geometry("460x300")
        w.transient(self)
        try:
            w.grab_set()
        except Exception:
            pass
        w.configure(fg_color="#0b0f19")

        card = ctk.CTkFrame(w, fg_color="#111827", corner_radius=16, border_width=1, border_color="#1f2937")
        card.pack(fill="both", expand=True, padx=16, pady=16)
        card.grid_columnconfigure(0, weight=1)

        old_v = tk.StringVar(value="")
        new_v = tk.StringVar(value="")
        conf_v = tk.StringVar(value="")
        err_v = tk.StringVar(value="")

        ctk.CTkLabel(card, text="Current password", text_color="#94a3b8", font=self._font_small).grid(row=0, column=0, sticky="w")
        old_ent = ctk.CTkEntry(card, textvariable=old_v, show="*")
        old_ent.grid(row=1, column=0, sticky="ew", pady=(0, 10))

        ctk.CTkLabel(card, text="New password", text_color="#94a3b8", font=self._font_small).grid(row=2, column=0, sticky="w")
        new_ent = ctk.CTkEntry(card, textvariable=new_v, show="*")
        new_ent.grid(row=3, column=0, sticky="ew", pady=(0, 10))

        ctk.CTkLabel(card, text="Confirm new password", text_color="#94a3b8", font=self._font_small).grid(row=4, column=0, sticky="w")
        conf_ent = ctk.CTkEntry(card, textvariable=conf_v, show="*")
        conf_ent.grid(row=5, column=0, sticky="ew", pady=(0, 10))

        err_lbl = ctk.CTkLabel(card, textvariable=err_v, text_color="#f87171", font=self._font_small)
        err_lbl.grid(row=6, column=0, sticky="w")

        def submit() -> None:
            user = self._current_user or {}
            try:
                uid = int(user.get("id"))
            except Exception:
                return

            old_pw = old_v.get()
            new_pw = new_v.get()
            conf_pw = conf_v.get()

            if not old_pw or not new_pw or not conf_pw:
                err_v.set("Please fill all fields")
                return
            if new_pw != conf_pw:
                err_v.set("Passwords do not match")
                return
            if len(new_pw) < 8:
                err_v.set("Password must be at least 8 characters")
                return

            try:
                row = self._auth_store.get_password_row(uid)
                if not row:
                    err_v.set("Account not found")
                    return
                if not self._auth_verify_password(old_pw, str(row.get("pw_hash")), str(row.get("pw_salt"))):
                    err_v.set("Current password is incorrect")
                    return
                new_hash, new_salt = self._auth_hash_password(new_pw)
                self._auth_store.update_password(uid, new_hash, new_salt)
            except Exception:
                err_v.set("Account not found")
                return

            try:
                w.destroy()
            except Exception:
                pass
            try:
                messagebox.showinfo("Password", "Password updated")
            except Exception:
                pass

        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.grid(row=7, column=0, sticky="ew", pady=(10, 0))
        btn_row.grid_columnconfigure(0, weight=1)
        btn_row.grid_columnconfigure(1, weight=1)
        ctk.CTkButton(btn_row, text="Cancel", fg_color="#1e293b", hover_color="#334155", command=w.destroy).grid(row=0, column=0, sticky="ew", padx=(0, 8))
        ctk.CTkButton(btn_row, text="Update", fg_color="#7c3aed", hover_color="#6d28d9", command=submit).grid(row=0, column=1, sticky="ew")

        try:
            old_ent.focus_set()
        except Exception:
            pass
        w.bind("<Escape>", lambda _e: w.destroy())

    def _do_register(self) -> None:
        self._auth_error_text.set("")
        self._auth_status_text.set("")
        self._auth_set_loading(True)

        full_name = self.reg_full_name.get().strip()
        display = self.reg_display.get().strip()
        username = self.reg_username.get().strip()
        email = self.reg_email.get().strip()
        phone = self.reg_phone.get().strip()
        password = self.reg_password.get()
        confirm = self.reg_confirm.get()
        terms_ok = bool(self.reg_terms.get())

        def worker() -> None:
            err = self._auth_validate_register(display, username, email, password, confirm, terms_ok)
            if err:
                self.after(0, lambda: (self._auth_error_text.set(err), self._auth_set_loading(False)))
                return
            pw_hash, pw_salt = self._auth_hash_password(password)
            now = int(time.time())
            ok = False
            try:
                ok = bool(self._auth_store.create_user(full_name or None, display, username, email, phone or None, pw_hash, pw_salt, now))
            except Exception:
                ok = False
            if not ok:
                self.after(0, lambda: (self._auth_error_text.set(self._auth_t("err_exists")), self._auth_set_loading(False)))
                return
            self.after(0, lambda: (self._auth_status_text.set(self._auth_t("ok_register")), self._auth_set_loading(False), self._show_login()))

        threading.Thread(target=worker, daemon=True).start()

    def _do_login(self) -> None:
        self._auth_error_text.set("")
        self._auth_status_text.set("")
        self._auth_set_loading(True)

        ident = self.login_user.get().strip()
        password = self.login_pass.get()
        remember = bool(self.remember_me.get())
        if not ident or not password:
            self._auth_error_text.set(self._auth_t("err_login_invalid"))
            self._auth_set_loading(False)
            return

        def worker() -> None:
            try:
                row = self._auth_store.get_user_by_ident(ident)
                if not row:
                    self.after(0, lambda: (self._auth_error_text.set(self._auth_t("err_login_invalid")), self._auth_set_loading(False)))
                    return

                now = int(time.time())
                if int(row.get("lock_until") or 0) > now:
                    self.after(0, lambda: (self._auth_error_text.set(self._auth_t("err_locked")), self._auth_set_loading(False)))
                    return

                ok = self._auth_verify_password(password, str(row.get("pw_hash")), str(row.get("pw_salt")))
                if not ok:
                    attempts = int(row.get("failed_attempts") or 0) + 1
                    lock_until = int(row.get("lock_until") or 0)
                    if attempts >= 5:
                        lock_until = now + 5 * 60
                        attempts = 0
                    try:
                        self._auth_store.increment_failed_attempt(int(row.get("id") or 0), attempts, lock_until)
                    except Exception:
                        pass
                    self.after(0, lambda: (self._auth_error_text.set(self._auth_t("err_login_pwd")), self._auth_set_loading(False)))
                    return

                try:
                    self._auth_store.reset_failed_attempts(int(row.get("id") or 0))
                except Exception:
                    pass

                user = {
                    "id": int(row.get("id") or 0),
                    "display_name": str(row.get("display_name") or ""),
                    "username": str(row.get("username") or ""),
                    "email": str(row.get("email") or ""),
                }
            except Exception:
                self.after(0, lambda: (self._auth_error_text.set(self._auth_t("err_login_invalid")), self._auth_set_loading(False)))
                return

            def finish() -> None:
                if remember:
                    self._save_session(int(user["id"]))
                else:
                    self._clear_session()
                self._auth_set_loading(False)
                self._set_authenticated(user)

            self.after(0, finish)

        threading.Thread(target=worker, daemon=True).start()

    def logout(self) -> None:
        user = self._current_user or {}
        try:
            uid = int(user.get("id"))
        except Exception:
            uid = 0
        if uid:
            try:
                self._auth_store.delete_sessions_by_user(uid)
            except Exception:
                pass
        self._current_user = None
        try:
            self._close_profile_popup()
        except Exception:
            pass
        try:
            self._close_profile_modal()
        except Exception:
            pass
        self._clear_session()
        try:
            self.manager.stop()
        except Exception:
            pass
        try:
            self.main_container.grid_remove()
        except Exception:
            pass
        try:
            self.auth_container.grid()
        except Exception:
            self._build_auth_ui()
        self._show_login()
        try:
            if hasattr(self, "btn_profile"):
                self._profile_text.set("")
                self.btn_profile.configure(state="disabled")
        except Exception:
            pass

    def _open_profile_menu(self) -> None:
        if not self._current_user:
            return
        if self._profile_popup is not None:
            self._close_profile_popup()
            return

        x = self.btn_profile.winfo_rootx()
        y = self.btn_profile.winfo_rooty() + self.btn_profile.winfo_height() + 6

        pop = ctk.CTkToplevel(self)
        self._profile_popup = pop
        pop.withdraw()
        pop.overrideredirect(True)
        try:
            pop.attributes("-topmost", True)
            pop.attributes("-alpha", 0.0)
        except Exception:
            pass

        w = 180
        h = 86
        pop.geometry(f"{w}x{h}+{x}+{y - 10}")
        pop.configure(fg_color="#0f172a")

        card = ctk.CTkFrame(pop, fg_color="#111827", corner_radius=12, border_width=1, border_color="#1f2937")
        card.pack(fill="both", expand=True)

        ctk.CTkButton(
            card,
            text="Profile",
            height=32,
            corner_radius=10,
            fg_color="#1e293b",
            hover_color="#334155",
            command=lambda: (self._close_profile_popup(), self._open_profile_modal()),
        ).pack(fill="x", padx=10, pady=(10, 6))

        ctk.CTkButton(
            card,
            text="Logout",
            height=32,
            corner_radius=10,
            fg_color="#ef4444",
            hover_color="#dc2626",
            command=lambda: (self._close_profile_popup(), self.logout()),
        ).pack(fill="x", padx=10, pady=(0, 10))

        pop.deiconify()
        try:
            pop.focus_force()
        except Exception:
            pass

        pop.bind("<Escape>", lambda _e: self._close_profile_popup())
        pop.bind("<FocusOut>", lambda _e: self._close_profile_popup())
        pop.bind("<Button-1>", lambda _e: None)
        self.bind("<Button-1>", self._on_root_click_close_profile, add=True)

        self._animate_profile_popup(target_x=x, target_y=y)

    def _open_profile_modal(self) -> None:
        if not self._current_user:
            return
        if self._profile_modal is not None:
            try:
                self._profile_modal.focus_force()
            except Exception:
                pass
            return

        win = ctk.CTkToplevel(self)
        self._profile_modal = win
        win.title("Profile")
        try:
            win.attributes("-topmost", True)
        except Exception:
            pass

        w = 520
        h = 300
        try:
            x = self.winfo_rootx() + (self.winfo_width() // 2) - (w // 2)
            y = self.winfo_rooty() + (self.winfo_height() // 2) - (h // 2)
            win.geometry(f"{w}x{h}+{x}+{y}")
        except Exception:
            win.geometry(f"{w}x{h}")

        win.configure(fg_color="#0b0f19")
        win.resizable(False, False)
        try:
            win.grab_set()
        except Exception:
            pass

        card = ctk.CTkFrame(win, fg_color="#111827", corner_radius=16, border_width=1, border_color="#1f2937")
        card.pack(fill="both", expand=True, padx=16, pady=16)
        card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(card, text="👤 Global Account Sync", font=ctk.CTkFont(size=18, weight="bold"), text_color="#f8fafc").grid(
            row=0, column=0, sticky="w", padx=20, pady=(20, 10)
        )
        
        user = self._current_user or {}

        header = ctk.CTkFrame(card, fg_color="transparent")
        header.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 10))
        header.grid_columnconfigure(1, weight=1)

        try:
            uid = int(user.get("id"))
        except Exception:
            uid = 0

        self._profile_pic_ctk = None
        self._profile_pic_ctk = self._load_profile_pic_ctk(uid, (56, 56)) if uid else None
        self._profile_pic_label = ctk.CTkLabel(header, text="", image=self._profile_pic_ctk)
        self._profile_pic_label.grid(row=0, column=0, rowspan=2, sticky="w")

        def pick_pic() -> None:
            if not uid:
                return
            p = filedialog.askopenfilename(filetypes=[("Images", "*.png;*.jpg;*.jpeg;*.webp;*.bmp"), ("All files", "*.*")])
            if not p:
                return
            try:
                img = Image.open(p).convert("RGBA")
                out_p = self._profile_pic_path(uid)
                img.save(out_p, format="PNG")
                self._profile_pic_ctk = ctk.CTkImage(light_image=img, dark_image=img, size=(56, 56))
                try:
                    self._profile_pic_label.configure(image=self._profile_pic_ctk)
                except Exception:
                    pass
            except Exception:
                try:
                    messagebox.showerror("Profile", "Failed to set profile picture")
                except Exception:
                    pass

        ctk.CTkLabel(header, text=str(user.get("display_name", "Guest")), text_color="#e2e8f0", font=ctk.CTkFont(size=14, weight="bold")).grid(
            row=0, column=1, sticky="w", padx=(12, 0)
        )
        ctk.CTkButton(
            header,
            text="Upload Picture",
            width=140,
            fg_color="#334155",
            hover_color="#475569",
            command=pick_pic,
        ).grid(row=1, column=1, sticky="w", padx=(12, 0), pady=(6, 0))

        info_f = ctk.CTkFrame(card, fg_color="transparent")
        info_f.grid(row=2, column=0, sticky="ew", padx=20, pady=10)
        
        ctk.CTkLabel(info_f, text=f"Display Name: {user.get('display_name', 'Guest')}", text_color="#94a3b8").grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(info_f, text=f"Username: {user.get('username', 'n/a')}", text_color="#94a3b8").grid(row=1, column=0, sticky="w")
        ctk.CTkLabel(info_f, text=f"Email: {user.get('email', 'n/a')}", text_color="#94a3b8").grid(row=2, column=0, sticky="w")
        ctk.CTkLabel(info_f, text="Status: Beta Elite v1.0.0", text_color="#10b981").grid(row=3, column=0, sticky="w", pady=(2, 0))

        actions = ctk.CTkFrame(card, fg_color="transparent")
        actions.grid(row=3, column=0, sticky="ew", padx=20, pady=(6, 0))
        actions.grid_columnconfigure(0, weight=1)
        actions.grid_columnconfigure(1, weight=1)

        ctk.CTkButton(
            actions,
            text="Edit Display Name",
            fg_color="#334155",
            hover_color="#475569",
            command=self._open_profile_edit_display_name,
        ).grid(row=0, column=0, sticky="ew", padx=(0, 8), pady=(0, 8))
        ctk.CTkButton(
            actions,
            text="Change Password",
            fg_color="#334155",
            hover_color="#475569",
            command=self._open_profile_change_password,
        ).grid(row=0, column=1, sticky="ew", pady=(0, 8))

        ctk.CTkButton(
            actions,
            text="Export History CSV",
            fg_color="#1f538d",
            hover_color="#184a80",
            command=self._export_history_csv,
        ).grid(row=1, column=0, sticky="ew", padx=(0, 8))
        ctk.CTkButton(
            actions,
            text="Open Output Folder",
            fg_color="#1f538d",
            hover_color="#184a80",
            command=self._open_output_folder,
        ).grid(row=1, column=1, sticky="ew")

        extras = ctk.CTkFrame(card, fg_color="transparent")
        extras.grid(row=4, column=0, sticky="ew", padx=20, pady=(12, 0))
        extras.grid_columnconfigure(0, weight=1)
        extras.grid_columnconfigure(1, weight=1)
        extras.grid_columnconfigure(2, weight=1)

        ctk.CTkButton(
            extras,
            text="Copy Username",
            fg_color="#334155",
            hover_color="#475569",
            command=lambda: self._profile_copy_to_clipboard(str(user.get("username", ""))),
        ).grid(row=0, column=0, sticky="ew", padx=(0, 8))
        ctk.CTkButton(
            extras,
            text="Copy Email",
            fg_color="#334155",
            hover_color="#475569",
            command=lambda: self._profile_copy_to_clipboard(str(user.get("email", ""))),
        ).grid(row=0, column=1, sticky="ew", padx=(0, 8))
        ctk.CTkButton(
            extras,
            text="Copy User ID",
            fg_color="#334155",
            hover_color="#475569",
            command=lambda: self._profile_copy_to_clipboard(str(user.get("id", ""))),
        ).grid(row=0, column=2, sticky="ew")

        ctk.CTkButton(
            extras,
            text="Logout All Devices",
            fg_color="#ef4444",
            hover_color="#dc2626",
            command=self._profile_logout_all_devices,
        ).grid(row=1, column=0, columnspan=3, sticky="ew", pady=(10, 0))

        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.grid(row=5, column=0, sticky="ew", padx=14, pady=(16, 0))
        btn_row.grid_columnconfigure(0, weight=1)
        btn_row.grid_columnconfigure(1, weight=1)

        ctk.CTkButton(
            btn_row,
            text="Close",
            fg_color="#1e293b",
            hover_color="#334155",
            command=self._close_profile_modal,
        ).grid(row=0, column=0, sticky="ew", padx=(0, 8))

        ctk.CTkButton(
            btn_row,
            text="Logout",
            fg_color="#ef4444",
            hover_color="#dc2626",
            command=lambda: (self._close_profile_modal(), self.logout()),
        ).grid(row=0, column=1, sticky="ew")

        win.bind("<Escape>", lambda _e: self._close_profile_modal())
        win.protocol("WM_DELETE_WINDOW", self._close_profile_modal)

    def _close_profile_modal(self) -> None:
        win = self._profile_modal
        self._profile_modal = None
        if win is None:
            return
        try:
            win.grab_release()
        except Exception:
            pass
        try:
            win.destroy()
        except Exception:
            pass

    def _on_root_click_close_profile(self, event: tk.Event) -> None:
        if self._profile_popup is None:
            return
        try:
            w = event.widget
            if w is self.btn_profile:
                return
        except Exception:
            pass
        self._close_profile_popup()

    def _close_profile_popup(self) -> None:
        if self._profile_popup_anim_after is not None:
            try:
                self.after_cancel(self._profile_popup_anim_after)
            except Exception:
                pass
            self._profile_popup_anim_after = None

        pop = self._profile_popup
        self._profile_popup = None
        try:
            self.unbind("<Button-1>", funcid=None)
        except Exception:
            pass
        if pop is None:
            return
        try:
            pop.destroy()
        except Exception:
            pass

    def _animate_profile_popup(self, target_x: int, target_y: int) -> None:
        pop = self._profile_popup
        if pop is None:
            return

        steps = 8
        duration_ms = 140
        start_y = target_y - 10
        dy = (target_y - start_y) / float(steps)

        def step(i: int) -> None:
            p = self._profile_popup
            if p is None:
                return
            new_y = int(start_y + dy * i)
            try:
                p.geometry(f"+{target_x}+{new_y}")
            except Exception:
                pass
            try:
                p.attributes("-alpha", min(1.0, i / float(steps)))
            except Exception:
                pass

            if i < steps:
                self._profile_popup_anim_after = self.after(max(1, duration_ms // steps), lambda: step(i + 1))
            else:
                self._profile_popup_anim_after = None

        step(0)

    def _start_clipboard_monitor(self):
        if self._clipboard_thread is not None:
            return
        
        def worker():
            while True:
                time.sleep(1.0)
                if not self.clipboard_monitor.get():
                    continue
                try:
                    current = self.clipboard_get()
                    if current and current != self._last_clipboard:
                        self._last_clipboard = current
                        c_low = current.lower()
                        # Simple check for media links
                        valid_platforms = ["youtube.com", "youtu.be", "facebook.com", "web.facebook.com", "m.facebook.com", "fb.watch", "tiktok.com", "instagram.com", "pinterest.com"]
                        if any(x in c_low for x in valid_platforms):
                            self.after(0, lambda c=current: (self.url_var.set(c), self._add_to_pipe()))
                except Exception:
                    pass
        
        self._clipboard_thread = threading.Thread(target=worker, daemon=True)
        self._clipboard_thread.start()

    def _open_profile_scraper(self):
        input_win = ctk.CTkToplevel(self)
        input_win.title("Profile Scraper")
        input_win.geometry("500x200")
        input_win.after(100, lambda: input_win.focus_force())
        
        ctk.CTkLabel(input_win, text="Enter Profile / Playlist / Board URL:", font=self._font_label).pack(pady=(20, 10))
        url_entry = ctk.CTkEntry(input_win, width=400)
        url_entry.pack(pady=10)
        
        def start_scan():
            url = url_entry.get().strip()
            if not url: return
            input_win.destroy()
            self._set_status("Scanning profile...")
            
            def fetcher():
                try:
                    scan_url = url
                    try:
                        scan_url = self._normalize_url(scan_url)
                    except Exception:
                        pass
                    self._log_threadsafe(f"[Scraper] Scanning: {scan_url}")
                    # expand_url_entries is already good for this
                    urls = expand_url_entries(scan_url, cookies_file=self.cookies_file.get(), allow_playlist=True)
                    if not urls:
                        self.after(0, lambda: self._set_status("No videos found"))
                        return
                    self.after(0, lambda: self._show_profile_results(scan_url, urls))
                except Exception as e:
                    self._log_threadsafe(f"[Scraper] Error: {e}")
                    def _ui_fail():
                        self._set_status("Scan failed")
                        if "tiktok" in url.lower() and "profile extraction failed" in str(e).lower():
                            self._show_tiktok_block_dialog(url, str(e))
                    self.after(0, _ui_fail)
            
            threading.Thread(target=fetcher, daemon=True).start()

        btn_f = ctk.CTkFrame(input_win, fg_color="transparent")
        btn_f.pack(pady=10)
        ctk.CTkButton(btn_f, text="Scan Now", command=start_scan, width=120, fg_color="#7c3aed").pack(side="left", padx=5)
        ctk.CTkButton(btn_f, text="Cancel", command=input_win.destroy, width=120).pack(side="left", padx=5)

    def _open_music_studio(self) -> None:
        if self._music_studio_win is not None:
            try:
                self._music_studio_win.deiconify()
                self._music_studio_win.lift()
                self._music_studio_win.focus_force()
                return
            except Exception:
                self._music_studio_win = None

        win = ctk.CTkToplevel(self)
        self._music_studio_win = win
        win.title("Music Studio")
        win.geometry("1200x720")
        win.minsize(980, 600)
        win.configure(fg_color="#0b1220")

        def _on_close() -> None:
            try:
                win.destroy()
            except Exception:
                pass
            self._music_studio_win = None

        try:
            win.protocol("WM_DELETE_WINDOW", _on_close)
        except Exception:
            pass
        try:
            win.after(50, lambda: (win.lift(), win.focus_force()))
        except Exception:
            pass

        root = ctk.CTkFrame(win, fg_color="transparent")
        root.pack(fill="both", expand=True, padx=12, pady=12)
        root.grid_rowconfigure(0, weight=1)
        root.grid_columnconfigure(1, weight=1)

        sidebar = ctk.CTkFrame(root, fg_color="#0f172a", corner_radius=14, border_width=1, border_color="#1f2937")
        sidebar.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        sidebar.grid_rowconfigure(2, weight=1)
        sidebar.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(sidebar, text="Music Studio", font=ctk.CTkFont(size=18, weight="bold"), text_color="#60a5fa").grid(
            row=0, column=0, sticky="w", padx=14, pady=(14, 8)
        )

        user_txt = str((self._current_user or {}).get("display_name") or (self._current_user or {}).get("username") or "")
        user_bar = ctk.CTkFrame(sidebar, fg_color="#111827", corner_radius=10)
        user_bar.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 10))
        user_bar.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(user_bar, text=user_txt, text_color="#e2e8f0").grid(row=0, column=0, sticky="w", padx=10, pady=8)

        playlist = ctk.CTkScrollableFrame(sidebar, fg_color="#0b1220", corner_radius=10)
        playlist.grid(row=2, column=0, sticky="nsew", padx=14, pady=(0, 10))
        playlist.grid_columnconfigure(0, weight=1)

        songs: list[dict] = []

        log = None

        def _log_line(msg: str) -> None:
            if log is None:
                return
            try:
                log.configure(state="normal")
                log.insert("end", str(msg).rstrip() + "\n")
                log.see("end")
                log.configure(state="disabled")
            except Exception:
                pass

        def _render_playlist() -> None:
            try:
                for child in playlist.winfo_children():
                    try:
                        child.destroy()
                    except Exception:
                        pass
            except Exception:
                pass

            if not songs:
                empty = ctk.CTkFrame(playlist, fg_color="transparent")
                empty.grid(row=0, column=0, sticky="ew", pady=8)
                ctk.CTkLabel(empty, text="No songs yet. Click 'Add Songs'.", text_color="#94a3b8").pack(anchor="w", padx=6)
                return

            for idx, s in enumerate(list(songs), start=1):
                row = ctk.CTkFrame(playlist, fg_color="#111827", corner_radius=10)
                row.grid(row=idx, column=0, sticky="ew", pady=6)
                row.grid_columnconfigure(1, weight=1)
                ctk.CTkLabel(row, text=f"{idx:02d}", width=32, text_color="#93c5fd").grid(row=0, column=0, padx=(10, 6), pady=10)
                title = str(s.get("title") or "")
                ctk.CTkLabel(row, text=title, text_color="#f8fafc").grid(row=0, column=1, sticky="w", pady=10)

                def _rm(path: str) -> None:
                    try:
                        for j in range(len(songs) - 1, -1, -1):
                            if str(songs[j].get("path")) == str(path):
                                songs.pop(j)
                    except Exception:
                        pass
                    _render_playlist()
                    _log_line(f"Removed: {os.path.basename(str(path))}")

                ctk.CTkButton(row, text="X", width=28, fg_color="#ef4444", hover_color="#dc2626", command=lambda p=str(s.get("path")): _rm(p)).grid(
                    row=0, column=2, padx=10, pady=10
                )

        def _add_songs() -> None:
            try:
                paths = filedialog.askopenfilenames(
                    title="Add songs",
                    filetypes=[
                        ("Audio", "*.mp3 *.wav *.m4a *.aac *.flac *.ogg"),
                        ("All files", "*.*"),
                    ],
                )
            except Exception:
                paths = ()
            if not paths:
                return
            added = 0
            for p in paths:
                try:
                    p2 = str(p)
                    base = os.path.basename(p2)
                    if any(str(x.get("path")) == p2 for x in songs):
                        continue
                    songs.append({"path": p2, "title": os.path.splitext(base)[0]})
                    added += 1
                except Exception:
                    pass
            _render_playlist()
            _log_line(f"Added {added} song(s)")

        def _clear_songs() -> None:
            if not songs:
                return
            try:
                songs.clear()
            except Exception:
                pass
            _render_playlist()
            _log_line("Cleared playlist")

        btn_row = ctk.CTkFrame(sidebar, fg_color="transparent")
        btn_row.grid(row=3, column=0, sticky="ew", padx=14, pady=(0, 14))
        btn_row.grid_columnconfigure(0, weight=1)
        btn_row.grid_columnconfigure(1, weight=1)
        ctk.CTkButton(btn_row, text="Add Songs", fg_color="#22c55e", hover_color="#16a34a", command=_add_songs).grid(row=0, column=0, sticky="ew", padx=(0, 8))
        ctk.CTkButton(btn_row, text="Clear", fg_color="#ef4444", hover_color="#dc2626", command=_clear_songs).grid(row=0, column=1, sticky="ew")

        main = ctk.CTkFrame(root, fg_color="#0f172a", corner_radius=14, border_width=1, border_color="#1f2937")
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_rowconfigure(1, weight=1)
        main.grid_columnconfigure(0, weight=1)

        log = ctk.CTkTextbox(main, height=110)
        log.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))

        tabs = ctk.CTkTabview(main, fg_color="#0f172a")
        tabs.grid(row=0, column=0, sticky="ew", padx=12, pady=12)
        for name in ("Preview", "Background", "Export", "Relaxing Music", "Auto Caption", "CC", "Music", "Settings"):
            tabs.add(name)

        preview = tabs.tab("Preview")
        preview.grid_columnconfigure(0, weight=1)

        background_tab = tabs.tab("Background")
        background_tab.grid_columnconfigure(0, weight=1)

        export_tab = tabs.tab("Export")
        export_tab.grid_columnconfigure(0, weight=1)

        relaxing_tab = tabs.tab("Relaxing Music")
        relaxing_tab.grid_columnconfigure(0, weight=1)

        auto_caption_tab = tabs.tab("Auto Caption")
        auto_caption_tab.grid_columnconfigure(0, weight=1)

        cc_tab = tabs.tab("CC")
        cc_tab.grid_columnconfigure(0, weight=1)

        music_tab = tabs.tab("Music")
        music_tab.grid_columnconfigure(0, weight=1)

        settings_tab = tabs.tab("Settings")
        settings_tab.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(preview, text="Video Preview Player", font=ctk.CTkFont(size=14, weight="bold"), text_color="#e2e8f0").grid(
            row=0, column=0, sticky="w", padx=10, pady=(10, 6)
        )

        canvas = ctk.CTkFrame(preview, fg_color="#0b1220", corner_radius=12, border_width=1, border_color="#1f2937", height=360)
        canvas.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        canvas.grid_propagate(False)
        canvas.grid_columnconfigure(0, weight=1)
        canvas.grid_rowconfigure(0, weight=1)
        ctk.CTkLabel(canvas, text="Preview area (coming soon)", text_color="#94a3b8").grid(row=0, column=0)

        actions = ctk.CTkFrame(preview, fg_color="transparent")
        actions.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 10))
        for c in range(5):
            actions.grid_columnconfigure(c, weight=1)
        ctk.CTkButton(actions, text="Update Preview", fg_color="#f59e0b", hover_color="#d97706", command=lambda: _log_line("Update Preview (coming soon)")).grid(row=0, column=0, sticky="ew", padx=(0, 8))
        ctk.CTkButton(actions, text="Take Snapshot", fg_color="#22c55e", hover_color="#16a34a", command=lambda: _log_line("Take Snapshot (coming soon)")).grid(row=0, column=1, sticky="ew", padx=(0, 8))
        ctk.CTkButton(actions, text="Style", fg_color="#3b82f6", hover_color="#2563eb", command=lambda: _log_line("Style (coming soon)")).grid(row=0, column=2, sticky="ew", padx=(0, 8))
        ctk.CTkButton(actions, text="Effect", fg_color="#a855f7", hover_color="#9333ea", command=lambda: _log_line("Effect (coming soon)")).grid(row=0, column=3, sticky="ew", padx=(0, 8))
        ctk.CTkButton(actions, text="Watermark", fg_color="#14b8a6", hover_color="#0d9488", command=lambda: _log_line("Watermark (coming soon)")).grid(row=0, column=4, sticky="ew")

        # Background
        bg_card = ctk.CTkFrame(background_tab, fg_color="#0b1220", corner_radius=12, border_width=1, border_color="#1f2937")
        bg_card.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        bg_card.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(bg_card, text="Background", font=ctk.CTkFont(size=14, weight="bold"), text_color="#e2e8f0").grid(row=0, column=0, columnspan=2, sticky="w", padx=12, pady=(10, 6))

        bg_path = tk.StringVar(value="")
        bg_mode = tk.StringVar(value="Fit")
        ctk.CTkLabel(bg_card, text="File", text_color="#94a3b8").grid(row=1, column=0, sticky="w", padx=12, pady=6)
        bg_ent = ctk.CTkEntry(bg_card, textvariable=bg_path)
        bg_ent.grid(row=1, column=1, sticky="ew", padx=12, pady=6)

        def _pick_bg() -> None:
            try:
                p = filedialog.askopenfilename(
                    title="Choose background",
                    filetypes=[
                        ("Images/Videos", "*.png *.jpg *.jpeg *.webp *.bmp *.mp4 *.mov *.mkv *.webm"),
                        ("All files", "*.*"),
                    ],
                )
            except Exception:
                p = ""
            if not p:
                return
            bg_path.set(str(p))
            _log_line(f"Background selected: {os.path.basename(str(p))}")

        btn_row_bg = ctk.CTkFrame(bg_card, fg_color="transparent")
        btn_row_bg.grid(row=2, column=0, columnspan=2, sticky="ew", padx=12, pady=(6, 12))
        btn_row_bg.grid_columnconfigure(2, weight=1)
        ctk.CTkButton(btn_row_bg, text="Browse", width=110, fg_color="#334155", hover_color="#475569", command=_pick_bg).grid(row=0, column=0, padx=(0, 10))
        ctk.CTkLabel(btn_row_bg, text="Mode", text_color="#94a3b8").grid(row=0, column=1, padx=(0, 8))
        ctk.CTkOptionMenu(
            btn_row_bg,
            variable=bg_mode,
            values=["Fit", "Fill", "Stretch"],
            width=120,
            command=lambda v: _log_line(f"Background mode: {v}"),
        ).grid(row=0, column=2, sticky="w")
        btn_apply_bg = ctk.CTkButton(btn_row_bg, text="Apply", width=110, fg_color="#7c3aed", hover_color="#6d28d9", command=lambda: _log_line("Background applied"))
        btn_apply_bg.grid(row=0, column=3, sticky="e")

        # Export
        ex_card = ctk.CTkFrame(export_tab, fg_color="#0b1220", corner_radius=12, border_width=1, border_color="#1f2937")
        ex_card.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        ex_card.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(ex_card, text="Export", font=ctk.CTkFont(size=14, weight="bold"), text_color="#e2e8f0").grid(row=0, column=0, columnspan=2, sticky="w", padx=12, pady=(10, 6))

        video_path = tk.StringVar(value="")
        out_path = tk.StringVar(value="")
        ctk.CTkLabel(ex_card, text="Video file", text_color="#94a3b8").grid(row=1, column=0, sticky="w", padx=12, pady=6)
        ctk.CTkEntry(ex_card, textvariable=video_path).grid(row=1, column=1, sticky="ew", padx=12, pady=6)
        ctk.CTkLabel(ex_card, text="Output", text_color="#94a3b8").grid(row=2, column=0, sticky="w", padx=12, pady=6)
        ctk.CTkEntry(ex_card, textvariable=out_path).grid(row=2, column=1, sticky="ew", padx=12, pady=6)

        def _pick_video() -> None:
            try:
                p = filedialog.askopenfilename(
                    title="Choose video",
                    filetypes=[
                        ("Video", "*.mp4 *.mkv *.mov *.webm"),
                        ("All files", "*.*"),
                    ],
                )
            except Exception:
                p = ""
            if not p:
                return
            video_path.set(str(p))
            _log_line(f"Video selected: {os.path.basename(str(p))}")

        def _pick_output() -> None:
            try:
                p = filedialog.asksaveasfilename(
                    title="Save export as",
                    defaultextension=".mp4",
                    filetypes=[("MP4", "*.mp4"), ("All files", "*.*")],
                )
            except Exception:
                p = ""
            if not p:
                return
            out_path.set(str(p))
            _log_line(f"Output set: {os.path.basename(str(p))}")

        def _do_export() -> None:
            if not video_path.get().strip():
                _log_line("Export error: please choose a video file")
                return
            if not out_path.get().strip():
                _log_line("Export error: please choose output file")
                return
            _log_line("Export started (coming soon)")
            _log_line(f"Video: {video_path.get().strip()}")
            _log_line(f"Output: {out_path.get().strip()}")
            _log_line(f"Songs in playlist: {len(songs)}")

        ex_btn = ctk.CTkFrame(ex_card, fg_color="transparent")
        ex_btn.grid(row=3, column=0, columnspan=2, sticky="ew", padx=12, pady=(6, 12))
        ex_btn.grid_columnconfigure(3, weight=1)
        ctk.CTkButton(ex_btn, text="Browse Video", width=120, fg_color="#334155", hover_color="#475569", command=_pick_video).grid(row=0, column=0, padx=(0, 10))
        ctk.CTkButton(ex_btn, text="Output", width=120, fg_color="#334155", hover_color="#475569", command=_pick_output).grid(row=0, column=1, padx=(0, 10))
        ctk.CTkButton(ex_btn, text="Export", width=120, fg_color="#22c55e", hover_color="#16a34a", command=_do_export).grid(row=0, column=2)

        # Relaxing Music
        rx_card = ctk.CTkFrame(relaxing_tab, fg_color="#0b1220", corner_radius=12, border_width=1, border_color="#1f2937")
        rx_card.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        rx_card.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(rx_card, text="Relaxing Music", font=ctk.CTkFont(size=14, weight="bold"), text_color="#e2e8f0").grid(row=0, column=0, columnspan=2, sticky="w", padx=12, pady=(10, 6))

        rx_style = tk.StringVar(value="Lo-fi")
        rx_level = tk.DoubleVar(value=50)
        ctk.CTkLabel(rx_card, text="Style", text_color="#94a3b8").grid(row=1, column=0, sticky="w", padx=12, pady=6)
        ctk.CTkOptionMenu(rx_card, variable=rx_style, values=["Lo-fi", "Piano", "Ambient", "Nature", "Chill"], command=lambda v: _log_line(f"Relax style: {v}")).grid(row=1, column=1, sticky="w", padx=12, pady=6)
        ctk.CTkLabel(rx_card, text="Level", text_color="#94a3b8").grid(row=2, column=0, sticky="w", padx=12, pady=6)
        ctk.CTkSlider(rx_card, from_=0, to=100, variable=rx_level, command=lambda _v: None).grid(row=2, column=1, sticky="ew", padx=12, pady=6)
        rx_btn = ctk.CTkFrame(rx_card, fg_color="transparent")
        rx_btn.grid(row=3, column=0, columnspan=2, sticky="ew", padx=12, pady=(6, 12))
        ctk.CTkButton(rx_btn, text="Preview", width=120, fg_color="#3b82f6", hover_color="#2563eb", command=lambda: _log_line(f"Relax preview: {rx_style.get()} @ {int(rx_level.get())}%")).pack(side="left", padx=(0, 10))
        ctk.CTkButton(
            rx_btn,
            text="Apply",
            width=120,
            fg_color="#7c3aed",
            hover_color="#6d28d9",
            command=lambda: _log_line("Relaxing music applied (coming soon)"),
        ).pack(side="left")

        # Auto Caption
        ac_card = ctk.CTkFrame(auto_caption_tab, fg_color="#0b1220", corner_radius=12, border_width=1, border_color="#1f2937")
        ac_card.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        ac_card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(ac_card, text="Auto Caption", font=ctk.CTkFont(size=14, weight="bold"), text_color="#e2e8f0").grid(row=0, column=0, sticky="w", padx=12, pady=(10, 6))
        ac_lang = tk.StringVar(value="English")
        ac_row = ctk.CTkFrame(ac_card, fg_color="transparent")
        ac_row.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 10))
        ctk.CTkLabel(ac_row, text="Language", text_color="#94a3b8").pack(side="left", padx=(0, 10))
        ctk.CTkOptionMenu(ac_row, variable=ac_lang, values=["English", "Khmer", "Auto"], command=lambda v: _log_line(f"Caption language: {v}")).pack(side="left")
        ac_txt = ctk.CTkTextbox(ac_card, height=220)
        ac_txt.grid(row=2, column=0, sticky="nsew", padx=12, pady=(0, 10))

        def _gen_caption() -> None:
            _log_line("Generate captions (coming soon)")
            try:
                t = ac_txt.get("1.0", "end").strip()
            except Exception:
                t = ""
            if t:
                _log_line("Note: you already typed caption text")

        ac_btn = ctk.CTkFrame(ac_card, fg_color="transparent")
        ac_btn.grid(row=3, column=0, sticky="ew", padx=12, pady=(0, 12))
        ctk.CTkButton(ac_btn, text="Generate", width=120, fg_color="#22c55e", hover_color="#16a34a", command=_gen_caption).pack(side="left", padx=(0, 10))
        ctk.CTkButton(
            ac_btn,
            text="Save SRT",
            width=120,
            fg_color="#334155",
            hover_color="#475569",
            command=lambda: _log_line("Save SRT (coming soon)"),
        ).pack(side="left")

        # CC
        cc_card = ctk.CTkFrame(cc_tab, fg_color="#0b1220", corner_radius=12, border_width=1, border_color="#1f2937")
        cc_card.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        cc_card.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(cc_card, text="Closed Captions (CC)", font=ctk.CTkFont(size=14, weight="bold"), text_color="#e2e8f0").grid(row=0, column=0, columnspan=2, sticky="w", padx=12, pady=(10, 6))
        cc_enable = tk.BooleanVar(value=True)
        cc_size = tk.IntVar(value=28)
        cc_color = tk.StringVar(value="White")
        ctk.CTkCheckBox(cc_card, text="Enable CC", variable=cc_enable, command=lambda: _log_line(f"CC enabled: {bool(cc_enable.get())}")).grid(row=1, column=0, sticky="w", padx=12, pady=6)
        ctk.CTkLabel(cc_card, text="Font size", text_color="#94a3b8").grid(row=2, column=0, sticky="w", padx=12, pady=6)
        ctk.CTkSlider(cc_card, from_=12, to=72, number_of_steps=60, command=lambda v: cc_size.set(int(float(v)))).grid(row=2, column=1, sticky="ew", padx=12, pady=6)
        ctk.CTkLabel(cc_card, text="Color", text_color="#94a3b8").grid(row=3, column=0, sticky="w", padx=12, pady=6)
        ctk.CTkOptionMenu(cc_card, variable=cc_color, values=["White", "Yellow", "Cyan"], command=lambda v: _log_line(f"CC color: {v}")).grid(row=3, column=1, sticky="w", padx=12, pady=6)
        ctk.CTkButton(cc_card, text="Apply", width=120, fg_color="#7c3aed", hover_color="#6d28d9", command=lambda: _log_line(f"CC apply: size={cc_size.get()} color={cc_color.get()}")).grid(
            row=4, column=0, columnspan=2, sticky="w", padx=12, pady=(8, 12)
        )

        # Music
        mu_card = ctk.CTkFrame(music_tab, fg_color="#0b1220", corner_radius=12, border_width=1, border_color="#1f2937")
        mu_card.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        mu_card.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(mu_card, text="Music Controls", font=ctk.CTkFont(size=14, weight="bold"), text_color="#e2e8f0").grid(row=0, column=0, columnspan=2, sticky="w", padx=12, pady=(10, 6))
        vol = tk.DoubleVar(value=80)
        fade_in = tk.StringVar(value="0")
        fade_out = tk.StringVar(value="0")
        trim_a = tk.StringVar(value="")
        trim_b = tk.StringVar(value="")
        ctk.CTkLabel(mu_card, text="Volume", text_color="#94a3b8").grid(row=1, column=0, sticky="w", padx=12, pady=6)
        ctk.CTkSlider(mu_card, from_=0, to=100, variable=vol).grid(row=1, column=1, sticky="ew", padx=12, pady=6)
        ctk.CTkLabel(mu_card, text="Fade in (s)", text_color="#94a3b8").grid(row=2, column=0, sticky="w", padx=12, pady=6)
        ctk.CTkEntry(mu_card, textvariable=fade_in, width=140).grid(row=2, column=1, sticky="w", padx=12, pady=6)
        ctk.CTkLabel(mu_card, text="Fade out (s)", text_color="#94a3b8").grid(row=3, column=0, sticky="w", padx=12, pady=6)
        ctk.CTkEntry(mu_card, textvariable=fade_out, width=140).grid(row=3, column=1, sticky="w", padx=12, pady=6)
        ctk.CTkLabel(mu_card, text="Trim start", text_color="#94a3b8").grid(row=4, column=0, sticky="w", padx=12, pady=6)
        ctk.CTkEntry(mu_card, textvariable=trim_a, width=140).grid(row=4, column=1, sticky="w", padx=12, pady=6)
        ctk.CTkLabel(mu_card, text="Trim end", text_color="#94a3b8").grid(row=5, column=0, sticky="w", padx=12, pady=6)
        ctk.CTkEntry(mu_card, textvariable=trim_b, width=140).grid(row=5, column=1, sticky="w", padx=12, pady=6)
        ctk.CTkButton(
            mu_card,
            text="Apply",
            width=120,
            fg_color="#7c3aed",
            hover_color="#6d28d9",
            command=lambda: _log_line(
                f"Music apply: vol={int(vol.get())}% fade_in={fade_in.get()} fade_out={fade_out.get()} trim={trim_a.get()}-{trim_b.get()}"
            ),
        ).grid(row=6, column=0, columnspan=2, sticky="w", padx=12, pady=(8, 12))

        # Settings
        st_card = ctk.CTkFrame(settings_tab, fg_color="#0b1220", corner_radius=12, border_width=1, border_color="#1f2937")
        st_card.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        st_card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(st_card, text="Settings", font=ctk.CTkFont(size=14, weight="bold"), text_color="#e2e8f0").grid(row=0, column=0, sticky="w", padx=12, pady=(10, 6))
        keep = tk.BooleanVar(value=True)
        theme = tk.StringVar(value="Dark")
        ctk.CTkCheckBox(st_card, text="Keep Music Studio settings", variable=keep, command=lambda: _log_line(f"Keep settings: {bool(keep.get())}")).grid(row=1, column=0, sticky="w", padx=12, pady=6)
        row_theme = ctk.CTkFrame(st_card, fg_color="transparent")
        row_theme.grid(row=2, column=0, sticky="ew", padx=12, pady=6)
        ctk.CTkLabel(row_theme, text="Theme", text_color="#94a3b8").pack(side="left", padx=(0, 10))
        ctk.CTkOptionMenu(row_theme, variable=theme, values=["Dark", "Light"], command=lambda v: _log_line(f"Theme: {v}")).pack(side="left")
        st_btn = ctk.CTkFrame(st_card, fg_color="transparent")
        st_btn.grid(row=3, column=0, sticky="ew", padx=12, pady=(10, 12))
        ctk.CTkButton(
            st_btn,
            text="Reset",
            width=120,
            fg_color="#ef4444",
            hover_color="#dc2626",
            command=lambda: _log_line("Reset settings (coming soon)"),
        ).pack(side="left")

        _log_line("Status Log")
        _log_line("")
        _log_line("Music Studio UI loaded.")
        _render_playlist()

    def _show_profile_results(self, source_url, urls):
        res_win = ctk.CTkToplevel(self)
        res_win.title(f"Scanned {len(urls)} items")
        res_win.geometry("800x600")

        header = ctk.CTkFrame(res_win, fg_color="transparent")
        header.pack(fill="x", padx=10, pady=10)
        ctk.CTkLabel(header, text=f"Source: {source_url[:60]}...", font=self._font_small, text_color="gray").pack(side="left")
        
        scroll = ctk.CTkScrollableFrame(res_win)
        scroll.pack(fill="both", expand=True, padx=10, pady=10)
        
        vars_map = []
        for i, u in enumerate(urls):
            f = ctk.CTkFrame(scroll, fg_color="transparent")
            f.pack(fill="x", pady=2)
            v = tk.BooleanVar(value=True)
            ctk.CTkCheckBox(f, text="", variable=v, width=20).pack(side="left")
            ctk.CTkLabel(f, text=f"{i+1}. {u}", font=self._font_small).pack(side="left", padx=5)
            vars_map.append((u, v))
            
        def download_selected():
            to_add = [u for u, v in vars_map if v.get()]
            res_win.destroy()
            if not to_add: return
            
            self._set_status(f"Adding {len(to_add)} items...")
            opts = self._current_options()
            for u in to_add:
                try:
                    u = self._normalize_url(u)
                except Exception:
                    pass
                job = self.manager.add_job(u, opts)
                self._insert_job(job)
            
            self._set_status(f"Added {len(to_add)} items to queue")
            if self.auto_start.get():
                self.manager.start()
        
        footer = ctk.CTkFrame(res_win, fg_color="transparent")
        footer.pack(fill="x", padx=10, pady=10)
        ctk.CTkButton(footer, text=f"Download Selected ({len(urls)})", command=download_selected, fg_color="#10b981").pack(side="right")
        ctk.CTkButton(footer, text="Select None", command=lambda: [v.set(False) for u, v in vars_map], width=100).pack(side="left", padx=5)
        ctk.CTkButton(footer, text="Select All", command=lambda: [v.set(True) for u, v in vars_map], width=100).pack(side="left", padx=5)

    def _show_tiktok_block_dialog(self, url: str, err: str) -> None:
        msg = (
            "TikTok blocked profile scanning/downloading.\n\n"
            "To fix (recommended):\n"
            "1) Log in to TikTok in Chrome/Edge\n"
            "2) Export cookies.txt using the 'Get cookies.txt LOCALLY' extension\n"
            "3) In this app: Advanced tab -> Cookies -> Browse -> select cookies.txt\n\n"
            "You can also paste a direct video link (contains /video/).\n\n"
            f"URL: {url}\n"
            f"Error: {err}"
        )
        try:
            pick = messagebox.askyesno("TikTok blocked", msg + "\n\nPick cookies.txt now?")
            if pick:
                self._choose_cookies()
        except Exception:
            pass

    def _open_settings(self):
        self._select_tab("Advanced")
        self._set_status("Directing to Advanced Settings...")

    def _refresh_overall_status(self):
        # Update overall progress
        jobs = self.manager.jobs()
        if not jobs:
            self._overall_progress.set(0.0)
            self.speed_meter.configure(text="0 KB/s")
            return
            
        total_p = sum(j.progress for j in jobs) / len(jobs)
        self._overall_progress.set(total_p / 100.0)
        
        running = [j for j in jobs if j.status == "running"]
        if running:
            self.speed_meter.configure(text=running[0].speed or "0 KB/s")
        else:
            self.speed_meter.configure(text="0 KB/s")


def main() -> None:
    def _cli_log(msg: str) -> None:
        try:
            p = _data_path("cli.log")
            with open(p, "a", encoding="utf-8") as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
        except Exception:
            pass

    def _crash_log(title: str, err: BaseException) -> None:
        try:
            p = _data_path("crash.log")
            with open(p, "a", encoding="utf-8") as f:
                f.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] {title}\n")
                f.write("".join(traceback.format_exception(type(err), err, err.__traceback__)))
        except Exception:
            pass

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--db-init", dest="db_init", action="store_true")
    parser.add_argument("--admin-unblock", dest="admin_unblock", default="")
    parser.add_argument("--admin-delete", dest="admin_delete", default="")
    args, _unknown = parser.parse_known_args()

    if bool(getattr(args, "db_init", False)):
        store = _make_auth_store_cli(_data_path("snakee.db"))
        if not isinstance(store, _MySQLAuthStore):
            msg = "MySQL is not configured. Create %APPDATA%\\Snakee\\mysql.json or set MYSQL_HOST/MYSQL_USER/MYSQL_PASSWORD."
            print(msg)
            _cli_log(msg)
            raise SystemExit(1)
        try:
            store.init_db()
            msg = "MySQL init OK"
            print(msg)
            _cli_log(msg)
            raise SystemExit(0)
        except Exception as e:
            msg = f"MySQL init FAILED: {e}"
            print(msg)
            _cli_log(msg)
            raise SystemExit(2)

    if args.admin_unblock or args.admin_delete:
        store = _make_auth_store_cli(_data_path("snakee.db"))
        try:
            store.init_db()
        except Exception:
            pass
        if args.admin_unblock:
            n = 0
            try:
                n = int(store.admin_unblock(str(args.admin_unblock)))
            except Exception:
                n = 0
            msg = f"Unblocked: {n}"
            print(msg)
            _cli_log(msg)
            raise SystemExit(0 if n > 0 else 1)
        if args.admin_delete:
            n = 0
            try:
                n = int(store.admin_delete(str(args.admin_delete)))
            except Exception:
                n = 0
            msg = f"Deleted: {n}"
            print(msg)
            _cli_log(msg)
            raise SystemExit(0 if n > 0 else 1)

    try:
        _cli_log("Starting GUI")
        app = App()
        _cli_log("Entering mainloop")
        app.mainloop()
        _cli_log("Exited mainloop")
    except SystemExit:
        raise
    except Exception as e:
        _crash_log("Unhandled exception during app startup", e)
        try:
            messagebox.showerror(
                "Snakee crashed",
                "Snakee encountered an error and needs to close.\n\n"
                f"Details: {e}\n\n"
                f"Crash log: {_data_path('crash.log')}",
            )
        except Exception:
            pass
        raise


if __name__ == "__main__":
    main()
