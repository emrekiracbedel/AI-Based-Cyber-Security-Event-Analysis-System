"""
MongoDB persistence for normalized logs and alerts. Fails soft if server is down.
"""

from __future__ import annotations

from datetime import datetime, timezone
from threading import Lock
from typing import Any

from pymongo import MongoClient
from pymongo.errors import PyMongoError

from app.config import settings

_client: MongoClient | None = None
_client_lock = Lock()
_indexes_ensured = False


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _get_client() -> MongoClient | None:
    global _client
    with _client_lock:
        if _client is not None:
            return _client
        try:
            _client = MongoClient(
                settings.mongodb_uri,
                serverSelectionTimeoutMS=2500,
                connectTimeoutMS=2500,
            )
            _client.admin.command("ping")
            return _client
        except PyMongoError:
            _client = None
            return None


def get_mongo_status() -> dict[str, Any]:
    c = _get_client()
    if c is None:
        return {"connected": False, "error": "unreachable_or_misconfigured"}
    try:
        c.admin.command("ping")
        return {"connected": True, "db": settings.mongodb_db}
    except PyMongoError as e:
        return {"connected": False, "error": str(e)}


def _ensure_indexes(db) -> None:
    global _indexes_ensured
    if _indexes_ensured:
        return
    db["normalized_logs"].create_index([("timestamp", -1)])
    db["normalized_logs"].create_index([("source_type", 1)])
    db["normalized_logs"].create_index([("source_ip", 1)])
    db["security_alerts"].create_index([("timestamp", -1)])
    db["security_alerts"].create_index([("id", 1)])
    _indexes_ensured = True


def insert_log_doc(doc: dict[str, Any]) -> bool:
    c = _get_client()
    if c is None:
        return False
    try:
        db = c[settings.mongodb_db]
        _ensure_indexes(db)
        row = {**doc, "ingested_at": _utc_now()}
        db["normalized_logs"].insert_one(row)
        return True
    except PyMongoError:
        return False


def insert_alert_doc(doc: dict[str, Any]) -> bool:
    c = _get_client()
    if c is None:
        return False
    try:
        db = c[settings.mongodb_db]
        _ensure_indexes(db)
        row = {**doc, "ingested_at": _utc_now()}
        db["security_alerts"].insert_one(row)
        return True
    except PyMongoError:
        return False


def list_recent_logs(limit: int = 50) -> list[dict[str, Any]]:
    c = _get_client()
    if c is None:
        return []
    try:
        db = c[settings.mongodb_db]
        cur = (
            db["normalized_logs"]
            .find({}, {"_id": 0})
            .sort("timestamp", -1)
            .limit(limit)
        )
        return list(cur)
    except PyMongoError:
        return []


def list_recent_alerts_for_dashboard(limit: int = 500) -> list[dict[str, Any]]:
    """Kayıtlı güvenlik uyarıları (en yeni önce). Dashboard hydrate için."""
    c = _get_client()
    if c is None:
        return []
    try:
        db = c[settings.mongodb_db]
        cur = (
            db["security_alerts"]
            .find({}, {"_id": 0})
            .sort("timestamp", -1)
            .limit(limit)
        )
        return list(cur)
    except PyMongoError:
        return []


def aggregate_src_dst_counts_from_logs(
    *,
    limit_docs: int = 8000,
) -> dict[tuple[str, str], int]:
    """Son normalize loglardan (src,dst) çiftleri — heatmap için."""
    c = _get_client()
    if c is None:
        return {}
    try:
        db = c[settings.mongodb_db]
        cur = (
            db["normalized_logs"]
            .find({}, {"_id": 0, "source_ip": 1, "destination_ip": 1})
            .sort("timestamp", -1)
            .limit(max(100, min(limit_docs, 50_000)))
        )
        counts: dict[tuple[str, str], int] = {}
        for row in cur:
            s = row.get("source_ip")
            d = row.get("destination_ip")
            if not s or not d:
                continue
            key = (str(s), str(d))
            counts[key] = counts.get(key, 0) + 1
        return counts
    except PyMongoError:
        return {}
