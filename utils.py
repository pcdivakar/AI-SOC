import sqlite3
import json
from datetime import datetime, timedelta

DB_PATH = "cache.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS nvd_cache (
                    cve_id TEXT PRIMARY KEY,
                    data TEXT,
                    fetched_at TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS epss_cache (
                    cve_id TEXT PRIMARY KEY,
                    score REAL,
                    fetched_at TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS kev_cache (
                    cve_id TEXT PRIMARY KEY,
                    status BOOLEAN,
                    fetched_at TIMESTAMP)''')
    conn.commit()
    conn.close()

def is_cache_fresh(fetched_at, ttl_hours=24):
    if not fetched_at:
        return False
    fetched = datetime.fromisoformat(fetched_at)
    return datetime.now() - fetched < timedelta(hours=ttl_hours)

def get_cached_nvd(cve_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT data, fetched_at FROM nvd_cache WHERE cve_id = ?", (cve_id,))
    row = c.fetchone()
    conn.close()
    if row and is_cache_fresh(row[1]):
        return json.loads(row[0])
    return None

def save_cached_nvd(cve_id, data):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("REPLACE INTO nvd_cache (cve_id, data, fetched_at) VALUES (?, ?, ?)",
              (cve_id, json.dumps(data), datetime.now().isoformat()))
    conn.commit()
    conn.close()

def get_cached_epss(cve_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT score, fetched_at FROM epss_cache WHERE cve_id = ?", (cve_id,))
    row = c.fetchone()
    conn.close()
    if row and is_cache_fresh(row[1], ttl_hours=6):
        return row[0]
    return None

def save_cached_epss(cve_id, score):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("REPLACE INTO epss_cache (cve_id, score, fetched_at) VALUES (?, ?, ?)",
              (cve_id, score, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def get_cached_kev(cve_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT status, fetched_at FROM kev_cache WHERE cve_id = ?", (cve_id,))
    row = c.fetchone()
    conn.close()
    if row and is_cache_fresh(row[1], ttl_hours=24):
        return row[0]
    return None

def save_cached_kev(cve_id, status):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("REPLACE INTO kev_cache (cve_id, status, fetched_at) VALUES (?, ?, ?)",
              (cve_id, status, datetime.now().isoformat()))
    conn.commit()
    conn.close()
