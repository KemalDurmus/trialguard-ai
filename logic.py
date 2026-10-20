import sqlite3
import hashlib
from datetime import datetime, timedelta
from user_agents import parse as parse_user_agent
from collections import defaultdict

DB_PATH = "trialguard.db"

def init_db(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS trials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            user_agent TEXT NOT NULL,
            timestamp DATETIME NOT NULL,
            device_fingerprint TEXT NOT NULL,
            os TEXT,
            browser TEXT,
            is_mobile INTEGER DEFAULT 0,
            country TEXT,
            city TEXT,
            is_abusive INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()

def _generate_device_fingerprint(user_agent_string):
    ua = parse_user_agent(user_agent_string)
    # Basit bir cihaz parmak izi oluşturma. Gerçek bir senaryoda, istemci tarafı JS ile daha fazla veri toplanır.
    fingerprint_components = [
        ua.os.family,
        ua.os.version_string,
        ua.browser.family,
        ua.browser.version_string,
        str(ua.is_mobile),
        str(ua.is_tablet),
        str(ua.is_pc),
    ]
    return hashlib.sha256("".join(fingerprint_components).encode()).hexdigest()

def _simulate_geo_ip(ip_address):
    # geoip2 kütüphanesi ve veritabanı gerektirdiğinden ve ağ çağrıları yasak olduğundan, basit bir simülasyon.
    if ip_address.startswith("192.168.") or ip_address.startswith("10.") or ip_address.startswith("172.16."):
        return "Yerel Ağ", "Yerel Ağ"
    elif ip_address == "127.0.0.1":
        return "Yerel", "Ana Bilgisayar"
    elif ip_address.startswith("5.10."): 
        return "Türkiye", "İstanbul"
    elif ip_address.startswith("8.8.8."): 
        return "ABD", "Mountain View"
    else:
        return "Bilinmiyor", "Bilinmiyor"

def add_trial_entry(user_id, ip_address, user_agent_string, timestamp_str, db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        raise ValueError("Geçersiz zaman damgası formatı. YYYY-MM-DD HH:MM:SS formatını kullanın.")

    device_fingerprint = _generate_device_fingerprint(user_agent_string)
    ua = parse_user_agent(user_agent_string)
    os_name = ua.os.family
    browser_name = ua.browser.family
    is_mobile = 1 if ua.is_mobile else 0
    country, city = _simulate_geo_ip(ip_address)

    cursor.execute("""
        INSERT INTO trials (user_id, ip_address, user_agent, timestamp, device_fingerprint, os, browser, is_mobile, country, city)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, ip_address, user_agent_string, timestamp, device_fingerprint, os_name, browser_name, is_mobile, country, city))
    conn.commit()
    conn.close()
    return True

def get_all_trials(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row 
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM trials ORDER BY timestamp DESC")
    trials = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return trials

def analyze_trials(db_path=DB_PATH, time_window_hours=24):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Analizden önce tüm suiistimal bayraklarını sıfırla
    cursor.execute("UPDATE trials SET is_abusive = 0")
    conn.commit()

    cursor.execute("SELECT id, user_id, ip_address, device_fingerprint, timestamp FROM trials")
    all_entries = cursor.fetchall()

    ip_device_groups = defaultdict(list)
    for entry_id, user_id, ip, device_fp, ts_str in all_entries:
        ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
        ip_device_groups[(ip, device_fp)].append({
            "id": entry_id,
            "user_id": user_id,
            "timestamp": ts
        })

    flagged_accounts = set()
    analysis_summary = []

    for (ip, device_fp), entries in ip_device_groups.items():
        entries.sort(key=lambda x: x["timestamp"])

        distinct_users_in_window = defaultdict(list) 
        for entry in entries:
            distinct_users_in_window[entry["user_id"]].append(entry["timestamp"])

        if len(distinct_users_in_window) > 1:
            # Aynı IP ve cihaz parmak izinden birden fazla farklı kullanıcı ID'si tespit edildi.
            # Bu, tek bir cihazdan birden fazla hesap açma suiistimalinin güçlü bir göstergesidir.
            for user_id in distinct_users_in_window.keys():
                flagged_accounts.add(user_id)
                analysis_summary.append(f"Potansiyel suiistimal: '{user_id}' kullanıcısı, aynı IP ({ip}) ve cihaz parmak izi ({device_fp[:8]}...) ile diğer kullanıcılarla birlikte tespit edildi.")
                # Bu kullanıcı ID'si, IP ve cihaz parmak izi kombinasyonuyla ilişkili tüm kayıtları suiistimal olarak işaretle
                cursor.execute("UPDATE trials SET is_abusive = 1 WHERE user_id = ? AND ip_address = ? AND device_fingerprint = ?", (user_id, ip, device_fp))
                conn.commit()

    conn.close()
    return list(flagged_accounts), analysis_summary

def generate_sample_data():
    now = datetime.now()
    sample_data = [
        # Meşru kullanıcılar
        {
            "user_id": "user_a",
            "ip_address": "5.10.10.1",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36",
            "timestamp": (now - timedelta(days=5)).strftime("%Y-%m-%d %H:%M:%S")
        },
        {
            "user_id": "user_b",
            "ip_address": "5.10.10.2",
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15",
            "timestamp": (now - timedelta(days=4)).strftime("%Y-%m-%d %H:%M:%S")
        },
        # Aynı IP'den gelen meşru aile üyeleri, farklı cihazlar (farklı parmak izleri)
        {
            "user_id": "family_member_1",
            "ip_address": "192.168.1.100",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36",
            "timestamp": (now - timedelta(hours=10)).strftime("%Y-%m-%d %H:%M:%S")
        },
        {
            "user_id": "family_member_2",
            "ip_address": "192.168.1.100",
            "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 15_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/99.0.4844.83 Mobile/15E148 Safari/604.1",
            "timestamp": (now - timedelta(hours=9)).strftime("%Y-%m-%d %H:%M:%S")
        },
        # Suiistimal örneği: Aynı cihazdan (aynı parmak izi), birden fazla farklı kullanıcı ID'si
        {
            "user_id": "abuser_1_account_1",
            "ip_address": "8.8.8.8",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36 Edg/99.0.1150.36",
            "timestamp": (now - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")
        },
        {
            "user_id": "abuser_1_account_2",
            "ip_address": "8.8.8.8",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36 Edg/99.0.1150.36",
            "timestamp": (now - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
        },
        {
            "user_id": "abuser_1_account_3",
            "ip_address": "8.8.8.8",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36 Edg/99.0.1150.36",
            "timestamp": now.strftime("%Y-%m-%d %H:%M:%S")
        },
        # Başka bir suiistimal örneği: Aynı IP'den, ufak UA değişiklikleriyle farklı parmak izi denemesi (ancak yine de aynı IP'den birden fazla hesap)
        {
            "user_id": "abuser_2_account_1",
            "ip_address": "5.10.10.50",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36",
            "timestamp": (now - timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S")
        },
        {
            "user_id": "abuser_2_account_2",
            "ip_address": "5.10.10.50",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.128 Safari/537.36", 
            "timestamp": (now - timedelta(minutes=20)).strftime("%Y-%m-%d %H:%M:%S")
        }
    ]
    return sample_data
