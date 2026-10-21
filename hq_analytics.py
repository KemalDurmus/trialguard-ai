"""HQ analitik katmanı — Geliştirici Ajan bu dosyaya dokunmaz.

- Sayfa görüntüleme + günlük tekil ziyaretçi (IP/UA özeti saklanır, ham IP saklanmaz)
- Bekleme listesi (/_hq/waitlist) ve geri bildirim (/_hq/feedback)
- Satın alma isteği (/_hq/buy): anında Telegram bildirimi; PAYMENT_URL ayarlıysa ödeme sayfasına yönlendirir
- /stats: STATS_TOKEN ile korunan özet; Agent HQ Analiz ekibi düzenli okur
- Yeni kayıt/geri bildirim olunca (HQ_TG_TOKEN + HQ_TG_CHAT varsa) Telegram bildirimi

Not: Ücretsiz barındırmada disk geçicidir; uygulama yeniden başlayınca sayaçlar sıfırlanabilir.
Bu yüzden /stats bir boot_id döndürür ve HQ her açılışın verisini ayrı ayrı biriktirir.
"""
import hashlib
import os
import re
import sqlite3
import threading
import time
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import abort, flash, jsonify, redirect, request

BASE = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("DATA_DIR", BASE / "data")) / "hq.sqlite3"
BOOT_ID = uuid.uuid4().hex[:12]
BOOT_AT = datetime.now(timezone.utc).isoformat(timespec="seconds")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[a-zA-Z]{2,24}$")
SKIP_PREFIXES = ("/static", "/health", "/stats", "/_hq", "/favicon")
_lock = threading.Lock()


def _db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS views (ts TEXT, day TEXT, path TEXT, visitor TEXT);
        CREATE TABLE IF NOT EXISTS signups (ts TEXT, email TEXT UNIQUE, page TEXT);
        CREATE TABLE IF NOT EXISTS feedback (ts TEXT, text TEXT, page TEXT);
        CREATE TABLE IF NOT EXISTS events (ts TEXT, name TEXT, page TEXT);
        CREATE TABLE IF NOT EXISTS purchases (ts TEXT, email TEXT, page TEXT);
    """)
    return conn


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _write(sql: str, args: tuple) -> bool:
    try:
        with _lock, _db() as conn:
            conn.execute(sql, args)
        return True
    except sqlite3.IntegrityError:
        return False
    except Exception:
        return False


def _visitor() -> str:
    ip = (request.headers.get("X-Forwarded-For", request.remote_addr or "") or "").split(",")[0].strip()
    ua = request.headers.get("User-Agent", "")
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return hashlib.sha256(f"{ip}|{ua}|{day}".encode()).hexdigest()[:16]


def _notify(text: str) -> None:
    token, chat = os.environ.get("HQ_TG_TOKEN"), os.environ.get("HQ_TG_CHAT")
    if not (token and chat):
        return

    def send():
        try:
            data = urllib.parse.urlencode({"chat_id": chat, "text": text[:3500]}).encode()
            urllib.request.urlopen(f"https://api.telegram.org/bot{token}/sendMessage", data=data, timeout=10)
        except Exception:
            pass

    threading.Thread(target=send, daemon=True).start()


def _app_title() -> str:
    try:
        import json
        return json.loads((BASE / "app_meta.json").read_text(encoding="utf-8")).get("app_title", "App")
    except Exception:
        return "App"


def init_app(app) -> None:
    app.jinja_env.globals["hq_price"] = os.environ.get("PRICE_TEXT", "")

    @app.before_request
    def _track():
        if request.method != "GET" or request.path.startswith(SKIP_PREFIXES):
            return
        if "bot" in request.headers.get("User-Agent", "").lower():
            return
        now = _now()
        _write("INSERT INTO views(ts, day, path, visitor) VALUES (?,?,?,?)",
               (now, now[:10], request.path[:200], _visitor()))

    @app.post("/_hq/waitlist")
    def _waitlist():
        email = (request.form.get("email") or "").strip().lower()[:254]
        if not EMAIL_RE.match(email):
            flash("Lütfen geçerli bir e-posta adresi gir.", "error")
        elif _write("INSERT INTO signups(ts, email, page) VALUES (?,?,?)",
                    (_now(), email, (request.referrer or "")[:200])):
            flash("Teşekkürler! Listeye eklendin, yenilikleri ilk sen duyacaksın. 🎉", "success")
            _notify(f"🎉 {_app_title()}: yeni bekleme listesi kaydı → {email}")
        else:
            flash("Bu e-posta zaten listede. 🙌", "success")
        return redirect(request.referrer or "/")

    @app.post("/_hq/buy")
    def _buy():
        email = (request.form.get("email") or "").strip().lower()[:254]
        if not EMAIL_RE.match(email):
            flash("Lütfen geçerli bir e-posta adresi gir.", "error")
            return redirect(request.referrer or "/")
        _write("INSERT INTO purchases(ts, email, page) VALUES (?,?,?)", (_now(), email, (request.referrer or "")[:200]))
        _notify(f"💰 SATIN ALMA İSTEĞİ — {_app_title()}\n{email}\nBu kişi ürünü almak istiyor; hemen ödeme bilgisiyle cevap ver.")
        pay = os.environ.get("PAYMENT_URL")
        if pay:
            return redirect(pay)
        flash("Teşekkürler! Ödeme ve kurulum bilgisini kısa süre içinde e-postana göndereceğiz. 🙌", "success")
        return redirect(request.referrer or "/")

    @app.post("/_hq/feedback")
    def _feedback():
        text = (request.form.get("text") or "").strip()[:2000]
        if len(text) < 3:
            flash("Geri bildirim çok kısa.", "error")
        else:
            _write("INSERT INTO feedback(ts, text, page) VALUES (?,?,?)", (_now(), text, (request.referrer or "")[:200]))
            flash("Geri bildirimin için teşekkürler! 💬", "success")
            _notify(f"💬 {_app_title()} geri bildirim: {text[:500]}")
        return redirect(request.referrer or "/")

    @app.post("/_hq/event")
    def _event():
        payload = (request.get_json(silent=True) or {}) if request.is_json else request.form
        name = str(payload.get("name") or "")
        if name:
            _write("INSERT INTO events(ts, name, page) VALUES (?,?,?)", (_now(), name[:80], request.path))
        return ("", 204)

    @app.get("/stats")
    def _stats():
        token = os.environ.get("STATS_TOKEN")
        if not token or request.headers.get("Authorization") != f"Bearer {token}":
            abort(404)
        with _lock, _db() as conn:
            q = lambda sql, *a: conn.execute(sql, a).fetchall()
            days = q("SELECT day, COUNT(*), COUNT(DISTINCT visitor) FROM views GROUP BY day ORDER BY day")
            return jsonify(
                boot_id=BOOT_ID, boot_at=BOOT_AT, generated_at=_now(),
                views=q("SELECT COUNT(*) FROM views")[0][0],
                uniques=sum(d[2] for d in days),
                by_day=[{"day": d[0], "views": d[1], "uniques": d[2]} for d in days],
                top_paths=[{"path": p, "views": n} for p, n in
                           q("SELECT path, COUNT(*) n FROM views GROUP BY path ORDER BY n DESC LIMIT 10")],
                signups=[{"ts": t, "email": e} for t, e in q("SELECT ts, email FROM signups ORDER BY ts")],
                feedback=[{"ts": t, "text": x} for t, x in q("SELECT ts, text FROM feedback ORDER BY ts")],
                purchases=[{"ts": t, "email": e} for t, e in q("SELECT ts, email FROM purchases ORDER BY ts")],
                events=[{"name": n, "count": c} for n, c in q("SELECT name, COUNT(*) FROM events GROUP BY name")],
            )
