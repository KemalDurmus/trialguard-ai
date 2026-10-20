"""Duman testi — Geliştirici Ajan her derlemeden sonra bunu çalıştırır.

1. Uygulama import edilip oluşturulabiliyor mu?
2. Parametresiz tüm GET rotaları 5xx vermeden açılıyor mu?
3. sample_requests.json içindeki örnek akışlar 5xx vermeden çalışıyor mu?
Hata olursa traceback stderr'e basılır ve çıkış kodu 1 olur.
"""
import json
import sys
import traceback
from pathlib import Path

BASE = Path(__file__).resolve().parent


def main() -> int:
    from app import create_app

    app = create_app()
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    client = app.test_client()
    failures = 0

    def check(method: str, path: str, data: dict | None = None) -> None:
        nonlocal failures
        try:
            resp = client.open(path, method=method, data=data or None)
        except Exception:
            failures += 1
            print(f"FAIL {method} {path} — istisna fırlattı:", file=sys.stderr)
            traceback.print_exc()
            return
        if resp.status_code >= 500:
            failures += 1
            print(f"FAIL {method} {path} -> {resp.status_code}", file=sys.stderr)
        else:
            print(f"ok   {method} {path} -> {resp.status_code}")

    for rule in app.url_map.iter_rules():
        if "GET" in rule.methods and not rule.arguments and rule.endpoint != "static":
            check("GET", rule.rule)

    samples_path = BASE / "sample_requests.json"
    if samples_path.exists():
        for s in json.loads(samples_path.read_text(encoding="utf-8")):
            data = {f["name"]: f["value"] for f in s.get("form_fields", [])}
            check(s["method"].upper(), s["path"], data)

    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        sys.exit(1)
