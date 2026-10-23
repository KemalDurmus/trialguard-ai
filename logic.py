"""Signup-list analysis: finds accounts that are probably the same person or throwaway signups.

Stateless: the uploaded list is analyzed in memory and never stored.
Every flag is explained in plain words and comes from a concrete rule, so the user can check it:
- same inbox: Gmail dots / "+tag" aliases that deliver to one mailbox
- customer-provided device/fingerprint id shared by several accounts
- several signups from one IP in a short time (or many from one IP overall — could be an office)
- the same browser (user agent) on the same IP
- disposable email domains
- numbered aliases (anna1@, anna2@, anna3@ on the same domain)
"""
from __future__ import annotations

import base64
import csv
import io
import re
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone

MAX_ROWS = 50000
WEIGHTS = {"inbox": 60, "device": 60, "ip_burst": 40, "disposable": 35, "ip_ua": 30, "ip_many": 20, "numbered": 20}
REASONS = {
    "inbox": "Same inbox as {acc}: {members}",
    "device": "Same device id as {acc}: {members}",
    "ip_burst": "{sig} from IP {ip} within {window}",
    "ip_ua": "Same browser and IP ({ip}) as {acc}: {members}",
    "ip_many": "{sig} from IP {ip} (could also be an office or school network)",
    "disposable": "Disposable email domain ({domain})",
    "numbered": "Numbered alias — {adr} like {pattern}",
}
# Gmail ignores dots; these providers deliver "name+anything@" to "name@"
DOT_INSENSITIVE = {"gmail.com", "googlemail.com"}
PLUS_ALIAS = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "icloud.com",
              "me.com", "mac.com", "fastmail.com", "fastmail.fm", "proton.me", "protonmail.com", "pm.me",
              "zoho.com", "yandex.com", "yandex.ru", "gmx.com", "hey.com"}
FREE_MAIL = PLUS_ALIAS | {"yahoo.com", "ymail.com", "aol.com", "mail.com", "gmx.net", "gmx.de", "web.de",
                          "hotmail.co.uk", "outlook.de", "yahoo.co.uk", "mail.ru", "qq.com", "163.com"}
DISPOSABLE = {
    "mailinator.com", "mailinator.net", "guerrillamail.com", "guerrillamail.net", "guerrillamail.org",
    "guerrillamail.biz", "guerrillamailblock.com", "sharklasers.com", "grr.la", "pokemail.net", "spam4.me",
    "10minutemail.com", "10minutemail.net", "10minutemail.co.uk", "20minutemail.com", "tempmail.com",
    "temp-mail.org", "temp-mail.io", "tempmail.net", "tempmailo.com", "tempmail.dev", "tempmailaddress.com",
    "tempr.email", "tempail.com", "tmpmail.org", "tmpmail.net", "tmpeml.com", "tmails.net", "yopmail.com",
    "yopmail.net", "yopmail.fr", "trashmail.com", "trashmail.net", "trashmail.de", "trash-mail.com",
    "throwawaymail.com", "throwam.com", "getnada.com", "nada.email", "maildrop.cc", "mailnesia.com",
    "dispostable.com", "discard.email", "discardmail.com", "fakeinbox.com", "fakemail.net", "emailondeck.com",
    "mintemail.com", "mohmal.com", "moakt.com", "mytemp.email", "burnermail.io", "33mail.com", "spamgourmet.com",
    "mailcatch.com", "mailpoof.com", "inboxkitten.com", "getairmail.com", "emailfake.com", "fakemailgenerator.com",
    "mail.tm", "mail.gw", "dropmail.me", "10mail.org", "anonbox.net", "spambox.us", "mailtemp.info",
    "luxusmail.org", "byom.de", "cs.email", "dcctb.com", "harakirimail.com", "incognitomail.org", "jetable.org",
    "mailforspam.com", "mailexpire.com", "meltmail.com", "mt2015.com", "nowmymail.com", "owlymail.com",
    "rcpt.at", "spamfree24.org", "tempinbox.com", "trbvm.com", "wegwerfmail.de", "wegwerfmail.net",
    "emailtemporanea.net", "minuteinbox.com", "linshiyouxiang.net", "smailpro.com", "emltmp.com",
}
ALIASES = {
    "email": ["email", "emailaddress", "mail", "useremail", "eposta", "epostaadresi"],
    "ip": ["ip", "ipaddress", "signupip", "clientip", "remoteaddr", "ipadresi"],
    "ua": ["useragent", "ua", "browser", "tarayici"],
    "device": ["deviceid", "device", "fingerprint", "visitorid", "fingerprintid", "cihaz", "cihazid"],
    "date": ["signupdate", "createdat", "created", "date", "signedupat", "registeredat", "timestamp", "time",
             "tarih", "kayittarihi"],
    "id": ["userid", "id", "accountid", "customerid", "user", "username", "name", "kullaniciid"],
}
_TR = str.maketrans("ıİşŞğĞüÜöÖçÇ", "iIsSgGuUoOcC")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")


def plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else ("es" if word.endswith("s") else "s"))


def _reason(rule: str, n: int = 0, **kw) -> str:
    return REASONS[rule].format(n=n, acc=plural(n, "other account"), sig=plural(n, "other signup"),
                                adr=plural(n, "other address"), **kw)


class ParseError(ValueError):
    pass


def _norm(h: str) -> str:
    return re.sub(r"[^a-z0-9]", "", h.translate(_TR).lower())


def _map_columns(headers: list[str]) -> dict[str, int]:
    normed = [_norm(h) for h in headers]
    found: dict[str, int] = {}
    for field, names in ALIASES.items():
        for i, h in enumerate(normed):
            if h in names and i not in found.values():
                found[field] = i
                break
        else:
            for i, h in enumerate(normed):
                if i not in found.values() and any(n in h for n in names if len(n) > 3):
                    found[field] = i
                    break
    return found


def _sniff(text: str) -> str:
    head = "\n".join(text.splitlines()[:10])
    try:
        return csv.Sniffer().sniff(head, delimiters=",;\t|").delimiter
    except csv.Error:
        counts = {d: head.count(d) for d in (",", ";", "\t", "|")}
        return max(counts, key=counts.get)


def _parse_dt(raw: str) -> datetime | None:
    v = (raw or "").strip().replace("Z", "")
    if not v:
        return None
    if re.fullmatch(r"\d{10}(\.\d+)?", v):  # unix seconds
        return datetime.fromtimestamp(float(v), timezone.utc).replace(tzinfo=None)
    if re.fullmatch(r"\d{13}", v):  # unix milliseconds
        return datetime.fromtimestamp(int(v) / 1000, timezone.utc).replace(tzinfo=None)
    v = re.sub(r"[+-]\d{2}:?\d{2}$", "", v)
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M", "%Y-%m-%d", "%d.%m.%Y %H:%M:%S", "%d.%m.%Y %H:%M", "%d.%m.%Y",
                "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M", "%m/%d/%Y", "%d/%m/%Y %H:%M", "%d/%m/%Y"):
        try:
            return datetime.strptime(v, fmt)
        except ValueError:
            continue
    return None


def canonical_inbox(email: str) -> str:
    local, _, domain = email.lower().partition("@")
    if domain == "googlemail.com":
        domain = "gmail.com"
    if domain in PLUS_ALIAS:
        local = local.split("+", 1)[0]
    if domain in DOT_INSENSITIVE:
        local = local.replace(".", "")
    return f"{local}@{domain}"


def is_disposable(domain: str) -> bool:
    parts = domain.lower().split(".")
    return any(".".join(parts[i:]) in DISPOSABLE for i in range(len(parts) - 1))


def _looks_binary(text: str) -> bool:
    """Resim, zip, PDF gibi metin olmayan dosyalar: NUL ya da çok sayıda kontrol karakteri içerir."""
    sample = text[:20000]
    if "\x00" in sample:
        return True
    ctrl = sum(1 for ch in sample if ord(ch) < 32 and ch not in "\r\n\t")
    return bool(sample) and ctrl / len(sample) > 0.02


def _read_table(text: str, delim: str) -> list[list[str]]:
    text = text.replace("\r\n", "\n").replace("\r", "\n")  # eski Mac satır sonları
    try:
        return [r for r in csv.reader(io.StringIO(text), delimiter=delim) if any(c.strip() for c in r)]
    except csv.Error as e:
        raise ParseError(f"This file couldn't be read as a CSV ({e}). Please export it again as CSV.") from e


def parse_signups(text: str) -> tuple[list[dict], list[str]]:
    text = (text or "").lstrip("﻿").strip()
    if not text:
        raise ParseError("No data received. Paste a CSV or upload a file.")
    if _looks_binary(text):
        raise ParseError("This doesn't look like a CSV or text file (it may be an image, PDF or spreadsheet). "
                         "Please export your signups as CSV and upload that.")
    delim = _sniff(text)
    table = _read_table(text, delim)
    if len(table) < 2:
        raise ParseError("The list needs a header row and at least one signup.")
    headers, body = table[0], table[1:MAX_ROWS + 1]
    cols = _map_columns(headers)
    if "email" not in cols:
        raise ParseError(f"Couldn't find an email column. Columns found: {', '.join(h.strip() for h in headers)}. "
                         "Name it e.g. Email (IP, User agent, Device id and Signup date are optional).")
    rows, skipped = [], []
    for n, r in enumerate(body, start=2):
        get = lambda f: r[cols[f]].strip() if f in cols and cols[f] < len(r) else ""
        email = get("email").lower()
        if not EMAIL_RE.match(email):
            skipped.append(n)
            continue
        rows.append({"line": n, "email": email, "id": get("id") or email, "ip": get("ip"),
                     "ua": get("ua"), "device": get("device"), "at": _parse_dt(get("date"))})
    if not rows:
        raise ParseError("No line had a valid email address.")
    warnings = []
    if skipped:
        shown = ", ".join(map(str, skipped[:8])) + (" …" if len(skipped) > 8 else "")
        warnings.append(f"{plural(len(skipped), 'line')} skipped because the email was empty or invalid "
                        f"({'line' if len(skipped) == 1 else 'lines'} {shown}).")
    if "ip" not in cols:
        warnings.append("No IP column found, so shared-IP checks are off. Add one for much better results.")
    if len(table) - 1 > MAX_ROWS:
        warnings.append(f"Only the first {MAX_ROWS:,} signups were analyzed.")
    return rows, warnings


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #
def _members(emails: list[str], pos: int, limit: int = 3) -> str:
    """Gruptaki diğer hesaplardan ilk `limit` tanesi (pos = bu hesabın gruptaki sırası).
    Yalnızca listenin başına bakar: büyük gruplarda her satır için tüm grubu taramak O(n²) idi."""
    head = emails[:limit + 1]
    others = (head[:pos] + head[pos + 1:])[:limit]
    rest = len(emails) - 1 - len(others)
    return ", ".join(others) + (f" +{rest}" if rest > 0 else "")


def analyze(rows: list[dict], burst_hours: int = 24, many_per_ip: int = 5) -> dict:
    flags: dict[int, dict[str, str]] = defaultdict(dict)  # row index -> {rule: reason}
    groups: list[dict] = []

    def group_by(key_fn, rule, title_fn, min_size=2):
        buckets = defaultdict(list)
        for i, r in enumerate(rows):
            k = key_fn(r)
            if k:
                buckets[k].append(i)
        for k, idx in buckets.items():
            if len(idx) >= min_size and len({rows[i]["email"] for i in idx}) >= min_size:
                members = [rows[i] for i in idx]
                emails = [m["email"] for m in members]
                for pos, i in enumerate(idx):
                    flags[i][rule] = _reason(rule, n=len(idx) - 1, members=_members(emails, pos),
                                                          ip=rows[i]["ip"], pattern=k if isinstance(k, str) else "",
                                                          window="", domain="")
                groups.append({"rule": rule, "title": title_fn(k, members), "members": emails})

    group_by(lambda r: canonical_inbox(r["email"]), "inbox", lambda k, m: f"{len(m)} accounts, one inbox ({k})")
    group_by(lambda r: r["device"], "device", lambda k, m: f"{len(m)} accounts on device {k[:24]}")
    group_by(lambda r: (r["ip"], r["ua"]) if r["ip"] and r["ua"] else None, "ip_ua",
             lambda k, m: f"{len(m)} accounts with the same browser on IP {k[0]}")

    # IP bursts (needs dates) and busy IPs
    by_ip = defaultdict(list)
    for i, r in enumerate(rows):
        if r["ip"]:
            by_ip[r["ip"]].append(i)
    window = timedelta(hours=burst_hours)
    for ip, idx in by_ip.items():
        if len({rows[i]["email"] for i in idx}) < 2:
            continue
        dated = sorted((i for i in idx if rows[i]["at"]), key=lambda i: rows[i]["at"])
        burst: set[int] = set()
        start = added = 0  # added: dated[:added] içinden pencereye girenler zaten burst'te
        for end in range(len(dated)):
            while rows[dated[end]]["at"] - rows[dated[start]]["at"] > window:
                start += 1
            if end - start + 1 >= 3:
                burst.update(dated[max(start, added):end + 1])
                added = end + 1
        if burst:
            for i in burst:
                flags[i]["ip_burst"] = _reason("ip_burst", n=len(burst) - 1, ip=ip,
                                                                  window=f"{burst_hours} hours", members="", pattern="", domain="")
            groups.append({"rule": "ip_burst", "title": f"{len(burst)} signups from {ip} within {burst_hours} hours",
                           "members": [rows[i]["email"] for i in sorted(burst, key=lambda i: rows[i]["at"])]})
        elif len(idx) >= many_per_ip:
            for i in idx:
                flags[i]["ip_many"] = _reason("ip_many", n=len(idx) - 1, ip=ip, members="", pattern="",
                                                                window="", domain="")
            groups.append({"rule": "ip_many", "title": f"{len(idx)} signups from {ip}",
                           "members": [rows[i]["email"] for i in idx]})

    # Numbered aliases on free mail providers: anna1@, anna2@, anna3@
    numbered = defaultdict(list)
    for i, r in enumerate(rows):
        local, _, domain = canonical_inbox(r["email"]).partition("@")
        # yalnızca 1-2 haneli numaralar: john1985@ / john1990@ gibi doğum yılları farklı kişiler olabilir
        m = re.fullmatch(r"(.*?[a-z])[._-]?(\d{1,2})", local)
        if m and domain in FREE_MAIL and len(m.group(1)) >= 4:
            numbered[f"{m.group(1)}<number>@{domain}"].append((i, int(m.group(2))))
    for pattern, hits in numbered.items():
        nums = sorted({n for _, n in hits})
        idx = [i for i, _ in hits]
        # ardışık/yakın numaralar (1, 2, 3 …) aynı kişinin seri hesaplarına işaret eder
        if len(nums) >= 3 and nums[-1] - nums[0] <= 2 * len(nums):
            for i in idx:
                flags[i]["numbered"] = _reason("numbered", n=len(idx) - 1, pattern=pattern, members="",
                                                                  ip="", window="", domain="")
            groups.append({"rule": "numbered", "title": f"{len(idx)} numbered addresses like {pattern}",
                           "members": [rows[i]["email"] for i in idx]})

    disposable = 0
    for i, r in enumerate(rows):
        domain = r["email"].partition("@")[2]
        if is_disposable(domain):
            disposable += 1
            flags[i]["disposable"] = _reason("disposable", domain=domain, n=0, members="", ip="", pattern="",
                                                                  window="")

    accounts = []
    for i, reasons in flags.items():
        score = min(100, sum(WEIGHTS[k] for k in reasons))
        r = rows[i]
        accounts.append({"line": r["line"], "email": r["email"], "id": r["id"], "ip": r["ip"], "score": score,
                         "level": "high" if score >= 60 else "medium" if score >= 35 else "low",
                         "reasons": list(reasons.values())})
    accounts.sort(key=lambda a: (-a["score"], a["line"]))
    order = ["inbox", "device", "ip_burst", "ip_ua", "numbered", "ip_many"]
    groups.sort(key=lambda g: (order.index(g["rule"]), -len(g["members"])))
    kept: list[dict] = []
    kept_sets: list[set[str]] = []
    for g in groups:  # aynı hesapları daha güçlü bir grup zaten gösteriyorsa tekrar listeleme
        members = set(g["members"])
        if not any(members <= k for k in kept_sets):
            kept.append(g)
            kept_sets.append(members)
    groups = kept
    high = sum(a["level"] == "high" for a in accounts)
    return {"total": len(rows), "flagged": len(accounts), "high": high, "disposable": disposable,
            "share": len(accounts) / len(rows) * 100 if rows else 0, "accounts": accounts, "groups": groups,
            "csv_data_uri": _report_uri(accounts)}


def _report_uri(accounts: list[dict]) -> str:
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["line", "email", "user_id", "ip", "risk_score", "level", "reasons"])
    for a in accounts:
        w.writerow([a["line"], a["email"], a["id"], a["ip"], a["score"], a["level"], " | ".join(a["reasons"])])
    return "data:text/csv;base64," + base64.b64encode(out.getvalue().encode("utf-8-sig")).decode()


def sample_csv(today: date | None = None) -> str:
    """A realistic signup export with a few abuse patterns mixed into normal signups."""
    base = datetime.combine(today or date.today(), datetime.min.time()) - timedelta(days=6)
    chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36"
    safari = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"
    iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"
    firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0"
    rows = [  # (user_id, email, ip, ua, hours after base)
        ("u1001", "maria.lopez.sample@gmail.com", "81.2.69.142", safari, 2),
        ("u1002", "dev@acme-sample.io", "203.0.113.10", chrome, 5),
        ("u1003", "mar.ialopez.sample+trial2@gmail.com", "81.2.69.142", safari, 30),   # same inbox as u1001
        ("u1004", "k.tanaka@sample-studio.jp", "198.51.100.23", firefox, 31),
        ("u1005", "quickuser@mailinator.com", "45.83.64.11", chrome, 40),              # disposable
        ("u1006", "trialhunter1@outlook.com", "45.83.64.11", chrome, 41),              # burst + numbered
        ("u1007", "trialhunter2@outlook.com", "45.83.64.11", chrome, 42),
        ("u1008", "trialhunter3@outlook.com", "45.83.64.11", chrome, 44),
        ("u1009", "sam@northwind-sample.com", "192.0.2.44", iphone, 60),
        ("u1010", "lee@northwind-sample.com", "192.0.2.44", chrome, 75),               # same office, different browser
        ("u1011", "anna.schmidt.sample@gmail.com", "198.51.100.77", safari, 90),
        ("u1012", "x7k2@10minutemail.com", "185.220.101.5", firefox, 100),            # disposable
        ("u1013", "priya.n.sample@icloud.com", "203.0.113.58", iphone, 120),
        ("u1014", "priya.n.sample+2@icloud.com", "203.0.113.91", iphone, 121),         # same inbox, new IP
    ]
    lines = ["user_id,email,signup_ip,user_agent,created_at"]
    for uid, email, ip, ua, h in rows:
        lines.append(f'{uid},{email},{ip},"{ua}",{(base + timedelta(hours=h)).isoformat(timespec="seconds")}')
    return "\n".join(lines) + "\n"
