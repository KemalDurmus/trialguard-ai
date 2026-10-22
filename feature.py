import logging

from flask import Blueprint, flash, redirect, render_template, request, url_for

import logic

bp = Blueprint("feature", __name__)


def _read_upload() -> str:
    f = request.files.get("file")
    if not f or not f.filename:
        return ""
    raw = f.read()
    for enc in ("utf-8-sig", "cp1252", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return ""


@bp.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@bp.route("/analyze", methods=["POST"])
def analyze():
    sample = bool(request.form.get("sample_data"))
    text = logic.sample_csv() if sample else (_read_upload() or request.form.get("signups", ""))
    try:
        rows, warnings = logic.parse_signups(text)
        result = logic.analyze(rows)
    except logic.ParseError as e:
        flash(str(e), "error")
        return redirect(url_for("feature.index"))
    except Exception:  # son güvence: kullanıcı asla sunucu hatası sayfası görmesin
        logging.getLogger(__name__).exception("analyze failed")
        flash("Sorry, this list couldn't be analyzed. Please check that it is a CSV export and try again.", "error")
        return redirect(url_for("feature.index"))
    return render_template("results.html", r=result, warnings=warnings, sample=sample)
