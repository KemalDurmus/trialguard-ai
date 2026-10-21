from flask import Blueprint, render_template, request, redirect, url_for, flash
from datetime import datetime
import logic

bp = Blueprint("feature", __name__, template_folder="templates", static_folder="static")

@bp.before_request
def before_request():
    logic.init_db(logic.DB_PATH)

@bp.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        action = request.form.get("action")

        if action == "add_trial":
            user_id = request.form.get("user_id")
            ip_address = request.form.get("ip_address")
            user_agent = request.form.get("user_agent")
            timestamp = request.form.get("timestamp")

            if not all([user_id, ip_address, user_agent, timestamp]):
                flash("Tüm alanları doldurmanız gerekmektedir.", "error")
            else:
                try:
                    logic.add_trial_entry(user_id, ip_address, user_agent, timestamp)
                    flash("Deneme kaydı başarıyla eklendi.", "success")
                except ValueError as e:
                    flash(f"Hata: {e}", "error")
                except Exception as e:
                    flash(f"Bir hata oluştu: {e}", "error")
            return redirect(url_for("feature.index"))

        elif action == "load_sample":
            try:
                sample_data = logic.generate_sample_data()
                for entry in sample_data:
                    logic.add_trial_entry(
                        entry["user_id"],
                        entry["ip_address"],
                        entry["user_agent"],
                        entry["timestamp"]
                    )
                flash(f"{len(sample_data)} örnek deneme kaydı yüklendi.", "success")
            except Exception as e:
                flash(f"Örnek veri yüklenirken hata oluştu: {e}", "error")
            return redirect(url_for("feature.index"))

        elif action == "analyze":
            try:
                flagged_accounts, analysis_summary = logic.analyze_trials()
                if flagged_accounts:
                    flash(f"Analiz tamamlandı. Potansiyel suiistimal tespit edilen kullanıcılar: {', '.join(flagged_accounts)}", "warning")
                else:
                    flash("Analiz tamamlandı. Herhangi bir suiistimal tespit edilmedi.", "success")
            except Exception as e:
                flash(f"Analiz sırasında hata oluştu: {e}", "error")
            return redirect(url_for("feature.index"))

    trials = logic.get_all_trials()
    flagged_accounts, analysis_summary = logic.analyze_trials()

    return render_template(
        "index.html",
        trials=trials,
        flagged_accounts=flagged_accounts,
        analysis_summary=analysis_summary,
        current_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
