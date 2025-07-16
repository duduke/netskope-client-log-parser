import os
import tempfile
import io
import zipfile
from flask import Flask, request, render_template, send_file, url_for
import pandas as pd
from collections import defaultdict

from parser_utils import (
    parse_log_lines,
    filter_by_minutes,
    parse_npa_log_lines,
)

app = Flask(__name__)
UPLOAD_FOLDER = tempfile.gettempdir()


def group_by_process_and_host(df: pd.DataFrame):
    grouped = defaultdict(lambda: defaultdict(int))
    for _, row in df.iterrows():
        proc = row["Process"]
        host = row["Destination Host"]
        grouped[proc][host] += 1
    return grouped


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return render_template("index.html")

    file = request.files.get("logfile")
    if not file or file.filename == "":
        return render_template("index.html", log_type_message="No file uploaded!")

    filename = file.filename
    fn_lower = filename.lower()
    minutes = request.form.get("minutes")
    minutes = int(minutes) if minutes and minutes.isdigit() else None

    # Save uploaded file
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    with open(filepath, "r", errors="ignore") as fh:
        lines = fh.readlines()

    # ── NSDEBUGLOG ──────────────────────────────────────────────────────────
    if "nsdebuglog" in fn_lower:
        log_type_message = "nsdebuglog log file detected!"

        df_tunnel, df_bypass, pop_entries, df_rtt, df_errors, steering_records, last_gateway, header_info = parse_log_lines(lines)

        if minutes is not None:
            df_tunnel, df_bypass, pop_entries, df_rtt, df_errors, steering_records = filter_by_minutes(
                df_tunnel, df_bypass, pop_entries, df_rtt, df_errors, steering_records, minutes
            )

        grouped_tunneled = group_by_process_and_host(df_tunnel)
        grouped_bypassed = group_by_process_and_host(df_bypass)

        # Dashboard stats
        stats = {
            "Log": "NS Debug",
            "Time Span (min)": minutes if minutes is not None else "All",
            "Errors": len(df_errors),
            "Tunnels": len(df_tunnel),
            "Bypasses": len(df_bypass),
        }

        # Write CSVs
        df_tunnel.to_csv(os.path.join(UPLOAD_FOLDER, "tunneled.csv"), index=False)
        df_bypass.to_csv(os.path.join(UPLOAD_FOLDER, "bypassed.csv"), index=False)
        df_rtt.to_csv(os.path.join(UPLOAD_FOLDER, "rtt.csv"), index=False)
        df_errors.to_csv(os.path.join(UPLOAD_FOLDER, "general_errors.csv"), index=False)

        return render_template(
            "results.html",
            log_type_message=log_type_message,
            stats=stats,
            header=header_info,
            last_gateway=last_gateway or "",
            pops=[line for _, line in pop_entries[-5:]] if pop_entries else [],
            df_rtt=df_rtt.to_html(classes="table table-sm", index=False),
            df_err=df_errors.to_html(classes="table table-sm", index=False),
            steering=steering_records,
            tunneled=grouped_tunneled,
            bypassed=grouped_bypassed,
        )

    # ── NPADEBUGLOG ─────────────────────────────────────────────────────────
    elif "npadebuglog" in fn_lower:
        log_type_message = "npadebuglog log file detected!"

        tenant_url, df_rtt_npa, df_err_npa, df_warn_npa, tunnel_events, policy_records = parse_npa_log_lines(lines)

        # Combine errors + warnings
        df_err_warn = pd.concat([df_err_npa, df_warn_npa]).sort_values("Timestamp")

        # Dashboard stats
        stats = {
            "Log": "NPA Debug",
            "Errors": len(df_err_warn),
            "Tunnels": len(tunnel_events),
            "Apps": len(policy_records),
        }

        # Write CSVs
        df_rtt_npa.to_csv(os.path.join(UPLOAD_FOLDER, "npa_rtt.csv"), index=False)
        df_err_warn.to_csv(os.path.join(UPLOAD_FOLDER, "npa_errors.csv"), index=False)

        return render_template(
            "npa_results.html",
            log_type_message=log_type_message,
            stats=stats,
            tenant_url=tenant_url,
            df_rtt_npa=df_rtt_npa.to_html(classes="table table-sm", index=False),
            error_table=df_err_warn.to_html(classes="table table-sm", index=False),
            tunnel_events=tunnel_events,
            policy_records=policy_records,
        )

    # ── INVALID LOG TYPE ────────────────────────────────────────────────────
    else:
        return render_template("index.html", log_type_message="invalid log file detected!")


@app.route("/download/<datatype>")
def download(datatype):
    files = {
        "tunneled": "tunneled.csv",
        "bypassed": "bypassed.csv",
        "rtt": "rtt.csv",
        "general": "general_errors.csv",
        "npa_rtt": "npa_rtt.csv",
        "npa_errors": "npa_errors.csv",
    }
    fname = files.get(datatype)
    if not fname:
        return "File not found", 404
    path = os.path.join(UPLOAD_FOLDER, fname)
    if not os.path.exists(path):
        return "File not found", 404
    return send_file(path, as_attachment=True)


@app.route("/export_all")
def export_all():
    mem = io.BytesIO()
    with zipfile.ZipFile(mem, "w") as z:
        for fname in (
            "tunneled.csv", "bypassed.csv", "rtt.csv", "general_errors.csv",
            "npa_rtt.csv", "npa_errors.csv"
        ):
            path = os.path.join(UPLOAD_FOLDER, fname)
            if os.path.exists(path):
                z.write(path, arcname=fname)
    mem.seek(0)
    return send_file(
        mem,
        download_name="all_logs_export.zip",
        as_attachment=True,
        mimetype="application/zip",
    )


if __name__ == "__main__":
    # listen on all interfaces
    app.run(host="0.0.0.0", port=5000, debug=True)
